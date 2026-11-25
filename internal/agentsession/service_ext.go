// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// registerDefaultAdapterCores wires the upgraded Native core plus Claude Code,
// Codex, OpenCode, DSH (DeepSeek Harness), and Generic ACP adapters onto Service.
// Caller-supplied opts.Cores run afterward and may override any entry.
func (s *Service) registerDefaultAdapterCores(opts Options) {
	skills := NewSkillRegistry()
	nativeOpts := NativeOptions{
		Secrets:             opts.Secrets,
		Client:              opts.HTTPClient,
		Logger:              opts.Logger,
		Providers:           s,
		MaxSteps:            opts.Native.MaxSteps,
		Timeout:             opts.Native.Timeout,
		Gate:                opts.Native.Gate,
		EgressAllowPrefixes: opts.Native.EgressAllowPrefixes,
		EgressAllowAddrs:    opts.Native.EgressAllowAddrs,
	}
	minter := opts.ApprovalMinter
	if minter == nil {
		if m, ok := opts.Approvals.(HostApprovalMinter); ok {
			minter = m
		}
	}
	nativeCore := NewEnhancedNativeCore(nativeOpts, skills)
	nativeCore.SetWorkspace(s.workspace)
	nativeCore.SetExchange(s.exchange)
	nativeCore.SetApprovalWiring(minter, opts.Approvals, opts.RoleResolver)
	s.cores[string(CoreNative)] = nativeCore
	s.cores[string(CoreClaudeCode)] = NewClaudeCodeCore(ClaudeCodeOptions{
		Bridge:    opts.Approvals,
		Providers: s,
		Skills:    skills,
		Auth:      s.cliAuth,
		Workspace: s.workspace,
	})
	s.cores[string(CoreCodex)] = NewCodexCore(CodexOptions{
		Minter:    minter,
		Bridge:    opts.Approvals,
		Providers: s,
		Skills:    skills,
		Auth:      s.cliAuth,
		Workspace: s.workspace,
	})
	s.cores[string(CoreOpencode)] = NewOpenCodeCore(OpenCodeOptions{
		Minter:    minter,
		Bridge:    opts.Approvals,
		Providers: s,
		Skills:    skills,
		Auth:      s.cliAuth,
	})
	s.cores[string(CoreDSH)] = NewDSHCore(DSHOptions{
		Minter:    minter,
		Bridge:    opts.Approvals,
		Providers: s,
		Skills:    skills,
		Auth:      s.cliAuth,
	})
	s.cores[string(CoreACP)] = NewGenericACPCore(GenericACPOptions{
		CoreName:    CoreACP,
		DisplayName: "Generic ACP Agent",
		Minter:      minter,
		Bridge:      opts.Approvals,
		Providers:   s,
		Skills:      skills,
		Auth:        s.cliAuth,
	})
}

// isDirectSlashCommand reports whether content is one of the panel-wide host
// slash commands handled deterministically by tryHandleSlashCommand without
// invoking an external LLM or CLI binary.
func isDirectSlashCommand(content string) bool {
	name, _, ok := ParseSlashCommand(content)
	if !ok {
		return false
	}
	switch name {
	case "status", "compact", "plan", "mode", "model", "effort", "context", "skills", "mcp", "help":
		return true
	default:
		return false
	}
}

// tryHandleSlashCommand intercepts panel-wide direct slash commands
// (/status, /compact, /plan, /mode, /model, /effort, /context, /skills, /mcp, /help)
// at turn start so they run against the host session runtime deterministically
// without calling an external LLM.
func (s *Service) tryHandleSlashCommand(ctx context.Context, rt *sessionRuntime, sess Session, hist []Message, tools []ToolSpec) bool {
	prompt := latestUserMessage(hist)
	name, args, ok := ParseSlashCommand(prompt)
	if !ok {
		return false
	}
	emit := func(e Event) error { return s.emit(ctx, rt, e) }
	owner := rt.owner()
	switch name {
	case "status":
		var cfg struct {
			Model            string `json:"model"`
			ReasoningEffort  string `json:"reasoning_effort"`
			MaxContextTokens int64  `json:"max_context_tokens"`
			PlanMode         bool   `json:"plan_mode"`
		}
		_ = json.Unmarshal(sess.Config, &cfg)
		extra := ""
		if cfg.Model != "" {
			extra += " · 模型 " + cfg.Model
		}
		if cfg.ReasoningEffort != "" {
			extra += " · 思考 " + cfg.ReasoningEffort
		}
		if cfg.MaxContextTokens > 0 {
			extra += " · 上下文 " + FormatContextTokensLabel(cfg.MaxContextTokens)
		} else {
			ctxTok, matched, prof := ResolveContextWindow(cfg.Model, 0)
			if matched {
				extra += fmt.Sprintf(" · 上下文 %s（自动匹配 %s）", FormatContextTokensLabel(ctxTok), prof.Family)
			} else {
				extra += " · 上下文 " + FormatContextTokensLabel(ctxTok) + "（自动默认）"
			}
		}
		if cfg.PlanMode {
			extra += " · 计划模式开"
		}
		res := CommandResult{
			Command: "/status",
			OK:      true,
			Summary: fmt.Sprintf("核心 %s · 权限模式 %s%s · 历史消息 %d 条 · 已挂载宿主工具 %d 项",
				sess.Core, sess.PermissionMode, extra, len(hist), len(tools)),
		}
		_ = emitExtended(emit, EventCommandResult, res)
		return true

	case "compact":
		cp, compRes, err := BuildCompactionCheckpoint(ctx, hist, CompactionOptions{}, nil)
		if err != nil {
			_ = emitExtended(emit, EventCommandResult, CommandResult{
				Command: "/compact", OK: false, Summary: "压缩失败：" + err.Error(),
			})
			return true
		}
		if compRes.DroppedMessages > 0 {
			if pErr := s.persistCompactionCheckpoint(ctx, rt, cp); pErr != nil {
				_ = emitExtended(emit, EventCommandResult, CommandResult{
					Command: "/compact", OK: false, Summary: "持久化压缩检查点失败：" + pErr.Error(),
				})
				return true
			}
		}
		_ = emitExtended(emit, EventSessionCompacted, compRes)
		return true

	case "plan":
		var cur struct {
			PlanMode bool `json:"plan_mode"`
		}
		_ = json.Unmarshal(sess.Config, &cur)
		next := !cur.PlanMode
		if strings.EqualFold(args, "on") || strings.EqualFold(args, "true") {
			next = true
		} else if strings.EqualFold(args, "off") || strings.EqualFold(args, "false") {
			next = false
		}
		patch, _ := json.Marshal(map[string]any{"plan_mode": next})
		if _, err := s.Update(ctx, owner, sess.ID, UpdateRequest{Config: patch}); err != nil {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/plan", OK: false, Summary: "切换计划模式失败：" + err.Error()})
			return true
		}
		msg := "已开启计划模式（锁定只读，优先输出执行清单与方案）"
		if !next {
			msg = "已关闭计划模式，恢复当前会话授权级别"
		}
		_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/plan", OK: true, Summary: msg})
		return true

	case "mode":
		m := operations.PermissionMode(strings.TrimSpace(args))
		if !m.Valid() || m == operations.PermissionCustom {
			_ = emitExtended(emit, EventCommandResult, CommandResult{
				Command: "/mode", OK: false, Summary: "用法：/mode <read_only|safe|full>",
			})
			return true
		}
		if s.roleResolver == nil && (m == operations.PermissionFull || sess.Core != CoreNative) {
			_ = emitExtended(emit, EventCommandResult, CommandResult{
				Command: "/mode", OK: false, Summary: "宿主权限解析器未就绪，已拒绝切换到高权限模式。",
			})
			return true
		}
		if berr := s.enforceSecurityBoundary(ctx, owner, sess.Core, m); berr != nil {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/mode", OK: false, Summary: problem.From(berr).Detail})
			return true
		}
		if _, err := s.Update(ctx, owner, sess.ID, UpdateRequest{PermissionMode: m}); err != nil {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/mode", OK: false, Summary: "切换权限模式失败：" + err.Error()})
			return true
		}
		_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/mode", OK: true, Summary: fmt.Sprintf("已切换权限模式为 %s", m)})
		return true

	case "model":
		fields := strings.Fields(args)
		if len(fields) == 0 {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/model", OK: false, Summary: "用法：/model <模型名> [思考挡位，可填任意自定义代号或 auto]"})
			return true
		}
		delta := map[string]any{"model": fields[0]}
		if len(fields) > 1 {
			rawEff := strings.TrimSpace(fields[1])
			if strings.EqualFold(rawEff, "auto") || strings.EqualFold(rawEff, "reset") {
				delta["reasoning_effort"] = ""
			} else {
				eff, err := ValidateReasoningEffort(rawEff, "/config/reasoning_effort")
				if err != nil {
					_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/model", OK: false, Summary: "思考挡位仅支持字母、数字及 . _ - : /（最长 48 字符）"})
					return true
				}
				delta["reasoning_effort"] = eff
			}
		}
		patch, _ := json.Marshal(delta)
		if _, err := s.Update(ctx, owner, sess.ID, UpdateRequest{Config: patch}); err != nil {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/model", OK: false, Summary: "切换模型失败：" + err.Error()})
			return true
		}
		summary := fmt.Sprintf("已切换推理模型为 %s", fields[0])
		if eff, ok := delta["reasoning_effort"].(string); ok && eff != "" {
			summary += "（自定义思考挡位：" + eff + "）"
		} else {
			resolved, matched, prof := ResolveReasoningEffort(fields[0], "")
			if matched {
				summary += fmt.Sprintf("（思考自动匹配 %s → %s", prof.Family, resolved)
			} else {
				summary += fmt.Sprintf("（思考默认 %s", resolved)
			}
			ctxTok, ctxMatched, _ := ResolveContextWindow(fields[0], 0)
			if ctxMatched {
				summary += " · 上下文自动 " + FormatContextTokensLabel(ctxTok) + "）"
			} else {
				summary += " · 上下文默认 " + FormatContextTokensLabel(ctxTok) + "）"
			}
		}
		_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/model", OK: true, Summary: summary})
		return true

	case "effort":
		rawEff := strings.TrimSpace(args)
		if rawEff == "" {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/effort", OK: false, Summary: "用法：/effort <自定义挡位代号，如 minimal/low/medium/high/xhigh/max/16384 或 auto>"})
			return true
		}
		eff := ""
		if !strings.EqualFold(rawEff, "auto") && !strings.EqualFold(rawEff, "reset") {
			var err error
			eff, err = ValidateReasoningEffort(rawEff, "/config/reasoning_effort")
			if err != nil {
				_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/effort", OK: false, Summary: "思考挡位仅支持字母、数字及 . _ - : /（最长 48 字符）"})
				return true
			}
		}
		patch, _ := json.Marshal(map[string]any{"reasoning_effort": eff})
		if _, err := s.Update(ctx, owner, sess.ID, UpdateRequest{Config: patch}); err != nil {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/effort", OK: false, Summary: "设置思考挡位失败：" + err.Error()})
			return true
		}
		msg := fmt.Sprintf("已将思考挡位设为自定义：%s", eff)
		if eff == "" {
			msg = "已恢复自动匹配思考挡位（命中内置模型清单时自动套用，未命中默认 high）"
		}
		_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/effort", OK: true, Summary: msg})
		return true

	case "context":
		raw := strings.ToLower(strings.TrimSpace(args))
		if raw == "" {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/context", OK: false, Summary: "用法：/context <tokens|auto>，例如 /context auto、/context 200k、/context 1m"})
			return true
		}
		var val int64
		if raw == "auto" || raw == "reset" || raw == "0" {
			val = 0
		} else {
			mult := int64(1)
			if strings.HasSuffix(raw, "k") {
				mult = 1000
				raw = strings.TrimSuffix(raw, "k")
			} else if strings.HasSuffix(raw, "m") {
				mult = 1_000_000
				raw = strings.TrimSuffix(raw, "m")
			}
			n, perr := strconv.ParseInt(raw, 10, 64)
			if perr != nil {
				_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/context", OK: false, Summary: "用法：/context <tokens|auto>，例如 /context auto、/context 128k 或 /context 1m"})
				return true
			}
			var verr error
			val, verr = ValidateMaxContextTokens(n*mult, "/config/max_context_tokens")
			if verr != nil {
				_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/context", OK: false, Summary: "上下文大小需为 0（自动）或 1024 ~ 10000000 之间"})
				return true
			}
		}
		patch, _ := json.Marshal(map[string]any{"max_context_tokens": val})
		if _, err := s.Update(ctx, owner, sess.ID, UpdateRequest{Config: patch}); err != nil {
			_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/context", OK: false, Summary: "设置上下文窗口失败：" + err.Error()})
			return true
		}
		msg := fmt.Sprintf("已将上下文窗口大小设为 %s（%d tokens）", FormatContextTokensLabel(val), val)
		if val == 0 {
			msg = "已恢复自动匹配上下文窗口（识别模型名自动选择，未命中默认 128K）"
		}
		_ = emitExtended(emit, EventCommandResult, CommandResult{Command: "/context", OK: true, Summary: msg})
		return true

	case "skills":
		list := s.BuiltinSkills()
		names := make([]string, 0, len(list))
		for _, sk := range list {
			names = append(names, sk.ID)
		}
		_ = emitExtended(emit, EventCommandResult, CommandResult{
			Command: "/skills",
			OK:      true,
			Summary: fmt.Sprintf("内置 %d 项 VPS 运维技能：%s", len(list), strings.Join(names, ", ")),
		})
		return true

	case "mcp":
		names := make([]string, 0, len(tools))
		for _, t := range tools {
			names = append(names, t.Action)
		}
		summary := fmt.Sprintf("宿主 MCP 工具桥当前已授权 %d 项动作（严格受 %s 权限模式约束）", len(tools), sess.PermissionMode)
		if len(names) > 0 {
			limit := len(names)
			if limit > 6 {
				limit = 6
			}
			summary += "：" + strings.Join(names[:limit], ", ")
		}
		_ = emitExtended(emit, EventCommandResult, CommandResult{
			Command: "/mcp", OK: true, Summary: summary,
		})
		return true

	case "help":
		_ = emitExtended(emit, EventCommandResult, CommandResult{
			Command: "/help",
			OK:      true,
			Summary: "可用快捷指令：/status、/compact、/plan [on|off]、/mode <read_only|safe|full>、/model <名称> [挡位]、/effort <none|low|medium|high|xhigh>、/context <大小>、/skills、/mcp、/help",
		})
		return true

	default:
		return false
	}
}

// CoreDescriptors returns live binary-availability and capability descriptors
// for every registered core (`native`, `codex`, `opencode`, `dsh`, `acp`, ...).
func (s *Service) CoreDescriptors(ctx context.Context) []CoreDescriptor {
	order := []CoreName{CoreNative, CoreCodex, CoreOpencode, CoreDSH, CoreClaudeCode, CoreACP}
	seen := map[CoreName]bool{}
	out := make([]CoreDescriptor, 0, len(s.cores))
	appendCore := func(name CoreName) {
		c, ok := s.cores[string(name)]
		if !ok || seen[name] {
			return
		}
		seen[name] = true
		if cc, ok := c.(CapableCore); ok {
			out = append(out, cc.Descriptor(ctx))
			return
		}
		out = append(out, CoreDescriptor{Name: name, DisplayName: string(name), Protocol: "custom", Available: true})
	}
	for _, n := range order {
		appendCore(n)
	}
	for k := range s.cores {
		appendCore(CoreName(k))
	}
	return out
}

// BuiltinSkills exposes the host's built-in VPS operational skills.
func (s *Service) BuiltinSkills() []SkillSpec {
	return NewSkillRegistry().List()
}

// CompactSession summarizes older messages in a session via CompactionEngine,
// persists the compaction checkpoint in agent_sessions.config_json so it takes
// effect across subsequent turns and host restarts, and leaves immutable
// transcript/audit rows untouched.
func (s *Service) CompactSession(ctx context.Context, owner actor.Actor, sessionID string) (CompactionResult, error) {
	rec, err := s.loadFor(ctx, owner, sessionID)
	if err != nil {
		return CompactionResult{}, err
	}
	if rec.Status.Busy() {
		return CompactionResult{}, problem.New(problem.StateConflict, "Cannot compact while a turn is running.")
	}
	hist, err := s.messages(ctx, rec.ID, 0, s.cfg.MaxHistory)
	if err != nil {
		return CompactionResult{}, err
	}
	cp, res, err := BuildCompactionCheckpoint(ctx, hist, CompactionOptions{}, nil)
	if err != nil {
		return CompactionResult{}, err
	}
	rt := s.runtimeFor(rec)
	if res.DroppedMessages > 0 {
		if err := s.persistCompactionCheckpoint(ctx, rt, cp); err != nil {
			return CompactionResult{}, err
		}
	}
	raw, _ := json.Marshal(res)
	_ = s.emit(ctx, rt, Event{Type: EventSessionCompacted, SessionID: rec.ID, Result: raw})
	return res, nil
}

// persistCompactionCheckpoint merges compaction_checkpoint into the session's
// config_json in SQLite (bumping revision) and updates the live runtime snapshot.
func (s *Service) persistCompactionCheckpoint(ctx context.Context, rt *sessionRuntime, cp CompactionCheckpoint) error {
	sess := rt.snapshot()
	owner := rt.owner()
	var updatedCfg json.RawMessage
	var updatedRev string
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		cur, err := loadSessionFor(ctx, tx, owner, sess.ID)
		if err != nil {
			return err
		}
		obj := map[string]any{}
		if len(cur.Config) > 0 {
			_ = json.Unmarshal(cur.Config, &obj)
		}
		obj["compaction_checkpoint"] = cp
		raw, err := json.Marshal(obj)
		if err != nil {
			return problem.Wrap(err)
		}
		if len(raw) > maxConfigBytes {
			return problem.New(problem.ValidationFailed, "Session config_json with compaction checkpoint exceeds 32 KiB.")
		}
		tx.SetOrigin(storage.Origin{Actor: owner})
		rev, err := tx.Changed(ctx, storage.Change{
			Subject:  sessionSubject(cur.ID),
			Kind:     storage.Updated,
			Pointers: []string{"/config"},
		})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_sessions SET config_json = ?, updated_at = ?, revision = ? WHERE session_id = ?`,
			string(raw), storage.FormatTime(tx.Now()), rev, cur.ID); err != nil {
			return fmt.Errorf("agentsession: persist compaction checkpoint: %w", err)
		}
		updatedCfg = raw
		updatedRev = storage.Revision(rev)
		return nil
	})
	if err != nil {
		return problem.From(err)
	}
	rt.mu.Lock()
	rt.session.Config = updatedCfg
	rt.session.Revision = updatedRev
	rt.mu.Unlock()
	return nil
}

// persistExternalResumeID merges an external CLI session/thread identifier into
// agent_sessions.config_json in SQLite and updates the live runtime snapshot so
// turn 2+ resumes the external conversation automatically.
func (s *Service) persistExternalResumeID(ctx context.Context, rt *sessionRuntime, key, externalID string) error {
	externalID = strings.TrimSpace(externalID)
	if externalID == "" || key == "" {
		return nil
	}
	sess := rt.snapshot()
	owner := rt.owner()
	var updatedCfg json.RawMessage
	var updatedRev string
	var changed bool
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		cur, err := loadSessionFor(ctx, tx, owner, sess.ID)
		if err != nil {
			return err
		}
		nextRaw, didChange, err := MergeExternalResumeConfig(cur.Config, key, externalID)
		if err != nil || !didChange {
			return err
		}
		tx.SetOrigin(storage.Origin{Actor: owner})
		rev, err := tx.Changed(ctx, storage.Change{
			Subject:  sessionSubject(cur.ID),
			Kind:     storage.Updated,
			Pointers: []string{"/config"},
		})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_sessions SET config_json = ?, updated_at = ?, revision = ? WHERE session_id = ?`,
			string(nextRaw), storage.FormatTime(tx.Now()), rev, cur.ID); err != nil {
			return fmt.Errorf("agentsession: persist external resume id: %w", err)
		}
		updatedCfg = nextRaw
		updatedRev = storage.Revision(rev)
		changed = true
		return nil
	})
	if err != nil {
		return problem.From(err)
	}
	if changed {
		rt.mu.Lock()
		rt.session.Config = updatedCfg
		rt.session.Revision = updatedRev
		rt.mu.Unlock()
	}
	return nil
}
