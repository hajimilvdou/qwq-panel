// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
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
	s.cores[string(CoreNative)] = NewEnhancedNativeCore(nativeOpts, skills)
	s.cores[string(CoreClaudeCode)] = NewClaudeCodeCore(ClaudeCodeOptions{
		Bridge:    opts.Approvals,
		Providers: s,
		Skills:    skills,
	})
	s.cores[string(CoreCodex)] = NewCodexCore(CodexOptions{
		Bridge:    opts.Approvals,
		Providers: s,
		Skills:    skills,
	})
	s.cores[string(CoreOpencode)] = NewOpenCodeCore(OpenCodeOptions{
		Bridge:    opts.Approvals,
		Providers: s,
		Skills:    skills,
	})
	s.cores[string(CoreDSH)] = NewDSHCore(DSHOptions{
		Bridge:    opts.Approvals,
		Providers: s,
		Skills:    skills,
	})
	s.cores[string(CoreACP)] = NewGenericACPCore(GenericACPOptions{
		CoreName:    CoreACP,
		DisplayName: "Generic ACP Agent",
		Bridge:      opts.Approvals,
		Providers:   s,
		Skills:      skills,
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
	case "status", "compact", "skills", "mcp", "help":
		return true
	default:
		return false
	}
}

// tryHandleSlashCommand intercepts panel-wide direct slash commands
// (/status, /compact, /skills, /mcp, /help) at turn start so they run against
// the host session runtime deterministically without calling an external LLM.
func (s *Service) tryHandleSlashCommand(ctx context.Context, rt *sessionRuntime, sess Session, hist []Message, tools []ToolSpec) bool {
	prompt := latestUserMessage(hist)
	name, _, ok := ParseSlashCommand(prompt)
	if !ok {
		return false
	}
	emit := func(e Event) error { return s.emit(ctx, rt, e) }
	switch name {
	case "status":
		res := CommandResult{
			Command: "/status",
			OK:      true,
			Summary: fmt.Sprintf("核心 %s · 权限模式 %s · 历史消息 %d 条 · 已挂载宿主工具 %d 项",
				sess.Core, sess.PermissionMode, len(hist), len(tools)),
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
			Summary: "可用快捷指令：/status（会话状态）、/compact（压缩上下文）、/skills（查看运维技能）、/mcp（查看宿主授权工具）、/help（帮助）",
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
