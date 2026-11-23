// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

type pipeLauncherFunc func(ctx context.Context, path string, args, env []string, workDir string) (*ChildProcess, error)

func (f pipeLauncherFunc) Start(ctx context.Context, path string, args, env []string, workDir string) (*ChildProcess, error) {
	return f(ctx, path, args, env, workDir)
}

// TestClaudeCodeStreamJSONAndPlanTelemetry verifies ClaudeCodeCore end-to-end
// over an in-memory pipe: thinking -> reasoning.delta, TodoWrite -> plan.updated,
// assistant text -> message.delta/completed, result usage -> telemetry.updated,
// --permission-mode mapping, and authenticated loopback --mcp-config injection.
func TestClaudeCodeStreamJSONAndPlanTelemetry(t *testing.T) {
	var capturedArgs []string
	ndjson := strings.Join([]string{
		`{"type":"assistant","message":{"id":"msg_c1","content":[{"type":"thinking","thinking":"Inspecting sshd config"},{"type":"tool_use","id":"tu_todo","name":"TodoWrite","input":{"todos":[{"id":"1","content":"Check sshd -T","status":"completed"},{"id":"2","content":"Audit cloud-init","status":"in_progress"}]}}]}}`,
		`{"type":"assistant","message":{"id":"msg_c1","content":[{"type":"text","text":"SSH configuration verified."}]}}`,
		`{"type":"result","subtype":"success","result":"SSH configuration verified.","num_turns":1,"duration_ms":420,"usage":{"input_tokens":1200,"output_tokens":80,"cache_read_input_tokens":900}}`,
	}, "\n") + "\n"

	core := NewClaudeCodeCore(ClaudeCodeOptions{
		Launcher: pipeLauncherFunc(func(_ context.Context, _ string, args, _ []string, _ string) (*ChildProcess, error) {
			capturedArgs = append([]string(nil), args...)
			pr, pw := io.Pipe()
			_, cw := io.Pipe()
			go func() {
				_, _ = io.WriteString(pw, ndjson)
				_ = pw.Close()
			}()
			return NewPipeProcess(cw, pr), nil
		}),
	})

	var mu sync.Mutex
	var events []Event
	err := core.Run(context.Background(), Turn{
		SessionID:      "sess_claude_1",
		PermissionMode: operations.PermissionReadOnly,
		Messages:       []Message{{Role: RoleUser, Content: "check sshd"}},
		Tools:          []ToolSpec{{Action: "security.sshd.status", Effect: operations.EffectRead}},
		Runner: RunnerFunc(func(_ context.Context, _ ToolCall) (ToolResult, error) {
			return ToolResult{Status: ToolSucceeded, Result: json.RawMessage(`{"ok":true}`)}, nil
		}),
	}, func(e Event) error {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("ClaudeCodeCore.Run: %v", err)
	}

	// Verify read_only mapped to --permission-mode plan and --mcp-config was injected.
	joined := strings.Join(capturedArgs, " ")
	if !strings.Contains(joined, "--permission-mode plan") {
		t.Fatalf("expected --permission-mode plan, got args: %s", joined)
	}
	if !strings.Contains(joined, "--mcp-config ") {
		t.Fatalf("expected loopback --mcp-config flag, got args: %s", joined)
	}

	seen := map[string]bool{}
	for _, ev := range events {
		seen[ev.Type] = true
	}
	for _, want := range []string{EventReasoningDelta, EventPlanUpdated, EventMessageDelta, EventMessageCompleted, EventTelemetryUpdated} {
		if !seen[want] {
			t.Fatalf("missing event %q in %+v", want, events)
		}
	}
}

// TestExternalCLIHardCancelMidTurn verifies context cancellation terminates an
// external CLI turn promptly without hanging or leaking goroutines.
func TestExternalCLIHardCancelMidTurn(t *testing.T) {
	pr, pw := io.Pipe()
	_, cw := io.Pipe()
	defer pw.Close()

	core := NewClaudeCodeCore(ClaudeCodeOptions{
		Launcher: pipeLauncherFunc(func(ctx context.Context, _ string, _, _ []string, _ string) (*ChildProcess, error) {
			go func() {
				<-ctx.Done()
				_ = pw.Close()
			}()
			return NewPipeProcess(cw, pr), nil
		}),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := core.Run(ctx, Turn{
		SessionID:      "sess_cancel_1",
		PermissionMode: operations.PermissionSafe,
		Messages:       []Message{{Role: RoleUser, Content: "long check"}},
	}, func(Event) error { return nil })

	if time.Since(start) > 2*time.Second {
		t.Fatalf("cancel took too long: %v", time.Since(start))
	}
	if err != nil && !strings.Contains(err.Error(), "context") && ctx.Err() == nil {
		t.Fatalf("unexpected error on cancel: %v", err)
	}
}

// TestExternalCLIDroppedResponseEOF verifies malformed or abruptly truncated
// NDJSON / JSON-RPC streams return a structured error instead of deadlocking.
func TestExternalCLIDroppedResponseEOF(t *testing.T) {
	t.Run("claude malformed json", func(t *testing.T) {
		err := ParseClaudeStreamJSON(context.Background(), strings.NewReader("{bad-json\n"), func(Event) error { return nil })
		if err == nil {
			t.Fatal("expected error for malformed JSON")
		}
		if p := problem.From(err); p.Code != problem.PluginError {
			t.Fatalf("code = %s, want PLUGIN_ERROR", p.Code)
		}
	})

	t.Run("jsonrpc abrupt EOF", func(t *testing.T) {
		pr, pw := io.Pipe()
		cr, cw := io.Pipe()
		defer cr.Close()
		go func() { _, _ = io.Copy(io.Discard, cr) }()
		rpc := NewJSONRPCConn(context.Background(), pr, cw, nil, nil)
		go func() {
			time.Sleep(15 * time.Millisecond)
			_ = pw.Close()
		}()
		var out map[string]any
		err := rpc.Call(context.Background(), "initialize", map[string]any{}, &out)
		if err == nil {
			t.Fatal("expected error when peer closes stdout without replying")
		}
		_ = cw.Close()
		<-rpc.Done()
	})
}

// TestMCPBridgeServerReadOnlyCeilingAndAuth verifies the loopback MCP server
// rejects unauthenticated/wrong-token callers and enforces PermissionReadOnly
// fail-closed even if an external CLI attempts to invoke a write action.
func TestMCPBridgeServerReadOnlyCeilingAndAuth(t *testing.T) {
	calledWrite := false
	calledRead := false
	srv, err := StartLoopbackMCPServer(NewMCPBridge(Turn{
		SessionID:      "sess_mcp_ro",
		PermissionMode: operations.PermissionReadOnly,
		Tools: []ToolSpec{
			{Action: "monitor.cpu.read", Effect: operations.EffectRead, Summary: "Read CPU"},
			{Action: "security.fw.apply", Effect: operations.EffectWrite, Summary: "Apply FW"},
		},
		Runner: RunnerFunc(func(_ context.Context, call ToolCall) (ToolResult, error) {
			if call.Action == "security.fw.apply" {
				calledWrite = true
			}
			if call.Action == "monitor.cpu.read" {
				calledRead = true
				return ToolResult{Status: ToolSucceeded, Result: json.RawMessage(`{"cpu":12}`)}, nil
			}
			return ToolResult{Status: ToolFailed}, nil
		}),
	}, false, func(Event) error { return nil }, nil))
	if err != nil {
		t.Fatalf("StartLoopbackMCPServer: %v", err)
	}
	defer srv.Close()

	// 1. Missing or wrong Bearer token must return 401.
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// 2. tools/list under read_only must only expose the read action, never the write action.
	listReq, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBufferString(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	listReq.Header.Set("Authorization", "Bearer "+srv.Token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	listBody, _ := io.ReadAll(listResp.Body)
	_ = listResp.Body.Close()
	if strings.Contains(string(listBody), "security_fw_apply") {
		t.Fatalf("read_only tools/list leaked write tool: %s", string(listBody))
	}

	// 3. Attempting to call the write tool directly must be denied fail-closed.
	callWriteReq, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBufferString(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"security_fw_apply","arguments":{}}}`))
	callWriteReq.Header.Set("Authorization", "Bearer "+srv.Token)
	callWriteResp, err := http.DefaultClient.Do(callWriteReq)
	if err != nil {
		t.Fatalf("tools/call write: %v", err)
	}
	_ = callWriteResp.Body.Close()
	if calledWrite {
		t.Fatal("write runner was called despite read_only mode")
	}

	// 4. Valid read tool succeeds through Runner.RunTool.
	callReadReq, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBufferString(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"monitor_cpu_read","arguments":{}}}`))
	callReadReq.Header.Set("Authorization", "Bearer "+srv.Token)
	callReadResp, err := http.DefaultClient.Do(callReadReq)
	if err != nil {
		t.Fatalf("tools/call read: %v", err)
	}
	_ = callReadResp.Body.Close()
	if !calledRead {
		t.Fatal("read runner was not invoked")
	}
}

// TestPersistenceAndSlashCommandsAllSQLCores verifies real SQLite Create/Get/Reload
// across all four 0007-persisted cores (native enhanced, claude-code, codex, opencode),
// verifies direct slash command execution (/status, /skills, /mcp, /compact) via
// Service.Send without touching an external model, and confirms normalizeConfig's
// 32KiB and secret-reference guards remain strictly enforced.
func TestPersistenceAndSlashCommandsAllSQLCores(t *testing.T) {
	h, _ := newNativeHost(t, func(o *Options) {
		o.Catalog = StaticCatalog{Tools: testTools()}
	})

	// 1. Enhanced native config persists and reloads cleanly through SQLite.
	enhancedCfg := json.RawMessage(`{"model":"gpt-5","base_url":"https://api.example.com/v1","stream":true,"enable_plan_tool":true,"plan_mode":true,"reasoning_effort":"medium","active_skills":["ssh-hardening"]}`)
	rec := h.create(ownerHuman, CreateRequest{
		Title:          "Enhanced Native",
		Core:           CoreNative,
		PermissionMode: operations.PermissionSafe,
		Config:         enhancedCfg,
	})
	loaded, err := h.svc.Get(context.Background(), ownerHuman, rec.ID)
	if err != nil {
		t.Fatalf("Get native: %v", err)
	}
	if !strings.Contains(string(loaded.Config), `"enable_plan_tool":true`) || !strings.Contains(string(loaded.Config), `"ssh-hardening"`) {
		t.Fatalf("enhanced native config lost on reload: %s", string(loaded.Config))
	}

	// 2. Direct slash commands (/status, /skills, /mcp, /compact) run cleanly via Send
	// without contacting any external model endpoint.
	for _, cmd := range []string{"/status", "/skills", "/mcp", "/compact"} {
		sub := h.subscribe(ownerHuman, rec.ID)
		h.send(ownerHuman, rec.ID, cmd)
		h.waitTurn(rec.ID)
		evts := drain(sub)
		wantType := EventCommandResult
		if cmd == "/compact" {
			wantType = EventSessionCompacted
		}
		if len(eventsOfType(evts, wantType)) == 0 {
			t.Fatalf("slash command %s emitted no %s event: %+v", cmd, wantType, evts)
		}
		requireStatus(t, h.svc, ownerHuman, rec.ID, StatusIdle)
	}

	// 3. External SQL-backed cores (claude-code, codex, opencode) persist and reload cleanly.
	for _, coreName := range []CoreName{CoreClaudeCode, CoreCodex, CoreOpencode} {
		extRec := h.create(ownerHuman, CreateRequest{
			Title:          "External " + string(coreName),
			Core:           coreName,
			PermissionMode: operations.PermissionReadOnly,
			Config:         json.RawMessage(`{"plan_mode":true,"active_skills":["ssh-hardening"]}`),
		})
		got, err := h.svc.Get(context.Background(), ownerHuman, extRec.ID)
		if err != nil {
			t.Fatalf("Get %s: %v", coreName, err)
		}
		if got.Core != coreName || got.PermissionMode != operations.PermissionReadOnly {
			t.Fatalf("reloaded %s mismatch: %+v", coreName, got)
		}
	}

	// 4. Negative checks: normalizeConfig still rejects plaintext secrets, secret refs, and >32KiB.
	if _, err := h.svc.Create(context.Background(), ownerHuman, CreateRequest{
		Core:   CoreCodex,
		Config: json.RawMessage(`{"api_key":"sk-forbidden"}`),
	}); err == nil {
		t.Fatal("expected plaintext api_key in config_json to be rejected")
	}
	if _, err := h.svc.Create(context.Background(), ownerHuman, CreateRequest{
		Core:   CoreNative,
		Config: json.RawMessage(`{"api_key_secret":"sec_01ref_leak"}`),
	}); err == nil {
		t.Fatal("expected secret reference in config_json to be rejected")
	}
	oversized := `{"pad":"` + strings.Repeat("a", 33*1024) + `"}`
	if _, err := h.svc.Create(context.Background(), ownerHuman, CreateRequest{
		Core:   CoreNative,
		Config: json.RawMessage(oversized),
	}); err == nil {
		t.Fatal("expected >32KiB config_json to be rejected")
	}

	// 5. Post-0024 migration: dsh and acp are valid cores and persist cleanly; RCE config keys are rejected.
	for _, coreName := range []CoreName{CoreDSH, CoreACP} {
		created, err := h.svc.Create(context.Background(), ownerHuman, CreateRequest{
			Core:   coreName,
			Config: json.RawMessage(`{"plan_mode":true}`),
		})
		if err != nil {
			t.Fatalf("Create %s after migration 0024 failed: %v", coreName, err)
		}
		if created.Core != coreName {
			t.Fatalf("expected core %s, got %s", coreName, created.Core)
		}
	}
	for _, badCfg := range []string{
		`{"binary":"/bin/sh"}`,
		`{"args":["-c","id"]}`,
		`{"work_dir":"/etc"}`,
		`{"server_url":"http://127.0.0.1:9999"}`,
	} {
		if _, err := h.svc.Create(context.Background(), ownerHuman, CreateRequest{
			Core:   CoreCodex,
			Config: json.RawMessage(badCfg),
		}); err == nil {
			t.Fatalf("expected dangerous config %s to be rejected", badCfg)
		}
	}
}
