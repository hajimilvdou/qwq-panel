// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestValidateAgentSessionSecurityBoundary(t *testing.T) {
	cases := []struct {
		name    string
		role    string
		core    string
		mode    string
		wantErr bool
	}{
		{"admin native safe", "admin", "native", "safe", false},
		{"admin codex full", "admin", "codex", "full", false},
		{"admin claude-code safe", "admin", "claude-code", "safe", false},
		{"operator native safe", "operator", "native", "safe", false},
		{"operator native read_only", "operator", "", "read_only", false},
		{"operator native full denied", "operator", "native", "full", true},
		{"operator codex denied", "operator", "codex", "safe", true},
		{"operator claude-code denied", "operator", "claude-code", "read_only", true},
		{"operator opencode denied", "operator", "opencode", "safe", true},
		{"operator dsh denied", "operator", "dsh", "safe", true},
		{"viewer native denied", "viewer", "native", "read_only", true},
		{"empty role denied", "", "native", "read_only", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAgentSessionSecurityBoundary(tc.role, tc.core, tc.mode)
			if tc.wantErr {
				if err == nil || !problem.HasCode(err, problem.PermissionDenied) {
					t.Fatalf("got err=%v, want PERMISSION_DENIED", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildSafeClaudeDisallowedTools(t *testing.T) {
	for _, mode := range []string{"", "read_only", "safe", "custom"} {
		got := BuildSafeClaudeDisallowedTools(mode)
		for _, tool := range []string{"Bash", "Write", "Edit", "Read", "Grep", "Glob"} {
			if !strings.Contains(got, tool) {
				t.Fatalf("mode %q missing disallowed tool %q in %q", mode, tool, got)
			}
		}
	}
	if got := BuildSafeClaudeDisallowedTools("full"); got != "" {
		t.Fatalf("full mode disallowed tools = %q, want empty", got)
	}
}

func TestMergeExternalResumeConfigAndValidation(t *testing.T) {
	out, changed, err := MergeExternalResumeConfig([]byte(`{"model":"o3"}`), "external_thread_id", "thr_abc123")
	if err != nil || !changed {
		t.Fatalf("merge failed: changed=%v err=%v", changed, err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["external_thread_id"] != "thr_abc123" || m["model"] != "o3" {
		t.Fatalf("merged = %+v", m)
	}
	// Idempotent second merge
	_, changed2, err := MergeExternalResumeConfig(out, "external_thread_id", "thr_abc123")
	if err != nil || changed2 {
		t.Fatalf("expected no-op second merge, changed=%v err=%v", changed2, err)
	}
	// Reject path traversal / bad chars
	if _, _, err := MergeExternalResumeConfig(out, "resume_session_id", "../bad"); err == nil {
		t.Fatal("expected invalid resume_session_id to be rejected")
	}
}

func TestResolveCLIProviderIDWithDefault(t *testing.T) {
	defFn := func(context.Context) (string, error) { return "aip_default_1", nil }
	if got := ResolveCLIProviderIDWithDefault(t.Context(), "oauth", "aip_explicit", defFn); got != "" {
		t.Fatalf("oauth mode must return empty, got %q", got)
	}
	if got := ResolveCLIProviderIDWithDefault(t.Context(), "", "aip_explicit", defFn); got != "aip_explicit" {
		t.Fatalf("explicit provider = %q, want aip_explicit", got)
	}
	if got := ResolveCLIProviderIDWithDefault(t.Context(), "", "", defFn); got != "aip_default_1" {
		t.Fatalf("default fallback = %q, want aip_default_1", got)
	}
	if got := ResolveCLIProviderIDWithDefault(t.Context(), "provider", "", defFn); got != "aip_default_1" {
		t.Fatalf("provider mode default fallback = %q, want aip_default_1", got)
	}
}

func TestCodexAppServerResumesThreadAndPersistsID(t *testing.T) {
	var (
		mu      sync.Mutex
		methods []string
		savedID string
	)
	launcher := fakePipeLauncher{
		serve: func(in io.Reader, out io.Writer) {
			sc := bufio.NewScanner(in)
			send := func(v any) {
				b, _ := json.Marshal(v)
				_, _ = out.Write(append(b, '\n'))
			}
			for sc.Scan() {
				var env rpcEnvelope
				if json.Unmarshal(sc.Bytes(), &env) != nil {
					continue
				}
				mu.Lock()
				methods = append(methods, env.Method)
				mu.Unlock()
				switch env.Method {
				case "initialize":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"ok": true}})
				case "thread/start":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"thread": map[string]any{"id": "thr_turn1"}}})
				case "thread/resume":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"thread": map[string]any{"id": "thr_turn1"}}})
				case "turn/start":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"turnId": "trn_1"}})
					send(map[string]any{"jsonrpc": "2.0", "method": "item/agentMessage/delta", "params": map[string]any{"delta": "ok"}})
					send(map[string]any{"jsonrpc": "2.0", "method": "turn/completed", "params": map[string]any{"status": "completed"}})
					return
				}
			}
		},
	}

	// Verify NewCodexCore wires default launcher when nil (fixes nil launcher bug).
	if def := NewCodexCore(CodexOptions{}); def.launcher == nil {
		t.Fatal("NewCodexCore left launcher nil")
	}

	core := NewCodexCore(CodexOptions{Launcher: launcher})
	// Turn 1: starts thread and persists external_thread_id
	err := core.Run(t.Context(), Turn{
		SessionID:      "sess_codex_resume",
		PermissionMode: operations.PermissionSafe,
		Messages:       []Message{{Role: RoleUser, Content: "hello"}},
		PersistExternalID: func(_ context.Context, key, id string) error {
			if key == "external_thread_id" {
				savedID = id
			}
			return nil
		},
	}, func(Event) error { return nil })
	if err != nil {
		t.Fatalf("turn 1 failed: %v", err)
	}
	if savedID != "thr_turn1" {
		t.Fatalf("saved thread id = %q, want thr_turn1", savedID)
	}

	// Turn 2: calls thread/resume with persisted ID
	mu.Lock()
	methods = nil
	mu.Unlock()
	err = core.Run(t.Context(), Turn{
		SessionID:      "sess_codex_resume",
		PermissionMode: operations.PermissionSafe,
		Config:         json.RawMessage(`{"external_thread_id":"thr_turn1"}`),
		Messages:       []Message{{Role: RoleUser, Content: "follow up"}},
	}, func(Event) error { return nil })
	if err != nil {
		t.Fatalf("turn 2 failed: %v", err)
	}
	mu.Lock()
	gotMethods := append([]string(nil), methods...)
	mu.Unlock()
	foundResume := false
	for _, m := range gotMethods {
		if m == "thread/resume" {
			foundResume = true
		}
		if m == "thread/start" {
			t.Fatalf("turn 2 unexpectedly called thread/start instead of thread/resume: %v", gotMethods)
		}
	}
	if !foundResume {
		t.Fatalf("turn 2 did not call thread/resume: %v", gotMethods)
	}
}

func TestAnthropicThinkingSignaturePersistedAcrossTurns(t *testing.T) {
	// Simulate persisted assistantContent loaded back into ModelMessage on a new turn
	// with a brand-new empty AnthropicThinkingKeeper (e.g. after approval resume or restart).
	ac := assistantContent{
		ReasoningContent: "checking ports",
		ThinkingBlocks: []AnthropicThinkingBlock{
			{Type: "thinking", Thinking: "checking ports", Signature: "sig_cryptographic_abc123"},
		},
		ToolCalls: []MessageToolCall{
			{CallID: "call_1", Action: "host.system.info", Arguments: json.RawMessage(`{}`)},
		},
	}
	raw, err := json.Marshal(ac)
	if err != nil {
		t.Fatalf("marshal assistantContent: %v", err)
	}
	hist := historyMessages([]Message{
		{Role: RoleAssistant, Content: "", ContentJSON: raw},
	}, newToolNames([]ToolSpec{{Action: "host.system.info"}}))
	if len(hist) != 1 || len(hist[0].ThinkingBlocks) != 1 {
		t.Fatalf("historyMessages lost thinking blocks: %+v", hist)
	}
	keeper := NewAnthropicThinkingKeeper() // fresh keeper on turn 2!
	blocks, hasThinking := keeper.BuildAssistantMessageBlocks(hist[0])
	if !hasThinking || len(blocks) < 2 {
		t.Fatalf("expected persisted thinking signature to survive across turns: hasThinking=%v blocks=%+v", hasThinking, blocks)
	}
	if blocks[0]["type"] != "thinking" || blocks[0]["signature"] != "sig_cryptographic_abc123" {
		t.Fatalf("unexpected thinking block: %+v", blocks[0])
	}
}
