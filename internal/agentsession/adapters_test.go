// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/operations"
)

// fakePipeLauncher drives an in-memory io.Pipe protocol script without spawning
// any external OS binary, making every adapter test deterministic under -race.
type fakePipeLauncher struct {
	serve func(in io.Reader, out io.Writer)
}

func (f fakePipeLauncher) Start(_ context.Context, _ string, _, _ []string, _ string) (*ChildProcess, error) {
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	go func() {
		defer s2cW.Close()
		defer c2sR.Close()
		f.serve(c2sR, s2cW)
	}()
	return NewPipeProcess(c2sW, s2cR), nil
}

type fakeMinter struct{ next int }

func (m *fakeMinter) MintApproval(_ context.Context, _ string, _ ExternalApprovalRequest) (string, string, error) {
	m.next++
	return fmt.Sprintf("apr_%d", m.next), fmt.Sprintf("op_%d", m.next), nil
}

type adapterFakeBridge struct{ decision string }

func (b adapterFakeBridge) Wait(_ context.Context, _ string) (ApprovalDecision, error) {
	return ApprovalDecision{Decision: b.decision, Comment: "operator decided"}, nil
}

func TestCodexAppServerBidirectionalApprovalAndStreaming(t *testing.T) {
	var approvedDecision string
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
				switch env.Method {
				case "initialize":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"ok": true}})
				case "thread/start":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"thread": map[string]any{"id": "thr_1"}}})
				case "turn/start":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"turnId": "trn_1"}})
					send(map[string]any{"jsonrpc": "2.0", "method": "item/reasoning/delta", "params": map[string]any{"delta": "Checking sshd..."}})
					send(map[string]any{"jsonrpc": "2.0", "method": "turn/plan/updated", "params": map[string]any{
						"plan": []map[string]any{{"step": "Inspect sshd", "status": "completed"}, {"step": "Apply fix", "status": "in_progress"}},
					}})
					send(map[string]any{
						"jsonrpc": "2.0", "id": 99, "method": "execCommandApproval",
						"params": map[string]any{"callId": "call_1", "command": []string{"systemctl", "reload", "sshd"}, "reason": "Apply SSH config"},
					})
				default:
					// Response to our server-to-client approval request id=99
					if string(env.ID) == "99" {
						var res struct {
							Decision string `json:"decision"`
						}
						_ = json.Unmarshal(env.Result, &res)
						approvedDecision = res.Decision
						send(map[string]any{"jsonrpc": "2.0", "method": "item/agentMessage/delta", "params": map[string]any{"delta": "SSH hardened."}})
						send(map[string]any{"jsonrpc": "2.0", "method": "thread/tokenUsage/updated", "params": map[string]any{
							"input_tokens": 2000, "cached_input_tokens": 1800, "output_tokens": 120,
						}})
						send(map[string]any{"jsonrpc": "2.0", "method": "turn/completed", "params": map[string]any{"status": "completed"}})
						return
					}
				}
			}
		},
	}

	core := NewCodexCore(CodexOptions{
		Launcher: launcher,
		Minter:   &fakeMinter{},
		Bridge:   adapterFakeBridge{decision: DecisionApprove},
	})

	var mu sync.Mutex
	var events []Event
	err := core.Run(context.Background(), Turn{
		SessionID:      "sess_codex",
		PermissionMode: operations.PermissionSafe,
		Messages:       []Message{{Role: RoleUser, Content: "Harden SSH"}},
	}, func(e Event) error {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("CodexCore.Run failed: %v", err)
	}
	if approvedDecision != "accept" {
		t.Fatalf("expected Codex approval decision 'accept', got %q", approvedDecision)
	}
	wantTypes := map[string]bool{
		EventReasoningDelta:   false,
		EventPlanUpdated:      false,
		EventApprovalRequired: false,
		EventApprovalDecided:  false,
		EventMessageDelta:     false,
		EventTelemetryUpdated: false,
	}
	for _, ev := range events {
		if _, ok := wantTypes[ev.Type]; ok {
			wantTypes[ev.Type] = true
		}
	}
	for typ, seen := range wantTypes {
		if !seen {
			t.Errorf("missing expected event type %q in Codex run", typ)
		}
	}
}

func TestOpenCodeServeHTTPAndPermissionCeiling(t *testing.T) {
	var permReply string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/session":
			_, _ = w.Write([]byte(`{"id":"oc_sess_1"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/prompt_async"):
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/permission/"):
			var body struct {
				Reply string `json:"reply"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			permReply = body.Reply
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/event":
			w.Header().Set("Content-Type", "text/event-stream")
			fl, _ := w.(http.Flusher)
			writeSSE := func(payload string) {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
				if fl != nil {
					fl.Flush()
				}
			}
			writeSSE(`{"type":"message.part.updated","properties":{"delta":"Checking routes","part":{"sessionID":"oc_sess_1","id":"p1","type":"reasoning"}}}`)
			writeSSE(`{"type":"permission.asked","properties":{"id":"perm_1","sessionID":"oc_sess_1","permission":"bash","patterns":["nft flush ruleset"]}}`)
			writeSSE(`{"type":"message.part.updated","properties":{"delta":"Read-only check done.","part":{"sessionID":"oc_sess_1","id":"p2","type":"text"}}}`)
			writeSSE(`{"type":"message.part.updated","properties":{"part":{"sessionID":"oc_sess_1","id":"p3","type":"step-finish","tokens":{"input":1000,"output":80,"cache":{"read":850}}}}}`)
			writeSSE(`{"type":"session.idle","properties":{"sessionID":"oc_sess_1"}}`)
		}
	}))
	defer srv.Close()

	core := NewOpenCodeCore(OpenCodeOptions{
		Client:    srv.Client(),
		ServerURL: srv.URL,
		Minter:    &fakeMinter{},
		Bridge:    adapterFakeBridge{decision: DecisionApprove},
	})

	// Untrusted per-session server_url must be rejected to prevent SSRF.
	if err := core.Run(context.Background(), Turn{
		SessionID:      "sess_oc_ssrf",
		PermissionMode: operations.PermissionReadOnly,
		Config:         json.RawMessage(`{"server_url":"http://169.254.169.254"}`),
		Messages:       []Message{{Role: RoleUser, Content: "Check firewall"}},
	}, func(Event) error { return nil }); err == nil {
		t.Fatal("expected untrusted server_url in session config to be rejected")
	}

	// Under read_only, even with an approving bridge, host MUST decline bash mutation!
	var gotText string
	err := core.Run(context.Background(), Turn{
		SessionID:      "sess_oc",
		PermissionMode: operations.PermissionReadOnly,
		Config:         json.RawMessage(`{"transport":"serve-http"}`),
		Messages:       []Message{{Role: RoleUser, Content: "Check firewall"}},
	}, func(e Event) error {
		if e.Type == EventMessageDelta {
			gotText += e.Delta
		}
		return nil
	})
	if err != nil {
		t.Fatalf("OpenCodeCore.Run failed: %v", err)
	}
	if permReply != "reject" {
		t.Fatalf("read_only ceiling must reject permission.asked, got %q", permReply)
	}
	if !strings.Contains(gotText, "Read-only check done.") {
		t.Fatalf("unexpected OpenCode text: %q", gotText)
	}
}

func TestDSHACPAdapterAndMCPBridge(t *testing.T) {
	var permOutcome string
	launcher := fakePipeLauncher{
		serve: func(in io.Reader, out io.Writer) {
			sc := bufio.NewScanner(in)
			send := func(v any) {
				b, _ := json.Marshal(v)
				_, _ = out.Write(append(b, '\n'))
			}
			var promptID json.RawMessage
			for sc.Scan() {
				var env rpcEnvelope
				if json.Unmarshal(sc.Bytes(), &env) != nil {
					continue
				}
				switch env.Method {
				case "initialize":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"protocolVersion": 1}})
				case "session/new":
					send(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": map[string]any{"sessionId": "dsh_1"}})
				case "session/prompt":
					promptID = env.ID
					send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{
						"update": map[string]any{
							"sessionUpdate": "plan",
							"entries":       []map[string]any{{"id": "1", "content": "Audit proxy r14", "status": "completed"}},
						},
					}})
					send(map[string]any{"jsonrpc": "2.0", "id": 77, "method": "session/request_permission", "params": map[string]any{
						"toolCall": map[string]any{"toolCallId": "tc_1", "title": "Apply proxy r14", "kind": "execute"},
						"options":  []map[string]any{{"optionId": "allow_once", "kind": "allow_once"}, {"optionId": "reject_once", "kind": "reject_once"}},
					}})
				default:
					if string(env.ID) == "77" {
						permOutcome = string(env.Result)
						send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{
							"update": map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]any{"type": "text", "text": "Applied via DSH ACP."}},
						}})
						send(map[string]any{"jsonrpc": "2.0", "id": promptID, "result": map[string]any{"stopReason": "end_turn"}})
						return
					}
				}
			}
		},
	}

	core := NewDSHCore(DSHOptions{
		Launcher: launcher,
		Minter:   &fakeMinter{},
		Bridge:   adapterFakeBridge{decision: DecisionApprove},
	})
	var seenPlan, seenMsg bool
	err := core.Run(context.Background(), Turn{
		SessionID:      "sess_dsh",
		PermissionMode: operations.PermissionSafe,
		Messages:       []Message{{Role: RoleUser, Content: "Apply r14"}},
	}, func(e Event) error {
		if e.Type == EventPlanUpdated {
			seenPlan = true
		}
		if e.Type == EventMessageDelta && strings.Contains(e.Delta, "Applied via DSH ACP") {
			seenMsg = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("DSHCore.Run failed: %v", err)
	}
	if !seenPlan || !seenMsg || !strings.Contains(permOutcome, "allow_once") {
		t.Fatalf("DSH ACP check failed: seenPlan=%v seenMsg=%v permOutcome=%s", seenPlan, seenMsg, permOutcome)
	}
}

func TestNativeCompactionSkillsAndSlashCommands(t *testing.T) {
	// 1. Compaction preserves tool-call pairing and shrinks older messages.
	history := []ModelMessage{
		{Role: LoopRoleSystem, Content: "System base prompt"},
		{Role: LoopRoleUser, Content: strings.Repeat("old user context ", 40)},
		{Role: LoopRoleAssistant, Content: strings.Repeat("old answer ", 40)},
		{Role: LoopRoleUser, Content: "Check ports"},
		{Role: LoopRoleAssistant, Content: "Checking", ToolCalls: []ModelToolCall{{CallID: "c1", Name: "read_ports", Arguments: json.RawMessage(`{}`)}}},
		{Role: LoopRoleTool, ToolCallID: "c1", Content: `{"ports":[22,443]}`},
		{Role: LoopRoleAssistant, Content: "Ports 22 and 443 are open."},
	}
	compacted, res, err := CompactTranscript(context.Background(), history, CompactionOptions{KeepRecentMessages: 4}, nil)
	if err != nil {
		t.Fatalf("CompactTranscript error: %v", err)
	}
	if res.DroppedMessages < 2 || len(compacted) >= len(history) {
		t.Fatalf("expected compaction to fold older turns, got dropped=%d len=%d", res.DroppedMessages, len(compacted))
	}

	// 2. Skills registry includes all 5 built-in VPS skills and parses SKILL.md.
	reg := NewSkillRegistry()
	if len(reg.List()) < 5 {
		t.Fatalf("expected at least 5 built-in VPS skills")
	}
	parsed := ParseSkillMarkdown("custom-tls", "个人", "", "---\nname: Custom TLS\ndescription: Check ACME\n---\nAlways check cert expiry.")
	if parsed.Name != "Custom TLS" || !strings.Contains(parsed.Instructions, "ACME") && !strings.Contains(parsed.Instructions, "cert expiry") {
		t.Fatalf("unexpected parsed SKILL.md: %+v", parsed)
	}

	// 3. Plaintext secret env is blocked by SanitizedEnv.
	if _, err := SanitizedEnv([]string{"QWQ_MASTER_KEY=leak"}); err == nil {
		t.Fatalf("expected SanitizedEnv to block host secret variable")
	}
}

func TestLoopbackMCPServerAuthAndRunner(t *testing.T) {
	called := false
	turn := Turn{
		SessionID:      "sess_mcp",
		PermissionMode: operations.PermissionSafe,
		Tools: []ToolSpec{
			{Action: "monitor.basic/stats.read", Summary: "Read host stats", Effect: "read", Risk: "low"},
		},
		Runner: RunnerFunc(func(_ context.Context, call ToolCall) (ToolResult, error) {
			called = true
			return ToolResult{Status: ToolSucceeded, Result: json.RawMessage(`{"cpu":19.6}`)}, nil
		}),
	}
	srv, err := StartLoopbackMCPServer(NewMCPBridge(turn, false, nil, nil))
	if err != nil {
		t.Fatalf("StartLoopbackMCPServer: %v", err)
	}
	defer srv.Close()

	// 1. Missing bearer token must be rejected with 401.
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("unauth POST failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without bearer token, got %d", resp.StatusCode)
	}

	// 2. Valid bearer token executes tools/call through Runner.
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"monitor_basic_stats_read","arguments":{}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+srv.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("auth POST failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !called {
		t.Fatalf("expected 200 and runner called, got status=%d called=%v", resp.StatusCode, called)
	}
}
