// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
)

// newNativeHost opens a host with a real secret store.
func newNativeHost(t *testing.T, tune ...func(*Options)) (*testHost, *secrets.Store) {
	t.Helper()
	keyDir := t.TempDir()
	var store *secrets.Store
	h := newTestHost(t, append(tune, func(o *Options) {
		// The fake model listens on loopback, which the default client refuses.
		o.HTTPClient = &http.Client{}
		keys, err := secrets.LoadKeyRing(keyDir)
		if err != nil {
			t.Fatalf("keys: %v", err)
		}
		st, err := secrets.New(secrets.Options{DB: o.DB, Keys: keys})
		if err != nil {
			t.Fatalf("secrets.New: %v", err)
		}
		store = st
		o.Secrets = st
	})...)
	return h, store
}

// modelReply is one scripted chat-completions answer.
type modelReply struct {
	status  int
	body    string
	content string
}

// modelServer is a fake OpenAI-compatible endpoint that records every request.
type modelServer struct {
	t        *testing.T
	mu       sync.Mutex
	requests []map[string]any
	auth     []string
	replies  []modelReply
	calls    int
	srv      *httptest.Server
}

// newModelServer starts the fake endpoint. Replies are served in order; the last
// one repeats.
func newModelServer(t *testing.T, replies ...modelReply) *modelServer {
	t.Helper()
	m := &modelServer{t: t, replies: replies}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read model request: %v", err)
			return
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Errorf("model request is not JSON: %v", err)
		}
		m.mu.Lock()
		m.requests = append(m.requests, doc)
		m.auth = append(m.auth, r.Header.Get("Authorization"))
		idx := m.calls
		m.calls++
		if idx >= len(m.replies) {
			idx = len(m.replies) - 1
		}
		reply := m.replies[idx]
		m.mu.Unlock()
		if reply.status != 0 && reply.status != http.StatusOK {
			w.WriteHeader(reply.status)
			_, _ = w.Write([]byte(reply.body))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case reply.content != "":
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, reply.content)
		default:
			_, _ = io.WriteString(w, reply.body)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

// request returns one recorded request body.
func (m *modelServer) request(i int) map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i >= len(m.requests) {
		m.t.Fatalf("model request %d missing (have %d)", i, len(m.requests))
	}
	return m.requests[i]
}

func (m *modelServer) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *modelServer) authorizations() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.auth...)
}

// nativeConfigJSON builds a session config for the fake server. It never
// carries a key: the key is stored with Service.SetAPIKey.
func nativeConfigJSON(url, model string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"base_url": url, "model": model})
	return raw
}

// toolCallReply is a model answer that proposes one function call.
func toolCallReply(id, name, args string) modelReply {
	return modelReply{body: fmt.Sprintf(
		`{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}]},"finish_reason":"tool_calls"}]}`,
		id, name, args)}
}

// TestNativeCoreToolCallRoundTrip runs the built-in core against a fake
// OpenAI-compatible endpoint: tool call, host runner, tool result, final text.
func TestNativeCoreToolCallRoundTrip(t *testing.T) {
	var runnerCalls int
	runner := &fakeRunner{fn: func(ctx context.Context, call ToolCall) (ToolResult, error) {
		runnerCalls++
		if call.Action != "host.users.list" {
			t.Errorf("runner action = %q", call.Action)
		}
		if string(call.Args) != `{"limit":5}` {
			t.Errorf("runner args = %s", call.Args)
		}
		return ToolResult{Status: ToolSucceeded, Result: json.RawMessage(`{"users":3}`)}, nil
	}}
	h, _ := newNativeHost(t, func(o *Options) {
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = runner
	})
	model := newModelServer(t,
		toolCallReply("call_1", "host_users_list", `{"limit":5}`),
		modelReply{content: "There are three users."},
	)
	rec := h.create(ownerHuman, CreateRequest{Config: nativeConfigJSON(model.srv.URL, "test-model")})
	h.setAPIKey(ownerHuman, rec.ID, "sk-secret-value")
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "how many users?")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusIdle)

	if runnerCalls != 1 {
		t.Fatalf("runner calls = %d", runnerCalls)
	}
	if model.callCount() != 2 {
		t.Fatalf("model calls = %d, want 2", model.callCount())
	}
	if auth := model.authorizations(); len(auth) != 2 || auth[0] != "Bearer sk-secret-value" {
		t.Fatalf("authorization headers = %v", auth)
	}
	// The first request offers the sanitized function names and no history.
	first := model.request(0)
	if first["model"] != "test-model" {
		t.Fatalf("model = %v", first["model"])
	}
	tools, _ := first["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools = %v", tools)
	}
	name := toolFunctionName(t, tools[0])
	if name != "host_users_list" {
		t.Fatalf("first tool name = %q", name)
	}
	if toolFunctionName(t, tools[1]) != "host_users_create" {
		t.Fatalf("second tool name = %q", toolFunctionName(t, tools[1]))
	}
	// The second request carries the assistant tool call and its result back.
	second := model.request(1)
	msgs, _ := second["messages"].([]any)
	var sawCall, sawResult bool
	var callID any
	for _, raw := range msgs {
		msg, _ := raw.(map[string]any)
		if tc, ok := msg["tool_calls"].([]any); ok && len(tc) > 0 {
			sawCall = true
			callID = tc[0].(map[string]any)["id"]
		}
		if msg["role"] == RoleTool && msg["tool_call_id"] == callID {
			sawResult = true
		}
	}
	if !sawCall || !sawResult {
		t.Fatalf("second request lost the tool pairing: %s", mustJSON(t, msgs))
	}

	events := drain(sub)
	requireEvents(t, events, EventToolCall, 1)
	requireEvents(t, events, EventToolResult, 1)
	requireEvents(t, events, EventTurnCompleted, 1)
	if eventsOfType(events, EventToolResult)[0].Status != string(ToolSucceeded) {
		t.Fatalf("tool result = %+v", eventsOfType(events, EventToolResult)[0])
	}
	msgs2, err := h.svc.Messages(context.Background(), ownerHuman, rec.ID, 0)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs2) != 4 {
		t.Fatalf("messages = %d, want 4 (%+v)", len(msgs2), msgs2)
	}
	if msgs2[3].Role != RoleAssistant || !strings.Contains(msgs2[3].Content, "three users") {
		t.Fatalf("final message = %+v", msgs2[3])
	}
	// The key never reached the transcript.
	for _, m := range msgs2 {
		if strings.Contains(m.Content, "sk-secret-value") {
			t.Fatalf("secret leaked into message %+v", m)
		}
	}
}

// toolFunctionName extracts tools[i].function.name.
func toolFunctionName(t *testing.T, raw any) string {
	t.Helper()
	tool, _ := raw.(map[string]any)
	fn, _ := tool["function"].(map[string]any)
	name, _ := fn["name"].(string)
	return name
}

// TestNativeCoreNotConfigured checks the clear UNAVAILABLE before a message is
// stored.
func TestNativeCoreNotConfigured(t *testing.T) {
	h, _ := newNativeHost(t)
	rec := h.create(ownerHuman, defaultCreate())
	_, err := h.svc.Send(context.Background(), ownerHuman, rec.ID, SendRequest{Content: "hi"})
	requireCode(t, err, problem.Unavailable)
	if !strings.Contains(problem.From(err).Detail, "base_url") {
		t.Fatalf("detail = %q", problem.From(err).Detail)
	}
	msgs, err := h.svc.Messages(context.Background(), ownerHuman, rec.ID, 0)
	if err != nil || len(msgs) != 0 {
		t.Fatalf("messages = %+v, %v", msgs, err)
	}
	// A key that cannot be resolved fails the turn asynchronously with
	// UNAVAILABLE (the secret row can disappear after the key was set, e.g.
	// with a database restored without it).
	rec2 := h.create(ownerHuman, CreateRequest{Config: nativeConfigJSON("https://model.example.test", "m")})
	h.setAPIKey(ownerHuman, rec2.ID, "sk-vanished")
	h.exec(`DELETE FROM secrets WHERE owner = ?`, "agent_sessions/"+rec2.ID)
	sub := h.subscribe(ownerHuman, rec2.ID)
	h.send(ownerHuman, rec2.ID, "hi")
	h.waitTurn(rec2.ID)
	events := drain(sub)
	requireEvents(t, events, EventError, 1)
	if e := eventsOfType(events, EventError)[0]; e.Code != string(problem.Unavailable) || !strings.Contains(e.Detail, "/api-key") {
		t.Fatalf("error = %+v", e)
	}
	requireStatus(t, h.svc, ownerHuman, rec2.ID, StatusFailed)
}

// TestNativeCoreDoesNotLeakKey checks that an endpoint error neither forwards
// nor logs the API key.
func TestNativeCoreDoesNotLeakKey(t *testing.T) {
	h, _ := newNativeHost(t)
	model := newModelServer(t, modelReply{status: http.StatusInternalServerError, body: `{"error":"bad key sk-do-not-leak"}`})
	rec := h.create(ownerHuman, CreateRequest{Config: nativeConfigJSON(model.srv.URL, "m")})
	h.setAPIKey(ownerHuman, rec.ID, "sk-do-not-leak")
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "hi")
	h.waitTurn(rec.ID)
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusFailed)

	events := drain(sub)
	requireEvents(t, events, EventError, 1)
	errEvent := eventsOfType(events, EventError)[0]
	if errEvent.Code != string(problem.Unavailable) {
		t.Fatalf("error code = %q", errEvent.Code)
	}
	if strings.Contains(errEvent.Detail, "sk-do-not-leak") {
		t.Fatalf("error detail leaks the key: %q", errEvent.Detail)
	}
	requireEvents(t, events, EventTurnCompleted, 1)
	if eventsOfType(events, EventTurnCompleted)[0].Status != string(StatusFailed) {
		t.Fatalf("turn.completed = %+v", eventsOfType(events, EventTurnCompleted)[0])
	}
}

// TestNativeRefusesForeignSecret is the AGT-02 regression: the native core only
// decrypts the session's own API key. A reference to any other secret fails the
// turn before the model endpoint is asked, so no other subsystem's plaintext can
// leave the host as a bearer token to a URL the session owner chose.
func TestNativeRefusesForeignSecret(t *testing.T) {
	cases := []struct {
		name    string
		purpose string
		owner   func(h *testHost, sessionID string) string
	}{
		{"host secret", "identity.totp", func(*testHost, string) string { return secrets.SystemOwner }},
		{"plugin config", "plugin.config", func(*testHost, string) string {
			return "plugins/com.example.vpn/instances/default"
		}},
		{"another session's key", "agent.native.api_key", func(h *testHost, _ string) string {
			return "agent_sessions/" + h.create(ownerOther, CreateRequest{}).ID
		}},
		{"own namespace, other purpose", "plugin.config", func(_ *testHost, sessionID string) string {
			return "agent_sessions/" + sessionID
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, store := newNativeHost(t)
			model := newModelServer(t, modelReply{content: "must not be asked"})
			rec := h.create(ownerHuman, CreateRequest{Config: nativeConfigJSON(model.srv.URL, "m")})
			plaintext := "foreign-value-" + tc.purpose
			ref := h.putSecret(store, tc.owner(h, rec.ID), tc.purpose, plaintext)
			// The api-key route never writes such a reference; plant it the way a
			// bug or a tampered row would.
			h.exec(`UPDATE agent_sessions SET api_key_ref = ? WHERE session_id = ?`, string(ref), rec.ID)

			sub := h.subscribe(ownerHuman, rec.ID)
			h.send(ownerHuman, rec.ID, "hi")
			h.waitTurn(rec.ID)
			requireStatus(t, h.svc, ownerHuman, rec.ID, StatusFailed)
			events := drain(sub)
			requireEvents(t, events, EventError, 1)
			if e := eventsOfType(events, EventError)[0]; e.Code != string(problem.Unavailable) || strings.Contains(e.Detail, plaintext) {
				t.Fatalf("error event = %+v", e)
			}
			if n := model.callCount(); n != 0 {
				t.Fatalf("model calls = %d, want 0 (authorization headers %q)", n, model.authorizations())
			}
		})
	}

	// A config written before the api-key route existed may still name a secret
	// in api_key_secret; the core no longer resolves config references at all.
	t.Run("legacy config reference", func(t *testing.T) {
		h, store := newNativeHost(t)
		model := newModelServer(t, modelReply{content: "ok"})
		rec := h.create(ownerHuman, CreateRequest{Config: nativeConfigJSON(model.srv.URL, "m")})
		ref := h.putSecret(store, secrets.SystemOwner, "identity.totp", "legacy-foreign-value")
		h.exec(`UPDATE agent_sessions SET config_json = json_set(config_json, '$.api_key_secret', ?)
			WHERE session_id = ?`, string(ref), rec.ID)
		h.send(ownerHuman, rec.ID, "hi")
		h.waitTurn(rec.ID)
		for _, auth := range model.authorizations() {
			if auth != "" {
				t.Fatalf("a config reference reached the model as %q", auth)
			}
		}
	})
}

// TestNativeCoreTimeout checks the per-request deadline.
func TestNativeCoreTimeout(t *testing.T) {
	h, _ := newNativeHost(t, func(o *Options) {
		o.Native.Timeout = 80 * time.Millisecond
	})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `{"choices":[]}`)
	}))
	defer slow.Close()
	rec := h.create(ownerHuman, CreateRequest{Config: nativeConfigJSON(slow.URL, "m")})
	h.setAPIKey(ownerHuman, rec.ID, "sk-timeout")
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "hi")
	h.waitTurn(rec.ID)
	events := drain(sub)
	requireEvents(t, events, EventError, 1)
	if eventsOfType(events, EventError)[0].Code != string(problem.Timeout) {
		t.Fatalf("error = %+v", eventsOfType(events, EventError)[0])
	}
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusFailed)
}

// TestNativeCoreStepLimit checks that the eight-step bound is enforced.
func TestNativeCoreStepLimit(t *testing.T) {
	h, _ := newNativeHost(t, func(o *Options) {
		o.Catalog = StaticCatalog{Tools: testTools()}
		o.Runner = &fakeRunner{}
	})
	model := newModelServer(t, toolCallReply("call_1", "host_users_list", `{}`))
	cfg, _ := json.Marshal(map[string]any{
		"base_url": model.srv.URL, "model": "m", "max_steps": 1,
	})
	rec := h.create(ownerHuman, CreateRequest{Config: cfg})
	h.setAPIKey(ownerHuman, rec.ID, "sk-steps")
	sub := h.subscribe(ownerHuman, rec.ID)
	h.send(ownerHuman, rec.ID, "loop")
	h.waitTurn(rec.ID)
	events := drain(sub)
	requireEvents(t, events, EventError, 1)
	errEvent := eventsOfType(events, EventError)[0]
	if errEvent.Code != string(problem.Unavailable) || !strings.Contains(errEvent.Detail, "step limit") {
		t.Fatalf("error = %+v", errEvent)
	}
	if model.callCount() != 1 {
		t.Fatalf("model calls = %d, want 1", model.callCount())
	}
	requireStatus(t, h.svc, ownerHuman, rec.ID, StatusFailed)
}

// TestToolNameMapping covers the OpenAI function-name sanitization and the
// collision suffix.
func TestToolNameMapping(t *testing.T) {
	used := map[string]bool{}
	if got := uniqueToolName("host.users.list", used); got != "host_users_list" {
		t.Fatalf("name = %q", got)
	}
	// A plugin operation may contain a slash and extra dots.
	if got := uniqueToolName("com.example.monitor/scan.run", used); got != "com_example_monitor_scan_run" {
		t.Fatalf("name = %q", got)
	}
	// A second id that sanitizes to the same name gets a stable suffix.
	first := uniqueToolName("a.b", map[string]bool{})
	collide := uniqueToolName("a/b", map[string]bool{first: true})
	if collide == first || len(collide) > 64 || !strings.HasPrefix(collide, "a_b_") {
		t.Fatalf("collision name = %q (first %q)", collide, first)
	}
	long := uniqueToolName(strings.Repeat("x", 100), map[string]bool{})
	if len(long) != 64 {
		t.Fatalf("long name length = %d", len(long))
	}
	if !strings.HasPrefix(uniqueToolName("", map[string]bool{}), "tool") {
		t.Fatal("empty action did not map to a usable name")
	}
	// The mapping used when replaying history equals the mapping of the current
	// tool list, including a collision suffix.
	specs := []ToolSpec{
		{Action: "a.b", Summary: "first", Effect: operations.EffectRead},
		{Action: "a/b", Summary: "second", Effect: operations.EffectRead},
	}
	_, names := openAITools(specs)
	history := []Message{
		{Role: RoleUser, Content: "hi"},
		{Role: RoleAssistant, ContentJSON: json.RawMessage(`{"tool_calls":[{"call_id":"c1","action":"a/b","arguments":{}}]}`)},
		{Role: RoleTool, Content: "ok", ContentJSON: json.RawMessage(`{"call_id":"c1","status":"succeeded"}`)},
	}
	msgs := buildChatMessages(history, &nativeConfig{}, names)
	var got string
	for _, m := range msgs {
		if len(m.ToolCalls) > 0 {
			got = m.ToolCalls[0].Function.Name
		}
	}
	if want := names.name("a/b"); got != want {
		t.Fatalf("replayed name = %q, want %q", got, want)
	}
}

// TestBuildChatMessagesDropsIncompleteStep checks the history sanitizer.
func TestBuildChatMessagesDropsIncompleteStep(t *testing.T) {
	history := []Message{
		{Role: RoleUser, Content: "hi"},
		{Role: RoleAssistant, Content: "calling", ContentJSON: json.RawMessage(`{"tool_calls":[{"call_id":"c1","action":"x.y","arguments":{}}]}`)},
		{Role: RoleUser, Content: "next"},
	}
	msgs := buildChatMessages(history, &nativeConfig{}, toolNames{byName: map[string]ToolSpec{}, ofTool: map[string]string{}})
	for _, m := range msgs {
		if len(m.ToolCalls) > 0 {
			t.Fatalf("incomplete step was kept: %+v", msgs)
		}
	}
	// Orphan tool results are dropped too.
	history = []Message{
		{Role: RoleUser, Content: "hi"},
		{Role: RoleTool, Content: "orphan", ContentJSON: json.RawMessage(`{"call_id":"c9","status":"succeeded"}`)},
	}
	msgs = buildChatMessages(history, &nativeConfig{}, toolNames{byName: map[string]ToolSpec{}, ofTool: map[string]string{}})
	for _, m := range msgs {
		if m.Role == RoleTool {
			t.Fatalf("orphan tool result was kept: %+v", msgs)
		}
	}
}

// TestModelClientBlocksPrivate: the default policy refuses a loopback endpoint
// and the session only learns a fixed message, never the address or the status.
func TestModelClientBlocksPrivate(t *testing.T) {
	model := newModelServer(t, modelReply{content: "secret"})
	core := NewNativeCore(NativeOptions{})
	_, err := core.complete(context.Background(), &nativeConfig{BaseURL: model.srv.URL, Model: "m"}, nil, chatRequest{Model: "m"})
	requireCode(t, err, problem.PermissionDenied)
	p := problem.From(err)
	if p.Detail != egressDeniedDetail || strings.Contains(p.Detail, "127.0.0.1") {
		t.Fatalf("detail = %q", p.Detail)
	}
	if model.callCount() != 0 {
		t.Fatalf("the endpoint was contacted %d times", model.callCount())
	}
}

// TestModelClientDefaultPolicy pins the address classes the default refuses.
func TestModelClientDefaultPolicy(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":         true,
		"2606:4700::1111": true,
		"::ffff:8.8.8.8":  true,
		"127.0.0.1":       false,
		"10.0.0.1":        false,
		"169.254.169.254": false,
		"100.64.0.1":      false,
		"192.0.0.1":       false,
		"198.18.0.1":      false,
		"0.0.0.0":         false,
		"::1":             false,
		"fc00::1":         false,
		"fe80::1":         false,
		"64:ff9b::a00:1":  false,
		// --- IPv6 特殊/过渡前缀与映射地址不能绕过真实目标的出站判断 -----------
		"10::1":                 false,
		"ff:ffff:ffff::1":       false,
		"64:ff9b:1::a00:1":      false,
		"100::1":                false,
		"100::ffff:ffff:ffff:1": false,
		"2001::1":               false,
		"2001:0:ffff:ffff::1":   false,
		"2002:a00:1::1":         false,
		"::ffff:10.0.0.1":       false,
	}
	for addr, want := range cases {
		ip := netip.MustParseAddr(addr)
		if got := defaultEgressAllow(netip.AddrPortFrom(ip, 443)); got != want {
			t.Errorf("%s: allow = %v, want %v", addr, got, want)
		}
	}
}

// TestModelClientAllowListPermitsLoopback: only the administrator's list opens
// a private endpoint.
func TestModelClientAllowListPermitsLoopback(t *testing.T) {
	model := newModelServer(t, modelReply{content: "hello"})
	u, err := url.Parse(model.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	core := NewNativeCore(NativeOptions{EgressAllowAddrs: []netip.AddrPort{netip.MustParseAddrPort(u.Host)}})
	msg, err := core.complete(context.Background(), &nativeConfig{BaseURL: model.srv.URL, Model: "m"}, nil, chatRequest{Model: "m"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if msg.Content != "hello" {
		t.Fatalf("content = %q", msg.Content)
	}

	other := NewNativeCore(NativeOptions{EgressAllowPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	_, err = other.complete(context.Background(), &nativeConfig{BaseURL: model.srv.URL, Model: "m"}, nil, chatRequest{Model: "m"})
	requireCode(t, err, problem.PermissionDenied)
}

// TestModelClientNoRedirect: a public endpoint cannot bounce the host to
// another address, and the failure names a class rather than a status code.
func TestModelClientNoRedirect(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	client := newModelClient(func(netip.AddrPort) bool { return true })
	resp, err := client.Post(srv.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || hits.Load() != 0 {
		t.Fatalf("status = %d, target hits = %d", resp.StatusCode, hits.Load())
	}

	core := NewNativeCore(NativeOptions{Client: client})
	_, err = core.complete(context.Background(), &nativeConfig{BaseURL: srv.URL, Model: "m"}, nil, chatRequest{Model: "m"})
	requireCode(t, err, problem.Unavailable)
	if strings.Contains(err.Error(), "307") {
		t.Fatalf("status code leaked: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("target hits = %d", hits.Load())
	}
}

// TestNativeConfigRejectsUserinfoQuery: a base_url is only scheme, host and path.
func TestNativeConfigRejectsUserinfoQuery(t *testing.T) {
	for _, raw := range []string{
		"https://user:pw@example.com/v1",
		"https://example.com/v1?x=1",
		"https://example.com/v1?",
		"https://example.com/v1#frag",
	} {
		_, err := decodeNativeConfig(mustJSON(t, map[string]string{"base_url": raw}))
		requireCode(t, err, problem.ValidationFailed)
	}
	if _, err := decodeNativeConfig(mustJSON(t, map[string]string{"base_url": "https://example.com/v1/"})); err != nil {
		t.Fatalf("plain url: %v", err)
	}
}
