// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretFieldUnmarshalMarshalAndResolve(t *testing.T) {
	type payload struct {
		APIKey SecretField `json:"api_key"`
	}

	// 1. Plain string
	var p1 payload
	dec := json.NewDecoder(strings.NewReader(`{"api_key":"sk-plain-123"}`))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p1); err != nil {
		t.Fatalf("plain decode failed: %v", err)
	}
	if p1.APIKey.Plain != "sk-plain-123" || p1.APIKey.IsEmpty() {
		t.Fatalf("unexpected plain SecretField: %+v", p1.APIKey)
	}
	marshaled, err := json.Marshal(p1)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(marshaled), "sk-plain-123") || !strings.Contains(string(marshaled), `"$secret_present":true`) {
		t.Fatalf("MarshalJSON leaked plaintext or missed redaction: %s", string(marshaled))
	}
	got, keep, err := p1.APIKey.ResolveString(context.Background(), nil, "plugin.operation")
	if err != nil || keep || got != "sk-plain-123" {
		t.Fatalf("ResolveString(plain) = %q, %v, %v", got, keep, err)
	}
	if p1.APIKey.Plain != "" {
		t.Fatalf("expected Plain to be cleared after ResolveString")
	}

	// 2. Host {$secret} envelope
	var p2 payload
	dec2 := json.NewDecoder(strings.NewReader(`{"api_key":{"$secret":"sec_123"}}`))
	dec2.DisallowUnknownFields()
	if err := dec2.Decode(&p2); err != nil {
		t.Fatalf("$secret decode failed: %v", err)
	}
	if p2.APIKey.SecretRef != "sec_123" {
		t.Fatalf("SecretRef = %q, want sec_123", p2.APIKey.SecretRef)
	}

	// Resolve via fake Host RevealSecret
	env := newTestEnv(t, newTestPlugin())
	env.initialize("s1", nil)
	env.start("s1")
	inst := env.instance("s1")
	opCtx := withCallInfo(context.Background(), callInfo{call: Call{OperationID: "op-reveal-1", TraceID: "tr-1"}})

	raw, keep, cleanup, err := p2.APIKey.ResolveBytes(opCtx, inst.Host(), "plugin.operation")
	if err != nil || keep || string(raw) != "s3cr3t" {
		t.Fatalf("ResolveBytes($secret) = %q, %v, %v", string(raw), keep, err)
	}
	cleanup()
	for _, b := range raw {
		if b != 0 {
			t.Fatalf("expected cleanup() to zero secret bytes")
		}
	}

	// 3. Keep marker
	var p3 payload
	dec3 := json.NewDecoder(strings.NewReader(`{"api_key":{"$keep_secret":true}}`))
	dec3.DisallowUnknownFields()
	if err := dec3.Decode(&p3); err != nil {
		t.Fatalf("$keep_secret decode failed: %v", err)
	}
	if !p3.APIKey.KeepExisting {
		t.Fatalf("expected KeepExisting=true")
	}
	val, keep, err := p3.APIKey.ResolveString(context.Background(), nil, "plugin.operation")
	if err != nil || !keep || val != "" {
		t.Fatalf("ResolveString($keep_secret) = %q, %v, %v", val, keep, err)
	}

	// 4. Unknown field rejected under DisallowUnknownFields
	var p4 payload
	dec4 := json.NewDecoder(strings.NewReader(`{"api_key":{"$secret":"sec_1","extra":1}}`))
	dec4.DisallowUnknownFields()
	if err := dec4.Decode(&p4); err == nil {
		t.Fatalf("expected error on unknown field inside secret object")
	}

	// 5. Non-string / non-object rejected
	var p5 payload
	if err := json.Unmarshal([]byte(`{"api_key":12345}`), &p5); err == nil {
		t.Fatalf("expected error on numeric secret field")
	}
}

func TestCapabilityContextAutonomous(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.initialize("a1", nil)
	env.start("a1")
	host := env.instance("a1").Host()

	// 1. Background context (no OperationID) -> auton:<reason>
	bgCtx := withCallInfo(context.Background(), callInfo{call: Call{TraceID: "tr-bg", InstanceID: "a1"}})
	hc, err := host.CapabilityContextAutonomous(bgCtx, "ban_loop")
	if err != nil {
		t.Fatalf("CapabilityContextAutonomous(bg) failed: %v", err)
	}
	if hc.GetOperationId() != AutonomousOperationPrefix+"ban_loop" || hc.GetTraceId() != "tr-bg" {
		t.Fatalf("unexpected HostCallContext: %+v", hc)
	}

	// 2. Existing dispatched OperationID is preserved verbatim
	opCtx := withCallInfo(context.Background(), callInfo{call: Call{OperationID: "op_real_123", TraceID: "tr-op"}})
	hc2, err := host.CapabilityContextAutonomous(opCtx, "ban_loop")
	if err != nil {
		t.Fatalf("CapabilityContextAutonomous(op) failed: %v", err)
	}
	if hc2.GetOperationId() != "op_real_123" {
		t.Fatalf("OperationId = %q, want op_real_123", hc2.GetOperationId())
	}

	// 3. PlanOperation context is strictly refused with PLAN_SIDE_EFFECT
	planCtx := withCallInfo(context.Background(), callInfo{planning: true})
	if _, err := host.CapabilityContextAutonomous(planCtx, "ban_loop"); CodeOf(err) != "PLAN_SIDE_EFFECT" {
		t.Fatalf("PlanOperation error = %v, want PLAN_SIDE_EFFECT", err)
	}

	// 4. Invalid reason characters rejected
	if _, err := host.CapabilityContextAutonomous(bgCtx, "bad reason/!"); CodeOf(err) != "INVALID_AUTONOMOUS_REASON" {
		t.Fatalf("invalid reason error = %v, want INVALID_AUTONOMOUS_REASON", err)
	}
}

func TestPublicStreamBridgeStreamingAndClose(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "qwq-ps-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fakeHostSock := filepath.Join(dir, "host.sock")
	if err := os.WriteFile(fakeHostSock, nil, 0o600); err != nil {
		t.Fatalf("create fake host.sock: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, chunk := range []string{"data: one\n\n", "data: two\n\n"} {
			_, _ = io.WriteString(w, chunk)
			if flusher != nil {
				flusher.Flush()
			}
		}
	})

	bridge, err := StartPublicStreamBridge(fakeHostSock, handler, nil)
	if err != nil {
		t.Fatalf("StartPublicStreamBridge failed: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = bridge.Close(ctx)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", bridge.SocketPath())
			},
		},
		Timeout: 3 * time.Second,
	}
	resp, err := client.Post("http://plugin.qwq.internal/v1/chat/completions", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("stream request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "data: one\n\ndata: two\n\n" {
		t.Fatalf("unexpected stream response: status=%d body=%q", resp.StatusCode, string(body))
	}
}

func TestPublicStreamBridgeEnvOverrideAndFailClosedVerifier(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "qwq-ps-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fakeHostSock := filepath.Join(dir, "h", "host.sock")
	if err := os.MkdirAll(filepath.Dir(fakeHostSock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeHostSock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	customSock := filepath.Join(dir, "s", PublicStreamSocketName)
	t.Setenv(EnvPublicStreamSocket, customSock)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	// 1. EnvPublicStreamSocket overrides the fallback HostDir path.
	bridge, err := StartPublicStreamBridge(fakeHostSock, handler, func(net.Conn) error { return nil })
	if err != nil {
		t.Fatalf("StartPublicStreamBridge with env override failed: %v", err)
	}
	if bridge.SocketPath() != customSock {
		t.Fatalf("SocketPath = %q, want %q", bridge.SocketPath(), customSock)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = bridge.Close(ctx)

	// 2. A rejecting verifier closes incoming connections fail-closed.
	rejectSock := filepath.Join(dir, "reject", PublicStreamSocketName)
	rejectedBridge, err := StartPublicStreamBridgeAt(rejectSock, fakeHostSock, handler, func(net.Conn) error {
		return errors.New("unauthorized peer")
	})
	if err != nil {
		t.Fatalf("StartPublicStreamBridgeAt reject failed: %v", err)
	}
	defer func() {
		c2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()
		_ = rejectedBridge.Close(c2)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", rejectedBridge.SocketPath())
			},
		},
		Timeout: time.Second,
	}
	if resp, err := client.Get("http://plugin.qwq.internal/health"); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("expected connection rejection when peer verifier fails, got status %d", resp.StatusCode)
	}
}
