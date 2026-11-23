// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/pluginpublic"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

type fakeAlertInvoker struct {
	mu       sync.Mutex
	payloads []AlertEventPayload
	rawJSONs [][]byte
	ch       chan struct{}
}

func (f *fakeAlertInvoker) DispatchInternalAlert(_ context.Context, payloadJSON []byte) error {
	var p AlertEventPayload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return err
	}
	f.mu.Lock()
	f.payloads = append(f.payloads, p)
	f.rawJSONs = append(f.rawJSONs, append([]byte(nil), payloadJSON...))
	f.mu.Unlock()
	select {
	case f.ch <- struct{}{}:
	default:
	}
	return nil
}

func TestAlertEventRelayForcesVerifiedSourceAndDelivers(t *testing.T) {
	inv := &fakeAlertInvoker{ch: make(chan struct{}, 4)}
	relay := NewAlertEventRelay(inv, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay.Start(ctx)
	defer relay.Stop()

	// Non-alert event is ignored
	relay.OnPluginEvent("security.basic", &platformv1.EventDraft{
		Type:        "security.info",
		PayloadJson: []byte(`{"title":"ignored"}`),
	}, "ev_1")

	// Alert event has spoofed source overwritten by verified publisherPluginID,
	// and must omit event_id / timestamp when marshaling notify.dispatch args.
	relay.OnPluginEvent("security.basic", &platformv1.EventDraft{
		Type:        "security.alert",
		PayloadJson: []byte(`{"source":"fake.plugin","severity":"critical","title":"SSH brute force blocked","message":"1.2.3.4","dedup_key":"ssh-1.2.3.4","tags":{"ip":"1.2.3.4"}}`),
	}, "ev_2")

	select {
	case <-inv.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert relay delivery")
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()
	if len(inv.payloads) != 1 || len(inv.rawJSONs) != 1 {
		t.Fatalf("delivered = %d, want 1", len(inv.payloads))
	}
	got := inv.payloads[0]
	if got.Source != "security.basic" || got.Severity != "critical" || got.Title != "SSH brute force blocked" || got.DedupKey != "ssh-1.2.3.4" {
		t.Fatalf("unexpected delivered alert: %+v", got)
	}

	// Verify strict notify.dispatch.request.json schema conformance (additionalProperties: false).
	var rawMap map[string]any
	if err := json.Unmarshal(inv.rawJSONs[0], &rawMap); err != nil {
		t.Fatalf("unmarshal dispatched json: %v", err)
	}
	allowed := map[string]bool{
		"source":    true,
		"severity":  true,
		"title":     true,
		"message":   true,
		"dedup_key": true,
		"tags":      true,
	}
	for k := range rawMap {
		if !allowed[k] {
			t.Fatalf("dispatched alert contains schema-forbidden key %q: %s", k, string(inv.rawJSONs[0]))
		}
	}
	if _, hasEventID := rawMap["event_id"]; hasEventID {
		t.Fatalf("dispatched alert must not include event_id: %s", string(inv.rawJSONs[0]))
	}
	if _, hasTimestamp := rawMap["timestamp"]; hasTimestamp {
		t.Fatalf("dispatched alert must not include timestamp: %s", string(inv.rawJSONs[0]))
	}
}

func TestAlertEventRelayPerPluginRateLimit(t *testing.T) {
	inv := &fakeAlertInvoker{ch: make(chan struct{}, 32)}
	relay := NewAlertEventRelay(inv, nil)

	var clockMu sync.Mutex
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	relay.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay.Start(ctx)
	defer relay.Stop()

	// A single noisy plugin sending 15 alerts within 1 minute must be capped at 10.
	for i := 0; i < 15; i++ {
		relay.OnPluginEvent("noisy.plugin", &platformv1.EventDraft{
			Type:        "noisy.alert",
			PayloadJson: []byte(`{"severity":"warn","title":"spam alert"}`),
		}, "ev_noisy")
	}
	// Another plugin must not be starved by noisy.plugin's rate limit.
	relay.OnPluginEvent("healthy.plugin", &platformv1.EventDraft{
		Type:        "healthy.alert",
		PayloadJson: []byte(`{"severity":"critical","title":"real alert"}`),
	}, "ev_healthy")

	for i := 0; i < 11; i++ {
		select {
		case <-inv.ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for alert #%d", i+1)
		}
	}

	// Ensure no extra alerts were enqueued beyond the 10+1 cap.
	select {
	case <-inv.ch:
		t.Fatal("received more alerts than allowed by per-plugin rate limit")
	case <-time.After(50 * time.Millisecond):
	}

	inv.mu.Lock()
	var noisyCount, healthyCount int
	for _, p := range inv.payloads {
		switch p.Source {
		case "noisy.plugin":
			noisyCount++
		case "healthy.plugin":
			healthyCount++
		}
	}
	inv.mu.Unlock()
	if noisyCount != alertRateLimitPerPlugin || healthyCount != 1 {
		t.Fatalf("delivered counts noisy=%d healthy=%d, want %d and 1", noisyCount, healthyCount, alertRateLimitPerPlugin)
	}

	// Advancing past the 1-minute window allows noisy.plugin to emit alerts again.
	clockMu.Lock()
	now = now.Add(alertRateLimitWindow + time.Second)
	clockMu.Unlock()

	relay.OnPluginEvent("noisy.plugin", &platformv1.EventDraft{
		Type:        "noisy.alert",
		PayloadJson: []byte(`{"severity":"info","title":"after window"}`),
	}, "ev_noisy_after")

	select {
	case <-inv.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert after rate-limit window reset")
	}
}

func TestInjectCanonicalPublicHeadersPreservesRelaySessionAndClientIP(t *testing.T) {
	hdr := make(http.Header)
	injectCanonicalPublicHeaders(hdr, pluginpublic.PublicRequest{
		ClientIP:        "203.0.113.42",
		RelayAuthBearer: "rly_sess_abc123",
		ExtraHeaders: map[string]string{
			"Host":              "relay.example.com",
			"X-Forwarded-Proto": "https",
		},
	})
	if hdr.Get("X-QWQ-Client-IP") != "203.0.113.42" {
		t.Fatalf("X-QWQ-Client-IP = %q", hdr.Get("X-QWQ-Client-IP"))
	}
	if hdr.Get("X-QWQ-Relay-Token") != "rly_sess_abc123" || hdr.Get("X-Relay-Session") != "rly_sess_abc123" {
		t.Fatalf("relay token headers = %q / %q", hdr.Get("X-QWQ-Relay-Token"), hdr.Get("X-Relay-Session"))
	}
	if hdr.Get("Host") != "relay.example.com" || hdr.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("extra headers = %q / %q", hdr.Get("Host"), hdr.Get("X-Forwarded-Proto"))
	}
}
