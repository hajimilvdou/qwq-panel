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
	ch       chan struct{}
}

func (f *fakeAlertInvoker) DispatchInternalAlert(_ context.Context, payloadJSON []byte) error {
	var p AlertEventPayload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return err
	}
	f.mu.Lock()
	f.payloads = append(f.payloads, p)
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

	// Alert event has spoofed source overwritten by verified publisherPluginID
	relay.OnPluginEvent("security.basic", &platformv1.EventDraft{
		Type:        "security.alert",
		PayloadJson: []byte(`{"source":"fake.plugin","severity":"critical","title":"SSH brute force blocked","message":"1.2.3.4"}`),
	}, "ev_2")

	select {
	case <-inv.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert relay delivery")
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()
	if len(inv.payloads) != 1 {
		t.Fatalf("delivered = %d, want 1", len(inv.payloads))
	}
	got := inv.payloads[0]
	if got.Source != "security.basic" || got.EventID != "ev_2" || got.Severity != "critical" {
		t.Fatalf("unexpected delivered alert: %+v", got)
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
