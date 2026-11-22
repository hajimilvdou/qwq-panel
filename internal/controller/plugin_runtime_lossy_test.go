// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
)

func TestHostEventSinkLossyRealtimeBypassesSQLite(t *testing.T) {
	ctx := t.Context()
	db := testDB(t)
	lossy := events.NewLossy(events.LossyConfig{})
	gen := ids.New(func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) })

	sink := &hostEventSink{
		db:         db,
		lossy:      lossy,
		ids:        gen,
		pluginID:   "monitor.basic",
		instanceID: "default",
		nodeID:     "local",
	}

	sub, err := lossy.Subscribe("monitor.basic.metrics.cpu")
	if err != nil {
		t.Fatalf("lossy.Subscribe: %v", err)
	}
	defer sub.Close()

	// 连续发布 2 条同 key 的高频遥测样本，内存层应合并为最新值且绝不写 SQLite。
	ref1, err := sink.Publish(ctx, hostsvc.EventDraft{
		Type:        "metrics.cpu",
		Subject:     "host",
		PayloadJSON: []byte(`{"pct":11}`),
	})
	if err != nil {
		t.Fatalf("Publish #1: %v", err)
	}
	if ref1.Sequence != 0 || ref1.EventID == "" {
		t.Fatalf("lossy ref1 = %+v, want Sequence=0 and non-empty EventID", ref1)
	}
	ref2, err := sink.Publish(ctx, hostsvc.EventDraft{
		Type:        "metrics.cpu",
		Subject:     "host",
		PayloadJSON: []byte(`{"pct":42}`),
	})
	if err != nil {
		t.Fatalf("Publish #2: %v", err)
	}
	if ref2.Sequence != 0 {
		t.Fatalf("lossy ref2 = %+v, want Sequence=0", ref2)
	}

	got, ok := sub.Next(ctx)
	if !ok {
		t.Fatal("expected lossy sample from subscriber")
	}
	sample, ok := got.(LossySample)
	if !ok {
		t.Fatalf("unexpected sample type %T", got)
	}
	if string(sample.Payload) != `{"pct":42}` {
		t.Fatalf("coalesced payload = %s, want {\"pct\":42}", sample.Payload)
	}

	var journalCount int
	if err := db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM event_journal WHERE type = ?`, "monitor.basic.metrics.cpu").Scan(&journalCount); err != nil {
		t.Fatalf("query event_journal: %v", err)
	}
	if journalCount != 0 {
		t.Fatalf("lossy telemetry wrote %d rows to SQLite event_journal, want 0", journalCount)
	}

	// 普通可靠事件仍照常持久化到 event_journal。
	relRef, err := sink.Publish(ctx, hostsvc.EventDraft{
		Type:        "alert.disk_full",
		Subject:     "host",
		PayloadJSON: []byte(`{"pct":95}`),
	})
	if err != nil {
		t.Fatalf("Publish reliable: %v", err)
	}
	if relRef.Sequence == 0 {
		t.Fatalf("reliable event returned Sequence=0")
	}
}
