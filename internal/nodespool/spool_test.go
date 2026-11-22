// SPDX-License-Identifier: AGPL-3.0-only

package nodespool

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestSpoolAppendReadAckAndIdempotency(t *testing.T) {
	ctx := t.Context()
	sp, err := Open(ctx, filepath.Join(t.TempDir(), "spool.db"), DefaultMaxBytes)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sp.Close()

	now := time.Date(2026, 11, 21, 16, 0, 0, 0, time.UTC)
	seq1, err := sp.Append(ctx, "ev_1", "op.receipt", PriorityCritical, []byte(`{"status":"ok"}`), now)
	if err != nil || seq1 != 1 {
		t.Fatalf("Append #1 seq=%d err=%v", seq1, err)
	}
	// 同 event_id 幂等返回原 seq。
	seq1Dup, err := sp.Append(ctx, "ev_1", "op.receipt", PriorityCritical, []byte(`{"status":"ok"}`), now)
	if err != nil || seq1Dup != seq1 {
		t.Fatalf("Append dup seq=%d want %d err=%v", seq1Dup, seq1, err)
	}
	seq2, err := sp.Append(ctx, "ev_2", "metrics.cpu", PriorityMetrics, []byte(`{"cpu":15}`), now.Add(time.Second))
	if err != nil || seq2 != 2 {
		t.Fatalf("Append #2 seq=%d err=%v", seq2, err)
	}

	entries, err := sp.ReadAfter(ctx, 0, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("ReadAfter len=%d err=%v", len(entries), err)
	}
	if entries[0].EventID != "ev_1" || entries[1].EventID != "ev_2" {
		t.Fatalf("unexpected order: %+v", entries)
	}

	deleted, err := sp.Ack(ctx, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("Ack(1) deleted=%d err=%v", deleted, err)
	}
	st, err := sp.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Count != 1 || st.FirstSeq != 2 || st.LastSeq != 2 {
		t.Fatalf("unexpected stats after ack: %+v", st)
	}
}

func TestSpoolEvictsMetricsBeforeCriticalUnderTightBudget(t *testing.T) {
	ctx := t.Context()
	// 严格 4 KiB 预算测试驱逐策略。
	sp, err := Open(ctx, filepath.Join(t.TempDir(), "spool.db"), 4096)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sp.Close()

	now := time.Now().UTC()
	payload512 := bytes.Repeat([]byte("m"), 512)

	// 先写入 2 条高优审计回执，再塞入 10 条低优监控采样。
	if _, err := sp.Append(ctx, "crit_1", "audit.ssh", PriorityCritical, payload512, now); err != nil {
		t.Fatalf("append crit_1: %v", err)
	}
	if _, err := sp.Append(ctx, "crit_2", "op.result", PriorityCritical, payload512, now); err != nil {
		t.Fatalf("append crit_2: %v", err)
	}
	for i := range 10 {
		if _, err := sp.Append(ctx, fmt.Sprintf("met_%d", i), "metrics.net", PriorityMetrics, payload512, now); err != nil {
			t.Fatalf("append met_%d: %v", i, err)
		}
	}

	// 再次写入一条高优操作回执，必须淘汰低优指标以保证高优回执落盘。
	if _, err := sp.Append(ctx, "crit_3", "op.result", PriorityCritical, payload512, now); err != nil {
		t.Fatalf("append crit_3: %v", err)
	}

	entries, err := sp.ReadAfter(ctx, 0, 100)
	if err != nil {
		t.Fatalf("ReadAfter: %v", err)
	}
	critFound := map[string]bool{}
	for _, e := range entries {
		if e.Priority == PriorityCritical {
			critFound[e.EventID] = true
		}
	}
	for _, id := range []string{"crit_1", "crit_2", "crit_3"} {
		if !critFound[id] {
			t.Fatalf("critical entry %s was lost during eviction!", id)
		}
	}
	st, err := sp.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.BytesUsed > st.MaxBytes {
		t.Fatalf("BytesUsed %d exceeded MaxBytes %d", st.BytesUsed, st.MaxBytes)
	}
	if st.DroppedMetrics == 0 {
		t.Fatalf("expected low-priority metrics to be dropped, got DroppedMetrics=0")
	}

	// 若继续只写高优事件直至塞满全部 4 KiB，再写高优事件应返回 ErrSpoolFull。
	var hitFull bool
	for i := range 20 {
		_, err := sp.Append(ctx, fmt.Sprintf("crit_fill_%d", i), "audit.fill", PriorityCritical, payload512, now)
		if errors.Is(err, ErrSpoolFull) {
			hitFull = true
			break
		}
		if err != nil {
			t.Fatalf("unexpected error while filling critical budget: %v", err)
		}
	}
	if !hitFull {
		t.Fatal("expected ErrSpoolFull once critical entries exhaust entire budget")
	}
}
