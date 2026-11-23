// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestUnreadableMountPreservesWholeHostDiskIOBPS(t *testing.T) {
	cfg := defaultConfig()
	cfg.DiskMounts = []string{"/", "/mnt/offline"}

	prev := sample(1000, 0, 0, 0, 10)
	prev.Disks = []*metricsv1.Disk{
		{Mount: "/", Device: "vda1", TotalBytes: 100, UsedBytes: 50, ReadSectors: 10, WriteSectors: 20},
		{Mount: "/mnt/offline", Device: "vdb1", TotalBytes: 200, UsedBytes: 100, ReadSectors: 5, WriteSectors: 5},
	}
	// /mnt/offline 暂时不可读（缺失于当前采样），"/" 正常递增 4 扇区读与 6 扇区写
	curr := sample(2000, 10, 90, 0, 14)
	curr.Disks = []*metricsv1.Disk{
		{Mount: "/", Device: "vda1", TotalBytes: 100, UsedBytes: 52, ReadSectors: 14, WriteSectors: 26},
	}

	pt := derive(curr, prev, cfg, 1)
	expectMetric(t, pt.DiskRead, 4*512)
	expectMetric(t, pt.DiskWrite, 6*512)
}

func TestSwapAndCPUIOWaitExportedSeparately(t *testing.T) {
	prev := &metricsv1.MetricsSnapshot{
		CollectedAtUnixMs: 1000,
		Cpu:               &metricsv1.Cpu{User: 0, System: 0, Idle: 0, Iowait: 0, CoreCount: 2},
		Memory:            &metricsv1.Memory{TotalBytes: 1024 << 20, AvailableBytes: 512 << 20, SwapTotalBytes: 512 << 20, SwapFreeBytes: 256 << 20},
		Load:              &metricsv1.Load{Load1: 1.2, Load5: 0.8, Load15: 0.4},
	}
	// user=10, sys=10, iowait=30, idle=50 -> total=100; cpu_pct=(100-50)=50 (not hiding iowait), cpu_iowait_percent=30
	curr := &metricsv1.MetricsSnapshot{
		CollectedAtUnixMs: 2000,
		Cpu:               &metricsv1.Cpu{User: 10, System: 10, Idle: 50, Iowait: 30, CoreCount: 2},
		Memory:            &metricsv1.Memory{TotalBytes: 1024 << 20, AvailableBytes: 256 << 20, SwapTotalBytes: 512 << 20, SwapFreeBytes: 128 << 20},
		Load:              &metricsv1.Load{Load1: 1.5, Load5: 1.1, Load15: 0.7},
	}

	pt := derive(curr, prev, defaultConfig(), 1)
	expectMetric(t, pt.CPU, 50)
	expectMetric(t, pt.CPUIOWait, 30)
	expectMetric(t, pt.Swap, 75)
	expectMetric(t, pt.SwapUsedMB, 384)
	expectMetric(t, pt.Load5, 1.1)
	expectMetric(t, pt.Load15, 0.7)
}

func TestThreeSampleCritEdgeAlertAndDebounce(t *testing.T) {
	hot := func(at int64, memAvail uint64) *metricsv1.MetricsSnapshot {
		return &metricsv1.MetricsSnapshot{
			CollectedAtUnixMs: at,
			Cpu:               &metricsv1.Cpu{User: uint64(at), Idle: 0, CoreCount: 1},
			Memory:            &metricsv1.Memory{TotalBytes: 1000, AvailableBytes: memAvail},
		}
	}
	source := &sequenceSource{values: []*metricsv1.MetricsSnapshot{
		hot(1000, 50), // 95% mem (#1)
		hot(2000, 50), // 95% mem (#2)
		hot(3000, 50), // 95% mem (#3 -> fires!)
		hot(4000, 50), // 95% mem (#4 -> debounced within 15m)
		hot(5000, 50), // 95% mem (#5 -> after +16m fires again!)
	}}
	s := mustSampler(t, defaultConfig(), source)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	step := 0
	s.now = func() time.Time {
		step++
		if step == 5 {
			now = now.Add(16 * time.Minute)
		} else {
			now = now.Add(time.Second)
		}
		return now
	}
	var fired []pluginsdk.EventDraft
	s.publishAlert = func(_ context.Context, draft pluginsdk.EventDraft) error {
		if draft.Subject == "metrics/mem" {
			fired = append(fired, draft)
		}
		return nil
	}

	for i := range 5 {
		if err := s.collect(t.Context()); err != nil {
			t.Fatalf("collect #%d: %v", i, err)
		}
	}
	if len(fired) != 2 {
		t.Fatalf("expected 2 mem crit alerts (edge + post-debounce), got %d", len(fired))
	}
	if fired[0].Type != "monitor.alert" {
		t.Fatalf("unexpected alert type: %q", fired[0].Type)
	}
	var payload map[string]any
	if err := json.Unmarshal(fired[0].Payload, &payload); err != nil || payload["metric"] != "mem" || payload["severity"] != "critical" {
		t.Fatalf("unexpected alert payload: %s", string(fired[0].Payload))
	}
}

type fakeMonitorHostKV struct {
	pb.UnimplementedHostStateServiceServer
	mu   sync.Mutex
	data map[string][]byte
}

func (k *fakeMonitorHostKV) GetState(_ context.Context, req *pb.GetStateRequest) (*pb.GetStateResponse, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	raw, ok := k.data[req.GetKey()]
	if !ok {
		return &pb.GetStateResponse{Found: false}, nil
	}
	return &pb.GetStateResponse{Found: true, Revision: "1", ValueJson: append([]byte(nil), raw...)}, nil
}

func (k *fakeMonitorHostKV) PutState(_ context.Context, req *pb.PutStateRequest) (*pb.PutStateResponse, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.data == nil {
		k.data = make(map[string][]byte)
	}
	k.data[req.GetKey()] = append([]byte(nil), req.GetValueJson()...)
	return &pb.PutStateResponse{Revision: "2"}, nil
}

func TestCoarseRingKVSaveAndRestoreAcrossRestart(t *testing.T) {
	listener := bufconn.Listen(128 << 10)
	hostServer := grpc.NewServer()
	kv := &fakeMonitorHostKV{}
	pb.RegisterHostStateServiceServer(hostServer, kv)
	go func() { _ = hostServer.Serve(listener) }()
	t.Cleanup(func() { hostServer.Stop(); _ = listener.Close() })

	conn, err := grpc.NewClient("passthrough:///monitor-kv",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	source := &sequenceSource{values: []*metricsv1.MetricsSnapshot{
		sample(1000, 0, 0, 0, 0),
		sample(2000, 40, 60, 1000, 2),
		sample(12000, 80, 120, 2000, 4),
	}}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

	srv1, err := pluginsdk.Serve(t.Context(), pluginsdk.Options{
		Plugin: &Plugin{source: source}, Manifest: Manifest(), Registrar: quietRegistrar{}, Host: conn, DefaultGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv1.Close()
	rc := &pb.RequestContext{InstanceId: "default", NodeId: "local", Locale: "zh-CN"}
	if _, err := srv1.Initialize(t.Context(), &pb.InitializeRequest{Context: rc, InstanceHandle: "mon-1", ConfigJson: []byte(`{}`), ConfigRevision: "1"}); err != nil {
		t.Fatal(err)
	}

	// Manually collect and persist via export/restore helpers + KV roundtrip
	s1 := mustSampler(t, defaultConfig(), source)
	s1.now = func() time.Time { now = now.Add(time.Second); return now }
	for range 3 {
		if err := s1.collect(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	snap := s1.exportCoarseSnapshot(now)
	if len(snap.Points) == 0 {
		t.Fatal("expected coarse snapshot points to be exported")
	}
	rawSnap, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.PutState(t.Context(), &pb.PutStateRequest{Key: coarseHistoryKVKey, ValueJson: rawSnap}); err != nil {
		t.Fatal(err)
	}

	// Restore within 1h succeeds
	s2 := mustSampler(t, defaultConfig(), nil)
	if !s2.restoreCoarseSnapshot(snap, now.Add(30*time.Minute)) {
		t.Fatal("expected coarse ring restore within 1h to succeed")
	}
	if len(s2.coarse.latest(10)) != len(snap.Points) {
		t.Fatalf("restored coarse count mismatch: got %d want %d", len(s2.coarse.latest(10)), len(snap.Points))
	}

	// Restore after >1h or mismatched interval is rejected
	s3 := mustSampler(t, defaultConfig(), nil)
	if s3.restoreCoarseSnapshot(snap, now.Add(61*time.Minute)) {
		t.Fatal("expected stale >1h coarse snapshot to be rejected")
	}
	cfgDiff := defaultConfig()
	cfgDiff.CoarseInterval = 20000
	s4 := mustSampler(t, cfgDiff, nil)
	if s4.restoreCoarseSnapshot(snap, now.Add(5*time.Minute)) {
		t.Fatal("expected interval-mismatched coarse snapshot to be rejected")
	}
}
