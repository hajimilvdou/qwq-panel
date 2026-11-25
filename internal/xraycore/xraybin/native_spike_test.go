// SPDX-License-Identifier: AGPL-3.0-only

//go:build x6spike && linux

package xraybin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/xraycore/xrayapi"
)

// TestNativePreflightAndPrivateStats 仅由隔离测试单元执行，不进入产品构建。
func TestNativePreflightAndPrivateStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	dir := os.Getenv("QWQ_X6_RUNTIME")
	if os.Geteuid() == 0 || !filepath.IsAbs(dir) || filepath.Dir(dir) != "/run" || len(filepath.Base(dir)) < len("qwq-x6-") || filepath.Base(dir)[:len("qwq-x6-")] != "qwq-x6-" {
		t.Fatal("spike requires its own dynamic UID and runtime directory")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal("runtime directory is unavailable")
	}
	owner, ok := sandbox.FileOwner(info)
	if !ok || owner != os.Geteuid() || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatal("runtime directory is not private to the dynamic UID")
	}
	binary, err := Locate()
	if err != nil {
		t.Fatal("packaged Xray verification failed")
	}
	candidate, port := spikeCandidate(t, dir)
	socket := filepath.Join(dir, "api.sock")
	baseline := spikeListeners(t)
	done := make(chan error, 1)
	go func() { done <- binary.Preflight(ctx, candidate) }()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
preflight:
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("real native preflight failed")
			}
			break preflight
		case <-ticker.C:
			spikeRequireListeners(t, baseline, 0)
		case <-ctx.Done():
			t.Fatal("native preflight exceeded its deadline")
		}
	}
	spikeRequireListeners(t, baseline, 0)
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preflight created an API socket")
	}
	t.Log("verified native preflight: no TCP listeners or API socket before, during and after")

	var firstPID int
	for generation := 0; generation < 2; generation++ {
		process := spikeStart(t, ctx, binary, candidate)
		if generation == 1 && process.command.Process.Pid == firstPID {
			t.Fatal("restart reused the old process")
		}
		firstPID = process.command.Process.Pid
		spikeWaitSocket(t, ctx, process, socket)
		spikeRequireListeners(t, baseline, port)
		spikeRequireCounters(t, ctx, binary, socket)
		client, err := xrayapi.New(socket)
		if err != nil {
			t.Fatal("minimal StatsService client rejected the private socket")
		}
		counters, err := client.Counters(ctx)
		if err != nil || len(counters) != 2 {
			client.Close()
			t.Fatal("minimal StatsService client could not read the real baseline")
		}
		value, err := client.Get(ctx, "inbound>>>qwq-in-proof>>>traffic>>>uplink")
		if err != nil || value != 0 {
			client.Close()
			t.Fatal("minimal client did not preserve the present zero counter")
		}
		_, err = client.Get(ctx, "user>>>qwq-user-absent>>>traffic>>>uplink")
		if !errors.Is(err, xrayapi.ErrMissing) {
			client.Close()
			t.Fatal("minimal client did not distinguish the missing user counter")
		}
		if err := client.Close(); err != nil {
			t.Fatal("minimal client cleanup failed")
		}
		t.Log("verified minimal QueryStats client: present zero, absent counter and bounded private UDS calls")
		if generation == 0 {
			spikeOtherUID(t, ctx, dir)
		}
		process.stop(t)
		spikeRemoveSocket(t, socket)
		spikeRequireListeners(t, baseline, 0)
	}
	if err := os.Remove(candidate); err != nil {
		t.Fatal("candidate cleanup failed")
	}
	t.Log("verified two Xray generations, private StatsService, read-only zero baseline and process/socket/port cleanup")
}

// spikeOtherUID 只交换完成标记，另一个 UID 的真实连接由 root 测试夹具执行。
func spikeOtherUID(t *testing.T, ctx context.Context, dir string) {
	t.Helper()
	ready, result := filepath.Join(dir, "other.ready"), filepath.Join(dir, "other.done")
	if err := os.WriteFile(ready, []byte("ready\n"), 0o600); err != nil {
		t.Fatal("cannot signal permission probe")
	}
	defer os.Remove(ready)
	defer os.Remove(result)
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("permission probe canceled")
		case <-deadline.C:
			t.Fatal("permission probe did not complete")
		case <-tick.C:
			data, err := os.ReadFile(result)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || string(data) != "denied\n" {
				t.Fatal("other UID was not denied")
			}
			t.Log("verified another UID cannot connect to the dynamic UID's 0600 filesystem socket")
			return
		}
	}
}
