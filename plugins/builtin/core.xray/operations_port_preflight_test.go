// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

// ======================== 真实监听与原快照：拒绝发生在停止旧核心之前 ========================

func TestApplyBusyTargetPortKeepsHealthyCore(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	setPortIntent(t, f, "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, "2")
	assertPortConflictPreservesCore(t, f)
}

func TestApplyBusyInitialPortHasNoProcessEffects(t *testing.T) {
	f := newApplyFixture(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	setPortIntent(t, f, "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, "1")
	_, err = f.engine.Execute(t.Context(), f.request())
	metadata, readErr := f.store.Committed(t.Context())
	if apply.ErrorCode(err) != "CORE_PORT_UNAVAILABLE" || readErr != nil || metadata != nil ||
		f.process.starts != 0 || f.process.stops != 0 || f.host.found {
		t.Fatalf("首次忙端口未在进程和提交前拒绝：code=%q starts=%d stops=%d", apply.ErrorCode(err), f.process.starts, f.process.stops)
	}
}

func TestApplyPortAddressWideningRejectsForeignListener(t *testing.T) {
	f := newApplyFixture(t)
	port := availablePort(t, "127.0.0.1")
	setPortIntent(t, f, "127.0.0.1", port, "1")
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	owned, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.Close() })
	foreign, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	// 两个监听都在本测试进程内；只允许跳过旧配置的精确地址与 inode。
	f.process.mu.Lock()
	f.process.snapshot.PID = os.Getpid()
	f.process.mu.Unlock()
	setPortIntent(t, f, "0.0.0.0", port, "2")
	assertPortConflictPreservesCore(t, f)
}

func TestApplyPortWildcardScopeRejectsOtherFamilyListener(t *testing.T) {
	reservation, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	actual := reservation.Addr().(*net.TCPAddr).AddrPort()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	if !actual.Addr().Is6() {
		t.Skip("本机通配 TCP 探针使用单 IPv4 族")
	}
	f := newApplyFixture(t)
	port := int(actual.Port())
	setPortIntent(t, f, "127.0.0.1", port, "1")
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	owned, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.Close() })
	foreign, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	f.process.mu.Lock()
	f.process.snapshot.PID = os.Getpid()
	f.process.mu.Unlock()
	setPortIntent(t, f, "0.0.0.0", port, "2")
	assertPortConflictPreservesCore(t, f)
}

// ======================== 正向边界：旧监听、通配族与探针回收 ========================

func TestApplyPortPreflightAllowsOwnedListener(t *testing.T) {
	for _, listen := range []string{"127.0.0.1", "0.0.0.0", "::1", "::"} {
		t.Run(listen, func(t *testing.T) {
			f := newApplyFixture(t)
			port := availablePort(t, listen)
			setPortIntent(t, f, listen, port, "1")
			if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", net.JoinHostPort(listen, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			f.process.mu.Lock()
			f.process.snapshot.PID = os.Getpid()
			f.process.mu.Unlock()
			starts, stops := f.process.starts, f.process.stops
			setPortIntent(t, f, listen, port, "2")
			result, err := f.engine.Execute(t.Context(), f.request())
			if err != nil || result.RunningRevision != "2" || f.process.starts != starts || f.process.stops != stops {
				t.Fatalf("相同原监听被误判或触发重启：code=%q", apply.ErrorCode(err))
			}
		})
	}
}

func TestApplyPortPreflightRejectsAnotherProcessOwner(t *testing.T) {
	f := newApplyFixture(t)
	port := availablePort(t, "127.0.0.1")
	setPortIntent(t, f, "127.0.0.1", port, "1")
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	// 监听在当前子进程启动后创建，父进程没有这个 fd；同地址和端口不能冒充归属。
	f.process.mu.Lock()
	f.process.snapshot.PID = os.Getppid()
	f.process.mu.Unlock()
	setPortIntent(t, f, "127.0.0.1", port, "2")
	assertPortConflictPreservesCore(t, f)
}

func TestApplyPortAddressWideningAllowsOnlyOwnedListener(t *testing.T) {
	f := newApplyFixture(t)
	port := availablePort(t, "127.0.0.1")
	setPortIntent(t, f, "127.0.0.1", port, "1")
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	f.process.mu.Lock()
	f.process.snapshot.PID = os.Getpid()
	f.process.mu.Unlock()
	setPortIntent(t, f, "0.0.0.0", port, "2")
	result, err := f.engine.Execute(t.Context(), f.request())
	if err != nil || result.RunningRevision != "2" || !result.Restarted {
		t.Fatalf("只有旧监听的地址扩大被误判：code=%q", apply.ErrorCode(err))
	}
}

func TestApplyPortPreflightClosesProbeAndSkipsDisabledCandidate(t *testing.T) {
	f := newApplyFixture(t)
	port := availablePort(t, "127.0.0.1")
	setPortIntent(t, f, "127.0.0.1", port, "1")
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal("预检没有关闭探针")
	}
	t.Cleanup(func() { _ = listener.Close() })
	var intent coreapi.Intent
	if err := json.Unmarshal(f.host.config, &intent); err != nil {
		t.Fatal(err)
	}
	disabled := false
	intent.Enabled = &disabled
	config, err := json.Marshal(&intent)
	if err != nil {
		t.Fatal(err)
	}
	f.host.config, f.host.revision = config, "2"
	result, err := f.engine.Execute(t.Context(), f.request())
	if err != nil || result.Enabled || result.ProcessState != "STOPPED" {
		t.Fatalf("禁用候选仍尝试绑定忙端口：code=%q", apply.ErrorCode(err))
	}
}

func availablePort(t *testing.T, listen string) int {
	t.Helper()
	reservation, err := net.Listen("tcp", net.JoinHostPort(listen, "0"))
	if err != nil {
		if listen == "::" || listen == "::1" {
			t.Skip("测试机没有可用 IPv6 监听")
		}
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func setPortIntent(t *testing.T, f *applyFixture, listen string, port int, revision string) {
	t.Helper()
	var intent coreapi.Intent
	if err := json.Unmarshal(f.host.config, &intent); err != nil {
		t.Fatal(err)
	}
	intent.Inbound.Listen, intent.Inbound.Port = listen, port
	config, err := json.Marshal(&intent)
	if err != nil {
		t.Fatal(err)
	}
	f.host.config, f.host.revision = config, revision
}

func assertPortConflictPreservesCore(t *testing.T, f *applyFixture) {
	t.Helper()
	before, err := f.store.Committed(t.Context())
	if err != nil || before == nil {
		t.Fatal("端口回归缺少真实已提交快照")
	}
	process := f.process.Snapshot(t.Context())
	starts, stops := f.process.starts, f.process.stops
	kv := bytes.Clone(f.host.kv)
	_, err = f.engine.Execute(t.Context(), f.request())
	after, readErr := f.store.Committed(t.Context())
	current := f.process.Snapshot(t.Context())
	if apply.ErrorCode(err) != "CORE_PORT_UNAVAILABLE" || readErr != nil || after == nil ||
		after.Current.Digest != before.Current.Digest || after.Current.Revision != before.Current.Revision ||
		f.process.starts != starts || f.process.stops != stops || current != process || !bytes.Equal(kv, f.host.kv) {
		t.Fatalf("忙端口使旧核心停止或提交变化：code=%q starts_delta=%d stops_delta=%d", apply.ErrorCode(err), f.process.starts-starts, f.process.stops-stops)
	}
}
