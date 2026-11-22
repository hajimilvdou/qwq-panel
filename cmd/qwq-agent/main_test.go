// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/qwq-panel/qwq/internal/cluster"
	"github.com/qwq-panel/qwq/internal/storage"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ======================== 基础子命令与参数校验测试 ========================

func TestCLIVersionHelpAndValidation(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"version"}, &out, &errBuf); code != 0 || !strings.Contains(out.String(), "qwq-agent") {
		t.Fatalf("version 失败: code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"help"}, &out, &errBuf); code != 0 || !strings.Contains(out.String(), "enroll") || !strings.Contains(out.String(), "run") {
		t.Fatalf("help 失败: code=%d out=%q", code, out.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"unknown-cmd"}, &out, &errBuf); code != 2 {
		t.Fatalf("未知子命令应返回 2，实际 %d", code)
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"enroll", "--controller", "127.0.0.1:8443"}, &out, &errBuf); code != 2 {
		t.Fatalf("enroll 缺少必填参数应返回 2，实际 %d", code)
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"run", "--controller", "127.0.0.1:8444", "--mode", "invalid"}, &out, &errBuf); code != 2 {
		t.Fatalf("run 非法 --mode 应返回 2，实际 %d", code)
	}
}

// ======================== probe_512m 24MiB 软内存上限生效测试 ========================

func TestApplyProbe512MModeSetsMemoryLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	var out bytes.Buffer
	if err := applyRuntimeMode(cluster.ModeProbe512M, &out); err != nil {
		t.Fatalf("applyRuntimeMode(probe_512m) 失败: %v", err)
	}
	gotLimit := debug.SetMemoryLimit(-1)
	if gotLimit != cluster.Probe512MMemoryLimitBytes {
		t.Fatalf("GOMEMLIMIT 未设置为 24 MiB: got %d want %d", gotLimit, cluster.Probe512MMemoryLimitBytes)
	}
	if !strings.Contains(out.String(), "mode=probe_512m") || !strings.Contains(out.String(), "max_plugin_memory_mb=64") {
		t.Fatalf("probe_512m 输出缺少预期运行档位信息: %q", out.String())
	}
}

// ======================== CLI 端到端 enroll + run --mode probe_512m 测试 ========================

func TestCLIEnrollAndRunProbe512ME2E(t *testing.T) {
	prevLimit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prevLimit) })

	ctrlDir := t.TempDir()
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(ctrlDir, "controller.db")})
	if err != nil {
		t.Fatalf("storage.Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ca, err := cluster.OpenCA(ctrlDir)
	if err != nil {
		t.Fatalf("OpenCA 失败: %v", err)
	}
	srv, err := cluster.NewServer(cluster.ServerOptions{
		DB:                db,
		CA:                ca,
		ServerDNSNames:    []string{"localhost"},
		ServerIPs:         []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		HeartbeatInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer 失败: %v", err)
	}

	enrollLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	enrollGRPC := grpc.NewServer(grpc.Creds(credentials.NewTLS(srv.ServerTLSConfig(false))))
	srv.RegisterEnrollment(enrollGRPC)
	go func() { _ = enrollGRPC.Serve(enrollLis) }()
	t.Cleanup(func() { enrollGRPC.Stop(); _ = enrollLis.Close() })

	sessLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sessGRPC := grpc.NewServer(grpc.Creds(credentials.NewTLS(srv.ServerTLSConfig(true))))
	srv.RegisterSession(sessGRPC)
	go func() { _ = sessGRPC.Serve(sessLis) }()
	t.Cleanup(func() { sessGRPC.Stop(); _ = sessLis.Close() })

	tok, err := srv.CreateEnrollmentToken(t.Context(), "probe-hk-1", cluster.ModeProbe512M, "usr_admin", 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken 失败: %v", err)
	}

	agentDir := t.TempDir()
	var enrollOut, enrollErr syncBuffer
	code := runWithContext(t.Context(), []string{
		"enroll",
		"--controller", enrollLis.Addr().String(),
		"--ca-hash", ca.SPKIPinSHA256(),
		"--token", tok.Token,
		"--data-dir", agentDir,
	}, &enrollOut, &enrollErr)
	if code != 0 || !strings.Contains(enrollOut.String(), "enrolled node_id=node_") {
		t.Fatalf("CLI enroll 失败: code=%d out=%q err=%q", code, enrollOut.String(), enrollErr.String())
	}

	runCtx, cancelRun := context.WithCancel(t.Context())
	var runOut, runErr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- runWithContext(runCtx, []string{
			"run",
			"--controller", sessLis.Addr().String(),
			"--mode", cluster.ModeProbe512M,
			"--data-dir", agentDir,
		}, &runOut, &runErr)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.ConnectedNodes()) == 1 && strings.Contains(runOut.String(), "connected node_id=") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	nodes := srv.ConnectedNodes()
	if len(nodes) != 1 || !slices.ContainsFunc(nodes, func(id string) bool { return strings.HasPrefix(id, "node_") }) {
		cancelRun()
		<-done
		t.Fatalf("CLI run 未成功接入控制面: connected=%v out=%q err=%q", nodes, runOut.String(), runErr.String())
	}

	cancelRun()
	exitCode := <-done
	if exitCode != 0 {
		t.Fatalf("收到取消信号后 CLI run 应优雅退出(0)，实际 %d err=%q", exitCode, runErr.String())
	}
	if !strings.Contains(runOut.String(), "mode=probe_512m") {
		t.Fatalf("CLI run 缺少 probe_512m 启动提示: %q", runOut.String())
	}
}
