// SPDX-License-Identifier: AGPL-3.0-only

package coreproc

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayconfig"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 纯 Go 受控 obfs 测试子进程夹具 ========================

// TestHelperObfsProcess 仅在测试子进程模式激活，模拟 simple-obfs 监听与崩溃行为。
func TestHelperObfsProcess(t *testing.T) {
	mode := os.Getenv("QWQ_TEST_OBFS_HELPER")
	if mode == "" {
		return
	}
	args := os.Args
	sep := -1
	for i, arg := range args {
		if arg == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(args) {
		os.Exit(2)
	}
	obfsArgs := args[sep+1:]
	var listenHost, portStr string
	for i := 0; i+1 < len(obfsArgs); i++ {
		switch obfsArgs[i] {
		case "-s":
			listenHost = obfsArgs[i+1]
		case "-p":
			portStr = obfsArgs[i+1]
		}
	}
	if portStr == "" {
		os.Exit(3)
	}
	if mode == "no-listen" {
		// 保持存活但不监听端口，用于触发就绪探针失败与整组回滚。
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
		<-sigCh
		os.Exit(0)
	}

	if mode == "crash-immediately" {
		os.Exit(1)
	}

	bindHost := obfsProbeHost(listenHost)
	ln, err := net.Listen("tcp", net.JoinHostPort(bindHost, portStr))
	if err != nil {
		os.Exit(4)
	}
	defer ln.Close()

	if mode == "crash-after-ready" {
		// 等待首次就绪探针连接成功后再退出，避免在慢速/竞态环境下竞态抖动。
		if conn, err := ln.Accept(); err == nil {
			_ = conn.Close()
		}
		time.Sleep(60 * time.Millisecond)
		os.Exit(1)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	<-sigCh
	os.Exit(0)
}

func testBinarySHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func freeLocalTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func helperCmdFactory(modeFn func(args []string) string) func(binaryPath string, args []string) *exec.Cmd {
	return func(binaryPath string, args []string) *exec.Cmd {
		cmdArgs := append([]string{"-test.run=^TestHelperObfsProcess$", "--"}, args...)
		cmd := exec.Command(binaryPath, cmdArgs...)
		cmd.Env = []string{
			"PATH=/usr/bin:/bin",
			"QWQ_TEST_OBFS_HELPER=" + modeFn(args),
		}
		setPlatformProcessAttrs(cmd)
		return cmd
	}
}

func portArgOf(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-p" {
			return args[i+1]
		}
	}
	return ""
}

// ======================== ObfsSupervisor 4 项核心场景测试 ========================

func TestObfsSupervisorRejectsSHA256Mismatch(t *testing.T) {
	sup := NewObfsSupervisor(os.Args[0], "sha256:"+strings.Repeat("0", 64))
	plan := xrayconfig.ObfsPlan{
		ProfileID: "ss-bad-hash",
		Mode:      "tls",
		Host:      "www.bing.com",
		External:  corev2.Listener{ProfileID: "ss-bad-hash", Network: "tcp", Listen: "127.0.0.1", Port: freeLocalTCPPort(t)},
		Target:    xrayconfig.ObfsTarget{Listen: "127.0.0.1", Port: 30001},
	}
	err := sup.StartAll(t.Context(), []xrayconfig.ObfsPlan{plan})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("期望拒绝 SHA-256 不匹配的二进制，实际 err=%v", err)
	}
}

func TestObfsSupervisorStartMultipleReadyAndStop(t *testing.T) {
	portA := freeLocalTCPPort(t)
	portB := freeLocalTCPPort(t)

	sup := NewObfsSupervisor(os.Args[0], testBinarySHA256(t, os.Args[0]))
	sup.cmdFactory = helperCmdFactory(func([]string) string { return "serve" })
	t.Cleanup(func() { sup.StopAll(2 * time.Second) })

	plans := []xrayconfig.ObfsPlan{
		{
			ProfileID: "ss-1",
			Mode:      "http",
			Host:      "www.bing.com",
			External:  corev2.Listener{ProfileID: "ss-1", Network: "tcp", Listen: "127.0.0.1", Port: portA},
			Target:    xrayconfig.ObfsTarget{Listen: "127.0.0.1", Port: 30001},
		},
		{
			ProfileID: "ss-2",
			Mode:      "tls",
			Host:      "www.bing.com",
			External:  corev2.Listener{ProfileID: "ss-2", Network: "tcp", Listen: "::", Port: portB},
			Target:    xrayconfig.ObfsTarget{Listen: "127.0.0.1", Port: 30002},
		},
	}
	if err := sup.StartAll(t.Context(), plans); err != nil {
		t.Fatalf("StartAll 应成功启动全部实例: %v", err)
	}
	if healthy, errText := sup.Status(); !healthy || errText != "" {
		t.Fatalf("运行期间应保持健康: healthy=%v err=%q", healthy, errText)
	}

	// 验证两端口均已真实监听。
	for _, port := range []int{portA, portB} {
		if err := waitLocalTCPReady(t.Context(), "127.0.0.1", port, time.Second); err != nil {
			t.Fatalf("端口 %d 未就绪: %v", port, err)
		}
	}

	sup.StopAll(2 * time.Second)
	// StopAll 返回后端口应释放，不再接受连接。
	for _, port := range []int{portA, portB} {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 150*time.Millisecond); err == nil {
			_ = conn.Close()
			t.Fatalf("StopAll 后端口 %d 仍在监听", port)
		}
	}
}

func TestObfsSupervisorCrashBackoffAndDegrade(t *testing.T) {
	t.Run("self_heal_after_single_crash", func(t *testing.T) {
		port := freeLocalTCPPort(t)
		var starts atomic.Int32

		sup := NewObfsSupervisor(os.Args[0], "")
		sup.initialBackoff = 20 * time.Millisecond
		sup.maxBackoff = 60 * time.Millisecond
		sup.cmdFactory = helperCmdFactory(func([]string) string {
			if starts.Add(1) == 1 {
				return "crash-after-ready"
			}
			return "serve"
		})
		t.Cleanup(func() { sup.StopAll(2 * time.Second) })

		plan := xrayconfig.ObfsPlan{
			ProfileID: "ss-heal",
			Mode:      "http",
			Host:      "www.bing.com",
			External:  corev2.Listener{ProfileID: "ss-heal", Network: "tcp", Listen: "127.0.0.1", Port: port},
			Target:    xrayconfig.ObfsTarget{Listen: "127.0.0.1", Port: 30006},
		}
		if err := sup.StartAll(t.Context(), []xrayconfig.ObfsPlan{plan}); err != nil {
			t.Fatalf("StartAll 失败: %v", err)
		}

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if starts.Load() >= 2 {
				if err := waitLocalTCPReady(t.Context(), "127.0.0.1", port, time.Second); err == nil {
					if healthy, errText := sup.Status(); !healthy || errText != "" {
						t.Fatalf("自愈后应保持健康: healthy=%v err=%q", healthy, errText)
					}
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("等待崩溃后退避自愈超时（已启动 %d 次）", starts.Load())
	})

	t.Run("degrade_after_five_consecutive_crashes", func(t *testing.T) {
		port := freeLocalTCPPort(t)
		var starts atomic.Int32

		sup := NewObfsSupervisor(os.Args[0], "")
		sup.initialBackoff = 20 * time.Millisecond
		sup.maxBackoff = 60 * time.Millisecond
		sup.cmdFactory = helperCmdFactory(func([]string) string {
			if starts.Add(1) == 1 {
				return "crash-after-ready"
			}
			return "crash-immediately"
		})
		t.Cleanup(func() { sup.StopAll(2 * time.Second) })

		plan := xrayconfig.ObfsPlan{
			ProfileID: "ss-flaky",
			Mode:      "tls",
			Host:      "www.bing.com",
			External:  corev2.Listener{ProfileID: "ss-flaky", Network: "tcp", Listen: "127.0.0.1", Port: port},
			Target:    xrayconfig.ObfsTarget{Listen: "127.0.0.1", Port: 30003},
		}
		if err := sup.StartAll(t.Context(), []xrayconfig.ObfsPlan{plan}); err != nil {
			t.Fatalf("首次就绪探测应通过: %v", err)
		}

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			healthy, errText := sup.Status()
			if !healthy && errText != "" {
				if got := starts.Load(); got != maxConsecutiveCrashes {
					t.Fatalf("期望连续启动 %d 次后降级停止，实际启动 %d 次", maxConsecutiveCrashes, got)
				}
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("等待连续 5 次崩溃进入降级状态超时（已启动 %d 次）", starts.Load())
	})
}

func TestObfsSupervisorRollbackOnProbeFailure(t *testing.T) {
	goodPort := freeLocalTCPPort(t)
	badPort := freeLocalTCPPort(t)
	badPortStr := strconv.Itoa(badPort)

	sup := NewObfsSupervisor(os.Args[0], "")
	sup.readyTimeout = 250 * time.Millisecond
	sup.cmdFactory = helperCmdFactory(func(args []string) string {
		if portArgOf(args) == badPortStr {
			return "no-listen"
		}
		return "serve"
	})
	t.Cleanup(func() { sup.StopAll(2 * time.Second) })

	plans := []xrayconfig.ObfsPlan{
		{
			ProfileID: "ss-good",
			Mode:      "http",
			Host:      "www.bing.com",
			External:  corev2.Listener{ProfileID: "ss-good", Network: "tcp", Listen: "127.0.0.1", Port: goodPort},
			Target:    xrayconfig.ObfsTarget{Listen: "127.0.0.1", Port: 30004},
		},
		{
			ProfileID: "ss-bad",
			Mode:      "tls",
			Host:      "www.bing.com",
			External:  corev2.Listener{ProfileID: "ss-bad", Network: "tcp", Listen: "127.0.0.1", Port: badPort},
			Target:    xrayconfig.ObfsTarget{Listen: "127.0.0.1", Port: 30005},
		},
	}

	err := sup.StartAll(t.Context(), plans)
	if err == nil {
		t.Fatal("第二个实例就绪失败时 StartAll 必须报错")
	}

	// 第一个已启动实例必须已随回滚停止，端口不再监听。
	if conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(goodPort)), 150*time.Millisecond); dialErr == nil {
		_ = conn.Close()
		t.Fatalf("就绪失败回滚后，首个实例端口 %d 仍在监听", goodPort)
	}
}
