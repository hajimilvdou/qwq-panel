// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

const (
	peerFixtureTimeout = 5 * time.Second
	peerChildSocketEnv = "QWQ_TEST_PRIVILEGED_PEER_SOCKET"
	peerArenaPrefix    = "qwq-peer-arena-"
)

type peerWireOutcome struct {
	UID     int
	OK      bool
	Code    string
	Closed  bool
	Failure string
}

// ======================== 真实 Unix socket；UID 只在连接子进程里降低 ========================

func peerUnixRequest(t *testing.T, server *helperServer, req sandbox.HelperRequest, clientUID int) peerWireOutcome {
	t.Helper()
	arena := peerArena(t)
	// Linux abstract socket 不依赖文件访问位；门禁必须由内核 UID 真正完成。
	address := "@" + filepath.Base(arena)
	listener, err := net.Listen("unix", address)
	if err != nil {
		t.Fatalf("创建 peer Unix listener 失败：%v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, listener, true) }()
	stop := func() {
		cancel()
		_ = listener.Close()
	}
	wait := peerFixtureWaiter(t, done, stop)
	var result peerWireOutcome
	if clientUID != os.Getuid() {
		if os.Geteuid() != 0 || clientUID <= 0 {
			t.Fatal("连接子进程只允许 root 测试降到明确的非 root UID")
		}
		result = peerChildRequest(t, arena, address, req, clientUID)
	} else {
		connection, err := net.DialTimeout("unix", address, peerFixtureTimeout)
		if err != nil {
			t.Fatalf("连接 peer Unix socket 失败：%v", err)
		}
		result = peerExchange(connection, req)
	}
	wait() // 取消前必须已经自然结束，明确验证 one-shot 排空。
	if result.UID != clientUID {
		t.Fatalf("连接进程未使用要求的 UID：got=%d want=%d", result.UID, clientUID)
	}
	return result
}

func peerPipeRequest(t *testing.T, h *testHost, req sandbox.HelperRequest) peerWireOutcome {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		h.server.serveConn(ctx, serverSide)
		done <- nil
	}()
	stop := func() {
		cancel()
		_ = serverSide.Close()
		_ = clientSide.Close()
	}
	wait := peerFixtureWaiter(t, done, stop)
	result := peerExchange(clientSide, req)
	wait()
	return result
}

func peerFixtureWaiter(t *testing.T, done <-chan error, stop func()) func() {
	t.Helper()
	var once sync.Once
	wait := func() {
		once.Do(func() {
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
					t.Errorf("peer 服务夹具退出失败：%v", err)
				}
			case <-time.After(peerFixtureTimeout):
				stop()
				t.Error("peer 服务未在期限内自然退出")
				select {
				case <-done:
				case <-time.After(peerFixtureTimeout):
					t.Error("peer 服务在关闭连接后仍未排空")
				}
			}
		})
	}
	t.Cleanup(func() { stop(); wait() })
	return wait
}

// ======================== 复用有界 JSON 协议；超时和坏响应不能冒充身份拒绝 ========================

type peerCountedReader struct {
	io.Reader
	bytes int
	err   error
}

func (r *peerCountedReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	r.bytes += n
	if err != nil {
		r.err = err
	}
	return n, err
}

func peerExchange(connection net.Conn, req sandbox.HelperRequest) peerWireOutcome {
	defer func() { _ = connection.Close() }()
	result := peerWireOutcome{UID: os.Getuid()}
	if err := connection.SetDeadline(time.Now().Add(peerFixtureTimeout)); err != nil {
		result.Closed = peerConnectionClosed(err)
		if !result.Closed {
			result.Failure = "deadline: " + err.Error()
		}
		return result
	}
	// 双向并行允许服务在正文读取前答复拒绝，net.Pipe 也不会形成写写死锁。
	written := make(chan error, 1)
	go func() { written <- sandbox.WriteHelperJSON(connection, req) }()
	reader := &peerCountedReader{Reader: connection}
	var response sandbox.HelperResponse
	readErr := sandbox.ReadHelperJSON(reader, &response)
	_ = connection.Close() // 唤醒任何仍在发送的正文，并在返回前等待发送协程。
	writeErr := <-written
	if writeErr != nil && !peerConnectionClosed(writeErr) {
		result.Failure = "write: " + writeErr.Error()
		return result
	}
	if readErr != nil {
		// ReadHelperJSON 把空 EOF 转为 JSON 错误；这里只接受真实零正文关闭。
		if reader.bytes == 0 && peerConnectionClosed(reader.err) {
			result.Closed = true
		} else {
			result.Failure = "read: " + readErr.Error()
		}
		return result
	}
	if writeErr != nil && response.OK {
		result.Failure = "请求正文未完整发送却收到成功响应"
		return result
	}
	result.OK, result.Code = response.OK, response.Code
	return result
}

func peerConnectionClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}

// ======================== 临时 arena：创建和递归清理均先核定绝对边界 ========================

func peerArena(t *testing.T) string {
	t.Helper()
	parent, err := filepath.Abs(os.TempDir())
	if err != nil {
		t.Fatalf("解析 peer 临时根失败：%v", err)
	}
	arena, err := os.MkdirTemp(parent, peerArenaPrefix)
	if err != nil {
		t.Fatalf("创建 peer arena 失败：%v", err)
	}
	t.Cleanup(func() {
		if err := checkPeerArena(parent, arena); err != nil {
			t.Errorf("拒绝清理边界不明的 peer arena：%v", err)
			return
		}
		if err := os.RemoveAll(arena); err != nil {
			t.Errorf("清理 peer arena 失败：%v", err)
		}
		if _, err := os.Lstat(arena); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("peer arena 清理后仍有残留：%v", err)
		}
	})
	if err := checkPeerArena(parent, arena); err != nil {
		t.Fatalf("peer arena 边界无效：%v", err)
	}
	if err := os.Chmod(arena, 0o755); err != nil {
		t.Fatalf("设置受控子进程 arena 访问位失败：%v", err)
	}
	return arena
}

func checkPeerArena(parent, arena string) error {
	absolute, err := filepath.Abs(arena)
	if err != nil || absolute != filepath.Clean(arena) || filepath.Dir(absolute) != parent ||
		!strings.HasPrefix(filepath.Base(absolute), peerArenaPrefix) {
		return errors.New("peer arena 不属于本次明确的临时根")
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("peer arena 不是本次创建的真实目录")
	}
	return nil
}

func peerChildBinary(t *testing.T, arena string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("定位当前测试二进制失败：%v", err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatalf("打开当前测试二进制失败：%v", err)
	}
	defer func() { _ = source.Close() }()
	path := filepath.Join(arena, "peer-test")
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatalf("建立受控连接测试二进制失败：%v", err)
	}
	_, copyErr := io.Copy(target, source)
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("复制受控连接测试二进制失败：copy=%v close=%v", copyErr, closeErr)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("设置连接测试二进制执行位失败：%v", err)
	}
	return path
}

func peerChildRequest(t *testing.T, arena, address string, req sandbox.HelperRequest, uid int) peerWireOutcome {
	t.Helper()
	var input bytes.Buffer
	if err := sandbox.WriteHelperJSON(&input, req); err != nil {
		t.Fatalf("编码连接子进程的测试请求失败：%v", err)
	}
	defer clear(input.Bytes())
	executable := peerChildBinary(t, arena)
	ctx, cancel := context.WithTimeout(t.Context(), peerFixtureTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestPrivilegedPeerClientProcess$")
	command.Env = []string{peerChildSocketEnv + "=" + address}
	command.Stdin = &input
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)},
	}
	command.WaitDelay = time.Second
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output() // Output 完整 Wait；超时由 CommandContext 杀死并回收。
	defer clear(output)
	if err != nil {
		t.Fatalf("受控连接子进程失败：%v stderr=%q", err, stderr.String())
	}
	if command.ProcessState == nil || !command.ProcessState.Success() {
		t.Fatal("受控连接子进程没有完整退出")
	}
	var result peerWireOutcome
	if err := sandbox.ReadHelperJSON(bytes.NewReader(output), &result); err != nil {
		t.Fatalf("受控连接子进程结果无效：%v", err)
	}
	return result
}

// TestPrivilegedPeerClientProcess 是当前测试二进制的受控连接入口，不启动服务。
func TestPrivilegedPeerClientProcess(t *testing.T) {
	address := os.Getenv(peerChildSocketEnv)
	if address == "" {
		return
	}
	if !strings.HasPrefix(address, "@"+peerArenaPrefix) {
		fmt.Fprintln(os.Stderr, "连接子进程地址不属于测试 arena")
		os.Exit(1)
	}
	var req sandbox.HelperRequest
	if err := sandbox.ReadHelperJSON(os.Stdin, &req); err != nil {
		fmt.Fprintln(os.Stderr, "连接子进程请求无效")
		os.Exit(1)
	}
	connection, err := net.DialTimeout("unix", address, peerFixtureTimeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "连接子进程无法连接 Unix socket:", err)
		os.Exit(1)
	}
	result := peerExchange(connection, req)
	if err := sandbox.WriteHelperJSON(os.Stdout, result); err != nil {
		fmt.Fprintln(os.Stderr, "连接子进程无法输出测试结果:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func peerFileOwner(info fs.FileInfo) (uint32, uint32, error) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid, stat.Gid, nil
	}
	return 0, 0, errors.New("Linux 夹具缺少真实 stat 属主元数据")
}
