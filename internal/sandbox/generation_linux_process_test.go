// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ======================== 真实子进程 fixture：只测试私有内核层，不伪称插件 unit/cgroup ========================

func TestGenerationKernelChild(t *testing.T) {
	if os.Getenv("QWQ_GENERATION_TEST_CHILD") != "1" {
		return
	}
	if _, err := fmt.Fprintln(os.Stdout, "generation-child-ready"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}

type generationKernelChild struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	cancel    context.CancelFunc
	started   bool
	done      chan struct{}
	readyDone chan struct{}
	waitErr   error
}

func startGenerationKernelChild(t *testing.T) *generationKernelChild {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(generationTestContext(t), 8*time.Second)
	child := &generationKernelChild{cancel: cancel, done: make(chan struct{}), readyDone: make(chan struct{})}
	child.cmd = exec.CommandContext(ctx, executable, "-test.run=^TestGenerationKernelChild$", "-test.timeout=7s")
	child.cmd.Env = []string{"QWQ_GENERATION_TEST_CHILD=1"}
	child.stdin, err = child.cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	child.stdout, err = child.cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(errors.Join(err, child.stdin.Close()))
	}
	t.Cleanup(func() { child.cleanup(t) })
	if err := child.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child.started = true
	go func() {
		child.waitErr = child.cmd.Wait()
		close(child.done)
	}()
	type readiness struct {
		line string
		err  error
	}
	ready := make(chan readiness, 1)
	go func() {
		defer close(child.readyDone)
		line, err := bufio.NewReader(child.stdout).ReadString('\n')
		ready <- readiness{line: line, err: err}
	}()
	select {
	case result := <-ready:
		if result.err != nil || result.line != "generation-child-ready\n" {
			t.Fatalf("真实子进程未就绪：%q %v", result.line, result.err)
		}
	case <-ctx.Done():
		t.Fatalf("真实子进程就绪超时：%v", ctx.Err())
	}
	return child
}

func (child *generationKernelChild) cleanup(t *testing.T) {
	t.Helper()
	child.cancel()
	for _, pipe := range []io.Closer{child.stdin, child.stdout} {
		if err := pipe.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("关闭子进程管道：%v", err)
		}
	}
	if !child.started {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, done := range []<-chan struct{}{child.done, child.readyDone} {
		select {
		case <-done:
		case <-ctx.Done():
			t.Errorf("子进程或读取协程未回收：%v", ctx.Err())
			return
		}
	}
}

func (child *generationKernelChild) exitNormally(ctx context.Context) error {
	if err := child.stdin.Close(); err != nil {
		return err
	}
	select {
	case <-child.done:
		return child.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func pinGenerationTestKernel(t *testing.T, child *generationKernelChild) (*kernelProcess, kernelProcessSnapshot) {
	t.Helper()
	process, snapshot, err := pinKernelProcess(generationTestContext(t), "/proc", child.cmd.Process.Pid, unix.PidfdOpen)
	if err != nil {
		t.Fatalf("真实固定 proc/pidfd 失败：%v", err)
	}
	t.Cleanup(func() {
		if err := process.Close(); err != nil {
			t.Errorf("关闭真实固定句柄：%v", err)
		}
	})
	return process, snapshot
}

func requireGenerationKernelAlive(t *testing.T, process *kernelProcess) {
	t.Helper()
	if err := process.signal(0); err != nil {
		t.Fatalf("替换子进程被误伤：%v", err)
	}
	exited, err := process.exited(generationTestContext(t))
	if err != nil || exited {
		t.Fatalf("替换子进程已退出：exited=%v %v", exited, err)
	}
}

func requireGenerationFDClosed(t *testing.T, fd int) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); !errors.Is(err, unix.EBADF) {
		t.Fatalf("失败路径泄漏 FD %d：%v", fd, err)
	}
}

func captureGenerationProcFDs(pid int) ([]int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	var captured []int
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			return nil, err
		}
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if target == "/proc" || target == "/proc/"+strconv.Itoa(pid) {
			captured = append(captured, fd)
		}
	}
	if len(captured) != 2 {
		return nil, fmt.Errorf("expected one proc root and one original proc directory, got %d", len(captured))
	}
	return captured, nil
}

// ======================== 原 procFD -> pidfd_open 窗口及固定句柄退出回归 ========================

func TestGenerationKernelPinRejectsExitedOriginalAndClosesReplacementFD(t *testing.T) {
	original, replacement := startGenerationKernelChild(t), startGenerationKernelChild(t)
	replacementProcess, _ := pinGenerationTestKernel(t, replacement)
	ctx, cancel := context.WithTimeout(generationTestContext(t), 2*time.Second)
	defer cancel()
	returnedFD := -1
	var procFDs []int
	process, _, err := pinKernelProcess(ctx, "/proc", original.cmd.Process.Pid, func(int, int) (int, error) {
		// 此时原 procFD 已取得；结束原子进程，再故意返回新进程 pidfd。
		var err error
		procFDs, err = captureGenerationProcFDs(original.cmd.Process.Pid)
		if err != nil {
			return -1, err
		}
		if err := original.exitNormally(ctx); err != nil {
			return -1, err
		}
		fd, err := unix.PidfdOpen(replacement.cmd.Process.Pid, 0)
		returnedFD = fd
		return fd, err
	})
	if process != nil || !errors.Is(err, ErrGenerationIdentity) || !errors.Is(err, unix.ESRCH) {
		t.Fatalf("原 procFD 的 signal=0 未挡住替换窗口：process=%v %v", process, err)
	}
	if returnedFD < 0 {
		t.Fatal("测试未取得替换 pidfd")
	}
	requireGenerationFDClosed(t, returnedFD)
	for _, fd := range procFDs {
		requireGenerationFDClosed(t, fd)
	}
	requireGenerationKernelAlive(t, replacementProcess)
}

func TestGenerationKernelPinRejectsDifferentLivePIDFD(t *testing.T) {
	original, replacement := startGenerationKernelChild(t), startGenerationKernelChild(t)
	originalProcess, _ := pinGenerationTestKernel(t, original)
	replacementProcess, _ := pinGenerationTestKernel(t, replacement)
	returnedFD := -1
	process, _, err := pinKernelProcess(generationTestContext(t), "/proc", original.cmd.Process.Pid, func(int, int) (int, error) {
		fd, err := unix.PidfdOpen(replacement.cmd.Process.Pid, 0)
		returnedFD = fd
		return fd, err
	})
	if process != nil || !errors.Is(err, ErrGenerationIdentity) {
		t.Fatalf("存活原 proc 与其他 pidfd 被误绑定：process=%v %v", process, err)
	}
	requireGenerationFDClosed(t, returnedFD)
	requireGenerationKernelAlive(t, originalProcess)
	requireGenerationKernelAlive(t, replacementProcess)
}

func TestGenerationKernelExitedFDDoesNotFollowNewMain(t *testing.T) {
	original, replacement := startGenerationKernelChild(t), startGenerationKernelChild(t)
	originalProcess, _ := pinGenerationTestKernel(t, original)
	replacementProcess, _ := pinGenerationTestKernel(t, replacement)
	ctx, cancel := context.WithTimeout(generationTestContext(t), 2*time.Second)
	defer cancel()
	if err := original.exitNormally(ctx); err != nil {
		t.Fatal(err)
	}
	exited, err := originalProcess.exited(ctx)
	if err != nil || !exited {
		t.Fatalf("真正 pidfd 未报告原退出：%v %v", exited, err)
	}
	if err := originalProcess.signal(unix.SIGTERM); !errors.Is(err, ErrGenerationExited) || !errors.Is(err, unix.ESRCH) {
		t.Fatalf("原退出句柄未返回 ESRCH：%v", err)
	}
	requireGenerationKernelAlive(t, replacementProcess)
}

func TestGenerationKernelCancelAfterPIDFDOpenClosesIt(t *testing.T) {
	child := startGenerationKernelChild(t)
	ctx, cancel := context.WithCancel(generationTestContext(t))
	defer cancel()
	returnedFD := -1
	var procFDs []int
	process, _, err := pinKernelProcess(ctx, "/proc", child.cmd.Process.Pid, func(pid, flags int) (int, error) {
		var err error
		procFDs, err = captureGenerationProcFDs(pid)
		if err != nil {
			return -1, err
		}
		fd, err := unix.PidfdOpen(pid, flags)
		returnedFD = fd
		cancel()
		return fd, err
	})
	if process != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("pidfd 后取消未关闭：process=%v %v", process, err)
	}
	requireGenerationFDClosed(t, returnedFD)
	for _, fd := range procFDs {
		requireGenerationFDClosed(t, fd)
	}
}

func TestGenerationKernelPIDFDOpenFailureClosesProcFDs(t *testing.T) {
	child := startGenerationKernelChild(t)
	cause := errors.New("test pidfd opener failure")
	var procFDs []int
	process, _, err := pinKernelProcess(generationTestContext(t), "/proc", child.cmd.Process.Pid, func(pid, _ int) (int, error) {
		var err error
		procFDs, err = captureGenerationProcFDs(pid)
		if err != nil {
			return -1, err
		}
		return -1, cause
	})
	if process != nil || !errors.Is(err, cause) {
		t.Fatalf("pidfd_open 错误未回传：process=%v %v", process, err)
	}
	for _, fd := range procFDs {
		requireGenerationFDClosed(t, fd)
	}
}

func TestGenerationKernelCloseCannotSignalReusedFDNumber(t *testing.T) {
	original, replacement := startGenerationKernelChild(t), startGenerationKernelChild(t)
	originalProcess, snapshot := pinGenerationTestKernel(t, original)
	replacementProcess, _ := pinGenerationTestKernel(t, replacement)
	staleFD := originalProcess.pidFD
	if err := originalProcess.Close(); err != nil {
		t.Fatal(err)
	}
	// F_DUPFD_CLOEXEC 只占用空闲 FD，不覆盖可能被 Go runtime 持有的描述符。
	reusedFD, err := unix.FcntlInt(uintptr(replacementProcess.pidFD), unix.F_DUPFD_CLOEXEC, staleFD)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeGenerationFD(reusedFD); err != nil {
			t.Errorf("关闭复用测试 FD：%v", err)
		}
	})
	if reusedFD != staleFD {
		t.Skip("原 FD 已被 runtime 占用，不能安全覆盖；此分支须在独立 Linux 门禁重跑")
	}
	if err := originalProcess.signal(unix.SIGTERM); !errors.Is(err, ErrGenerationClosed) {
		t.Fatalf("Close 后信号触及复用 FD：%v", err)
	}
	if _, err := originalProcess.exited(generationTestContext(t)); !errors.Is(err, ErrGenerationClosed) {
		t.Fatalf("Close 后 poll 触及复用 FD：%v", err)
	}
	if err := originalProcess.verify(generationTestContext(t), snapshot); !errors.Is(err, ErrGenerationClosed) {
		t.Fatalf("Close 后相对读取触及复用 FD：%v", err)
	}
	requireGenerationKernelAlive(t, replacementProcess)
}

func TestGenerationKernelConcurrentSignalPollAndClose(t *testing.T) {
	child := startGenerationKernelChild(t)
	process, _ := pinGenerationTestKernel(t, child)
	ctx, cancel := context.WithTimeout(generationTestContext(t), 2*time.Second)
	defer cancel()
	results := make(chan error, 256)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 16 {
				if ctx.Err() != nil {
					return
				}
				results <- process.signal(unix.SIGCONT)
				_, err := process.exited(ctx)
				results <- err
			}
		}()
	}
	close(start)
	if err := process.Close(); err != nil {
		t.Error(err)
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("并发固定句柄工作未回收")
	}
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, ErrGenerationClosed) {
			t.Fatalf("并发动作出现非关闭错误：%v", err)
		}
	}
}

func TestGenerationProcessStatHandlesSpacesAndParentheses(t *testing.T) {
	fields := []string{"S"}
	for range 18 {
		fields = append(fields, "0")
	}
	fields = append(fields, "987654321", "0", "0")
	for _, comm := range []string{"plain", "with space", "has ) nested ( name", "line\nbreak)"} {
		data := "42 (" + comm + ") " + strings.Join(fields, " ") + "\n"
		pid, ticks, err := parseGenerationProcessStat(data)
		if err != nil || pid != 42 || ticks != 987654321 {
			t.Fatalf("comm=%q 导致字段 22 错位：pid=%d ticks=%d %v", comm, pid, ticks, err)
		}
	}
	for _, data := range []string{"", "42 (broken", "0 (name) " + strings.Join(fields, " "), "42 (name) S 1", "42 (name) " + strings.Join(fields[:19], " ") + " -1"} {
		if _, _, err := parseGenerationProcessStat(data); !errors.Is(err, ErrGenerationIdentity) {
			t.Fatalf("残缺 stat 未拒绝：%q %v", data, err)
		}
	}
}

func TestGenerationProcessUIDRequiresFourIdenticalKernelUIDs(t *testing.T) {
	uid, err := parseGenerationProcessUID("Name:\tchild\nUid:\t1234\t1234\t1234\t1234\n")
	if err != nil || uid != 1234 {
		t.Fatalf("真实四 UID 未解析：%d %v", uid, err)
	}
	for _, data := range []string{"", "Uid:\t1 1 1\n", "Uid:\t1 1 0 1\n", "Uid:\t-1 -1 -1 -1\n", "Uid:\t1 1 1 1\nUid:\t1 1 1 1\n"} {
		if _, err := parseGenerationProcessUID(data); !errors.Is(err, ErrGenerationIdentity) {
			t.Fatalf("歧义 UID 未拒绝：%q %v", data, err)
		}
	}
}
