// SPDX-License-Identifier: AGPL-3.0-only

package coreproc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/xraycore/xrayconfig"
)

// ======================== 受控 simple-obfs 子进程监管器 ========================

const (
	defaultObfsInitialBackoff = 500 * time.Millisecond
	defaultObfsMaxBackoff     = 5 * time.Second
	defaultObfsReadyTimeout   = 3 * time.Second
	defaultObfsHealthyReset   = 30 * time.Second
	maxConsecutiveCrashes     = 5
)

type obfsInstance struct {
	plan xrayconfig.ObfsPlan

	mu  sync.Mutex
	cmd *exec.Cmd
}

func (i *obfsInstance) setCmd(cmd *exec.Cmd) {
	i.mu.Lock()
	i.cmd = cmd
	i.mu.Unlock()
}

func (i *obfsInstance) currentCmd() *exec.Cmd {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.cmd
}

// ObfsSupervisor 监管与 Xray 配对运行的 simple-obfs 外层受控子进程。
// 每个实例固定最小环境、回环转发目标、就绪探针及指数退避重启策略。
type ObfsSupervisor struct {
	binaryPath        string
	expectedSHA256    string
	probeFn           func(ctx context.Context, host string, port int, timeout time.Duration) error
	cmdFactory        func(binaryPath string, args []string) *exec.Cmd
	initialBackoff    time.Duration
	maxBackoff        time.Duration
	readyTimeout      time.Duration
	healthyResetAfter time.Duration

	mu          sync.Mutex
	runCancel   context.CancelFunc
	stopTimeout time.Duration
	instances   []*obfsInstance
	degraded    bool
	lastErr     string
	wg          sync.WaitGroup
}

// NewObfsSupervisor 创建 simple-obfs 子进程监管器。
// expectedSHA256 为空时跳过哈希校验；非空时必须精确匹配 "sha256:<64位小写hex>"。
func NewObfsSupervisor(binaryPath, expectedSHA256 string) *ObfsSupervisor {
	return &ObfsSupervisor{
		binaryPath:        strings.TrimSpace(binaryPath),
		expectedSHA256:    strings.TrimSpace(expectedSHA256),
		probeFn:           waitLocalTCPReady,
		initialBackoff:    defaultObfsInitialBackoff,
		maxBackoff:        defaultObfsMaxBackoff,
		readyTimeout:      defaultObfsReadyTimeout,
		healthyResetAfter: defaultObfsHealthyReset,
	}
}

// StartAll 先停止已有实例，再按计划启动并逐一探测全部 simple-obfs 子进程。
// 任意实例校验、启动或就绪探测失败都会回滚停止整组子进程并返回错误。
func (s *ObfsSupervisor) StartAll(parentCtx context.Context, plans []xrayconfig.ObfsPlan) error {
	s.StopAll(5 * time.Second)
	if len(plans) == 0 {
		s.mu.Lock()
		s.degraded = false
		s.lastErr = ""
		s.mu.Unlock()
		return nil
	}
	if err := verifyObfsBinary(s.binaryPath, s.expectedSHA256); err != nil {
		return err
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	runCtx, runCancel := context.WithCancel(parentCtx)

	s.mu.Lock()
	s.runCancel = runCancel
	s.stopTimeout = 5 * time.Second
	s.instances = nil
	s.degraded = false
	s.lastErr = ""
	s.mu.Unlock()

	probe := s.probeFn
	if probe == nil {
		probe = waitLocalTCPReady
	}
	readyTimeout := s.readyTimeoutDuration()

	for _, plan := range plans {
		args, err := buildObfsArgs(plan)
		if err != nil {
			s.StopAll(3 * time.Second)
			return err
		}
		cmd, waitCh, err := s.spawnProcess(args)
		if err != nil {
			s.StopAll(3 * time.Second)
			return fmt.Errorf("coreproc: start obfs %s: %w", plan.ProfileID, err)
		}
		startedAt := time.Now()

		probeCtx, probeCancel := context.WithCancel(runCtx)
		probeDone := make(chan error, 1)
		go func(p xrayconfig.ObfsPlan) {
			probeDone <- probe(probeCtx, obfsProbeHost(p.External.Listen), p.External.Port, readyTimeout)
		}(plan)

		var probeErr error
		var earlyExit bool
		var exitErr error
		select {
		case probeErr = <-probeDone:
			probeCancel()
		case exitErr = <-waitCh:
			earlyExit = true
			probeCancel()
			<-probeDone
		}

		if earlyExit {
			s.StopAll(3 * time.Second)
			return fmt.Errorf("coreproc: obfs %s exited before ready: %v", plan.ProfileID, exitErr)
		}
		if probeErr != nil {
			terminateObfsProcess(cmd, waitCh, 2*time.Second)
			s.StopAll(3 * time.Second)
			return fmt.Errorf("coreproc: obfs %s readiness probe failed: %w", plan.ProfileID, probeErr)
		}

		inst := &obfsInstance{plan: plan, cmd: cmd}
		s.mu.Lock()
		s.instances = append(s.instances, inst)
		s.mu.Unlock()

		s.wg.Add(1)
		go s.supervise(runCtx, inst, waitCh, startedAt)
	}
	return nil
}

// StopAll 停止全部托管中的 simple-obfs 子进程，并在有界超时内等待回收完成。
func (s *ObfsSupervisor) StopAll(timeout time.Duration) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	s.mu.Lock()
	cancel := s.runCancel
	s.runCancel = nil
	s.stopTimeout = timeout
	s.instances = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// Status 返回当前监管器健康状态与降级错误文本。
func (s *ObfsSupervisor) Status() (healthy bool, errText string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded {
		return false, s.lastErr
	}
	return true, ""
}

// OwnedPIDs 返回当前监管中所有存活 simple-obfs 子进程的 PID，供端口占用归属核验。
func (s *ObfsSupervisor) OwnedPIDs() []int {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pids := make([]int, 0, len(s.instances))
	for _, inst := range s.instances {
		if cmd := inst.currentCmd(); cmd != nil && cmd.Process != nil && cmd.Process.Pid > 0 {
			pids = append(pids, cmd.Process.Pid)
		}
	}
	return pids
}

// ======================== 子进程崩溃退避重启与优雅回收 ========================

func (s *ObfsSupervisor) supervise(runCtx context.Context, inst *obfsInstance, waitCh chan error, startedAt time.Time) {
	defer s.wg.Done()

	consecutiveCrashes := 0
	backoff := s.initialBackoffDuration()
	maxBackoff := s.maxBackoffDuration()
	healthyReset := s.healthyResetDuration()

	for {
		select {
		case <-runCtx.Done():
			terminateObfsProcess(inst.currentCmd(), waitCh, s.stopTimeoutDuration())
			return
		case exitErr := <-waitCh:
			if runCtx.Err() != nil {
				return
			}
			if time.Since(startedAt) >= healthyReset {
				consecutiveCrashes = 0
				backoff = s.initialBackoffDuration()
			}
			consecutiveCrashes++
			if consecutiveCrashes >= maxConsecutiveCrashes {
				s.mu.Lock()
				s.degraded = true
				s.lastErr = fmt.Sprintf("obfs instance %s crashed %d consecutive times: %v", inst.plan.ProfileID, consecutiveCrashes, exitErr)
				s.mu.Unlock()
				return
			}

			timer := time.NewTimer(backoff)
			select {
			case <-runCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}

			args, err := buildObfsArgs(inst.plan)
			if err != nil {
				waitCh = make(chan error, 1)
				waitCh <- err
				startedAt = time.Now()
				continue
			}
			cmd, nextWait, err := s.spawnProcess(args)
			if err != nil {
				inst.setCmd(nil)
				waitCh = make(chan error, 1)
				waitCh <- err
				startedAt = time.Now()
				continue
			}
			inst.setCmd(cmd)
			startedAt = time.Now()
			waitCh = nextWait
		}
	}
}

// spawnThreadLockedProcess 在独立绑定 OS 线程的守护协程内执行 cmd.Start() + cmd.Wait()，
// 防止 Linux PR_SET_PDEATHSIG 因 Go 调度器回收空闲 M 线程而向 obfs-server 误发 SIGTERM。
func spawnThreadLockedProcess(buildCmd func() *exec.Cmd) (*exec.Cmd, chan error, error) {
	type startRes struct {
		cmd *exec.Cmd
		err error
	}
	started := make(chan startRes, 1)
	waitCh := make(chan error, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		cmd := buildCmd()
		if err := cmd.Start(); err != nil {
			started <- startRes{err: err}
			close(waitCh)
			return
		}
		started <- startRes{cmd: cmd}
		waitCh <- cmd.Wait()
		close(waitCh)
	}()

	res := <-started
	if res.err != nil {
		return nil, nil, res.err
	}
	return res.cmd, waitCh, nil
}

func (s *ObfsSupervisor) spawnProcess(args []string) (*exec.Cmd, chan error, error) {
	return spawnThreadLockedProcess(func() *exec.Cmd {
		if s.cmdFactory != nil {
			return s.cmdFactory(s.binaryPath, args)
		}
		cmd := exec.Command(s.binaryPath, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		setPlatformProcessAttrs(cmd)
		return cmd
	})
}

func (s *ObfsSupervisor) initialBackoffDuration() time.Duration {
	if s.initialBackoff > 0 {
		return s.initialBackoff
	}
	return defaultObfsInitialBackoff
}

func (s *ObfsSupervisor) maxBackoffDuration() time.Duration {
	if s.maxBackoff > 0 {
		return s.maxBackoff
	}
	return defaultObfsMaxBackoff
}

func (s *ObfsSupervisor) readyTimeoutDuration() time.Duration {
	if s.readyTimeout > 0 {
		return s.readyTimeout
	}
	return defaultObfsReadyTimeout
}

func (s *ObfsSupervisor) healthyResetDuration() time.Duration {
	if s.healthyResetAfter > 0 {
		return s.healthyResetAfter
	}
	return defaultObfsHealthyReset
}

func (s *ObfsSupervisor) stopTimeoutDuration() time.Duration {
	s.mu.Lock()
	t := s.stopTimeout
	s.mu.Unlock()
	if t <= 0 {
		return 3 * time.Second
	}
	return t
}

func terminateObfsProcess(cmd *exec.Cmd, waitCh <-chan error, timeout time.Duration) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = cmd.Process.Kill()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-waitCh:
		return
	case <-timer.C:
		_ = cmd.Process.Kill()
		<-waitCh
	}
}

// ======================== 二进制哈希校验、参数构造与本地 TCP 探测 ========================

func verifyObfsBinary(binaryPath, expectedSHA256 string) error {
	if binaryPath == "" {
		return errors.New("coreproc: obfs binary path is empty")
	}
	info, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("coreproc: stat obfs binary: %w", err)
	}
	if info.IsDir() {
		return errors.New("coreproc: obfs binary path is a directory")
	}
	if expectedSHA256 == "" {
		return nil
	}
	if !strings.HasPrefix(expectedSHA256, "sha256:") || len(expectedSHA256) != len("sha256:")+64 {
		return errors.New("coreproc: expected obfs sha256 format is invalid")
	}
	file, err := os.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("coreproc: open obfs binary: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("coreproc: hash obfs binary: %w", err)
	}
	actual := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if actual != expectedSHA256 {
		return errors.New("coreproc: obfs binary sha256 mismatch")
	}
	return nil
}

func buildObfsArgs(plan xrayconfig.ObfsPlan) ([]string, error) {
	if plan.Mode != "http" && plan.Mode != "tls" {
		return nil, fmt.Errorf("coreproc: unsupported obfs mode %q", plan.Mode)
	}
	if plan.External.Port < 1 || plan.External.Port > 65535 {
		return nil, fmt.Errorf("coreproc: invalid obfs external port %d", plan.External.Port)
	}
	if plan.Target.Port < 1 || plan.Target.Port > 65535 || strings.TrimSpace(plan.Target.Listen) == "" {
		return nil, fmt.Errorf("coreproc: invalid obfs target %s:%d", plan.Target.Listen, plan.Target.Port)
	}
	listenHost := strings.TrimSpace(plan.External.Listen)
	if listenHost == "" || listenHost == "::" {
		listenHost = "::0"
	}
	return []string{
		"-s", listenHost,
		"-p", strconv.Itoa(plan.External.Port),
		"--obfs", plan.Mode,
		"-r", net.JoinHostPort(plan.Target.Listen, strconv.Itoa(plan.Target.Port)),
		"--timeout", "300",
	}, nil
}

func obfsProbeHost(listen string) string {
	host := strings.Trim(strings.TrimSpace(listen), "[]")
	if host == "" || host == "::" || host == "::0" || host == "0.0.0.0" {
		return "127.0.0.1"
	}
	return host
}

func waitLocalTCPReady(ctx context.Context, host string, port int, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultObfsReadyTimeout
	}
	addr := net.JoinHostPort(strings.Trim(strings.TrimSpace(host), "[]"), strconv.Itoa(port))
	deadline := time.Now().Add(timeout)
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tcp readiness timeout for %s: %w", addr, err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
