// SPDX-License-Identifier: AGPL-3.0-only

// Package coreproc 持有一个受 SDK 后台生命周期约束的核心进程。
package coreproc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/internal/xraycore/xrayapi"
	"github.com/qwq-panel/qwq/internal/xraycore/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

var (
	ErrOptions        = errors.New("coreproc: invalid lifecycle dependencies")
	ErrStart          = errors.New("coreproc: managed process could not start")
	ErrAlreadyRunning = errors.New("coreproc: another managed process is still active")
	ErrStop           = errors.New("coreproc: process stop is not confirmed")
	ErrExited         = errors.New("coreproc: committed core process exited")
	ErrUnhealthy      = errors.New("coreproc: private API is not healthy")
)

// Stats 只暴露生产只读客户端已有的方法，不提供 reset 或通用 RPC。
type Stats interface {
	Get(context.Context, string) (int64, error)
	Counters(context.Context) (map[string]int64, error)
	Close() error
}

const (
	// DefaultMaxRestarts 是已提交核心进程意外退出时的默认最大有界重启次数；超出后置为退化态，保留驱动 RPC 通道存活。
	DefaultMaxRestarts        = 5
	defaultRestartBackoff     = 500 * time.Millisecond
	defaultRestartMaxBackoff  = 16 * time.Second
	defaultHealthyResetWindow = 30 * time.Second
)

// Options 的 Command 由已核验 Binary 提供，Track 必须绑定实例的 SDK Go。
type Options struct {
	Socket            string
	Command           func(context.Context, string) (*exec.Cmd, error)
	Track             func(func(context.Context)) error
	API               func(string) (Stats, error)
	OnExit            func(error)
	StopGrace         time.Duration
	MaxRestarts       int
	RestartBackoff    time.Duration
	RestartMaxBackoff time.Duration
	HealthyResetAfter time.Duration
}

// StartSpec 来自已验证 generation，不从 operation 接受自由程序或参数。
type StartSpec struct {
	ConfigPath string
	Digest     string
	InboundID  string
}

// Snapshot 是进程与 API 的分别观测；PID 只供内部验证，不进入 JSON。
type Snapshot struct {
	State    string `json:"process_state"`
	APIState string `json:"api_state"`
	Epoch    string `json:"reset_epoch,omitempty"`
	Digest   string `json:"config_digest,omitempty"`
	PID      int    `json:"-"`
}

// Manager 每实例持有一个 slot，替换必须等待原进程 Wait 完成。
type Manager struct {
	mu      sync.Mutex
	options Options
	current *processSlot
}

type processSlot struct {
	context     context.Context
	cancel      context.CancelFunc
	started     chan error
	done        chan struct{}
	state       string
	spec        StartSpec
	command     *exec.Cmd
	api         Stats
	epoch       string
	committed   bool
	intentional bool
	closeFailed bool
	exitCode    int
}

// New 只检查依赖，不创建 socket、进程或后台 goroutine。
func New(options Options) (*Manager, error) {
	if options.Command == nil || options.Track == nil || !xrayconfig.ValidSocket(options.Socket) {
		return nil, ErrOptions
	}
	if options.StopGrace == 0 {
		options.StopGrace = time.Second
	}
	if options.StopGrace <= 0 || options.StopGrace > 5*time.Second {
		return nil, ErrOptions
	}
	if options.API == nil {
		options.API = func(socket string) (Stats, error) { return xrayapi.New(socket) }
	}
	if options.MaxRestarts == 0 {
		options.MaxRestarts = DefaultMaxRestarts
	}
	if options.RestartBackoff <= 0 {
		options.RestartBackoff = defaultRestartBackoff
	}
	if options.RestartMaxBackoff <= 0 {
		options.RestartMaxBackoff = defaultRestartMaxBackoff
	}
	if options.RestartMaxBackoff < options.RestartBackoff {
		options.RestartMaxBackoff = options.RestartBackoff
	}
	if options.HealthyResetAfter <= 0 {
		options.HealthyResetAfter = defaultHealthyResetWindow
	}
	return &Manager{options: options}, nil
}

// Start 等待启动确认；成功后请求 context 不拥有子进程运行期。
func (m *Manager) Start(ctx context.Context, spec StartSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !state.ValidDigest(spec.Digest) {
		return ErrStart
	}
	if _, err := coreapi.InboundTag(spec.InboundID); err != nil {
		return ErrStart
	}
	runContext, cancel := context.WithCancel(context.Background())
	slot := &processSlot{context: runContext, cancel: cancel, started: make(chan error, 1), done: make(chan struct{}), state: "STARTING", spec: spec, exitCode: -1}
	m.mu.Lock()
	if m.current != nil && !slotDone(m.current) {
		m.mu.Unlock()
		cancel()
		return ErrAlreadyRunning
	}
	m.current = slot
	m.mu.Unlock()
	if err := m.options.Track(func(background context.Context) { m.run(background, ctx, slot) }); err != nil {
		cancel()
		m.mu.Lock()
		slot.state = "STOPPED"
		close(slot.done)
		m.mu.Unlock()
		return ErrStart
	}
	select {
	case err := <-slot.started:
		if err != nil {
			return waitStartCleanup(ctx, slot, err)
		}
		return err
	case <-ctx.Done():
		m.mu.Lock()
		slot.intentional = true
		m.mu.Unlock()
		cancel()
		return waitStartCleanup(ctx, slot, ctx.Err())
	}
}

// ======================== 启动失败的有界回收 ========================

// waitStartCleanup 等同一 slot 完成回收；超时保留归属和原错误，不允许第二进程。
func waitStartCleanup(ctx context.Context, slot *processSlot, cause error) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	select {
	case <-slot.done:
		return cause
	case <-cleanup.Done():
		return errors.Join(cause, ErrStop)
	}
}

// ======================== 唯一被跟踪的启动与 Wait runner ========================
func (m *Manager) run(background, request context.Context, slot *processSlot) {
	stopBackground := context.AfterFunc(background, slot.cancel)
	defer stopBackground()
	defer slot.cancel()
	if background.Err() != nil || request.Err() != nil || slot.context.Err() != nil {
		slot.started <- ErrStart
		m.finish(background, slot)
		return
	}
	if err := m.clearSocket(request); err != nil {
		slot.started <- err
		m.finish(background, slot)
		return
	}
	command, err := m.options.Command(slot.context, slot.spec.ConfigPath)
	var entropy [16]byte
	if err == nil {
		_, err = rand.Read(entropy[:])
	}
	if err != nil || command == nil {
		slot.started <- ErrStart
		m.finish(background, slot)
		return
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = m.options.StopGrace
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	if request.Err() != nil || background.Err() != nil || slot.context.Err() != nil {
		slot.started <- ErrStart
		m.finish(background, slot)
		return
	}
	if err := command.Start(); err != nil {
		slot.started <- ErrStart
		m.finish(background, slot)
		return
	}
	m.mu.Lock()
	slot.command, slot.state, slot.epoch = command, "RUNNING", hex.EncodeToString(entropy[:])
	m.mu.Unlock()
	slot.started <- nil

	// 已提交的核心进程意外退出时，在本管理槽内执行有界指数退避重启（最多 MaxRestarts 次）；
	// 超出次数后释放槽并触发 OnExit(ErrExited)，同时保持外层插件 RPC 通道存活以便管理员修复配置。
	maxRestarts := m.options.MaxRestarts
	backoff := m.options.RestartBackoff
	restarts := 0
	for {
		startedAt := time.Now()
		// 所有退出信息留在本层，原生诊断不会进入错误、日志或响应。
		waitError := command.Wait()
		m.mu.Lock()
		if command.ProcessState != nil {
			slot.exitCode = command.ProcessState.ExitCode()
		} else if waitError != nil {
			slot.exitCode = -1
		}
		unexpected := slot.committed && !slot.intentional && slot.context.Err() == nil && background.Err() == nil
		m.mu.Unlock()

		if !unexpected || maxRestarts <= 0 {
			break
		}
		if time.Since(startedAt) >= m.options.HealthyResetAfter {
			restarts = 0
			backoff = m.options.RestartBackoff
		}

		var nextCmd *exec.Cmd
		var nextEpoch string
		recovered := false
		for restarts < maxRestarts {
			restarts++
			m.mu.Lock()
			slot.state = "STARTING"
			oldClient := slot.api
			slot.api = nil
			m.mu.Unlock()
			if oldClient != nil {
				_ = oldClient.Close()
			}

			timer := time.NewTimer(backoff)
			select {
			case <-slot.context.Done():
				timer.Stop()
				m.finish(background, slot)
				return
			case <-background.Done():
				timer.Stop()
				m.finish(background, slot)
				return
			case <-timer.C:
			}
			backoff *= 2
			if backoff > m.options.RestartMaxBackoff {
				backoff = m.options.RestartMaxBackoff
			}

			m.mu.Lock()
			cancelled := slot.intentional || slot.context.Err() != nil || background.Err() != nil
			m.mu.Unlock()
			if cancelled {
				m.finish(background, slot)
				return
			}

			cleanupCtx, cleanupCancel := context.WithTimeout(slot.context, time.Second)
			clearErr := m.clearSocket(cleanupCtx)
			cleanupCancel()
			if clearErr != nil {
				continue
			}

			cmd, cmdErr := m.options.Command(slot.context, slot.spec.ConfigPath)
			var nextEntropy [16]byte
			if cmdErr == nil {
				_, cmdErr = rand.Read(nextEntropy[:])
			}
			if cmdErr != nil || cmd == nil {
				continue
			}
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			cmd.WaitDelay = m.options.StopGrace
			cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
			if err := cmd.Start(); err != nil {
				continue
			}
			nextCmd = cmd
			nextEpoch = hex.EncodeToString(nextEntropy[:])
			recovered = true
			break
		}
		if !recovered {
			break
		}
		m.mu.Lock()
		slot.command, slot.state, slot.epoch, slot.exitCode = nextCmd, "RUNNING", nextEpoch, -1
		m.mu.Unlock()
		command = nextCmd
	}
	m.finish(background, slot)
}

func (m *Manager) finish(background context.Context, slot *processSlot) {
	m.mu.Lock()
	slot.state = "STOPPED"
	client := slot.api
	slot.api = nil
	unexpected := slot.committed && !slot.intentional && slot.context.Err() == nil && background.Err() == nil
	m.mu.Unlock()
	closeFailed := false
	if client != nil {
		closeFailed = client.Close() != nil
	}
	if slot.command != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		closeFailed = m.clearSocket(cleanup) != nil || closeFailed
		cancel()
	}
	m.mu.Lock()
	slot.closeFailed = closeFailed
	close(slot.done)
	m.mu.Unlock()
	if unexpected && m.options.OnExit != nil {
		m.options.OnExit(ErrExited)
	}
}

// MarkCommitted 将候选切换为故障域成员；已经退出的候选不能被提交。
func (m *Manager) MarkCommitted() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil || m.current.state != "RUNNING" || slotDone(m.current) || m.current.context.Err() != nil {
		return ErrStart
	}
	m.current.committed = true
	return nil
}

// Stop 先取消运行期，再等待 runner 回收；不确定时保留 slot，拒绝第二进程。
func (m *Manager) Stop(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	m.mu.Lock()
	slot := m.current
	if slot != nil {
		slot.intentional = true
	}
	m.mu.Unlock()
	if slot == nil {
		return nil
	}
	slot.cancel()
	select {
	case <-slot.done:
		m.mu.Lock()
		failed := slot.closeFailed
		m.mu.Unlock()
		if failed {
			return ErrUnhealthy
		}
		return nil
	case <-ctx.Done():
		return errors.Join(ErrStop, ctx.Err())
	}
}

func slotDone(slot *processSlot) bool {
	select {
	case <-slot.done:
		return true
	default:
		return false
	}
}
