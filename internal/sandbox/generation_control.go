// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// ======================== 固定对象接口：路径仅来自可信启动配置 ========================

// DefaultGenerationPinTimeout 等默认预算受同一请求 context 收紧；各阶段不能另起总预算。
const (
	DefaultGenerationPinTimeout  = 5 * time.Second
	DefaultGenerationStopTimeout = 25 * time.Second
	DefaultGenerationGrace       = 10 * time.Second
	DefaultGenerationCheckEvery  = 50 * time.Millisecond
)

var (
	ErrGenerationClosed = errors.New("sandbox: the pinned generation is closed")
	ErrGenerationExited = errors.New("sandbox: the pinned process has exited")
)

// GenerationKernelPaths 只能在可信进程启动时配置，禁止从 HelperRequest 接收。
// BootIDPath 可指向内核文件的只读 bind；文件仍必须来自真实 procfs。
type GenerationKernelPaths struct {
	ProcRoot   string
	CgroupRoot string
	BootIDPath string
}

func (paths GenerationKernelPaths) normalized() (GenerationKernelPaths, error) {
	if paths.ProcRoot == "" {
		paths.ProcRoot = "/proc"
	}
	if paths.CgroupRoot == "" {
		paths.CgroupRoot = "/sys/fs/cgroup"
	}
	if paths.BootIDPath == "" {
		paths.BootIDPath = "/proc/sys/kernel/random/boot_id"
	}
	for _, value := range []string{paths.ProcRoot, paths.CgroupRoot, paths.BootIDPath} {
		if !path.IsAbs(value) || path.Clean(value) != value || value == "/" || strings.ContainsAny(value, "\x00\r\n") {
			return GenerationKernelPaths{}, fmt.Errorf("%w: invalid trusted kernel path", ErrGenerationIdentity)
		}
	}
	return paths, nil
}

// GenerationProfileReader 只读实际 loaded 属性；实现必须遵守传入的 context。
type GenerationProfileReader interface {
	ReadGenerationProfile(ctx context.Context, pluginID string) (LoadedGenerationProfile, error)
}

// GenerationPinner 保留启动配置的私有副本，不暴露任何可复用 FD 数字。
type GenerationPinner struct {
	paths    GenerationKernelPaths
	profiles GenerationProfileReader
}

// NewGenerationPinner 不提供弱 profile、root UID 或 named stop 的回退开关。
func NewGenerationPinner(paths GenerationKernelPaths, profiles GenerationProfileReader) (*GenerationPinner, error) {
	if profiles == nil {
		return nil, ErrGenerationProfile
	}
	normalized, err := paths.normalized()
	if err != nil {
		return nil, err
	}
	return &GenerationPinner{paths: normalized, profiles: profiles}, nil
}

// Pin 固定实际插件代次。expected=nil 仅用于观察；停止必须给完整 expected。
// 调用方接管句柄，并在观察返回前 Close；StopPinnedGeneration 则接管并关闭它。
func (pinner *GenerationPinner) Pin(ctx context.Context, pluginID string, expected *ProcessProof) (PinnedGeneration, error) {
	if pinner == nil || pinner.profiles == nil {
		return nil, ErrGenerationProfile
	}
	if err := ValidateID(pluginID); err != nil {
		return nil, err
	}
	var expectedCopy *ProcessProof
	if expected != nil {
		copied := *expected
		if copied.Validate(pluginID) != nil {
			return nil, ErrGenerationIdentity
		}
		expectedCopy = &copied
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultGenerationPinTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return pinGenerationPlatform(ctx, pluginID, expectedCopy, pinner.paths, pinner.profiles)
}

// PinForStop 在同一 Pin 预算内启动完整内核观察，再复核原进程/profile/非空组。
// 观察用 Pin 不承担 perf 资源；停止只能使用本方法取得的强观察句柄。
func (pinner *GenerationPinner) PinForStop(ctx context.Context, pluginID string, expected ProcessProof) (pinned PinnedGeneration, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultGenerationPinTimeout)
	defer cancel()
	pinned, err = pinner.Pin(ctx, pluginID, &expected)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, pinned.Close())
			pinned = nil
		}
	}()
	if err = armGenerationStopPlatform(ctx, pluginID, pinned, pinner.profiles); err != nil {
		return pinned, err
	}
	return pinned, nil
}

// GenerationSignal 只允许固定停止策略需要的三个信号，不能承载任意外部 signal。
type GenerationSignal uint8

const (
	// GenerationTerminate 请求原进程正常退出。
	GenerationTerminate GenerationSignal = iota + 1
	// GenerationContinue 唤醒被挂起的原进程，使 TERM 得以处理。
	GenerationContinue
	// GenerationKill 仅在同一原进程的 grace 到期时强制退出。
	GenerationKill
)

// PinnedGeneration 的所有动作都使用同一内核对象；Close 必须与动作互斥。
// OriginalExited 只通过真正 pidfd poll；它不代表 OriginalCgroupEmpty。
type PinnedGeneration interface {
	Proof() ProcessProof
	Signal(signal GenerationSignal) error
	OriginalExited(ctx context.Context) (bool, error)
	OriginalCgroupEmpty(ctx context.Context) (bool, error)
	Close() error
}

// GenerationStopPolicy 限制停止阶段为 25s；调用方还须为 Pin 和响应共用原请求预算。
type GenerationStopPolicy struct {
	Timeout    time.Duration
	Grace      time.Duration
	CheckEvery time.Duration
}

func (policy GenerationStopPolicy) normalized() (GenerationStopPolicy, error) {
	if policy.Timeout == 0 {
		policy.Timeout = DefaultGenerationStopTimeout
	}
	if policy.Grace == 0 {
		policy.Grace = DefaultGenerationGrace
	}
	if policy.CheckEvery == 0 {
		policy.CheckEvery = DefaultGenerationCheckEvery
	}
	if policy.Timeout <= 0 || policy.Timeout > DefaultGenerationStopTimeout || policy.Grace <= 0 ||
		policy.Grace >= policy.Timeout || policy.CheckEvery <= 0 || policy.CheckEvery > time.Second {
		return GenerationStopPolicy{}, errors.New("sandbox: invalid bounded generation stop policy")
	}
	return policy, nil
}

// ======================== 有界停止：原主退出和原组清空共同形成完成证据 ========================

// StopPinnedGeneration 接管句柄，包括拒绝、错误和取消路径；不会选择另一个代次。
func StopPinnedGeneration(ctx context.Context, pluginID string, expected ProcessProof, pinned PinnedGeneration, policy GenerationStopPolicy) (observation StopObservation, err error) {
	if pinned == nil {
		return observation, ErrGenerationIdentity
	}
	defer func() { err = errors.Join(err, pinned.Close()) }()
	observation.Proof = pinned.Proof()
	if expected.Validate(pluginID) != nil || observation.Proof != expected {
		return observation, ErrGenerationIdentity
	}
	policy, err = policy.normalized()
	if err != nil {
		return observation, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return observation, errors.Join(ErrGenerationUnconfirmed, err)
	}
	for _, signal := range []GenerationSignal{GenerationTerminate, GenerationContinue} {
		if err := ctx.Err(); err != nil {
			return observation, errors.Join(ErrGenerationUnconfirmed, err)
		}
		if err := pinned.Signal(signal); err != nil {
			if errors.Is(err, ErrGenerationExited) {
				break
			}
			return observation, errors.Join(ErrGenerationUnconfirmed, err)
		}
	}
	grace := time.NewTimer(policy.Grace)
	defer grace.Stop()
	checks := time.NewTicker(policy.CheckEvery)
	defer checks.Stop()
	graceReady := grace.C
	for {
		// 真正 pidfd 已确认的退出不可逆；超时后的读取错误不能覆盖这条原事实。
		if !observation.OriginalExited {
			exited, pollErr := pinned.OriginalExited(ctx)
			if pollErr != nil {
				return observation, errors.Join(ErrGenerationUnconfirmed, pollErr)
			}
			observation.OriginalExited = exited
		}
		observation.OriginalCgroupEmpty, err = pinned.OriginalCgroupEmpty(ctx)
		if err != nil {
			return observation, errors.Join(ErrGenerationUnconfirmed, err)
		}
		if err := ctx.Err(); err != nil {
			return observation, errors.Join(ErrGenerationUnconfirmed, err)
		}
		if observation.OriginalExited && observation.OriginalCgroupEmpty {
			return observation, observation.ValidateCompleted(pluginID, expected)
		}
		select {
		case <-ctx.Done():
			return observation, errors.Join(ErrGenerationUnconfirmed, ctx.Err())
		case <-graceReady:
			graceReady = nil
			if !observation.OriginalExited {
				if err := ctx.Err(); err != nil {
					return observation, errors.Join(ErrGenerationUnconfirmed, err)
				}
				if err := pinned.Signal(GenerationKill); err != nil && !errors.Is(err, ErrGenerationExited) {
					return observation, errors.Join(ErrGenerationUnconfirmed, err)
				}
			}
		case <-checks.C:
		}
	}
}
