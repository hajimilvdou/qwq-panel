// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ======================== 生产 Pin：严格 profile 与原内核对象一并绑定 ========================

type linuxPinnedGeneration struct {
	proof    ProcessProof
	snapshot kernelProcessSnapshot
	profile  LoadedGenerationProfile
	process  *kernelProcess
	cgroup   *pinnedGenerationCgroup
	watcher  *generationPerfWatcher
}

func pinGenerationPlatform(ctx context.Context, pluginID string, expected *ProcessProof, paths GenerationKernelPaths, profiles GenerationProfileReader) (pinned PinnedGeneration, err error) {
	before, err := profiles.ReadGenerationProfile(ctx, pluginID)
	if err != nil {
		return nil, err
	}
	if err := before.Validate(pluginID); err != nil {
		return nil, err
	}
	process, snapshot, err := pinKernelProcess(ctx, paths.ProcRoot, before.MainPID, unix.PidfdOpen)
	if err != nil {
		return nil, err
	}
	var cgroup *pinnedGenerationCgroup
	defer func() {
		if err != nil {
			err = errors.Join(err, process.Close(), cgroup.Close())
			pinned = nil
		}
	}()
	cgroupPath, err := UnifiedCgroupPath(snapshot.cgroupData)
	if err != nil || cgroupPath != before.ControlGroup || snapshot.uid == 0 {
		return nil, errors.Join(ErrGenerationIdentity, err)
	}
	cgroup, err = pinGenerationCgroup(ctx, paths.CgroupRoot, cgroupPath)
	if err != nil {
		return nil, err
	}
	empty, err := cgroup.empty(ctx)
	if err != nil || empty {
		return nil, errors.Join(ErrGenerationIdentity, err)
	}
	bootID, err := readGenerationBootID(ctx, paths.BootIDPath)
	if err != nil {
		return nil, err
	}
	after, err := profiles.ReadGenerationProfile(ctx, pluginID)
	if err != nil {
		return nil, err
	}
	if after.Validate(pluginID) != nil || before != after {
		return nil, ErrGenerationProfile
	}
	if err := process.verify(ctx, snapshot); err != nil {
		return nil, err
	}
	proof := ProcessProof{Version: 1, Unit: before.Unit, PID: snapshot.pid, KernelStartTicks: snapshot.startTicks,
		BootID: bootID, InvocationID: before.InvocationID, UID: snapshot.uid, Cgroup: cgroupPath,
		CgroupDevice: cgroup.device, CgroupInode: cgroup.inode}
	if proof.Validate(pluginID) != nil || (expected != nil && proof != *expected) {
		return nil, ErrGenerationIdentity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &linuxPinnedGeneration{proof: proof, snapshot: snapshot, profile: before, process: process, cgroup: cgroup}, nil
}

// ======================== 停止专用 Pin：先 arm，后重验，接受前不能有未覆盖窗口 ========================

func armGenerationStopPlatform(ctx context.Context, pluginID string, generation PinnedGeneration, profiles GenerationProfileReader) error {
	pinned, ok := generation.(*linuxPinnedGeneration)
	if !ok || pinned.process == nil || pinned.cgroup == nil || pinned.watcher != nil {
		return ErrGenerationIdentity
	}
	watcher, err := newGenerationPerfWatcher(ctx, pinned.cgroup, pinned.proof.Cgroup)
	if err != nil {
		return err
	}
	pinned.watcher = watcher
	after, err := profiles.ReadGenerationProfile(ctx, pluginID)
	if err != nil {
		return err
	}
	if after != pinned.profile {
		return ErrGenerationProfile
	}
	if err := pinned.process.verify(ctx, pinned.snapshot); err != nil {
		return err
	}
	empty, err := pinned.cgroup.empty(ctx)
	if err != nil || empty {
		return errors.Join(ErrGenerationIdentity, err)
	}
	if err := watcher.validateArmed(ctx); err != nil {
		return err
	}
	if watcher.zero {
		return ErrGenerationIdentity
	}
	return ctx.Err()
}

func (pinned *linuxPinnedGeneration) Proof() ProcessProof {
	if pinned == nil {
		return ProcessProof{}
	}
	return pinned.proof
}

func (pinned *linuxPinnedGeneration) Signal(signal GenerationSignal) error {
	if pinned == nil || pinned.process == nil {
		return ErrGenerationClosed
	}
	var number unix.Signal
	switch signal {
	case GenerationTerminate:
		number = unix.SIGTERM
	case GenerationContinue:
		number = unix.SIGCONT
	case GenerationKill:
		number = unix.SIGKILL
	default:
		return errors.New("sandbox: unsupported generation signal")
	}
	return pinned.process.signal(number)
}

func (pinned *linuxPinnedGeneration) OriginalExited(ctx context.Context) (bool, error) {
	if pinned == nil || pinned.process == nil {
		return false, ErrGenerationClosed
	}
	return pinned.process.exited(ctx)
}

func (pinned *linuxPinnedGeneration) OriginalCgroupEmpty(ctx context.Context) (bool, error) {
	if pinned == nil || pinned.cgroup == nil {
		return false, ErrGenerationClosed
	}
	if pinned.watcher != nil {
		return pinned.watcher.empty(ctx)
	}
	return pinned.cgroup.empty(ctx)
}

func (pinned *linuxPinnedGeneration) Close() error {
	if pinned == nil {
		return nil
	}
	return errors.Join(pinned.process.Close(), pinned.watcher.Close(), pinned.cgroup.Close())
}

// ======================== 原 cgroup 只读句柄：永不按原路径重新挑选新目录 ========================

type pinnedGenerationCgroup struct {
	mu       sync.Mutex
	fd       int
	eventsFD int
	device   uint64
	inode    uint64
	closed   bool
	closeErr error
}

func pinGenerationCgroup(ctx context.Context, rootPath, cgroupPath string) (pinned *pinnedGenerationCgroup, err error) {
	if !validGenerationCgroupPath(cgroupPath) || len(cgroupPath) > 4096 {
		return nil, ErrGenerationIdentity
	}
	fd, err := openAbsoluteGenerationDirectory(ctx, rootPath)
	if err != nil {
		return nil, errors.Join(ErrGenerationIdentity, err)
	}
	eventsFD := -1
	defer func() {
		if err != nil {
			err = errors.Join(err, closeGenerationFD(fd), closeGenerationFD(eventsFD))
			pinned = nil
		}
	}()
	if err = requireGenerationFilesystem(fd, unix.CGROUP2_SUPER_MAGIC); err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(cgroupPath, "/"), "/") {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		next, openErr := unix.Openat(fd, component, generationDirectoryFlags, 0)
		closeErr := closeGenerationFD(fd)
		fd = -1
		if openErr != nil {
			return nil, errors.Join(ErrGenerationIdentity, openErr, closeErr)
		}
		fd = next
		if closeErr != nil {
			return nil, closeErr
		}
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, errors.Join(ErrGenerationIdentity, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Ino == 0 {
		return nil, ErrGenerationIdentity
	}
	if err = requireGenerationFilesystem(fd, unix.CGROUP2_SUPER_MAGIC); err != nil {
		return nil, err
	}
	eventsFD, err = openPinnedGenerationFile(ctx, fd, "cgroup.events")
	if err != nil {
		return nil, errors.Join(ErrGenerationIdentity, err)
	}
	if err = requireGenerationFilesystem(eventsFD, unix.CGROUP2_SUPER_MAGIC); err != nil {
		return nil, err
	}
	return &pinnedGenerationCgroup{fd: fd, eventsFD: eventsFD, device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func (pinned *pinnedGenerationCgroup) empty(ctx context.Context) (bool, error) {
	pinned.mu.Lock()
	defer pinned.mu.Unlock()
	if pinned.closed {
		return false, ErrGenerationClosed
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrGenerationUnconfirmed, err)
	}
	// kernfs 的文件本身也在 Pin 时固定；seek/read 不会跟随删除后重建的目录或文件。
	// rmdir 后内核若拒绝读取，必须保留未确认，不能据目录已消失生成完成回执。
	if _, err := unix.Seek(pinned.eventsFD, 0, io.SeekStart); err != nil {
		return false, errors.Join(ErrGenerationUnconfirmed, err)
	}
	body, err := readGenerationFD(ctx, pinned.eventsFD, 4096)
	if err != nil {
		return false, errors.Join(ErrGenerationUnconfirmed, err)
	}
	return parseGenerationCgroupEvents(string(body))
}

func (pinned *pinnedGenerationCgroup) Close() error {
	if pinned == nil {
		return nil
	}
	pinned.mu.Lock()
	defer pinned.mu.Unlock()
	if pinned.closed {
		return pinned.closeErr
	}
	pinned.closed = true
	fd, eventsFD := pinned.fd, pinned.eventsFD
	pinned.fd, pinned.eventsFD = -1, -1
	pinned.closeErr = errors.Join(closeGenerationFD(fd), closeGenerationFD(eventsFD))
	return pinned.closeErr
}

func parseGenerationCgroupEvents(data string) (bool, error) {
	found, empty := false, false
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return false, ErrGenerationUnconfirmed
		}
		if fields[0] != "populated" {
			continue
		}
		if found || (fields[1] != "0" && fields[1] != "1") {
			return false, ErrGenerationUnconfirmed
		}
		found, empty = true, fields[1] == "0"
	}
	if !found {
		return false, fmt.Errorf("%w: missing populated value", ErrGenerationUnconfirmed)
	}
	return empty, nil
}
