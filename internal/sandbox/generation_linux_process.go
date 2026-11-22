// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ======================== 内核窄层：真实子进程测试不绕过生产 profile/UID 门禁 ========================

type kernelProcessSnapshot struct {
	pid        int
	startTicks uint64
	uid        uint32
	cgroupData string
}

type kernelProcess struct {
	mu       sync.Mutex
	procFD   int
	pidFD    int
	closed   bool
	closeErr error
}

type generationPIDFDOpener func(pid, flags int) (int, error)

func pinKernelProcess(ctx context.Context, procRoot string, pid int, openPIDFD generationPIDFDOpener) (process *kernelProcess, snapshot kernelProcessSnapshot, err error) {
	if pid <= 1 || openPIDFD == nil {
		return nil, snapshot, ErrGenerationIdentity
	}
	rootFD, err := openAbsoluteGenerationDirectory(ctx, procRoot)
	if err != nil {
		return nil, snapshot, errors.Join(ErrGenerationIdentity, err)
	}
	defer func() {
		err = errors.Join(err, closeGenerationFD(rootFD))
		if err != nil {
			err = errors.Join(err, process.Close())
			process = nil
		}
	}()
	if err = requireGenerationFilesystem(rootFD, unix.PROC_SUPER_MAGIC); err != nil {
		return nil, snapshot, err
	}
	procFD, err := unix.Openat(rootFD, strconv.Itoa(pid), generationDirectoryFlags, 0)
	if err != nil {
		return nil, snapshot, errors.Join(ErrGenerationIdentity, err)
	}
	process = &kernelProcess{procFD: procFD, pidFD: -1}
	snapshot, err = readKernelProcessSnapshot(ctx, procFD)
	if err != nil || snapshot.pid != pid {
		return process, snapshot, errors.Join(ErrGenerationIdentity, err)
	}
	if err = ctx.Err(); err != nil {
		return process, snapshot, err
	}
	process.pidFD, err = openPIDFD(pid, 0)
	if err != nil {
		return process, snapshot, generationKernelError(ErrGenerationIdentity, err)
	}
	if process.pidFD < 0 {
		return process, snapshot, ErrGenerationIdentity
	}
	if err = ctx.Err(); err != nil {
		return process, snapshot, err
	}
	// 先固定 proc 对象，再开数字 PID；只对原 procFD 发 signal=0 核验窗口。
	if err = unix.PidfdSendSignal(procFD, 0, nil, 0); err != nil {
		return process, snapshot, generationKernelError(ErrGenerationIdentity, err)
	}
	// fdinfo 的 Pid 按该 procfs 的 PID namespace 映射；必须仍指向原 proc 对象。
	// 不能仅假设 procfs 的 namespace 与 pidfd_open 使用的 namespace 一致。
	mappedPID, err := readGenerationPIDFDInfo(ctx, rootFD, process.pidFD)
	if err != nil || mappedPID != snapshot.pid {
		return process, snapshot, errors.Join(ErrGenerationIdentity, err)
	}
	if err = process.verify(ctx, snapshot); err != nil {
		return process, snapshot, err
	}
	return process, snapshot, nil
}

func (process *kernelProcess) verify(ctx context.Context, expected kernelProcessSnapshot) error {
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.closed {
		return ErrGenerationClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(process.procFD, 0, nil, 0); err != nil {
		return generationKernelError(ErrGenerationIdentity, err)
	}
	if err := unix.PidfdSendSignal(process.pidFD, 0, nil, 0); err != nil {
		return generationKernelError(ErrGenerationIdentity, err)
	}
	actual, err := readKernelProcessSnapshot(ctx, process.procFD)
	if err != nil || actual != expected {
		return errors.Join(ErrGenerationIdentity, err)
	}
	return ctx.Err()
}

func (process *kernelProcess) signal(signal unix.Signal) error {
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.closed {
		return ErrGenerationClosed
	}
	err := unix.PidfdSendSignal(process.pidFD, signal, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return errors.Join(ErrGenerationExited, err)
	}
	return generationKernelError(nil, err)
}

func (process *kernelProcess) exited(ctx context.Context) (bool, error) {
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.closed {
		return false, ErrGenerationClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	fds := []unix.PollFd{{Fd: int32(process.pidFD), Events: unix.POLLIN}}
	_, err := unix.Poll(fds, 0)
	if err != nil {
		return false, generationKernelError(ErrGenerationUnconfirmed, err)
	}
	events := fds[0].Revents
	if events&(unix.POLLERR|unix.POLLNVAL) != 0 {
		return false, ErrGenerationUnconfirmed
	}
	return events&(unix.POLLIN|unix.POLLHUP) != 0, nil
}

func (process *kernelProcess) Close() error {
	if process == nil {
		return nil
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.closed {
		return process.closeErr
	}
	process.closed = true
	procFD, pidFD := process.procFD, process.pidFD
	process.procFD, process.pidFD = -1, -1
	process.closeErr = errors.Join(closeGenerationFD(procFD), closeGenerationFD(pidFD))
	return process.closeErr
}

func generationKernelError(identity, cause error) error {
	if cause == nil {
		return nil
	}
	if errors.Is(cause, unix.ENOSYS) {
		return errors.Join(ErrGenerationUnsupported, cause)
	}
	return errors.Join(identity, cause)
}

// ======================== 原 procFD 相对读取：stat 的 comm 允许空格和右括号 ========================

func readKernelProcessSnapshot(ctx context.Context, procFD int) (kernelProcessSnapshot, error) {
	stat, err := readPinnedGenerationFile(ctx, procFD, "stat", 64<<10)
	if err != nil {
		return kernelProcessSnapshot{}, err
	}
	pid, ticks, err := parseGenerationProcessStat(string(stat))
	if err != nil {
		return kernelProcessSnapshot{}, err
	}
	status, err := readPinnedGenerationFile(ctx, procFD, "status", 64<<10)
	if err != nil {
		return kernelProcessSnapshot{}, err
	}
	uid, err := parseGenerationProcessUID(string(status))
	if err != nil {
		return kernelProcessSnapshot{}, err
	}
	cgroup, err := readPinnedGenerationFile(ctx, procFD, "cgroup", 64<<10)
	if err != nil {
		return kernelProcessSnapshot{}, err
	}
	return kernelProcessSnapshot{pid: pid, startTicks: ticks, uid: uid, cgroupData: string(cgroup)}, nil
}

func parseGenerationProcessStat(data string) (int, uint64, error) {
	left, right := strings.IndexByte(data, '('), strings.LastIndexByte(data, ')')
	if left < 1 || right <= left || right+1 >= len(data) || data[right+1] != ' ' {
		return 0, 0, ErrGenerationIdentity
	}
	pid, err := strconv.ParseInt(strings.TrimSpace(data[:left]), 10, 32)
	if err != nil || pid <= 0 {
		return 0, 0, ErrGenerationIdentity
	}
	// suffix[0] 是字段 3（state），因此字段 22（starttime）是 suffix[19]。
	suffix := strings.Fields(data[right+1:])
	if len(suffix) < 20 || len(suffix[0]) != 1 {
		return 0, 0, ErrGenerationIdentity
	}
	ticks, err := strconv.ParseUint(suffix[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, 0, ErrGenerationIdentity
	}
	return int(pid), ticks, nil
}

func parseGenerationProcessUID(data string) (uint32, error) {
	var uid uint32
	found := false
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if found || len(fields) != 4 {
			return 0, ErrGenerationIdentity
		}
		for index, value := range fields {
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil || (index > 0 && uint32(parsed) != uid) {
				return 0, ErrGenerationIdentity
			}
			uid = uint32(parsed)
		}
		found = true
	}
	if !found {
		return 0, ErrGenerationIdentity
	}
	return uid, nil
}

func readGenerationPIDFDInfo(ctx context.Context, procRootFD, pidFD int) (pid int, err error) {
	// self 是内核生成的 proc magic link，唯一允许跟随的目录，不接外部内容。
	selfFD, err := unix.Openat(procRootFD, "self", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, closeGenerationFD(selfFD)) }()
	infoFD, err := unix.Openat(selfFD, "fdinfo", generationDirectoryFlags, 0)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, closeGenerationFD(infoFD)) }()
	body, err := readPinnedGenerationFile(ctx, infoFD, strconv.Itoa(pidFD), 4096)
	if err != nil {
		return 0, err
	}
	return parseGenerationPIDFDInfo(string(body))
}

func parseGenerationPIDFDInfo(data string) (pid int, err error) {
	found := false
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "Pid:") {
			continue
		}
		value, parseErr := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "Pid:")), 10, 32)
		if found || parseErr != nil || value <= 1 {
			return 0, ErrGenerationIdentity
		}
		found, pid = true, int(value)
	}
	if !found {
		return 0, fmt.Errorf("%w: missing pidfd Pid", ErrGenerationIdentity)
	}
	return pid, nil
}
