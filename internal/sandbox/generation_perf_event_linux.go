// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ======================== 每 CPU 两个窄事件：捕获原组，独立 guard 共享同一 ring ========================

const generationPerfDataPages = 8
const generationPerfHeadOffset = 1024

type generationGuardReading struct {
	enabled uint64
	running uint64
}

type generationPerfCPU struct {
	cpu            int
	bufferFD       int
	captureFD      int
	guardFD        int
	mapping        []byte
	data           []byte
	head           *uint64
	tail           *uint64
	captureEnabled bool
	guardEnabled   bool
	consumed       uint64
	closed         bool
	closeErr       error
}

func generationTraceAttribute(identifier uint16, guard bool) unix.PerfEventAttr {
	format := uint64(unix.PERF_FORMAT_LOST)
	if guard {
		format |= unix.PERF_FORMAT_TOTAL_TIME_ENABLED | unix.PERF_FORMAT_TOTAL_TIME_RUNNING
	}
	return unix.PerfEventAttr{
		Type: unix.PERF_TYPE_TRACEPOINT, Size: unix.PERF_ATTR_SIZE_VER0, Config: uint64(identifier),
		Sample: 1, Sample_type: unix.PERF_SAMPLE_TIME | unix.PERF_SAMPLE_CPU | unix.PERF_SAMPLE_RAW,
		Read_format: format, Bits: unix.PerfBitDisabled | unix.PerfBitPinned, Wakeup: 1,
	}
}

func openGenerationTraceEvent(ctx context.Context, cpu int, identifier uint16, guard bool) (int, error) {
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	attribute := generationTraceAttribute(identifier, guard)
	fd, err := unix.PerfEventOpen(&attribute, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, errors.Join(ErrGenerationUnsupported, err)
	}
	return fd, nil
}

func newGenerationPerfCPU(ctx context.Context, cpu, pageSize int, layout generationPerfLayout) (ring *generationPerfCPU, err error) {
	ring = &generationPerfCPU{cpu: cpu, bufferFD: -1, captureFD: -1, guardFD: -1}
	defer func() {
		if err != nil {
			err = errors.Join(err, ring.Close())
		}
	}()
	// buffer owner 始终 disabled，仅持有 mmap；真正 capture 在 guard 已证活跃后才创建。
	// 否则 capture 可能先被 hotplug 拆出，而随后新建的 guard 仍通过活跃门禁。
	ring.bufferFD, err = openGenerationTraceEvent(ctx, cpu, layout.populatedID, false)
	if err != nil {
		return ring, err
	}
	ring.mapping, err = unix.Mmap(ring.bufferFD, 0, (generationPerfDataPages+1)*pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return ring, errors.Join(ErrGenerationUnsupported, err)
	}
	if err = ring.bindMapping(pageSize); err != nil {
		return ring, err
	}
	ring.guardFD, err = openGenerationTraceEvent(ctx, cpu, layout.hotplugID, true)
	if err != nil {
		return ring, err
	}
	// guard 不设置 filter，不排除 kernel，不继承；两事件按当前 CPU 共享完整样本输出。
	if err = unix.IoctlSetInt(ring.guardFD, unix.PERF_EVENT_IOC_SET_OUTPUT, ring.bufferFD); err != nil {
		return ring, errors.Join(ErrGenerationUnsupported, err)
	}
	for _, fd := range []int{ring.bufferFD, ring.guardFD} {
		if err = ctx.Err(); err != nil {
			return ring, err
		}
		// 仅在首次 enable 之前清零；guard 启动段的任何记录都不能 reset 掉。
		if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_RESET, 0); err != nil {
			return ring, errors.Join(ErrGenerationUnsupported, err)
		}
	}
	return ring, nil
}

func (ring *generationPerfCPU) prepareCapture(ctx context.Context, layout generationPerfLayout, inode uint64) error {
	if ring.closed || !ring.guardEnabled || ring.captureFD != -1 {
		return generationPerfRejected("capture was not created after guard activation")
	}
	fd, err := openGenerationTraceEvent(ctx, ring.cpu, layout.populatedID, false)
	if err != nil {
		return err
	}
	ring.captureFD = fd
	if err = unix.IoctlSetString(fd, unix.PERF_EVENT_IOC_SET_FILTER, fmt.Sprintf("id == %d && root == 0", inode)); err != nil {
		return errors.Join(ErrGenerationUnsupported, err)
	}
	if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_OUTPUT, ring.bufferFD); err != nil {
		return errors.Join(ErrGenerationUnsupported, err)
	}
	return nil
}

func (ring *generationPerfCPU) bindMapping(pageSize int) error {
	if len(ring.mapping) != (generationPerfDataPages+1)*pageSize || pageSize < 4096 || pageSize > 65536 || pageSize&(pageSize-1) != 0 ||
		uintptr(unsafe.Pointer(&ring.mapping[0]))&7 != 0 {
		return generationPerfRejected("invalid mmap alignment or geometry")
	}
	offset := binary.NativeEndian.Uint64(ring.mapping[generationPerfHeadOffset+16:])
	size := binary.NativeEndian.Uint64(ring.mapping[generationPerfHeadOffset+24:])
	if offset != uint64(pageSize) || size != uint64(pageSize*generationPerfDataPages) || offset+size != uint64(len(ring.mapping)) {
		return generationPerfRejected("kernel mmap geometry differs from the bounded ring")
	}
	ring.head = (*uint64)(unsafe.Pointer(&ring.mapping[generationPerfHeadOffset]))
	ring.tail = (*uint64)(unsafe.Pointer(&ring.mapping[generationPerfHeadOffset+8]))
	ring.data = ring.mapping[offset : offset+size]
	return nil
}

func (ring *generationPerfCPU) enable(ctx context.Context, guard bool) error {
	if ring.closed {
		return ErrGenerationClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fd := ring.captureFD
	if guard {
		fd = ring.guardFD
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return errors.Join(ErrGenerationUnsupported, err)
	}
	if guard {
		ring.guardEnabled = true
	} else {
		ring.captureEnabled = true
	}
	return nil
}

func (ring *generationPerfCPU) disable(guard bool) error {
	fd, enabled := ring.captureFD, ring.captureEnabled
	if guard {
		fd, enabled = ring.guardFD, ring.guardEnabled
	}
	if !enabled {
		return nil
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
		return errors.Join(ErrGenerationUnconfirmed, err)
	}
	if guard {
		ring.guardEnabled = false
	} else {
		ring.captureEnabled = false
	}
	return nil
}

// ======================== acquire/release 消费：ACK 之前 kernel 不可覆盖未读区域 ========================

func (ring *generationPerfCPU) consume(ctx context.Context, layout generationPerfLayout, inode uint64, cgroup string) (bool, error) {
	if ring.closed || ring.head == nil || ring.tail == nil {
		return false, ErrGenerationClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Go 的 SC atomic 包含所需 acquire/release 屏障，不能用普通 slice 读取 head/tail。
	head := atomic.LoadUint64(ring.head)
	tail := atomic.LoadUint64(ring.tail)
	count, zero, err := decodeGenerationPerfRing(ring.data, head, tail, layout, inode, cgroup, ring.cpu)
	if err != nil {
		return false, err
	}
	if count > math.MaxUint64-ring.consumed {
		return false, generationPerfRejected("sample accounting overflow")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	ring.consumed += count
	atomic.StoreUint64(ring.tail, head)
	return zero, nil
}

func readGenerationPerfCounter(ctx context.Context, fd, size int) ([]byte, error) {
	body := make([]byte, size+1)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := unix.Read(fd, body)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, errors.Join(ErrGenerationUnconfirmed, err)
		}
		if n != size {
			return nil, generationPerfRejected("counter read has an unexpected ABI size")
		}
		return body[:n], nil
	}
}

func decodeGenerationGuardReading(raw []byte) (generationGuardReading, error) {
	if len(raw) != 32 || binary.NativeEndian.Uint64(raw) != 0 || binary.NativeEndian.Uint64(raw[24:]) != 0 {
		return generationGuardReading{}, generationPerfRejected("guard observed hotplug, loss or an invalid counter ABI")
	}
	enabled, running := binary.NativeEndian.Uint64(raw[8:]), binary.NativeEndian.Uint64(raw[16:])
	if enabled == 0 || running != enabled {
		return generationGuardReading{}, generationPerfRejected("guard was not continuously scheduled")
	}
	return generationGuardReading{enabled: enabled, running: running}, nil
}

func (ring *generationPerfCPU) guardReading(ctx context.Context) (generationGuardReading, error) {
	raw, err := readGenerationPerfCounter(ctx, ring.guardFD, 32)
	if err != nil {
		return generationGuardReading{}, err
	}
	return decodeGenerationGuardReading(raw)
}

func requireGenerationGuardAdvanced(before, after generationGuardReading) error {
	if after.enabled <= before.enabled || after.running <= before.running {
		return generationPerfRejected("guard FD is detached or its running clock is frozen")
	}
	return nil
}

func (ring *generationPerfCPU) verifyFinal(ctx context.Context) error {
	if ring.captureEnabled || ring.guardEnabled {
		return generationPerfRejected("final accounting requires all events disabled")
	}
	raw, err := readGenerationPerfCounter(ctx, ring.captureFD, 16)
	if err != nil {
		return err
	}
	if err := checkGenerationPerfCount(raw, ring.consumed); err != nil {
		return err
	}
	if _, err = ring.guardReading(ctx); err != nil {
		return err
	}
	if atomic.LoadUint64(ring.head) != atomic.LoadUint64(ring.tail) {
		return generationPerfRejected("disabled ring contains unconsumed records")
	}
	return nil
}

func (ring *generationPerfCPU) Close() error {
	if ring == nil {
		return nil
	}
	if ring.closed {
		return ring.closeErr
	}
	ring.closed = true
	errs := []error{ring.disable(false), ring.disable(true)}
	if ring.mapping != nil {
		if err := unix.Munmap(ring.mapping); err != nil {
			errs = append(errs, err)
		} else {
			ring.mapping, ring.data, ring.head, ring.tail = nil, nil, nil, nil
		}
	}
	errs = append(errs, closeGenerationFD(ring.guardFD), closeGenerationFD(ring.captureFD), closeGenerationFD(ring.bufferFD))
	ring.guardFD, ring.captureFD, ring.bufferFD = -1, -1, -1
	ring.closeErr = errors.Join(errs...)
	return ring.closeErr
}
