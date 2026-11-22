// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// ======================== 时间状态门禁：counter0 不代表未附着的 guard 仍然有效 ========================

func generationGuardTestRead(value, enabled, running, lost uint64) []byte {
	body := make([]byte, 32)
	for index, number := range []uint64{value, enabled, running, lost} {
		binary.NativeEndian.PutUint64(body[index*8:], number)
	}
	return body
}

func TestGenerationPerfGuardRejectsColdDetachedClock(t *testing.T) {
	first, err := decodeGenerationGuardReading(generationGuardTestRead(0, 100, 100, 0))
	if err != nil {
		t.Fatal(err)
	}
	second, err := decodeGenerationGuardReading(generationGuardTestRead(0, 101, 101, 0))
	if err != nil || requireGenerationGuardAdvanced(first, second) != nil {
		t.Fatalf("active guard rejected: %v", err)
	}
	for _, body := range [][]byte{
		generationGuardTestRead(0, 0, 0, 0),
		generationGuardTestRead(0, 101, 100, 0),
		generationGuardTestRead(0, 100, 101, 0),
		generationGuardTestRead(1, 101, 101, 0),
		generationGuardTestRead(0, 101, 101, 1),
		make([]byte, 16), make([]byte, 31), make([]byte, 33),
	} {
		if _, err := decodeGenerationGuardReading(body); !errors.Is(err, ErrGenerationUnconfirmed) {
			t.Fatalf("inactive/lost/malformed guard accepted: %v", err)
		}
	}
	if err := requireGenerationGuardAdvanced(first, first); !errors.Is(err, ErrGenerationUnconfirmed) {
		t.Fatalf("frozen detached running clock accepted: %v", err)
	}
	if err := requireGenerationGuardAdvanced(first, generationGuardReading{enabled: 101, running: 100}); !errors.Is(err, ErrGenerationUnconfirmed) {
		t.Fatalf("INACTIVE enable-only progress accepted: %v", err)
	}
}

func TestGenerationPerfAttributesKeepGuardUnfilteredKernelSampling(t *testing.T) {
	for _, guard := range []bool{false, true} {
		attribute := generationTraceAttribute(321, guard)
		if attribute.Type != unix.PERF_TYPE_TRACEPOINT || attribute.Config != 321 || attribute.Size != 64 || attribute.Sample != 1 ||
			attribute.Bits != unix.PerfBitDisabled|unix.PerfBitPinned || attribute.Sample_type != unix.PERF_SAMPLE_TIME|unix.PERF_SAMPLE_CPU|unix.PERF_SAMPLE_RAW {
			t.Fatalf("guard=%v: altered fixed trace attributes: %+v", guard, attribute)
		}
		format := uint64(unix.PERF_FORMAT_LOST)
		if guard {
			format |= unix.PERF_FORMAT_TOTAL_TIME_ENABLED | unix.PERF_FORMAT_TOTAL_TIME_RUNNING
		}
		if attribute.Read_format != format {
			t.Fatalf("guard=%v read_format=%d", guard, attribute.Read_format)
		}
	}
}

// ======================== Go 内存模型夹具：验证消费 ACK，不冒充真实 kernel mmap ========================

func generationPerfHeapRing(t *testing.T) *generationPerfCPU {
	t.Helper()
	ring := &generationPerfCPU{cpu: 3, bufferFD: -1, captureFD: -1, guardFD: -1, mapping: make([]byte, 9*4096)}
	binary.NativeEndian.PutUint64(ring.mapping[1040:], 4096)
	binary.NativeEndian.PutUint64(ring.mapping[1048:], 8*4096)
	if err := ring.bindMapping(4096); err != nil {
		t.Fatal(err)
	}
	return ring
}

func TestGenerationPerfConsumeAcknowledgesOnlyWholeValidRing(t *testing.T) {
	ring := generationPerfHeapRing(t)
	record := generationPerfTestRecord(454, generationPerfTestInode, generationPerfTestPath, 3, 0)
	copy(ring.data, record)
	atomic.StoreUint64(ring.head, uint64(len(record)))
	zero, err := ring.consume(t.Context(), generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath)
	if err != nil || !zero || ring.consumed != 1 || atomic.LoadUint64(ring.tail) != uint64(len(record)) {
		t.Fatalf("zero=%v consumed=%d tail=%d err=%v", zero, ring.consumed, atomic.LoadUint64(ring.tail), err)
	}
	zero, err = ring.consume(t.Context(), generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath)
	if err != nil || zero || ring.consumed != 1 {
		t.Fatalf("duplicate sample accounting: zero=%v count=%d err=%v", zero, ring.consumed, err)
	}
}

func TestGenerationPerfConsumeKeepsTailOnFailureOrCancel(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		ring := generationPerfHeapRing(t)
		zero := generationPerfTestRecord(454, generationPerfTestInode, generationPerfTestPath, 3, 0)
		lost := make([]byte, 8)
		binary.NativeEndian.PutUint32(lost, unix.PERF_RECORD_LOST)
		binary.NativeEndian.PutUint16(lost[6:], 8)
		copy(ring.data, append(zero, lost...))
		atomic.StoreUint64(ring.head, uint64(len(zero)+len(lost)))
		ctx, stop := context.WithCancel(t.Context())
		if cancel {
			stop()
		}
		found, err := ring.consume(ctx, generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath)
		stop()
		if err == nil || found || ring.consumed != 0 || atomic.LoadUint64(ring.tail) != 0 {
			t.Fatalf("cancel=%v failed capture acknowledged: found=%v consumed=%d tail=%d err=%v", cancel, found, ring.consumed, atomic.LoadUint64(ring.tail), err)
		}
	}
}

func TestGenerationPerfMemoryBudgetLimitsConcurrentMappings(t *testing.T) {
	release, err := reserveGenerationPerfMemory(generationPerfMemoryLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	if extra, err := reserveGenerationPerfMemory(1); !errors.Is(err, ErrGenerationUnsupported) || extra != nil {
		t.Fatalf("mapping budget overcommit: release=%v err=%v", extra != nil, err)
	}
	release()
	release()
	second, err := reserveGenerationPerfMemory(generationPerfMemoryLimit)
	if err != nil {
		t.Fatalf("exact mapping lease was not reclaimed: %v", err)
	}
	second()
}
