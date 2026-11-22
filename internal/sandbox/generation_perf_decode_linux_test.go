// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// ======================== 独立 ABI 夹具：完整原 inode、迟读和跨 ring 边界 ========================

var generationPerfTestLayout = generationPerfLayout{populatedID: 454, hotplugID: 139}

const generationPerfTestInode = uint64(1<<63 + 17)
const generationPerfTestPath = "/system.slice/qwq-plugin@alpha.service"

func generationPerfTestRecord(eventID uint16, inode uint64, cgroup string, cpu int, value uint32) []byte {
	raw := make([]byte, 32+len(cgroup)+1)
	binary.NativeEndian.PutUint16(raw, eventID)
	binary.NativeEndian.PutUint32(raw[12:], 2)
	binary.NativeEndian.PutUint64(raw[16:], inode)
	binary.NativeEndian.PutUint32(raw[24:], uint32(len(cgroup)+1)<<16|32)
	binary.NativeEndian.PutUint32(raw[28:], value)
	copy(raw[32:], cgroup)
	record := make([]byte, (28+len(raw)+7)&^7)
	binary.NativeEndian.PutUint32(record, unix.PERF_RECORD_SAMPLE)
	binary.NativeEndian.PutUint16(record[6:], uint16(len(record)))
	binary.NativeEndian.PutUint64(record[8:], 123456789)
	binary.NativeEndian.PutUint32(record[16:], uint32(cpu))
	binary.NativeEndian.PutUint32(record[24:], uint32(len(raw)))
	copy(record[28:], raw)
	return record
}

func generationPerfTestRing(record []byte, tail uint64) []byte {
	data := make([]byte, 512)
	for index, value := range record {
		data[(int(tail)+index)&(len(data)-1)] = value
	}
	return data
}

func TestGenerationPerfRingPreservesExplicitLateZero(t *testing.T) {
	record := generationPerfTestRecord(454, generationPerfTestInode, generationPerfTestPath, 3, 0)
	for _, tail := range []uint64{0, 504, 1<<40 + 504} {
		data := generationPerfTestRing(record, tail)
		count, zero, err := decodeGenerationPerfRing(data, tail+uint64(len(record)), tail, generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath, 3)
		if err != nil || count != 1 || !zero {
			t.Fatalf("tail=%d: count=%d zero=%v err=%v", tail, count, zero, err)
		}
	}
}

func TestGenerationPerfSampleIgnoresUndeclaredPadding(t *testing.T) {
	record := generationPerfTestRecord(454, generationPerfTestInode, generationPerfTestPath, 3, 0)
	rawSize := int(binary.NativeEndian.Uint32(record[24:]))
	if 28+rawSize >= len(record) {
		t.Fatal("independent fixture must exercise at least one padding byte")
	}
	for index := 28 + rawSize; index < len(record); index++ {
		record[index] = 0xff
	}
	count, zero, err := decodeGenerationPerfRing(generationPerfTestRing(record, 0), uint64(len(record)), 0, generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath, 3)
	if err != nil || count != 1 || !zero {
		t.Fatalf("undeclared padding: count=%d zero=%v err=%v", count, zero, err)
	}
}

func TestGenerationPerfRingRequiresCompleteOriginalIdentity(t *testing.T) {
	valid := generationPerfTestRecord(454, generationPerfTestInode, generationPerfTestPath, 3, 0)
	tests := []struct {
		name string
		edit func([]byte)
	}{
		{"other_trace", func(body []byte) { binary.NativeEndian.PutUint16(body[28:], 455) }},
		{"truncated_inode", func(body []byte) { binary.NativeEndian.PutUint64(body[44:], 17) }},
		{"other_root", func(body []byte) { binary.NativeEndian.PutUint32(body[36:], 1) }},
		{"negative_level", func(body []byte) { binary.NativeEndian.PutUint32(body[40:], ^uint32(0)) }},
		{"other_cpu", func(body []byte) { binary.NativeEndian.PutUint32(body[16:], 4) }},
		{"reserved_cpu", func(body []byte) { binary.NativeEndian.PutUint32(body[20:], 1) }},
		{"zero_clock", func(body []byte) { binary.NativeEndian.PutUint64(body[8:], 0) }},
		{"nonzero", func(body []byte) { binary.NativeEndian.PutUint32(body[56:], 1) }},
		{"non_boolean", func(body []byte) { binary.NativeEndian.PutUint32(body[56:], 2) }},
		{"path_outside_raw", func(body []byte) { binary.NativeEndian.PutUint32(body[52:], 8<<16|65535) }},
		{"empty_path", func(body []byte) { binary.NativeEndian.PutUint32(body[52:], 32) }},
		{"path_in_header", func(body []byte) { binary.NativeEndian.PutUint32(body[52:], 1<<16|16) }},
		{"missing_terminator", func(body []byte) { body[60+len(generationPerfTestPath)] = 'x' }},
		{"interior_terminator", func(body []byte) { body[61] = 0 }},
		{"different_path", func(body []byte) { body[61] = 'x' }},
		{"invalid_utf8", func(body []byte) { body[61] = 0xff }},
		{"short_raw", func(body []byte) { binary.NativeEndian.PutUint32(body[24:], 31) }},
		{"oversized_raw", func(body []byte) { binary.NativeEndian.PutUint32(body[24:], generationMaxPerfRaw+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := slices.Clone(valid)
			test.edit(record)
			count, zero, err := decodeGenerationPerfRing(generationPerfTestRing(record, 504), 504+uint64(len(record)), 504, generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath, 3)
			if !errors.Is(err, ErrGenerationUnconfirmed) || count != 0 || zero {
				t.Fatalf("count=%d zero=%v err=%v", count, zero, err)
			}
		})
	}
}

func TestGenerationPerfRingRejectsLossHotplugAndIncompleteSuffix(t *testing.T) {
	zero := generationPerfTestRecord(454, generationPerfTestInode, generationPerfTestPath, 3, 0)
	hotplug := generationPerfTestRecord(139, 0, "", 3, 0)
	for _, kind := range []uint32{unix.PERF_RECORD_LOST, unix.PERF_RECORD_LOST_SAMPLES, unix.PERF_RECORD_THROTTLE, 999} {
		bad := make([]byte, 24)
		binary.NativeEndian.PutUint32(bad, kind)
		binary.NativeEndian.PutUint16(bad[6:], 24)
		records := append(slices.Clone(zero), bad...)
		if count, found, err := decodeGenerationPerfRing(generationPerfTestRing(records, 0), uint64(len(records)), 0, generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath, 3); err == nil || count != 0 || found {
			t.Fatalf("kind=%d: count=%d zero=%v err=%v", kind, count, found, err)
		}
	}
	for _, records := range [][]byte{hotplug, append(slices.Clone(zero), hotplug...), append(slices.Clone(zero), 1, 2, 3)} {
		if count, found, err := decodeGenerationPerfRing(generationPerfTestRing(records, 0), uint64(len(records)), 0, generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath, 3); err == nil || count != 0 || found {
			t.Fatalf("count=%d zero=%v err=%v", count, found, err)
		}
	}
}

func TestGenerationPerfRingRejectsOverrunAndReversal(t *testing.T) {
	for _, bounds := range [][3]int{{512, 513, 0}, {512, 3, 4}, {65, 0, 0}, {0, 0, 0}, {32, 0, 0}} {
		if _, zero, err := decodeGenerationPerfRing(make([]byte, bounds[0]), uint64(bounds[1]), uint64(bounds[2]), generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath, 3); err == nil || zero {
			t.Fatalf("bounds=%v zero=%v err=%v", bounds, zero, err)
		}
	}
	if count, zero, err := decodeGenerationPerfRing(make([]byte, 512), 7, 7, generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath, 3); err != nil || count != 0 || zero {
		t.Fatalf("empty ring count=%d zero=%v err=%v", count, zero, err)
	}
}

func TestGenerationPerfCountDetectsUnpublishedLoss(t *testing.T) {
	raw := make([]byte, 16)
	binary.NativeEndian.PutUint64(raw, 3)
	if err := checkGenerationPerfCount(raw, 3); err != nil {
		t.Fatal(err)
	}
	if err := checkGenerationPerfCount(raw, 2); !errors.Is(err, ErrGenerationUnconfirmed) {
		t.Fatalf("missing SAMPLE accepted: %v", err)
	}
	binary.NativeEndian.PutUint64(raw[8:], 1)
	if err := checkGenerationPerfCount(raw, 3); !errors.Is(err, ErrGenerationUnconfirmed) {
		t.Fatalf("unpublished LOST accepted: %v", err)
	}
	for _, size := range []int{0, 8, 15, 17, 24, 32} {
		if err := checkGenerationPerfCount(make([]byte, size), 0); !errors.Is(err, ErrGenerationUnconfirmed) {
			t.Fatalf("read size=%d accepted: %v", size, err)
		}
	}
}

func FuzzGenerationPerfRingBounds(f *testing.F) {
	valid := generationPerfTestRecord(454, generationPerfTestInode, generationPerfTestPath, 3, 0)
	f.Add(valid, uint64(len(valid)), uint64(0))
	f.Add([]byte{1, 2, 3}, uint64(3), uint64(0))
	f.Add(valid, uint64(1025), uint64(0))
	f.Fuzz(func(t *testing.T, raw []byte, head, tail uint64) {
		if len(raw) > 8192 {
			return
		}
		data := make([]byte, 1024)
		copy(data, raw)
		count, zero, err := decodeGenerationPerfRing(data, head, tail, generationPerfTestLayout, generationPerfTestInode, generationPerfTestPath, 3)
		if err != nil && (count != 0 || zero) {
			t.Fatalf("failed partial capture returned count=%d zero=%v", count, zero)
		}
	})
}
