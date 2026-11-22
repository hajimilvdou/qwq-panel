// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// ======================== 完整 ring 消费：未知、热插拔、非零与丢样本一律拒绝 ========================

const generationMaxPerfRaw = 8192

func generationRingBytes(data []byte, absolute uint64, length int) []byte {
	offset := int(absolute & uint64(len(data)-1))
	first := min(length, len(data)-offset)
	if first == length {
		return data[offset : offset+length]
	}
	wrapped := make([]byte, length)
	copy(wrapped, data[offset:])
	copy(wrapped[first:], data[:length-first])
	return wrapped
}

func decodeGenerationPerfRing(data []byte, head, tail uint64, layout generationPerfLayout, inode uint64, cgroup string, cpu int) (samples uint64, zero bool, err error) {
	if len(data) < 64 || len(data)&(len(data)-1) != 0 || tail > head || head-tail > uint64(len(data)) {
		return 0, false, generationPerfRejected("invalid ring bounds")
	}
	for cursor := tail; cursor < head; {
		remaining := head - cursor
		if remaining < 8 {
			return 0, false, generationPerfRejected("partial record header")
		}
		header := generationRingBytes(data, cursor, 8)
		kind := binary.NativeEndian.Uint32(header)
		size := int(binary.NativeEndian.Uint16(header[6:]))
		if size < 8 || size&7 != 0 || uint64(size) > remaining || size > len(data) {
			return 0, false, generationPerfRejected("invalid record length")
		}
		if kind != unix.PERF_RECORD_SAMPLE {
			return 0, false, generationPerfRejected("lost or unknown record")
		}
		record := generationRingBytes(data, cursor, size)
		isZero, sampleErr := decodeGenerationPerfSample(record, layout, inode, cgroup, cpu)
		if sampleErr != nil {
			return 0, false, sampleErr
		}
		samples++
		zero = zero || isZero
		cursor += uint64(size)
	}
	return samples, zero, nil
}

func decodeGenerationPerfSample(record []byte, layout generationPerfLayout, inode uint64, cgroup string, cpu int) (bool, error) {
	if len(record) < 32 || binary.NativeEndian.Uint64(record[8:]) == 0 ||
		binary.NativeEndian.Uint32(record[16:]) != uint32(cpu) || binary.NativeEndian.Uint32(record[20:]) != 0 {
		return false, generationPerfRejected("invalid sample CPU or clock")
	}
	rawSize := uint64(binary.NativeEndian.Uint32(record[24:]))
	if rawSize < 32 || rawSize > generationMaxPerfRaw || (28+rawSize+7)&^7 != uint64(len(record)) {
		return false, generationPerfRejected("invalid sample raw length")
	}
	raw := record[28 : 28+rawSize]
	typeID := binary.NativeEndian.Uint16(raw)
	// cpuhp_enter 在上线准备和下线回调前同步发出；任何记录都使本次覆盖失效。
	// 不解析或输出 guard 的 fun 指针，避免传播不需要的内核地址。
	if typeID == layout.hotplugID {
		return false, generationPerfRejected("CPU hotplug invalidated coverage")
	}
	if typeID != layout.populatedID || binary.NativeEndian.Uint32(raw[8:]) != 0 ||
		int32(binary.NativeEndian.Uint32(raw[12:])) < 0 || binary.NativeEndian.Uint64(raw[16:]) != inode {
		return false, generationPerfRejected("sample differs from original cgroup")
	}
	location := binary.NativeEndian.Uint32(raw[24:])
	offset, length := uint64(location&0xffff), uint64(location>>16)
	if offset < 32 || length == 0 || length > 4097 || offset+length > rawSize {
		return false, generationPerfRejected("invalid dynamic cgroup path")
	}
	encoded := raw[offset : offset+length]
	if encoded[len(encoded)-1] != 0 || bytes.IndexByte(encoded[:len(encoded)-1], 0) >= 0 ||
		!utf8.Valid(encoded[:len(encoded)-1]) || string(encoded[:len(encoded)-1]) != cgroup {
		return false, generationPerfRejected("sample path differs from original cgroup")
	}
	if binary.NativeEndian.Uint32(raw[28:]) != 0 {
		return false, generationPerfRejected("original cgroup became populated")
	}
	return true, nil
}

// PERF_FORMAT_LOST 的非 GROUP read 恰为 value/lost 两个 u64。
// 即使 LOST record 还没写入 ring，独立计数和 SAMPLE 总数也必须同时完整。
func checkGenerationPerfCount(raw []byte, consumed uint64) error {
	if len(raw) != 16 || binary.NativeEndian.Uint64(raw[8:]) != 0 || binary.NativeEndian.Uint64(raw) != consumed {
		return generationPerfRejected("counter or loss does not match complete samples")
	}
	return nil
}

func generationPerfRejected(reason string) error {
	return fmt.Errorf("%w: perf %s", ErrGenerationUnconfirmed, reason)
}
