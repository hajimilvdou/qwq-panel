// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"bufio"
	"bytes"
	"math"
	"strconv"
	"strings"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
)

// ======================== Linux proc 原始字段 ========================
// 字段依据 docs.kernel.org/filesystems/proc.html；不把 guest 计数重复相加，
// 不把 iowait 当作额外精确指标。CPU 只返回原始 jiffies，速率由消费者差分。

func lines(data []byte) *bufio.Scanner {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	return scanner
}

func parseCPU(data []byte) *metricsv1.Cpu {
	var result *metricsv1.Cpu
	var cores uint32
	scanner := lines(data)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "cpu" {
			if len(fields) < 9 || result != nil {
				return nil
			}
			var values [8]uint64
			for index := range values {
				value, err := strconv.ParseUint(fields[index+1], 10, 64)
				if err != nil {
					return nil
				}
				values[index] = value
			}
			result = &metricsv1.Cpu{User: values[0], Nice: values[1], System: values[2], Idle: values[3], Iowait: values[4], Irq: values[5], Softirq: values[6], Steal: values[7]}
		} else if strings.HasPrefix(fields[0], "cpu") {
			if _, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "cpu"), 10, 32); err == nil && cores < 4096 {
				cores++
			}
		}
	}
	if scanner.Err() != nil {
		return nil
	}
	if result != nil {
		result.CoreCount = cores
	}
	return result
}

func parseMemory(data []byte) *metricsv1.Memory {
	result := &metricsv1.Memory{}
	seen := make(map[string]bool, 6)
	scanner := lines(data)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		var target *uint64
		switch key {
		case "MemTotal":
			target = &result.TotalBytes
		case "MemAvailable":
			target = &result.AvailableBytes
		case "Buffers":
			target = &result.BuffersBytes
		case "Cached":
			target = &result.CachedBytes
		case "SwapTotal":
			target = &result.SwapTotalBytes
		case "SwapFree":
			target = &result.SwapFreeBytes
		default:
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" || seen[key] {
			return nil
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > math.MaxUint64/1024 {
			return nil
		}
		*target = value * 1024
		seen[key] = true
	}
	if scanner.Err() != nil || !seen["MemTotal"] || !seen["MemAvailable"] || result.TotalBytes == 0 || result.AvailableBytes > result.TotalBytes || result.SwapFreeBytes > result.SwapTotalBytes {
		return nil
	}
	return result
}

func finiteNonnegative(text string) (float64, bool) {
	value, err := strconv.ParseFloat(text, 64)
	return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func parseLoad(data []byte) *metricsv1.Load {
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil
	}
	var values [3]float64
	for index := range values {
		value, ok := finiteNonnegative(fields[index])
		if !ok {
			return nil
		}
		values[index] = value
	}
	return &metricsv1.Load{Load1: values[0], Load5: values[1], Load15: values[2]}
}

func parseUptime(data []byte) (uint64, bool) {
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, false
	}
	value, ok := finiteNonnegative(fields[0])
	if !ok || value >= math.Exp2(64) {
		return 0, false
	}
	return uint64(value), true
}

func parseNet(data []byte) []*metricsv1.NetIf {
	var result []*metricsv1.NetIf
	scanner := lines(data)
	seen := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.LastIndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if !validDeviceName(name) || seen[name] {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			continue
		}
		var values [4]uint64
		valid := true
		for index, field := range []int{0, 1, 8, 9} {
			value, err := strconv.ParseUint(fields[field], 10, 64)
			if err != nil {
				valid = false
				break
			}
			values[index] = value
		}
		if !valid {
			continue
		}
		result = append(result, &metricsv1.NetIf{Name: name, RxBytes: values[0], RxPackets: values[1], TxBytes: values[2], TxPackets: values[3]})
		seen[name] = true
		if len(result) >= MaxInterfaces {
			break
		}
	}
	if scanner.Err() != nil {
		return nil
	}
	return result
}

func validDeviceName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, char := range name {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && !strings.ContainsRune("_.:@-", char) {
			return false
		}
	}
	return true
}
