// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ======================== 当前 trace ABI：事件号动态读取，未知布局明确拒绝 ========================

const (
	generationMaxPerfCPUs = 64
	generationMaxCPUIndex = 4095
)

type generationTraceField struct {
	typeName string
	offset   uint64
	size     uint64
	signed   uint64
}

type generationPerfLayout struct {
	populatedID uint16
	hotplugID   uint16
}

var generationTraceFieldPattern = regexp.MustCompile(`^\s*field:([^;]+);\s*offset:([0-9]+);\s*size:([0-9]+);\s*signed:([01]);\s*$`)

var generationTraceCommonFields = map[string]generationTraceField{
	"common_type":          {"unsigned short", 0, 2, 0},
	"common_flags":         {"unsigned char", 2, 1, 0},
	"common_preempt_count": {"unsigned char", 3, 1, 0},
	"common_pid":           {"int", 4, 4, 1},
}

var generationPopulatedTraceFields = map[string]generationTraceField{
	"root":  {"int", 8, 4, 1},
	"level": {"int", 12, 4, 1},
	"id":    {"u64", 16, 8, 0},
	"path":  {"__data_loc char[]", 24, 4, 0},
	"val":   {"int", 28, 4, 1},
}

var generationHotplugTraceFields = map[string]generationTraceField{
	"cpu":    {"unsigned int", 8, 4, 0},
	"target": {"int", 12, 4, 1},
	"idx":    {"int", 16, 4, 1},
	"fun":    {"void *", 24, 8, 0},
}

func parseGenerationTraceFormat(name, idText, format string, eventFields map[string]generationTraceField) (uint16, error) {
	identifier := strings.TrimSuffix(idText, "\n")
	id, err := strconv.ParseUint(identifier, 10, 16)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != identifier || len(format) > 32<<10 {
		return 0, ErrGenerationUnsupported
	}
	seen := make(map[string]bool, len(generationTraceCommonFields)+len(eventFields))
	nameSeen, idSeen := false, false
	for _, line := range strings.Split(format, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "name:"):
			if nameSeen || strings.TrimSpace(strings.TrimPrefix(trimmed, "name:")) != name {
				return 0, ErrGenerationUnsupported
			}
			nameSeen = true
		case strings.HasPrefix(trimmed, "ID:"):
			if idSeen || strings.TrimSpace(strings.TrimPrefix(trimmed, "ID:")) != identifier {
				return 0, ErrGenerationUnsupported
			}
			idSeen = true
		case strings.Contains(line, "field:"):
			parts := generationTraceFieldPattern.FindStringSubmatch(line)
			if parts == nil {
				return 0, ErrGenerationUnsupported
			}
			declaration := strings.Fields(parts[1])
			if len(declaration) < 2 {
				return 0, ErrGenerationUnsupported
			}
			fieldName := declaration[len(declaration)-1]
			expected, found := generationTraceCommonFields[fieldName]
			if !found {
				expected, found = eventFields[fieldName]
			}
			if !found || seen[fieldName] || strings.Join(declaration[:len(declaration)-1], " ") != expected.typeName {
				return 0, ErrGenerationUnsupported
			}
			for index, wanted := range []uint64{expected.offset, expected.size, expected.signed} {
				actual, parseErr := strconv.ParseUint(parts[index+2], 10, 64)
				if parseErr != nil || actual != wanted {
					return 0, ErrGenerationUnsupported
				}
			}
			seen[fieldName] = true
		}
	}
	if !nameSeen || !idSeen || len(seen) != len(generationTraceCommonFields)+len(eventFields) {
		return 0, ErrGenerationUnsupported
	}
	return uint16(id), nil
}

// ======================== 内核元数据读取：只认 root 控制的真实 tracefs/sysfs ========================

func readGenerationPerfText(ctx context.Context, filename string, filesystem int64, limit int) (body []byte, err error) {
	parent, err := openAbsoluteGenerationDirectory(ctx, path.Dir(filename))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeGenerationFD(parent)) }()
	fd, err := openPinnedGenerationFile(ctx, parent, path.Base(filename))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeGenerationFD(fd)) }()
	if err = requireGenerationFilesystem(fd, filesystem); err != nil {
		return nil, err
	}
	var info unix.Stat_t
	if err = unix.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if info.Uid != 0 || info.Mode&0o022 != 0 {
		return nil, ErrGenerationIdentity
	}
	return readGenerationFD(ctx, fd, limit)
}

func readGenerationTrace(ctx context.Context, group, name string, fields map[string]generationTraceField) (uint16, error) {
	for _, root := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		directory := path.Join(root, "events", group, name)
		identifier, err := readGenerationPerfText(ctx, path.Join(directory, "id"), unix.TRACEFS_MAGIC, 64)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			continue
		}
		if err != nil {
			return 0, errors.Join(ErrGenerationUnsupported, err)
		}
		format, err := readGenerationPerfText(ctx, path.Join(directory, "format"), unix.TRACEFS_MAGIC, 32<<10)
		if err != nil {
			return 0, errors.Join(ErrGenerationUnsupported, err)
		}
		return parseGenerationTraceFormat(name, string(identifier), string(format), fields)
	}
	return 0, ErrGenerationUnsupported
}

func readGenerationPerfLayout(ctx context.Context) (generationPerfLayout, error) {
	populated, err := readGenerationTrace(ctx, "cgroup", "cgroup_notify_populated", generationPopulatedTraceFields)
	if err != nil {
		return generationPerfLayout{}, err
	}
	hotplug, err := readGenerationTrace(ctx, "cpuhp", "cpuhp_enter", generationHotplugTraceFields)
	if err != nil {
		return generationPerfLayout{}, err
	}
	if populated == hotplug {
		return generationPerfLayout{}, ErrGenerationUnsupported
	}
	return generationPerfLayout{populatedID: populated, hotplugID: hotplug}, nil
}

// ======================== CPU 清单：有界解析，重叠或缺失都不能形成覆盖事实 ========================

func parseGenerationPerfCPUs(text string) ([]int, error) {
	text = strings.TrimSuffix(text, "\n")
	if text == "" || len(text) > 1024 {
		return nil, ErrGenerationUnsupported
	}
	seen := make(map[int]bool)
	for _, component := range strings.Split(text, ",") {
		firstText, lastText, ranged := strings.Cut(component, "-")
		if !ranged {
			lastText = firstText
		}
		first, firstErr := strconv.ParseUint(firstText, 10, 12)
		last, lastErr := strconv.ParseUint(lastText, 10, 12)
		if firstErr != nil || lastErr != nil || first > last || last > generationMaxCPUIndex ||
			strconv.FormatUint(first, 10) != firstText || strconv.FormatUint(last, 10) != lastText {
			return nil, ErrGenerationUnsupported
		}
		for cpu := int(first); cpu <= int(last); cpu++ {
			if seen[cpu] || len(seen) == generationMaxPerfCPUs {
				return nil, ErrGenerationUnsupported
			}
			seen[cpu] = true
		}
	}
	cpus := make([]int, 0, len(seen))
	for cpu := range seen {
		cpus = append(cpus, cpu)
	}
	slices.Sort(cpus)
	return cpus, nil
}

func readGenerationPerfCPUs(ctx context.Context, name string) ([]int, error) {
	if name != "online" && name != "possible" {
		return nil, fmt.Errorf("%w: invalid CPU inventory", ErrGenerationIdentity)
	}
	body, err := readGenerationPerfText(ctx, path.Join("/sys/devices/system/cpu", name), unix.SYSFS_MAGIC, 1024)
	if err != nil {
		return nil, errors.Join(ErrGenerationUnsupported, err)
	}
	return parseGenerationPerfCPUs(string(body))
}
