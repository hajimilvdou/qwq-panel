// SPDX-License-Identifier: AGPL-3.0-only

package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const (
	MaxComposeYAMLBytes = 128 << 10
	MaxComposeOutput    = 64 << 10
)

// ForbiddenHostMountPrefixes 严禁容器挂载（无论短语法 `- src:dst` 还是长语法 `type: bind, source: ...`）的宿主机敏感路径树。
var ForbiddenHostMountPrefixes = []string{
	"/etc",
	"/root",
	"/boot",
	"/proc",
	"/sys",
	"/dev",
	"/run/qwq",
	"/var/run/qwq",
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/lib/docker",
	"/var/lib/qwq",
	"/var/lib/qwq-plugins",
	"/var/lib/qwq-plugin-data",
	"/var/lib/qwq-privileged",
	"/var/lib/qwq-capability",
	"/opt/qwq",
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
}

// BlockedLinuxCapabilities 严禁在 cap_add 中声明的高危逃逸能力。
var BlockedLinuxCapabilities = []string{
	"ALL",
	"SYS_ADMIN",
	"CAP_SYS_ADMIN",
	"SYS_MODULE",
	"CAP_SYS_MODULE",
	"SYS_RAWIO",
	"CAP_SYS_RAWIO",
	"SYS_PTRACE",
	"CAP_SYS_PTRACE",
	"SYS_BOOT",
	"CAP_SYS_BOOT",
	"DAC_READ_SEARCH",
	"CAP_DAC_READ_SEARCH",
	"DAC_OVERRIDE",
	"CAP_DAC_OVERRIDE",
	"BPF",
	"CAP_BPF",
	"PERFMON",
	"CAP_PERFMON",
}

// ValidateComposeYAMLStrict 使用基于缩进栈的键值/列表令牌状态机（零外部依赖，且免疫冒号前后空格、多行值、YAML 布尔别名 yes/on/true、路径 // 与 .. 折叠、变量插值、转义序列、内联/跨行流式语法及高危指令绕过）
// 对 Compose YAML 执行结构化安全扫描。
func ValidateComposeYAMLStrict(raw string) ([]string, error) {
	if len(raw) == 0 || len(raw) > MaxComposeYAMLBytes {
		return nil, fmt.Errorf("compose_yaml 长度必须在 1..%d 字节之间", MaxComposeYAMLBytes)
	}
	if strings.ContainsRune(raw, '\x00') {
		return nil, errors.New("compose_yaml 不得包含 NUL 字节")
	}

	type indentScope struct {
		indent int
		key    string
	}
	var stack []indentScope
	hasServices := false
	var warnings []string

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for lineNo, rawLine := range lines {
		line := stripYAMLComment(rawLine)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "---" || trimmed == "..." {
			continue
		}
		// 1. 禁止 Compose 变量插值（防止 ${X:-true} 或 ${V:-/}:/host 绕过静态检查）
		if strings.Contains(trimmed, "${") {
			return nil, fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止使用变量插值 (${...})", lineNo+1)
		}
		// 2. 禁止键名或引号字符串中的反斜杠转义（防止 "\x70rivileged" / "\u0070id" / "\x2fetc:/host" 绕过）
		if hasYAMLBackslashEscape(trimmed) {
			return nil, fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止在键名或引号字符串中使用反斜杠转义", lineNo+1)
		}
		// 3. 禁止 YAML 锚点/别名/合并键/自定义标签注入（防止 &p true / *p / <<: / !!bool 绕过）
		if hasYAMLAnchorOrAlias(trimmed) {
			return nil, fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止使用 YAML 锚点、别名、合并键或自定义标签", lineNo+1)
		}
		// 4. 禁止非空内联流式映射 {...}（仅允许字面空 {}）与跨行/未闭合流式序列 [...] 及未闭合引号
		if err := validateYAMLFlowSyntax(lineNo+1, trimmed); err != nil {
			return nil, err
		}
		// 禁止 YAML 显式复合键语法（? key / : val）
		if trimmed == "?" || strings.HasPrefix(trimmed, "? ") || strings.HasPrefix(trimmed, "?\t") || strings.HasPrefix(trimmed, ":") {
			return nil, fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止使用 YAML 显式复合键语法", lineNo+1)
		}

		indent := countLeadingIndent(rawLine)
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent && !strings.HasPrefix(trimmed, "-") {
			stack = stack[:len(stack)-1]
		}
		for len(stack) > 1 && indent < stack[len(stack)-1].indent && strings.HasPrefix(trimmed, "-") {
			stack = stack[:len(stack)-1]
		}

		pathKeys := make([]string, len(stack))
		for i, s := range stack {
			pathKeys[i] = s.key
		}

		// 处理列表项 `- ...`
		if strings.HasPrefix(trimmed, "-") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			parentKey := ""
			if len(pathKeys) > 0 {
				parentKey = pathKeys[len(pathKeys)-1]
			}
			// 禁止在受控指令列表中使用 YAML 流式映射 `{...}` 规避长语法检查
			if strings.HasPrefix(item, "{") {
				return nil, fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 列表项禁止使用内联流式映射", lineNo+1)
			}
			// 检查列表项内部是否自身是 `key: val`（如长语法 volumes `- type: bind` / `source: /etc`）
			if k, v, ok := splitYAMLKeyValue(item); ok {
				if err := checkComposeDirective(lineNo+1, append(pathKeys, k), k, v, &warnings); err != nil {
					return nil, err
				}
				stack = append(stack, indentScope{indent: indent + 1, key: k})
				continue
			}
			cleanItem := unquoteYAML(item)
			switch parentKey {
			case "volumes":
				if strings.HasPrefix(strings.TrimSpace(item), "[") {
					return nil, fmt.Errorf("第 %d 行：出于安全限制，volumes 列表项禁止嵌套流式序列", lineNo+1)
				}
				if err := validateVolumeShortSpec(lineNo+1, cleanItem); err != nil {
					return nil, err
				}
			case "cap_add":
				if isBlockedCap(cleanItem) {
					return nil, fmt.Errorf("第 %d 行：禁止授予高危容器内核能力 %q", lineNo+1, cleanItem)
				}
			case "devices":
				return nil, fmt.Errorf("第 %d 行：禁止挂载宿主机物理设备 (devices)", lineNo+1)
			case "security_opt":
				low := strings.ToLower(cleanItem)
				if strings.Contains(low, "unconfined") || strings.Contains(low, "disable") {
					return nil, fmt.Errorf("第 %d 行：禁止通过 security_opt 关闭 AppArmor/Seccomp/SELinux 隔离", lineNo+1)
				}
			}
			continue
		}

		// 处理常规键值行 `key : value`
		key, val, ok := splitYAMLKeyValue(trimmed)
		if !ok {
			// 多行标量续行（例如 `privileged:\n  true`）：检查父键是否为敏感布尔/路径键
			if len(pathKeys) > 0 {
				lastKey := pathKeys[len(pathKeys)-1]
				if err := checkComposeDirective(lineNo+1, pathKeys, lastKey, trimmed, &warnings); err != nil {
					return nil, err
				}
			}
			continue
		}

		if len(stack) == 0 && key == "services" {
			hasServices = true
		}

		nextPath := append(append([]string(nil), pathKeys...), key)
		if err := checkComposeDirective(lineNo+1, nextPath, key, val, &warnings); err != nil {
			return nil, err
		}
		if val == "" || isYAMLBlockScalar(val) {
			stack = append(stack, indentScope{indent: indent, key: key})
		}
	}

	if !hasServices {
		return nil, errors.New("compose_yaml 缺少顶层 services 定义")
	}
	return warnings, nil
}

func checkComposeDirective(lineNo int, keyPath []string, key, rawVal string, warnings *[]string) error {
	val := unquoteYAML(rawVal)
	lowVal := strings.ToLower(val)

	switch key {
	case "driver_opts", "build", "extends", "include", "secrets", "configs",
		"env_file", "cgroup", "cgroup_parent", "uts", "userns_mode", "volumes_from":
		return fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止使用 %s 指令", lineNo, key)
	case "privileged":
		if isYAMLTruthy(lowVal) || isYAMLBlockScalar(rawVal) || strings.HasPrefix(val, "[") {
			return fmt.Errorf("第 %d 行：严禁部署 privileged 特权容器", lineNo)
		}
	case "pid":
		if lowVal == "host" || isYAMLBlockScalar(rawVal) || strings.HasPrefix(val, "[") {
			return fmt.Errorf("第 %d 行：严禁使用 pid: host 共享宿主机进程命名空间", lineNo)
		}
	case "ipc":
		if lowVal == "host" || isYAMLBlockScalar(rawVal) || strings.HasPrefix(val, "[") {
			return fmt.Errorf("第 %d 行：严禁使用 ipc: host 共享宿主机 IPC 命名空间", lineNo)
		}
	case "devices":
		if val != "" && val != "[]" {
			return fmt.Errorf("第 %d 行：严禁挂载宿主机设备 (devices)", lineNo)
		}
	case "security_opt":
		if strings.HasPrefix(val, "[") {
			for _, item := range splitInlineYAMLList(val) {
				low := strings.ToLower(item)
				if strings.Contains(low, "unconfined") || strings.Contains(low, "disable") {
					return fmt.Errorf("第 %d 行：禁止通过 security_opt 关闭 AppArmor/Seccomp/SELinux 隔离", lineNo)
				}
			}
		} else if strings.Contains(lowVal, "unconfined") || strings.Contains(lowVal, "disable") {
			return fmt.Errorf("第 %d 行：禁止通过 security_opt 关闭 AppArmor/Seccomp/SELinux 隔离", lineNo)
		}
	case "network_mode":
		if lowVal == "host" {
			appendWarnUnique(warnings, "检测到 network_mode: host（容器将共享宿主机网络端口空间，请确认端口无冲突）")
		}
	case "source", "src":
		if slices.Contains(keyPath, "volumes") && val != "" {
			if err := validateHostBindPath(lineNo, val); err != nil {
				return err
			}
		}
	case "cap_add":
		if strings.HasPrefix(val, "[") {
			for _, item := range splitInlineYAMLList(val) {
				if isBlockedCap(item) {
					return fmt.Errorf("第 %d 行：禁止授予高危容器能力 %q", lineNo, item)
				}
			}
		} else if val != "" && isBlockedCap(val) {
			return fmt.Errorf("第 %d 行：禁止授予高危容器能力 %q", lineNo, val)
		}
	case "volumes":
		if strings.HasPrefix(val, "[") {
			if strings.Contains(val, "{") {
				return fmt.Errorf("第 %d 行：出于安全限制，volumes 禁止使用内联流式映射", lineNo)
			}
			for _, item := range splitInlineYAMLList(val) {
				if err := validateVolumeShortSpec(lineNo, item); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateVolumeShortSpec(lineNo int, spec string) error {
	// 命名卷（无 `/`、`.`、`~` 前缀，如 `db_data:/var/lib/mysql`）安全放行
	first, rest, hasColon := strings.Cut(spec, ":")
	if !hasColon {
		return nil
	}
	src := strings.TrimSpace(first)
	if src == "" {
		return fmt.Errorf("第 %d 行：非法的空挂载源路径", lineNo)
	}
	if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") || strings.Contains(src, "/") || strings.Contains(rest, "docker.sock") {
		return validateHostBindPath(lineNo, src)
	}
	return nil
}

func validateHostBindPath(lineNo int, src string) error {
	if strings.HasPrefix(src, "~") || strings.Contains(src, "..") || strings.Contains(src, `\`) {
		return fmt.Errorf("第 %d 行：禁止包含 ~、.. 或反斜杠的宿主机挂载路径 %q", lineNo, src)
	}
	if !strings.HasPrefix(src, "/") {
		// 栈工作目录内的受控子目录（如 ./data）允许挂载
		cleanedRel := filepath.ToSlash(filepath.Clean(src))
		if cleanedRel == "." || cleanedRel == ".." || strings.HasPrefix(cleanedRel, "../") {
			return fmt.Errorf("第 %d 行：禁止越出当前 Compose 栈目录的挂载路径 %q", lineNo, src)
		}
		return nil
	}
	cleaned := path.Clean(src)
	if cleaned == "/" {
		return fmt.Errorf("第 %d 行：严禁将宿主机根目录 / 挂载进容器", lineNo)
	}
	for _, blocked := range ForbiddenHostMountPrefixes {
		if cleaned == blocked || strings.HasPrefix(cleaned, blocked+"/") {
			return fmt.Errorf("第 %d 行：严禁挂载受保护的宿主机敏感路径 %q", lineNo, cleaned)
		}
	}
	return nil
}

func isYAMLTruthy(low string) bool {
	switch strings.TrimSpace(low) {
	case "true", "yes", "on", "y", "1", "[true]":
		return true
	default:
		return false
	}
}

func isBlockedCap(capName string) bool {
	up := strings.ToUpper(strings.TrimSpace(capName))
	return slices.Contains(BlockedLinuxCapabilities, up)
}

func splitYAMLKeyValue(s string) (key, val string, ok bool) {
	idx := strings.IndexByte(s, ':')
	if idx <= 0 {
		return "", "", false
	}
	// 冒号后必须是行尾或空白字符才是 YAML 键值分隔符（避免把 `127.0.0.1:8080` 误判为键值）
	if idx+1 < len(s) && s[idx+1] != ' ' && s[idx+1] != '\t' {
		return "", "", false
	}
	k := strings.ToLower(strings.Trim(strings.TrimSpace(s[:idx]), `"'`))
	if k == "" || strings.ContainsAny(k, " \t") {
		return "", "", false
	}
	v := strings.TrimSpace(s[idx+1:])
	return k, v, true
}

func stripYAMLComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle && (i == 0 || line[i-1] != '\\') {
			inDouble = !inDouble
		} else if c == '#' && !inSingle && !inDouble && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

func hasYAMLBackslashEscape(trimmed string) bool {
	if strings.HasSuffix(trimmed, `\`) {
		return true
	}
	inSingle, inDouble, seenColon := false, false, false
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		} else if c == '\\' {
			if inSingle || inDouble || !seenColon {
				return true
			}
		} else if c == ':' && !inSingle && !inDouble {
			seenColon = true
		}
	}
	return false
}

func validateYAMLFlowSyntax(lineNo int, trimmed string) error {
	inSingle, inDouble := false, false
	bracketDepth := 0
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}
		switch c {
		case '{':
			j := i + 1
			for j < len(trimmed) && (trimmed[j] == ' ' || trimmed[j] == '\t') {
				j++
			}
			if j >= len(trimmed) || trimmed[j] != '}' {
				return fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止使用非空内联流式映射或跨行流式映射", lineNo)
			}
			i = j
		case '}':
			return fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止使用非空或未闭合流式映射", lineNo)
		case '[':
			bracketDepth++
			if bracketDepth > 1 {
				return fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止使用嵌套流式序列", lineNo)
			}
		case ']':
			bracketDepth--
			if bracketDepth < 0 {
				return fmt.Errorf("第 %d 行：存在未匹配的流式序列闭合括号", lineNo)
			}
		}
	}
	if inSingle || inDouble {
		return fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止跨行或未闭合的引号字符串", lineNo)
	}
	if bracketDepth != 0 {
		return fmt.Errorf("第 %d 行：出于安全限制，受管 Compose 禁止跨行或未闭合的流式序列", lineNo)
	}
	return nil
}

func isYAMLBlockScalar(rawVal string) bool {
	v := strings.TrimSpace(rawVal)
	return strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">")
}

func hasYAMLAnchorOrAlias(trimmed string) bool {
	inSingle, inDouble := false, false
	var cur strings.Builder
	tokens := make([]string, 0, 4)
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			flush()
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			flush()
			continue
		}
		if inSingle || inDouble {
			continue
		}
		if c == ' ' || c == '\t' {
			flush()
			continue
		}
		cur.WriteByte(c)
	}
	flush()

	for _, tok := range tokens {
		if strings.Contains(tok, "!!") {
			return true
		}
		clean := strings.Trim(tok, "[]{},")
		if clean == "" {
			continue
		}
		if clean == "<<" || strings.HasPrefix(clean, "<<:") {
			return true
		}
		if len(clean) > 1 && (clean[0] == '&' || clean[0] == '*') {
			return true
		}
		if clean[0] == '!' {
			return true
		}
	}
	return false
}

func countLeadingIndent(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			n++
		} else if s[i] == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func splitInlineYAMLList(raw string) []string {
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(raw), "["), "]"))
	if inner == "" {
		return nil
	}
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := unquoteYAML(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func appendWarnUnique(list *[]string, msg string) {
	if !slices.Contains(*list, msg) {
		*list = append(*list, msg)
	}
}

// BuildSafeDockerUpdatePayload 构造兼容无 swapaccount=1 1C1G 内核的容器限额更新载荷：
// 设置 MemorySwap: -1 让内核自适应，避免 `Your kernel does not support swap limit capabilities` 阻断内存限额调整。
func BuildSafeDockerUpdatePayload(memoryLimitMB int64, cpuQuotaPercent float64) ([]byte, error) {
	payload := make(map[string]any, 3)
	if memoryLimitMB > 0 {
		if memoryLimitMB < 6 || memoryLimitMB > 65536 {
			return nil, errors.New("memory_limit_mb 超出合理范围 (6..65536 MiB)")
		}
		payload["Memory"] = memoryLimitMB * 1024 * 1024
		payload["MemorySwap"] = int64(-1)
	}
	if cpuQuotaPercent > 0 {
		if cpuQuotaPercent < 1 || cpuQuotaPercent > 6400 {
			return nil, errors.New("cpu_percent 超出合理范围 (1..6400%)")
		}
		payload["NanoCPUs"] = int64(cpuQuotaPercent * 1e7)
	}
	if len(payload) == 0 {
		return nil, errors.New("至少需要指定 memory_limit_mb 或 cpu_percent 之一")
	}
	return json.Marshal(payload)
}
