// SPDX-License-Identifier: AGPL-3.0-only

// Package names 共享域名、zone 和证书 SAN 的规范化规则。
package names

import (
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/idna"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// ID 校验资源标识，标识不能作为任意路径或主机名使用。
func ID(value string) bool { return identifier.MatchString(value) }

// DNS 规范化真实 DNS 名称；underscore 仅供 TXT 等记录所有者使用。
func DNS(value string, underscore bool) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "/\\:@*\x00\r\n") {
		return "", fault.New("VALIDATION_FAILED", "域名格式无效")
	}
	value = strings.TrimSuffix(value, ".")
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fault.New("VALIDATION_FAILED", "此处需要 DNS 域名")
	}
	labels := strings.Split(value, ".")
	for index, label := range labels {
		prefix := ""
		if underscore && strings.HasPrefix(label, "_") {
			prefix, label = "_", strings.TrimPrefix(label, "_")
		}
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", fault.New("VALIDATION_FAILED", "域名标签无效")
		}
		label = prefix + strings.ToLower(ascii)
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fault.New("VALIDATION_FAILED", "域名标签长度或格式无效")
		}
		for _, char := range label {
			if char != '-' && !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && !(underscore && char == '_') {
				return "", fault.New("VALIDATION_FAILED", "域名包含不支持的字符")
			}
		}
		labels[index] = label
	}
	value = strings.Join(labels, ".")
	if len(labels) < 2 || len(value) > 253 {
		return "", fault.New("VALIDATION_FAILED", "需要完整的 DNS 域名")
	}
	return value, nil
}

// InZone 使用标签边界匹配，拒绝 example.com.attacker.tld 等伪造后缀。
func InZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

// SAN 允许左侧一个通配符，zone 校验仍使用真实基础域名。
func SAN(value string) (string, error) {
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	name, err := DNS(value, false)
	if err != nil {
		return "", err
	}
	if wildcard {
		name = "*." + name
	}
	return name, nil
}
