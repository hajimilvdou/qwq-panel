// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"encoding/hex"
	"strings"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 提供商记录身份与写前复核 ========================

func cloudflareID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && value == strings.ToLower(value)
}

func aliyunID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func aliyunZoneID(value string) bool {
	if aliyunID(value) {
		return true
	}
	if len(value) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		ch := value[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		isHex := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func writeRecord(scope dns.Scope, record dns.Record, create bool) (dns.Record, error) {
	if !record.Type.Supported() || (create && record.ID != "") || (!create && !names.ID(record.ID)) || record.ProviderRevision != "" {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "DNS 写入记录类型或宿主版本无效")
	}
	if record.TTL != 1 && (record.TTL < 60 || record.TTL > 86400) {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "DNS 写入 TTL 无效")
	}
	if scope.Kind == dns.Aliyun && (record.Proxied || record.TTL == 1) {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "阿里云记录必须指定 TTL 且不支持 Cloudflare 代理")
	}
	if record.ManagedBy != "" {
		decoded, err := hex.DecodeString(record.ManagedBy)
		if err != nil || len(decoded) != 32 {
			return dns.Record{}, fault.New("VALIDATION_FAILED", "DNS challenge 归属标记无效")
		}
	}
	return dns.CanonicalRecord(scope, record)
}

func compareRecord(current, expected dns.Record) error {
	if current.ID != expected.ID || expected.Revision == "" || current.Revision != expected.Revision {
		return notSent(fault.New("REVISION_CONFLICT", "DNS 记录在写前复核时已改变"))
	}
	return nil
}

func canonicalZone(id, name string) (Zone, error) {
	canonical, err := names.DNS(name, false)
	if err != nil || !names.ID(id) {
		return Zone{}, fault.New("PROVIDER_INVALID", "提供商 zone 身份无效")
	}
	return Zone{ID: id, Name: canonical}, nil
}

func recordName(scope dns.Scope, rr string) (string, error) {
	if rr == "@" {
		return scope.ZoneName, nil
	}
	if rr == "" || strings.HasSuffix(rr, ".") {
		return "", fault.New("PROVIDER_INVALID", "阿里云记录 RR 无效")
	}
	return rr + "." + scope.ZoneName, nil
}

func relativeRecord(scope dns.Scope, name string) (string, error) {
	if name == scope.ZoneName {
		return "@", nil
	}
	if !names.InZone(name, scope.ZoneName) {
		return "", fault.New("ZONE_DENIED", "DNS 记录不在授权 zone 内")
	}
	return strings.TrimSuffix(name, "."+scope.ZoneName), nil
}
