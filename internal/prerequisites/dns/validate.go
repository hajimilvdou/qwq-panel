// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 外部输入与远端快照校验 ========================

func validateScope(scope Scope) error {
	zone, err := names.DNS(scope.ZoneName, false)
	if err != nil || zone != scope.ZoneName || !names.ID(scope.ProviderID) || !names.ID(scope.ZoneID) || !names.ID(scope.Revision) {
		return fault.New("SCOPE_INVALID", "DNS 资源范围无效")
	}
	if scope.Kind != Cloudflare && scope.Kind != Aliyun && scope.Kind != DNSPod {
		return fault.New("SCOPE_INVALID", "DNS 提供商不受支持")
	}
	return nil
}

func validateRequest(request Request) (Request, error) {
	if err := validateScope(request.Scope); err != nil {
		return Request{}, err
	}
	if !names.ID(request.Caller.OwnerID) || (request.Caller.OperationID != "" && !names.ID(request.Caller.OperationID)) || !names.ID(request.AttemptID) || len(request.ExpectedRevision) != 64 {
		return Request{}, fault.New("VALIDATION_FAILED", "写入需要有效 owner、operation、attempt 和快照版本")
	}
	if request.Change.Action != Create && request.Change.Action != Update && request.Change.Action != Delete {
		return Request{}, fault.New("VALIDATION_FAILED", "DNS 变更动作无效")
	}
	record, err := normalizeRecord(request.Scope, request.Change.Record, true)
	if err != nil {
		return Request{}, err
	}
	if request.Change.Action == Create && record.ID != "" {
		return Request{}, fault.New("VALIDATION_FAILED", "新建记录不能指定提供商记录 ID")
	}
	if request.Change.Action != Create && !names.ID(record.ID) {
		return Request{}, fault.New("VALIDATION_FAILED", "修改或删除需要提供商记录 ID")
	}
	if request.Change.Action != Create && len(request.Change.ExpectedRecordRevision) != 64 {
		return Request{}, fault.New("VALIDATION_FAILED", "修改或删除需要原记录版本")
	}
	if request.CertificateID != "" && !names.ID(request.CertificateID) {
		return Request{}, fault.New("VALIDATION_FAILED", "证书资源标识无效")
	}
	if record.ManagedBy != "" {
		return Request{}, fault.New("VALIDATION_FAILED", "记录归属由宿主控制")
	}
	if record.ProviderRevision != "" {
		return Request{}, fault.New("VALIDATION_FAILED", "提供商元数据版本由宿主控制")
	}
	request.Change.Record = record
	return request, nil
}

func normalizeRecord(scope Scope, record Record, mutation bool) (Record, error) {
	name, err := names.DNS(record.Name, true)
	if strings.HasPrefix(record.Name, "*.") {
		name, err = names.SAN(record.Name)
	}
	if err != nil || !names.InZone(name, scope.ZoneName) || (record.ID != "" && !names.ID(record.ID)) {
		return Record{}, fault.New("ZONE_DENIED", "记录必须位于已授权 zone 内")
	}
	record.Name = name
	if mutation && !record.Type.Supported() {
		return Record{}, fault.New("VALIDATION_FAILED", "仅允许 A、AAAA、CNAME、TXT、MX、CAA、SRV 和 NS 记录")
	}
	if mutation && record.TTL != 1 && (record.TTL < 60 || record.TTL > 86400) {
		return Record{}, fault.New("VALIDATION_FAILED", "TTL 必须为自动或 60 至 86400 秒")
	}
	if mutation && scope.Kind != Cloudflare && record.TTL == 1 {
		return Record{}, fault.New("VALIDATION_FAILED", "非 Cloudflare DNS 提供商必须指定 TTL，不支持自动 TTL")
	}
	if record.TTL == 0 || record.TTL > 604800 || len(record.Value) > 4096 || strings.ContainsAny(record.Value, "\x00\r\n") {
		return Record{}, fault.New("VALIDATION_FAILED", "提供商记录内容无效")
	}
	if record.ManagedBy != "" && len(record.ManagedBy) != 64 {
		return Record{}, fault.New("PROVIDER_INVALID", "提供商记录归属格式无效")
	}
	if record.ProviderRevision != "" {
		if decoded, err := hex.DecodeString(record.ProviderRevision); err != nil || len(decoded) != sha256.Size {
			return Record{}, fault.New("PROVIDER_INVALID", "提供商记录元数据指纹无效")
		}
	}
	switch record.Type {
	case A, AAAA:
		address, err := netip.ParseAddr(record.Value)
		if err != nil || address.Zone() != "" || (record.Type == A && !address.Is4()) || (record.Type == AAAA && (!address.Is6() || address.Is4In6())) {
			return Record{}, fault.New("VALIDATION_FAILED", "A 或 AAAA 地址与记录类型不匹配")
		}
		record.Value = address.String()
	case CNAME:
		target, err := names.DNS(record.Value, true)
		if err != nil || (mutation && target == name) {
			return Record{}, fault.New("VALIDATION_FAILED", "CNAME 目标域名无效")
		}
		record.Value = target
	case TXT:
		if mutation && len(record.Value) > 2048 {
			return Record{}, fault.New("VALIDATION_FAILED", "TXT 内容超过上限")
		}
	case MX:
		norm, err := normalizeMXValue(record.Value)
		if err != nil {
			if mutation {
				return Record{}, err
			}
		} else {
			record.Value = norm
		}
	case NS:
		target, err := names.DNS(record.Value, false)
		if err != nil {
			if mutation {
				return Record{}, fault.New("VALIDATION_FAILED", "NS 目标域名无效")
			}
		} else {
			record.Value = target
		}
	case CAA:
		norm, err := normalizeCAAValue(record.Value)
		if err != nil {
			if mutation {
				return Record{}, err
			}
		} else {
			record.Value = norm
		}
	case SRV:
		norm, err := normalizeSRVValue(record.Value)
		if err != nil {
			if mutation {
				return Record{}, err
			}
		} else {
			record.Value = norm
		}
	default:
		if len(record.Type) == 0 || len(record.Type) > 16 {
			return Record{}, fault.New("PROVIDER_INVALID", "提供商返回无效记录类型")
		}
	}
	if record.Proxied && (scope.Kind != Cloudflare || (record.Type != A && record.Type != AAAA && record.Type != CNAME)) {
		return Record{}, fault.New("VALIDATION_FAILED", "此记录不支持 HTTP 代理")
	}
	record.Revision = ""
	record.Revision, err = digest(record)
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// ValidateScope 供宿主真实适配器复用相同的固定提供商和 zone 边界。
func ValidateScope(scope Scope) error { return validateScope(scope) }

// CanonicalRecord 复用业务快照的记录校验与完整指纹，不提供写入权限。
func CanonicalRecord(scope Scope, record Record) (Record, error) {
	return normalizeRecord(scope, record, false)
}

// ParseMXValue 解析标准 MX 值 "<priority> <exchange>"（若省略优先级则默认 10）。
func ParseMXValue(raw string) (uint16, string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 1 {
		target, err := names.DNS(fields[0], false)
		if err != nil {
			return 0, "", fault.New("VALIDATION_FAILED", "MX 目标域名无效")
		}
		return 10, target, nil
	}
	if len(fields) != 2 {
		return 0, "", fault.New("VALIDATION_FAILED", "MX 记录格式应为「优先级 目标域名」，例如 10 mail.example.com")
	}
	prio, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return 0, "", fault.New("VALIDATION_FAILED", "MX 优先级必须在 0 至 65535 之间")
	}
	target, err := names.DNS(fields[1], false)
	if err != nil {
		return 0, "", fault.New("VALIDATION_FAILED", "MX 目标域名无效")
	}
	return uint16(prio), target, nil
}

func normalizeMXValue(raw string) (string, error) {
	prio, target, err := ParseMXValue(raw)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d %s", prio, target), nil
}

// ParseCAAValue 解析标准 CAA 值 "<flags> <tag> <value>"，供提供商适配器组装结构化字段。
func ParseCAAValue(raw string) (uint8, string, string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) < 3 {
		return 0, "", "", fault.New("VALIDATION_FAILED", "CAA 记录格式应为「flags tag value」，例如 0 issue \"letsencrypt.org\"")
	}
	flags, err := strconv.ParseUint(fields[0], 10, 8)
	if err != nil {
		return 0, "", "", fault.New("VALIDATION_FAILED", "CAA flags 必须在 0 至 255 之间")
	}
	tag := strings.ToLower(fields[1])
	switch tag {
	case "issue", "issuewild", "iodef", "contactemail", "contactphone":
	default:
		return 0, "", "", fault.New("VALIDATION_FAILED", "CAA tag 仅支持 issue、issuewild、iodef、contactemail 或 contactphone")
	}
	val := strings.TrimSpace(strings.Join(fields[2:], " "))
	val = strings.Trim(val, "\"")
	if len(val) > 512 || strings.ContainsAny(val, "\x00\r\n\"") {
		return 0, "", "", fault.New("VALIDATION_FAILED", "CAA 记录值无效")
	}
	return uint8(flags), tag, val, nil
}

func normalizeCAAValue(raw string) (string, error) {
	flags, tag, val, err := ParseCAAValue(raw)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d %s %q", flags, tag, val), nil
}

// ParseSRVValue 解析标准 SRV 值 "<priority> <weight> <port> <target>"，供提供商适配器组装结构化字段。
func ParseSRVValue(raw string) (uint16, uint16, uint16, string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) != 4 {
		return 0, 0, 0, "", fault.New("VALIDATION_FAILED", "SRV 记录格式应为「优先级 权重 端口 目标域名」，例如 10 5 443 target.example.com")
	}
	prio, err1 := strconv.ParseUint(fields[0], 10, 16)
	weight, err2 := strconv.ParseUint(fields[1], 10, 16)
	port, err3 := strconv.ParseUint(fields[2], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0, "", fault.New("VALIDATION_FAILED", "SRV 优先级、权重和端口必须为 0 至 65535 的整数")
	}
	target := fields[3]
	if target != "." {
		var err error
		target, err = names.DNS(target, false)
		if err != nil {
			return 0, 0, 0, "", fault.New("VALIDATION_FAILED", "SRV 目标域名无效")
		}
	}
	return uint16(prio), uint16(weight), uint16(port), target, nil
}

func normalizeSRVValue(raw string) (string, error) {
	prio, weight, port, target, err := ParseSRVValue(raw)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d %d %d %s", prio, weight, port, target), nil
}

func normalizedSnapshot(scope Scope, records []Record, maxRecords int) ([]Record, string, error) {
	if len(records) > maxRecords {
		return nil, "", fault.New("RESOURCE_EXHAUSTED", "zone 记录数超过首期上限")
	}
	out := make([]Record, 0, len(records))
	ids := make(map[string]bool, len(records))
	for _, record := range records {
		if !names.ID(record.ID) || ids[record.ID] {
			return nil, "", fault.New("PROVIDER_INVALID", "提供商返回重复或无效记录 ID")
		}
		ids[record.ID] = true
		normalized, err := normalizeRecord(scope, record, false)
		if err != nil {
			return nil, "", err
		}
		out = append(out, normalized)
	}
	slices.SortFunc(out, func(a, b Record) int { return strings.Compare(a.ID, b.ID) })
	revision, err := digest(out)
	if err != nil {
		return nil, "", err
	}
	return out, revision, nil
}

func digest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fault.New("STATE_INVALID", "DNS 数据无法计算安全版本")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func journalKey(scope Scope) string {
	sum := sha256.Sum256([]byte(scope.ProviderID + "\x00" + scope.ZoneID))
	return "dns/journal/" + hex.EncodeToString(sum[:])
}

func sameContent(a, b Record) bool {
	a.ID, a.Revision, b.ID, b.Revision = "", "", "", ""
	a.ManagedBy, b.ManagedBy = "", ""
	// 元数据仍参与完整 revision；业务对账只比较实际 DNS 内容。
	a.ProviderRevision, b.ProviderRevision = "", ""
	return a == b
}

func planChange(request Request, records []Record, revision string) (Plan, error) {
	if request.ExpectedRevision != revision {
		return Plan{}, fault.New("REVISION_CONFLICT", "DNS 快照已变化，请重新预演")
	}
	desired := request.Change.Record
	plan := Plan{Revision: revision, Warnings: []string{}}
	for _, existing := range records {
		if existing.ID == desired.ID && desired.ID != "" {
			copy := existing
			plan.Before = &copy
			if existing.Revision != request.Change.ExpectedRecordRevision {
				return Plan{}, fault.New("RECORD_CONFLICT", "记录内容与预演前提不符")
			}
		}
		if request.Change.Action != Delete && existing.ID != desired.ID && existing.Name == desired.Name {
			if existing.Type == CNAME || desired.Type == CNAME {
				return Plan{}, fault.New("CNAME_CONFLICT", "CNAME 不能与同名记录共存")
			}
			if sameContent(existing, desired) {
				return Plan{}, fault.New("RECORD_EXISTS", "相同记录已存在")
			}
		}
	}
	if request.Change.Action != Create && plan.Before == nil {
		return Plan{}, fault.New("NOT_FOUND", "提供商记录已不存在")
	}
	if request.Change.Action != Delete {
		copy := desired
		plan.After = &copy
		if desired.Proxied {
			plan.Warnings = append(plan.Warnings, "CLOUDFLARE_PROXY_UDP_UNSUPPORTED")
		}
	}
	return plan, nil
}
