// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
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
	if scope.Kind != Cloudflare && scope.Kind != Aliyun {
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
		return Record{}, fault.New("VALIDATION_FAILED", "首期仅允许 A、AAAA、CNAME 和 TXT")
	}
	if mutation && record.TTL != 1 && (record.TTL < 60 || record.TTL > 86400) {
		return Record{}, fault.New("VALIDATION_FAILED", "TTL 必须为自动或 60 至 86400 秒")
	}
	if mutation && scope.Kind == Aliyun && record.TTL == 1 {
		return Record{}, fault.New("VALIDATION_FAILED", "阿里云 DNS 必须指定 TTL，不支持 Cloudflare 自动 TTL")
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
			return Record{}, fault.New("VALIDATION_FAILED", "TXT 内容超过首期上限")
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
