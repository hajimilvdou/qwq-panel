// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 腾讯云 DNSPod API v3 (TC3-HMAC-SHA256) ========================

const (
	dnspodHost    = "dnspod.tencentcloudapi.com"
	dnspodService = "dnspod"
	dnspodVersion = "2021-03-23"
	dnspodAlg     = "TC3-HMAC-SHA256"
)

type dnspodProvider struct {
	scope  dns.Scope
	client *apiClient
}

func dnspodID(value string) bool {
	if len(value) == 0 || len(value) > 20 {
		return false
	}
	v, err := strconv.ParseUint(value, 10, 64)
	return err == nil && v > 0
}

func tc3HMACSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func tc3SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func dnspodAuthorization(secretID string, secretKey []byte, action string, body []byte, now time.Time) (string, string) {
	ts := now.UTC().Unix()
	date := now.UTC().Format("2006-01-02")
	tsStr := strconv.FormatInt(ts, 10)

	canonicalHeaders := fmt.Sprintf("content-type:application/json; charset=utf-8\nhost:%s\nx-tc-action:%s\n", dnspodHost, strings.ToLower(action))
	signedHeaders := "content-type;host;x-tc-action"
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		tc3SHA256Hex(body),
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, dnspodService)
	stringToSign := strings.Join([]string{
		dnspodAlg,
		tsStr,
		credentialScope,
		tc3SHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	tc3Secret := make([]byte, 3+len(secretKey))
	copy(tc3Secret, "TC3")
	copy(tc3Secret[3:], secretKey)
	defer clear(tc3Secret)

	secretDate := tc3HMACSHA256(tc3Secret, date)
	defer clear(secretDate)
	secretService := tc3HMACSHA256(secretDate, dnspodService)
	defer clear(secretService)
	secretSigning := tc3HMACSHA256(secretService, "tc3_request")
	defer clear(secretSigning)

	sig := hex.EncodeToString(tc3HMACSHA256(secretSigning, stringToSign))
	auth := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		dnspodAlg, secretID, credentialScope, signedHeaders, sig)
	return auth, tsStr
}

type dnspodAPIError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

func (c *apiClient) dnspod(ctx context.Context, scope dns.Scope, action string, payload any, mutation bool) (json.RawMessage, *dnspodAPIError, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fault.New("VALIDATION_FAILED", "腾讯云 DNSPod 请求无法编码")
	}
	data, header, requestErr := c.request(ctx, scope, mutation, func(credentials Credentials) (*http.Request, error) {
		auth, tsStr := dnspodAuthorization(credentials.AccessKeyID, credentials.AccessKeySecret, action, bodyBytes, c.clock.Now())
		request, err := http.NewRequest(http.MethodPost, dnspodEndpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
		request.Header.Set("Host", dnspodHost)
		request.Header.Set("X-TC-Action", action)
		request.Header.Set("X-TC-Version", dnspodVersion)
		request.Header.Set("X-TC-Timestamp", tsStr)
		request.Header.Set("Authorization", auth)
		return request, nil
	})
	var transportFailure *fault.Error
	if errors.As(requestErr, &transportFailure) && transportFailure.Uncertain {
		return nil, nil, requestErr
	}
	var env struct {
		Response json.RawMessage `json:"Response"`
	}
	if json.Unmarshal(data, &env) == nil && len(env.Response) > 0 {
		var meta struct {
			RequestID string          `json:"RequestId"`
			Error     *dnspodAPIError `json:"Error"`
		}
		if json.Unmarshal(env.Response, &meta) == nil && meta.Error != nil && meta.Error.Code != "" {
			// 允许调用方区分 NoDataOfRecord / NoDataOfDomain 空集合响应
			if meta.Error.Code == "ResourceNotFound.NoDataOfRecord" || meta.Error.Code == "ResourceNotFound.NoDataOfDomain" {
				return env.Response, meta.Error, nil
			}
			code, uncertain := "PROVIDER_UNAVAILABLE", mutation
			switch {
			case strings.HasPrefix(meta.Error.Code, "AuthFailure"), strings.HasPrefix(meta.Error.Code, "UnauthorizedOperation"):
				code, uncertain = "CREDENTIAL_REVOKED", false
			case strings.HasPrefix(meta.Error.Code, "RequestLimitExceeded"), strings.HasPrefix(meta.Error.Code, "LimitExceeded"):
				code, uncertain = "RATE_LIMITED", false
			case strings.HasPrefix(meta.Error.Code, "ResourceNotFound"), strings.Contains(meta.Error.Code, "RecordIdInvalid"):
				code, uncertain = "NOT_FOUND", false
			case strings.Contains(meta.Error.Code, "RecordExist"), strings.Contains(meta.Error.Code, "Conflict"):
				code, uncertain = "RECORD_CONFLICT", false
			case strings.HasPrefix(meta.Error.Code, "InvalidParameter"), strings.HasPrefix(meta.Error.Code, "MissingParameter"):
				code, uncertain = "VALIDATION_FAILED", false
			case strings.HasPrefix(meta.Error.Code, "InternalError"):
				code, uncertain = "PROVIDER_UNAVAILABLE", mutation
			}
			return nil, meta.Error, apiFailure(code, uncertain, retryAt(c.clock.Now(), header.Get("Retry-After")))
		}
		if requestErr != nil {
			return nil, nil, requestErr
		}
		if !names.ID(meta.RequestID) {
			return nil, nil, apiFailure("PROVIDER_INVALID", mutation, time.Time{})
		}
		return env.Response, nil, nil
	}
	if requestErr != nil {
		return nil, nil, requestErr
	}
	return nil, nil, apiFailure("PROVIDER_INVALID", mutation, time.Time{})
}

type dnspodRecord struct {
	record dns.Record
	line   string
}

func dnspodRecordRevision(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return "", fault.New("PROVIDER_INVALID", "腾讯云 DNSPod 记录对象格式无效")
	}
	var trailing any
	if !errors.Is(dec.Decode(&trailing), io.EOF) {
		return "", fault.New("PROVIDER_INVALID", "腾讯云 DNSPod 记录对象包含尾随数据")
	}
	delete(obj, "RequestId")
	delete(obj, "DomainId")
	// 归一化 List 与 DescribeRecord 的字段差异（RecordId vs Id, Name vs SubDomain, Type vs RecordType, Line vs RecordLine, Status vs Enabled）
	normalized := map[string]any{
		"id":      firstNonNil(obj["RecordId"], obj["Id"]),
		"sub":     firstNonNil(obj["Name"], obj["SubDomain"]),
		"type":    firstNonNil(obj["Type"], obj["RecordType"]),
		"value":   obj["Value"],
		"ttl":     obj["TTL"],
		"line":    firstNonNil(obj["Line"], obj["RecordLine"]),
		"mx":      obj["MX"],
		"enabled": normalizeDNSPodEnabled(firstNonNil(obj["Status"], obj["Enabled"])),
	}
	rawNorm, err := json.Marshal(normalized)
	if err != nil {
		return "", fault.New("PROVIDER_INVALID", "腾讯云 DNSPod 记录对象无法规范化")
	}
	return providerRevision(rawNorm)
}

func normalizeDNSPodEnabled(v any) any {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		switch strings.ToUpper(strings.TrimSpace(val)) {
		case "ENABLE", "ENABLED", "1", "TRUE":
			return true
		case "DISABLE", "DISABLED", "0", "FALSE":
			return false
		}
		return val
	case json.Number:
		if n, err := val.Int64(); err == nil {
			if n == 1 {
				return true
			}
			if n == 0 {
				return false
			}
		}
		return val
	case float64:
		if val == 1 {
			return true
		}
		if val == 0 {
			return false
		}
		return val
	default:
		return v
	}
}

func firstNonNil(a, b any) any {
	if a != nil {
		return a
	}
	return b
}

func parseDNSPodRecord(scope dns.Scope, raw json.RawMessage) (dnspodRecord, error) {
	var payload struct {
		RecordID   uint64         `json:"RecordId"`
		ID         uint64         `json:"Id"`
		Name       string         `json:"Name"`
		SubDomain  string         `json:"SubDomain"`
		Type       dns.RecordType `json:"Type"`
		RecordType dns.RecordType `json:"RecordType"`
		Value      string         `json:"Value"`
		TTL        uint32         `json:"TTL"`
		Line       string         `json:"Line"`
		RecordLine string         `json:"RecordLine"`
		MX         *uint16        `json:"MX"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return dnspodRecord{}, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod 记录格式无效")
	}
	recID := payload.RecordID
	if recID == 0 {
		recID = payload.ID
	}
	idStr := strconv.FormatUint(recID, 10)
	if !dnspodID(idStr) {
		return dnspodRecord{}, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod 记录 ID 无效")
	}
	rr := payload.Name
	if rr == "" {
		rr = payload.SubDomain
	}
	recType := payload.Type
	if recType == "" {
		recType = payload.RecordType
	}
	line := payload.Line
	if line == "" {
		line = payload.RecordLine
	}
	if len(line) > 64 || strings.ContainsAny(line, "\x00\r\n") {
		return dnspodRecord{}, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod 记录线路无效")
	}
	if line == "" {
		line = "默认"
	}
	fqdn, err := recordName(scope, rr)
	if err != nil {
		return dnspodRecord{}, err
	}
	version, err := dnspodRecordRevision(raw)
	if err != nil {
		return dnspodRecord{}, err
	}
	value := payload.Value
	if recType == dns.MX && payload.MX != nil && !strings.Contains(strings.TrimSpace(value), " ") {
		value = fmt.Sprintf("%d %s", *payload.MX, strings.TrimSuffix(strings.TrimSpace(value), "."))
	}
	record, err := dns.CanonicalRecord(scope, dns.Record{
		ID:               idStr,
		Type:             recType,
		Name:             fqdn,
		Value:            value,
		TTL:              payload.TTL,
		ProviderRevision: version,
	})
	return dnspodRecord{record: record, line: line}, err
}

func (p *dnspodProvider) records(ctx context.Context, scope dns.Scope) ([]dnspodRecord, error) {
	if err := sameScope(p.scope, scope); err != nil {
		return nil, err
	}
	var records []dnspodRecord
	seen := map[string]bool{}
	const pageSize = 100
	for page := 0; page < 41; page++ {
		offset := page * pageSize
		respRaw, apiErr, err := p.client.dnspod(ctx, scope, "DescribeRecordList", map[string]any{
			"Domain": scope.ZoneName,
			"Offset": offset,
			"Limit":  pageSize,
		}, false)
		if err != nil {
			return nil, err
		}
		if apiErr != nil && apiErr.Code == "ResourceNotFound.NoDataOfRecord" {
			return records, nil
		}
		var result struct {
			RecordCountInfo struct {
				TotalCount int `json:"TotalCount"`
				ListCount  int `json:"ListCount"`
			} `json:"RecordCountInfo"`
			RecordList []json.RawMessage `json:"RecordList"`
		}
		if json.Unmarshal(respRaw, &result) != nil || result.RecordCountInfo.TotalCount < 0 || result.RecordCountInfo.TotalCount > maxProviderRecords || len(result.RecordList) > pageSize {
			return nil, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod zone 分页无效或超过上限")
		}
		for _, raw := range result.RecordList {
			rec, err := parseDNSPodRecord(scope, raw)
			if err != nil || seen[rec.record.ID] {
				return nil, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod 记录无效或重复")
			}
			seen[rec.record.ID] = true
			records = append(records, rec)
		}
		if offset+len(result.RecordList) >= result.RecordCountInfo.TotalCount || len(result.RecordList) == 0 {
			if len(records) != result.RecordCountInfo.TotalCount {
				return nil, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod zone 分页不完整")
			}
			return records, nil
		}
	}
	return nil, fault.New("RESOURCE_EXHAUSTED", "腾讯云 DNSPod zone 记录超过查询预算")
}

func (p *dnspodProvider) List(ctx context.Context, scope dns.Scope) ([]dns.Record, error) {
	entries, err := p.records(ctx, scope)
	if err != nil {
		return nil, err
	}
	out := make([]dns.Record, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.record)
	}
	return out, nil
}

func (p *dnspodProvider) get(ctx context.Context, scope dns.Scope, id string) (dnspodRecord, error) {
	if sameScope(p.scope, scope) != nil || !dnspodID(id) {
		return dnspodRecord{}, fault.New("SCOPE_INVALID", "腾讯云 DNSPod 记录查询范围无效")
	}
	recID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return dnspodRecord{}, fault.New("SCOPE_INVALID", "腾讯云 DNSPod 记录 ID 无效")
	}
	respRaw, apiErr, err := p.client.dnspod(ctx, scope, "DescribeRecord", map[string]any{
		"Domain":   scope.ZoneName,
		"RecordId": recID,
	}, false)
	if err != nil {
		return dnspodRecord{}, err
	}
	if apiErr != nil {
		return dnspodRecord{}, fault.New("NOT_FOUND", "腾讯云 DNSPod 记录不存在")
	}
	var result struct {
		RecordInfo json.RawMessage `json:"RecordInfo"`
	}
	if json.Unmarshal(respRaw, &result) != nil || len(result.RecordInfo) == 0 {
		return dnspodRecord{}, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod 记录查询响应无效")
	}
	return parseDNSPodRecord(scope, result.RecordInfo)
}

func dnspodWritePayload(scope dns.Scope, record dns.Record, line string) (map[string]any, error) {
	rr, err := relativeRecord(scope, record.Name)
	if err != nil {
		return nil, err
	}
	if line == "" {
		line = "默认"
	}
	val := record.Value
	body := map[string]any{
		"Domain":     scope.ZoneName,
		"SubDomain":  rr,
		"RecordType": string(record.Type),
		"RecordLine": line,
		"TTL":        record.TTL,
	}
	if record.Type == dns.MX {
		prio, target, err := dns.ParseMXValue(record.Value)
		if err != nil {
			return nil, err
		}
		val = target
		body["MX"] = prio
	}
	body["Value"] = val
	return body, nil
}

func dnspodChangedID(respRaw json.RawMessage, expected string) (string, error) {
	var result struct {
		RecordID uint64 `json:"RecordId"`
	}
	if json.Unmarshal(respRaw, &result) != nil {
		return "", apiFailure("PROVIDER_INVALID", true, time.Time{})
	}
	idStr := strconv.FormatUint(result.RecordID, 10)
	if !dnspodID(idStr) || (expected != "" && idStr != expected) {
		return "", apiFailure("PROVIDER_INVALID", true, time.Time{})
	}
	return idStr, nil
}

func (p *dnspodProvider) Create(ctx context.Context, scope dns.Scope, input dns.Record) (dns.Record, error) {
	if err := sameScope(p.scope, scope); err != nil {
		return dns.Record{}, err
	}
	record, err := writeRecord(scope, input, true)
	if err != nil {
		return dns.Record{}, err
	}
	body, err := dnspodWritePayload(scope, record, "默认")
	if err != nil {
		return dns.Record{}, err
	}
	respRaw, _, err := p.client.dnspod(ctx, scope, "CreateRecord", body, true)
	if err != nil {
		return dns.Record{}, err
	}
	if record.ID, err = dnspodChangedID(respRaw, ""); err != nil {
		return dns.Record{}, err
	}
	record.ManagedBy, record.Revision = "", ""
	return dns.CanonicalRecord(scope, record)
}

func (p *dnspodProvider) Update(ctx context.Context, scope dns.Scope, before, input dns.Record) (dns.Record, error) {
	record, err := writeRecord(scope, input, false)
	if err != nil || record.ID != before.ID {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "腾讯云 DNSPod 更新不能更换记录 ID")
	}
	current, err := p.get(ctx, scope, before.ID)
	if err != nil {
		return dns.Record{}, err
	}
	if err := compareRecord(current.record, before); err != nil {
		return dns.Record{}, err
	}
	if !current.record.Type.Supported() {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "此 DNS 记录类型不能修改")
	}
	recID, err := strconv.ParseUint(before.ID, 10, 64)
	if err != nil {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "腾讯云 DNSPod 记录 ID 无效")
	}
	body, err := dnspodWritePayload(scope, record, current.line)
	if err != nil {
		return dns.Record{}, err
	}
	body["RecordId"] = recID
	respRaw, _, err := p.client.dnspod(ctx, scope, "ModifyRecord", body, true)
	if err != nil {
		return dns.Record{}, err
	}
	if _, err := dnspodChangedID(respRaw, before.ID); err != nil {
		return dns.Record{}, err
	}
	record.ManagedBy, record.Revision = "", ""
	return dns.CanonicalRecord(scope, record)
}

func (p *dnspodProvider) Delete(ctx context.Context, scope dns.Scope, before dns.Record) error {
	current, err := p.get(ctx, scope, before.ID)
	if err != nil {
		return err
	}
	if err := compareRecord(current.record, before); err != nil {
		return err
	}
	if !current.record.Type.Supported() {
		return fault.New("VALIDATION_FAILED", "此 DNS 记录类型不能删除")
	}
	recID, err := strconv.ParseUint(before.ID, 10, 64)
	if err != nil {
		return fault.New("VALIDATION_FAILED", "腾讯云 DNSPod 记录 ID 无效")
	}
	_, _, err = p.client.dnspod(ctx, scope, "DeleteRecord", map[string]any{
		"Domain":   scope.ZoneName,
		"RecordId": recID,
	}, true)
	return err
}

func dnspodZones(ctx context.Context, client *apiClient) ([]Zone, error) {
	var zones []Zone
	seen := map[string]bool{}
	const pageSize = 100
	for page := 0; page < 4; page++ {
		offset := page * pageSize
		respRaw, apiErr, err := client.dnspod(ctx, dns.Scope{Kind: dns.DNSPod}, "DescribeDomainList", map[string]any{
			"Offset": offset,
			"Limit":  pageSize,
		}, false)
		if err != nil {
			return nil, err
		}
		if apiErr != nil && apiErr.Code == "ResourceNotFound.NoDataOfDomain" {
			return zones, nil
		}
		var result struct {
			DomainCountInfo struct {
				AllTotal int `json:"AllTotal"`
			} `json:"DomainCountInfo"`
			DomainList []struct {
				DomainID uint64 `json:"DomainId"`
				Name     string `json:"Name"`
			} `json:"DomainList"`
		}
		if json.Unmarshal(respRaw, &result) != nil || result.DomainCountInfo.AllTotal < 0 || result.DomainCountInfo.AllTotal > maxProviderZones || len(result.DomainList) > pageSize {
			return nil, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod zone 列表无效或超过上限")
		}
		for _, entry := range result.DomainList {
			idStr := strconv.FormatUint(entry.DomainID, 10)
			zone, err := canonicalZone(idStr, entry.Name)
			if err != nil || !dnspodID(zone.ID) || seen[zone.ID] {
				return nil, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod zone 身份重复或无效")
			}
			seen[zone.ID] = true
			zones = append(zones, zone)
		}
		if offset+len(result.DomainList) >= result.DomainCountInfo.AllTotal || len(result.DomainList) == 0 {
			if len(zones) != result.DomainCountInfo.AllTotal {
				return nil, fault.New("PROVIDER_INVALID", "腾讯云 DNSPod zone 列表不完整")
			}
			return zones, nil
		}
	}
	return nil, fault.New("RESOURCE_EXHAUSTED", "腾讯云 DNSPod zone 列表超过查询预算")
}
