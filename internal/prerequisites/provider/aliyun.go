// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 阿里云 DNS RPC 2015-01-09 ========================
// HMAC-SHA1 仅用于官方 RPC 签名协议；证书、材料摘要和资源指纹仍采用 SHA-256。

type aliyunProvider struct {
	scope  dns.Scope
	client *apiClient
}

func rpcEncode(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	return strings.ReplaceAll(encoded, "%7E", "~")
}

func aliyunSignature(method string, parameters url.Values, secret []byte) string {
	canonical := strings.ReplaceAll(parameters.Encode(), "+", "%20")
	key := make([]byte, len(secret)+1)
	copy(key, secret)
	key[len(secret)] = '&'
	defer clear(key)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write([]byte(method + "&%2F&" + rpcEncode(canonical)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (c *apiClient) aliyun(ctx context.Context, scope dns.Scope, action string, arguments url.Values, mutation bool) ([]byte, error) {
	data, header, requestErr := c.request(ctx, scope, mutation, func(credentials Credentials) (*http.Request, error) {
		parameters := make(url.Values, len(arguments)+8)
		for key, values := range arguments {
			parameters[key] = append([]string(nil), values...)
		}
		nonce := make([]byte, 24)
		if _, err := io.ReadFull(c.random, nonce); err != nil {
			return nil, err
		}
		parameters.Set("Action", action)
		parameters.Set("Version", "2015-01-09")
		parameters.Set("Format", "JSON")
		parameters.Set("AccessKeyId", credentials.AccessKeyID)
		parameters.Set("SignatureMethod", "HMAC-SHA1")
		parameters.Set("SignatureVersion", "1.0")
		parameters.Set("SignatureNonce", hex.EncodeToString(nonce))
		parameters.Set("Timestamp", c.clock.Now().UTC().Format("2006-01-02T15:04:05Z"))
		parameters.Set("Signature", aliyunSignature(http.MethodPost, parameters, credentials.AccessKeySecret))
		request, err := http.NewRequest(http.MethodPost, aliyunEndpoint, strings.NewReader(parameters.Encode()))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return request, nil
	})
	var transportFailure *fault.Error
	if errors.As(requestErr, &transportFailure) && transportFailure.Uncertain {
		return nil, requestErr
	}
	var envelope struct{ Code, RequestID string }
	if json.Unmarshal(data, &envelope) == nil && envelope.Code != "" {
		code, uncertain := "PROVIDER_UNAVAILABLE", mutation
		switch {
		case strings.HasPrefix(envelope.Code, "InvalidAccessKeyId"), strings.HasPrefix(envelope.Code, "SignatureDoesNotMatch"), strings.HasPrefix(envelope.Code, "Forbidden"), strings.HasPrefix(envelope.Code, "InvalidSecurityToken"):
			code, uncertain = "CREDENTIAL_REVOKED", false
		case strings.HasPrefix(envelope.Code, "Throttling"), strings.HasPrefix(envelope.Code, "QuotaExceed"):
			code, uncertain = "RATE_LIMITED", false
		case strings.HasPrefix(envelope.Code, "InvalidDomainName.NoExist"), strings.HasPrefix(envelope.Code, "InvalidRecordId.NotFound"):
			code, uncertain = "NOT_FOUND", false
		case strings.HasPrefix(envelope.Code, "DomainRecordDuplicate"), strings.HasPrefix(envelope.Code, "InvalidRR.Conflict"):
			code, uncertain = "RECORD_CONFLICT", false
		case strings.HasPrefix(envelope.Code, "InvalidParameter"), strings.HasPrefix(envelope.Code, "MissingParameter"), strings.HasPrefix(envelope.Code, "InvalidDomainName"), strings.HasPrefix(envelope.Code, "InvalidRR"), strings.HasPrefix(envelope.Code, "InvalidType"), strings.HasPrefix(envelope.Code, "InvalidValue"), strings.HasPrefix(envelope.Code, "InvalidTTL"):
			code, uncertain = "VALIDATION_FAILED", false
		case strings.HasPrefix(envelope.Code, "InternalError"), strings.HasPrefix(envelope.Code, "ServiceUnavailable"):
			code, uncertain = "PROVIDER_UNAVAILABLE", mutation
		}
		return nil, apiFailure(code, uncertain, retryAt(c.clock.Now(), header.Get("Retry-After")))
	}
	if requestErr != nil {
		return nil, requestErr
	}
	if !names.ID(envelope.RequestID) {
		return nil, apiFailure("PROVIDER_INVALID", mutation, time.Time{})
	}
	return data, nil
}

type aliyunRecord struct {
	record dns.Record
	line   string
}

func parseAliyunRecord(scope dns.Scope, raw json.RawMessage) (aliyunRecord, error) {
	var payload struct {
		RecordID string         `json:"RecordId"`
		Domain   string         `json:"DomainName"`
		RR       string         `json:"RR"`
		Type     dns.RecordType `json:"Type"`
		Value    string         `json:"Value"`
		TTL      uint32         `json:"TTL"`
		Line     string         `json:"Line"`
	}
	if json.Unmarshal(raw, &payload) != nil || !aliyunID(payload.RecordID) || len(payload.Line) > 64 || strings.ContainsAny(payload.Line, "\x00\r\n") {
		return aliyunRecord{}, fault.New("PROVIDER_INVALID", "阿里云记录身份无效")
	}
	if payload.Domain != "" {
		domain, err := names.DNS(payload.Domain, false)
		if err != nil || domain != scope.ZoneName {
			return aliyunRecord{}, fault.New("ZONE_DENIED", "阿里云记录不属于授权 zone")
		}
	}
	name, err := recordName(scope, payload.RR)
	if err != nil {
		return aliyunRecord{}, err
	}
	version, err := providerRevision(raw)
	if err != nil {
		return aliyunRecord{}, err
	}
	record, err := dns.CanonicalRecord(scope, dns.Record{ID: payload.RecordID, Type: payload.Type, Name: name, Value: payload.Value, TTL: payload.TTL, ProviderRevision: version})
	line := payload.Line
	if line == "" {
		line = "default"
	}
	return aliyunRecord{record: record, line: line}, err
}

func (p *aliyunProvider) records(ctx context.Context, scope dns.Scope) ([]aliyunRecord, error) {
	if err := sameScope(p.scope, scope); err != nil {
		return nil, err
	}
	var records []aliyunRecord
	seen := map[string]bool{}
	for page := 1; page <= 41; page++ {
		data, err := p.client.aliyun(ctx, scope, "DescribeDomainRecords", url.Values{"DomainName": {scope.ZoneName}, "PageNumber": {strconv.Itoa(page)}, "PageSize": {"100"}}, false)
		if err != nil {
			return nil, err
		}
		var result struct {
			PageNumber int `json:"PageNumber"`
			PageSize   int `json:"PageSize"`
			TotalCount int `json:"TotalCount"`
			Records    struct {
				Records []json.RawMessage `json:"Record"`
			} `json:"DomainRecords"`
		}
		if json.Unmarshal(data, &result) != nil || result.PageNumber != page || result.PageSize != 100 || result.TotalCount < 0 || result.TotalCount > maxProviderRecords || len(result.Records.Records) > 100 {
			return nil, fault.New("PROVIDER_INVALID", "阿里云 zone 分页无效或超过上限")
		}
		for _, raw := range result.Records.Records {
			record, err := parseAliyunRecord(scope, raw)
			if err != nil || seen[record.record.ID] {
				return nil, fault.New("PROVIDER_INVALID", "阿里云 zone 记录无效或重复")
			}
			seen[record.record.ID] = true
			records = append(records, record)
		}
		if page*100 >= result.TotalCount {
			if len(records) != result.TotalCount {
				return nil, fault.New("PROVIDER_INVALID", "阿里云 zone 分页不完整")
			}
			return records, nil
		}
	}
	return nil, fault.New("RESOURCE_EXHAUSTED", "阿里云 zone 记录超过查询预算")
}

func (p *aliyunProvider) List(ctx context.Context, scope dns.Scope) ([]dns.Record, error) {
	entries, err := p.records(ctx, scope)
	if err != nil {
		return nil, err
	}
	records := make([]dns.Record, 0, len(entries))
	for _, entry := range entries {
		records = append(records, entry.record)
	}
	return records, nil
}

// get 先用 RecordId 核验远端 zone，再以同一分页 API 完整对象复核指纹。
// 避免 Get/List 响应投影不同或 RequestId 变化制造错误版本，同时保护所有远端元数据。
func (p *aliyunProvider) get(ctx context.Context, scope dns.Scope, id string) (aliyunRecord, error) {
	if sameScope(p.scope, scope) != nil || !aliyunID(id) {
		return aliyunRecord{}, fault.New("SCOPE_INVALID", "阿里云记录查询范围无效")
	}
	data, err := p.client.aliyun(ctx, scope, "DescribeDomainRecordInfo", url.Values{"RecordId": {id}}, false)
	if err != nil {
		return aliyunRecord{}, err
	}
	var identity struct{ RecordID, DomainName string }
	if json.Unmarshal(data, &identity) != nil || identity.RecordID != id {
		return aliyunRecord{}, fault.New("PROVIDER_INVALID", "阿里云记录查询身份无效")
	}
	domain, err := names.DNS(identity.DomainName, false)
	if err != nil || domain != scope.ZoneName {
		return aliyunRecord{}, fault.New("ZONE_DENIED", "阿里云记录不属于授权 zone")
	}
	entries, err := p.records(ctx, scope)
	if err != nil {
		return aliyunRecord{}, err
	}
	for _, entry := range entries {
		if entry.record.ID == id {
			return entry, nil
		}
	}
	return aliyunRecord{}, fault.New("NOT_FOUND", "阿里云记录不存在")
}

func aliyunWriteParameters(scope dns.Scope, record dns.Record) (url.Values, error) {
	rr, err := relativeRecord(scope, record.Name)
	if err != nil {
		return nil, err
	}
	return url.Values{"RR": {rr}, "Type": {string(record.Type)}, "Value": {record.Value}, "TTL": {strconv.FormatUint(uint64(record.TTL), 10)}}, nil
}

func aliyunChangedID(data []byte, expected string) (string, error) {
	var result struct {
		RecordID string `json:"RecordId"`
	}
	if json.Unmarshal(data, &result) != nil || !aliyunID(result.RecordID) || (expected != "" && result.RecordID != expected) {
		return "", apiFailure("PROVIDER_INVALID", true, time.Time{})
	}
	return result.RecordID, nil
}

func (p *aliyunProvider) Create(ctx context.Context, scope dns.Scope, input dns.Record) (dns.Record, error) {
	if err := sameScope(p.scope, scope); err != nil {
		return dns.Record{}, err
	}
	record, err := writeRecord(scope, input, true)
	if err != nil {
		return dns.Record{}, err
	}
	parameters, err := aliyunWriteParameters(scope, record)
	if err != nil {
		return dns.Record{}, err
	}
	parameters.Set("DomainName", scope.ZoneName)
	parameters.Set("Line", "default")
	data, err := p.client.aliyun(ctx, scope, "AddDomainRecord", parameters, true)
	if err != nil {
		return dns.Record{}, err
	}
	if record.ID, err = aliyunChangedID(data, ""); err != nil {
		return dns.Record{}, err
	}
	// 阿里云新建响应只确认 ID；没有原子 remark 归属，不冒充 Cloudflare marker。
	// 返回 ID 后由 DNS Manager 先持久化，再读取完整对象确认。
	record.ManagedBy, record.Revision = "", ""
	return dns.CanonicalRecord(scope, record)
}

func (p *aliyunProvider) Update(ctx context.Context, scope dns.Scope, before, input dns.Record) (dns.Record, error) {
	record, err := writeRecord(scope, input, false)
	if err != nil || record.ID != before.ID {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "阿里云更新不能更换记录 ID")
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
	parameters, err := aliyunWriteParameters(scope, record)
	if err != nil {
		return dns.Record{}, err
	}
	parameters.Set("RecordId", before.ID)
	parameters.Set("Line", current.line)
	data, err := p.client.aliyun(ctx, scope, "UpdateDomainRecord", parameters, true)
	if err != nil {
		return dns.Record{}, err
	}
	if _, err := aliyunChangedID(data, before.ID); err != nil {
		return dns.Record{}, err
	}
	record.ManagedBy, record.Revision = "", ""
	return dns.CanonicalRecord(scope, record)
}

func (p *aliyunProvider) Delete(ctx context.Context, scope dns.Scope, before dns.Record) error {
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
	data, err := p.client.aliyun(ctx, scope, "DeleteDomainRecord", url.Values{"RecordId": {before.ID}}, true)
	if err != nil {
		return err
	}
	_, err = aliyunChangedID(data, before.ID)
	return err
}

func aliyunZones(ctx context.Context, client *apiClient) ([]Zone, error) {
	var zones []Zone
	seen := map[string]bool{}
	for page := 1; page <= 6; page++ {
		data, err := client.aliyun(ctx, dns.Scope{Kind: dns.Aliyun}, "DescribeDomains", url.Values{"PageNumber": {strconv.Itoa(page)}, "PageSize": {"50"}}, false)
		if err != nil {
			return nil, err
		}
		var result struct {
			PageNumber int `json:"PageNumber"`
			PageSize   int `json:"PageSize"`
			TotalCount int `json:"TotalCount"`
			Domains    struct {
				Domains []struct{ DomainID, DomainName string } `json:"Domain"`
			} `json:"Domains"`
		}
		if json.Unmarshal(data, &result) != nil || result.PageNumber != page || result.PageSize != 50 || result.TotalCount < 0 || result.TotalCount > maxProviderZones || len(result.Domains.Domains) > 50 {
			return nil, fault.New("PROVIDER_INVALID", "阿里云 zone 列表无效或超过上限")
		}
		for _, entry := range result.Domains.Domains {
			zone, err := canonicalZone(entry.DomainID, entry.DomainName)
			if err != nil || !aliyunZoneID(zone.ID) || seen[zone.ID] {
				return nil, fault.New("PROVIDER_INVALID", "阿里云 zone 身份重复或无效")
			}
			seen[zone.ID] = true
			zones = append(zones, zone)
		}
		if page*50 >= result.TotalCount {
			if len(zones) != result.TotalCount {
				return nil, fault.New("PROVIDER_INVALID", "阿里云 zone 列表不完整")
			}
			return zones, nil
		}
	}
	return nil, fault.New("RESOURCE_EXHAUSTED", "阿里云 zone 列表超过查询预算")
}
