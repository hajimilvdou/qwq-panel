// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== Cloudflare REST v4 ========================

const cloudflareMarkerPrefix = "qwq:dns01:"

type cloudflareProvider struct {
	scope  dns.Scope
	client *apiClient
}

type cloudflareEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code int `json:"code"`
	} `json:"errors"`
	Info struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *apiClient) cloudflare(ctx context.Context, scope dns.Scope, method, path string, body []byte, mutation bool) (cloudflareEnvelope, error) {
	data, _, err := c.request(ctx, scope, mutation, func(credentials Credentials) (*http.Request, error) {
		request, err := http.NewRequest(method, cloudflareEndpoint+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+string(credentials.Token))
		if len(body) != 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		return request, nil
	})
	if err != nil {
		return cloudflareEnvelope{}, err
	}
	var envelope cloudflareEnvelope
	if json.Unmarshal(data, &envelope) != nil || len(envelope.Result) == 0 {
		return cloudflareEnvelope{}, apiFailure("PROVIDER_INVALID", mutation, time.Time{})
	}
	if envelope.Success && len(envelope.Errors) != 0 {
		return cloudflareEnvelope{}, apiFailure("PROVIDER_INVALID", mutation, time.Time{})
	}
	if !envelope.Success {
		code, uncertain := "PROVIDER_UNAVAILABLE", mutation
		if len(envelope.Errors) == 0 {
			return cloudflareEnvelope{}, apiFailure("PROVIDER_INVALID", mutation, time.Time{})
		}
		for _, issue := range envelope.Errors {
			switch issue.Code {
			case 10000, 9109:
				code, uncertain = "CREDENTIAL_REVOKED", false
			case 81057, 81058:
				code, uncertain = "RECORD_CONFLICT", false
			case 81044:
				code, uncertain = "NOT_FOUND", false
			default:
				return cloudflareEnvelope{}, apiFailure("PROVIDER_UNAVAILABLE", mutation, time.Time{})
			}
		}
		return cloudflareEnvelope{}, apiFailure(code, uncertain, time.Time{})
	}
	return envelope, nil
}

func cloudflareRecord(scope dns.Scope, raw json.RawMessage) (dns.Record, error) {
	var payload struct {
		ID      string         `json:"id"`
		Type    dns.RecordType `json:"type"`
		Name    string         `json:"name"`
		Content string         `json:"content"`
		TTL     uint32         `json:"ttl"`
		Proxied bool           `json:"proxied"`
		Comment string         `json:"comment"`
	}
	if json.Unmarshal(raw, &payload) != nil || !cloudflareID(payload.ID) {
		return dns.Record{}, fault.New("PROVIDER_INVALID", "Cloudflare 记录身份无效")
	}
	version, err := providerRevision(raw)
	if err != nil {
		return dns.Record{}, err
	}
	record := dns.Record{ID: payload.ID, Type: payload.Type, Name: payload.Name, Value: payload.Content, TTL: payload.TTL, Proxied: payload.Proxied, ProviderRevision: version}
	if strings.HasPrefix(payload.Comment, cloudflareMarkerPrefix) {
		marker := strings.TrimPrefix(payload.Comment, cloudflareMarkerPrefix)
		if len(marker) != 64 {
			return dns.Record{}, fault.New("PROVIDER_INVALID", "Cloudflare 宿主归属标记无效")
		}
		record.ManagedBy = marker
	}
	return dns.CanonicalRecord(scope, record)
}

func (p *cloudflareProvider) List(ctx context.Context, scope dns.Scope) ([]dns.Record, error) {
	if err := sameScope(p.scope, scope); err != nil {
		return nil, err
	}
	var records []dns.Record
	seen := map[string]bool{}
	for page := 1; page <= 41; page++ {
		result, err := p.client.cloudflare(ctx, scope, http.MethodGet, "/zones/"+scope.ZoneID+"/dns_records?per_page=100&page="+strconv.Itoa(page), nil, false)
		if err != nil {
			return nil, err
		}
		var entries []json.RawMessage
		if json.Unmarshal(result.Result, &entries) != nil || result.Info.Page != page || result.Info.Count != len(entries) || result.Info.TotalCount < 0 || result.Info.TotalCount > maxProviderRecords || len(entries) > 100 || result.Info.TotalPages > 41 {
			return nil, fault.New("PROVIDER_INVALID", "Cloudflare zone 分页无效或超过上限")
		}
		for _, entry := range entries {
			record, err := cloudflareRecord(scope, entry)
			if err != nil || seen[record.ID] {
				return nil, fault.New("PROVIDER_INVALID", "Cloudflare zone 记录无效或重复")
			}
			seen[record.ID] = true
			records = append(records, record)
		}
		if result.Info.TotalPages <= page {
			if len(records) != result.Info.TotalCount {
				return nil, fault.New("PROVIDER_INVALID", "Cloudflare zone 分页不完整")
			}
			return records, nil
		}
	}
	return nil, fault.New("RESOURCE_EXHAUSTED", "Cloudflare zone 记录超过查询预算")
}

func (p *cloudflareProvider) get(ctx context.Context, scope dns.Scope, id string) (dns.Record, error) {
	if sameScope(p.scope, scope) != nil || !cloudflareID(id) {
		return dns.Record{}, fault.New("SCOPE_INVALID", "Cloudflare 记录查询范围无效")
	}
	result, err := p.client.cloudflare(ctx, scope, http.MethodGet, "/zones/"+scope.ZoneID+"/dns_records/"+id, nil, false)
	if err != nil {
		return dns.Record{}, err
	}
	return cloudflareRecord(scope, result.Result)
}

func cloudflareWriteBody(record dns.Record) ([]byte, error) {
	comment := ""
	if record.ManagedBy != "" {
		comment = cloudflareMarkerPrefix + record.ManagedBy
	}
	return json.Marshal(struct {
		Name    string         `json:"name"`
		Type    dns.RecordType `json:"type"`
		Content string         `json:"content"`
		TTL     uint32         `json:"ttl"`
		Proxied bool           `json:"proxied"`
		Comment string         `json:"comment,omitempty"`
	}{record.Name, record.Type, record.Value, record.TTL, record.Proxied, comment})
}

func (p *cloudflareProvider) Create(ctx context.Context, scope dns.Scope, input dns.Record) (dns.Record, error) {
	if err := sameScope(p.scope, scope); err != nil {
		return dns.Record{}, err
	}
	record, err := writeRecord(scope, input, true)
	if err != nil {
		return dns.Record{}, err
	}
	body, err := cloudflareWriteBody(record)
	if err != nil {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "Cloudflare 记录无法编码")
	}
	result, err := p.client.cloudflare(ctx, scope, http.MethodPost, "/zones/"+scope.ZoneID+"/dns_records", body, true)
	if err != nil {
		return dns.Record{}, err
	}
	created, err := cloudflareRecord(scope, result.Result)
	if err != nil {
		return dns.Record{}, apiFailure("PROVIDER_INVALID", true, time.Time{})
	}
	return created, nil
}

func (p *cloudflareProvider) Update(ctx context.Context, scope dns.Scope, before, input dns.Record) (dns.Record, error) {
	record, err := writeRecord(scope, input, false)
	if err != nil || record.ID != before.ID {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "Cloudflare 更新不能更换记录 ID")
	}
	current, err := p.get(ctx, scope, before.ID)
	if err != nil {
		return dns.Record{}, err
	}
	if err := compareRecord(current, before); err != nil {
		return dns.Record{}, err
	}
	if !current.Type.Supported() {
		return dns.Record{}, notSent(fault.New("VALIDATION_FAILED", "此 DNS 记录类型不能修改"))
	}
	body, err := cloudflareWriteBody(record)
	if err != nil {
		return dns.Record{}, fault.New("VALIDATION_FAILED", "Cloudflare 记录无法编码")
	}
	result, err := p.client.cloudflare(ctx, scope, http.MethodPatch, "/zones/"+scope.ZoneID+"/dns_records/"+before.ID, body, true)
	if err != nil {
		return dns.Record{}, err
	}
	updated, err := cloudflareRecord(scope, result.Result)
	if err != nil || updated.ID != before.ID {
		return dns.Record{}, apiFailure("PROVIDER_INVALID", true, time.Time{})
	}
	return updated, nil
}

func (p *cloudflareProvider) Delete(ctx context.Context, scope dns.Scope, before dns.Record) error {
	current, err := p.get(ctx, scope, before.ID)
	if err != nil {
		return err
	}
	if err := compareRecord(current, before); err != nil {
		return err
	}
	if !current.Type.Supported() {
		return fault.New("VALIDATION_FAILED", "此 DNS 记录类型不能删除")
	}
	result, err := p.client.cloudflare(ctx, scope, http.MethodDelete, "/zones/"+scope.ZoneID+"/dns_records/"+before.ID, nil, true)
	if err != nil {
		return err
	}
	var deleted struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(result.Result, &deleted) != nil || deleted.ID != before.ID {
		return apiFailure("PROVIDER_INVALID", true, time.Time{})
	}
	return nil
}

func cloudflareZones(ctx context.Context, client *apiClient) ([]Zone, error) {
	var zones []Zone
	seen := map[string]bool{}
	for page := 1; page <= 6; page++ {
		result, err := client.cloudflare(ctx, dns.Scope{Kind: dns.Cloudflare}, http.MethodGet, "/zones?status=active&per_page=50&page="+strconv.Itoa(page), nil, false)
		if err != nil {
			return nil, err
		}
		var entries []struct{ ID, Name string }
		if json.Unmarshal(result.Result, &entries) != nil || result.Info.Page != page || result.Info.Count != len(entries) || len(entries) > 50 || result.Info.TotalCount > maxProviderZones {
			return nil, fault.New("PROVIDER_INVALID", "Cloudflare zone 列表无效或超过上限")
		}
		for _, entry := range entries {
			zone, err := canonicalZone(entry.ID, entry.Name)
			if err != nil || !cloudflareID(zone.ID) || seen[zone.ID] {
				return nil, fault.New("PROVIDER_INVALID", "Cloudflare zone 身份重复或无效")
			}
			seen[zone.ID] = true
			zones = append(zones, zone)
		}
		if result.Info.TotalPages <= page {
			if len(zones) != result.Info.TotalCount {
				return nil, fault.New("PROVIDER_INVALID", "Cloudflare zone 列表不完整")
			}
			return zones, nil
		}
	}
	return nil, fault.New("RESOURCE_EXHAUSTED", "Cloudflare zone 列表超过查询预算")
}
