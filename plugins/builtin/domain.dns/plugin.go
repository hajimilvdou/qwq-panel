// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	dnsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/dns/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 内置清单与插件生命周期 ========================

//go:embed manifest.json
var manifestJSON []byte
var buildVersion string

const providerSummaryKey = "summary/providers"

// Manifest 返回当前内置 DNS 控制器插件的嵌入清单。
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

// Plugin 实现按需拉起、无常驻后台的 DNS 托管控制器插件。
type Plugin struct {
	now func() time.Time
}

// New 构造内置 domain.dns 插件实例工厂。
func New() *Plugin {
	return &Plugin{now: time.Now}
}

func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	if err := validateConfigJSON(info.Config); err != nil {
		return nil, err
	}
	nowFn := p.now
	if nowFn == nil {
		nowFn = time.Now
	}
	inst := &instance{
		InstanceBase: pluginsdk.NewInstanceBase(info),
		now:          nowFn,
		cache:        make(map[string]cachedProvider),
	}
	inst.register()
	return inst, nil
}

type cachedProvider struct {
	Enabled   bool
	ZoneCount uint32
}

type instance struct {
	*pluginsdk.InstanceBase
	now   func() time.Time
	mu    sync.Mutex
	cache map[string]cachedProvider
}

func (i *instance) ValidateConfig(_ context.Context, cfg pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	return pluginsdk.ConfigValidation{}, validateConfigJSON(cfg.JSON)
}

func (i *instance) ApplyConfig(_ context.Context, cfg pluginsdk.Config) error {
	return validateConfigJSON(cfg.JSON)
}

func (i *instance) Health(context.Context) pluginsdk.Health {
	return pluginsdk.Health{Message: "DNS 托管能力就绪"}
}

func validateConfigJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	var cfg struct{}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "",
			Code:    "INVALID_CONFIG",
			Message: "DNS 插件配置必须是空 JSON 对象",
		})
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "",
			Code:    "INVALID_CONFIG",
			Message: "DNS 插件配置包含多余内容",
		})
	}
	return nil
}

// ======================== 请求/响应 DTO（严禁保存或输出明文凭据） ========================

type providerTargetInput struct {
	ProviderID string `json:"provider_id"`
}

type zoneTargetInput struct {
	ProviderID string `json:"provider_id"`
	ZoneID     string `json:"zone_id"`
}

type recordAttemptInput struct {
	ProviderID string `json:"provider_id"`
	ZoneID     string `json:"zone_id"`
	AttemptID  string `json:"attempt_id"`
}

type providerStatusSummary struct {
	Total     int    `json:"total"`
	Enabled   int    `json:"enabled"`
	Zones     int    `json:"zones"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type providerStatusResponse struct {
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"`
	Percent   float64   `json:"percent"`
	Sub       string    `json:"sub"`
	Level     string    `json:"level"`
	Spark     []float64 `json:"spark"`
	Total     int       `json:"total"`
	Enabled   int       `json:"enabled"`
	Zones     int       `json:"zones"`
	UpdatedAt string    `json:"updated_at,omitempty"`
}

type providerDTO struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Revision  string `json:"revision"`
	Enabled   bool   `json:"enabled"`
	ZoneCount uint32 `json:"zone_count"`
	LastError string `json:"last_error,omitempty"`
}

type zoneDTO struct {
	ProviderID string `json:"provider_id"`
	ZoneID     string `json:"zone_id"`
	Name       string `json:"name"`
	Revision   string `json:"revision"`
	Authorized bool   `json:"authorized"`
}

type recordDTO struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	Name             string `json:"name"`
	Value            string `json:"value"`
	TTL              uint32 `json:"ttl"`
	Proxied          bool   `json:"proxied"`
	Revision         string `json:"revision"`
	ManagedChallenge bool   `json:"managed_challenge"`
}

type observationDTO struct {
	Source      string   `json:"source"`
	Kind        string   `json:"kind"`
	Values      []string `json:"values"`
	CollectedAt string   `json:"collected_at"`
	ErrorCode   string   `json:"error_code,omitempty"`
}

// ======================== 11 个受控操作注册与转发 ========================

func (i *instance) register() {
	i.HandleInvoke("providers.status", i.providersStatus)
	i.HandleJob("providers.list", i.providersList)
	i.HandleJob("providers.register", i.providersRegister)
	i.HandleJob("providers.zones", i.providersZones)
	i.HandleJob("providers.revoke", i.providersRevoke)
	i.HandleJob("zones.authorize", i.zonesAuthorize)
	i.HandleJob("zones.revoke", i.zonesRevoke)
	i.HandleJob("records.list", i.recordsList)
	i.HandleJob("records.apply", i.recordsApply)
	i.HandleJob("records.reconcile", i.recordsReconcile)
	i.HandleJob("dns.check", i.dnsCheck)
}

func (i *instance) providersStatus(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	host := req.Host()
	if host == nil || host.Conn() == nil {
		return pluginsdk.Response{}, pluginsdk.ErrNoHost
	}
	raw, _, found, err := host.GetState(ctx, providerSummaryKey)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	var summary providerStatusSummary
	if found && len(raw) > 0 {
		if json.Unmarshal(raw, &summary) != nil {
			summary = providerStatusSummary{}
		}
	}
	percent := 0.0
	if summary.Total > 0 {
		percent = math.Round(float64(summary.Enabled)*1000/float64(summary.Total)) / 10
	}
	level := "ok"
	sub := "尚未同步 DNS 提供商"
	if summary.Total > 0 {
		sub = fmt.Sprintf("共 %d 个提供商，已发现 %d 个托管域", summary.Total, summary.Zones)
		if summary.Enabled == 0 {
			level = "warn"
		}
	}
	out := providerStatusResponse{
		Value:     float64(summary.Enabled),
		Unit:      "个",
		Percent:   percent,
		Sub:       sub,
		Level:     level,
		Spark:     []float64{float64(summary.Enabled)},
		Total:     summary.Total,
		Enabled:   summary.Enabled,
		Zones:     summary.Zones,
		UpdatedAt: summary.UpdatedAt,
	}
	return marshalResponse(out)
}

func (i *instance) providersList(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	client, meta, err := dnsClientReadOnly(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ListProviders(ctx, &dnsv1.ListProvidersRequest{Context: meta})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	items := make([]providerDTO, 0, len(resp.GetProviders()))
	nextCache := make(map[string]cachedProvider, len(resp.GetProviders()))
	for _, p := range resp.GetProviders() {
		dto := toProviderDTO(p)
		items = append(items, dto)
		nextCache[dto.ID] = cachedProvider{Enabled: dto.Enabled, ZoneCount: dto.ZoneCount}
	}
	i.replaceSummary(ctx, req.Host(), nextCache)
	return marshalResult(struct {
		Providers []providerDTO `json:"providers"`
	}{Providers: items})
}

func (i *instance) providersRegister(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	// 仅读取 provider_id；凭据已由宿主提前提取保护，绝不解码、记录或写入 KV。
	var in providerTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.ProviderID == "" {
		return pluginsdk.Result{}, missingFieldError("/provider_id", "缺少提供商 ID")
	}
	client, meta, err := dnsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RegisterProvider(ctx, &dnsv1.RegisterProviderRequest{
		Context:          meta,
		ProviderId:       in.ProviderID,
		ExpectedRevision: expectedRevision(req, "providers/"+in.ProviderID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	prov := toProviderDTO(resp.GetProvider())
	zones := toZoneDTOs(resp.GetZones())
	i.upsertSummary(ctx, req.Host(), prov)
	return marshalResult(struct {
		Provider providerDTO `json:"provider"`
		Zones    []zoneDTO   `json:"zones"`
	}{Provider: prov, Zones: zones})
}

func (i *instance) providersZones(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in providerTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.ProviderID == "" {
		return pluginsdk.Result{}, missingFieldError("/provider_id", "缺少提供商 ID")
	}
	client, meta, err := dnsClientReadOnly(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.DiscoverZones(ctx, &dnsv1.DiscoverZonesRequest{
		Context:    meta,
		ProviderId: in.ProviderID,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Zones []zoneDTO `json:"zones"`
	}{Zones: toZoneDTOs(resp.GetZones())})
}

func (i *instance) providersRevoke(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in providerTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.ProviderID == "" {
		return pluginsdk.Result{}, missingFieldError("/provider_id", "缺少提供商 ID")
	}
	client, meta, err := dnsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RevokeProvider(ctx, &dnsv1.RevokeProviderRequest{
		Context:          meta,
		ProviderId:       in.ProviderID,
		ExpectedRevision: expectedRevision(req, "providers/"+in.ProviderID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	prov := toProviderDTO(resp.GetProvider())
	i.upsertSummary(ctx, req.Host(), prov)
	return marshalResult(struct {
		Provider providerDTO `json:"provider"`
	}{Provider: prov})
}

func (i *instance) zonesAuthorize(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in zoneTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireZoneTarget(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := dnsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.AuthorizeZone(ctx, &dnsv1.AuthorizeZoneRequest{
		Context:          meta,
		ProviderId:       in.ProviderID,
		ZoneId:           in.ZoneID,
		ExpectedRevision: expectedRevision(req, "zones/"+in.ProviderID+"/"+in.ZoneID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Zone zoneDTO `json:"zone"`
	}{Zone: toZoneDTO(resp.GetZone())})
}

func (i *instance) zonesRevoke(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in zoneTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireZoneTarget(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := dnsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RevokeZone(ctx, &dnsv1.RevokeZoneRequest{
		Context:          meta,
		ProviderId:       in.ProviderID,
		ZoneId:           in.ZoneID,
		ExpectedRevision: expectedRevision(req, "zones/"+in.ProviderID+"/"+in.ZoneID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Zone zoneDTO `json:"zone"`
	}{Zone: toZoneDTO(resp.GetZone())})
}

func (i *instance) recordsList(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in zoneTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireZoneTarget(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := dnsClientReadOnly(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ListRecords(ctx, &dnsv1.ListRecordsRequest{
		Context:    meta,
		ProviderId: in.ProviderID,
		ZoneId:     in.ZoneID,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	records := make([]recordDTO, 0, len(resp.GetRecords()))
	for _, r := range resp.GetRecords() {
		records = append(records, toRecordDTO(r))
	}
	return marshalResult(struct {
		Revision string      `json:"revision"`
		Records  []recordDTO `json:"records"`
	}{Revision: resp.GetRevision(), Records: records})
}

func (i *instance) recordsApply(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in recordAttemptInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireRecordAttempt(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := dnsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ApplyRecord(ctx, &dnsv1.ApplyRecordRequest{
		Context:          meta,
		ProviderId:       in.ProviderID,
		ZoneId:           in.ZoneID,
		AttemptId:        in.AttemptID,
		ExpectedRevision: expectedRevision(req, "zones/"+in.ProviderID+"/"+in.ZoneID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(toRecordMutateDTO(resp.GetState(), resp.GetRevision(), resp.GetRecord()))
}

func (i *instance) recordsReconcile(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in recordAttemptInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireRecordAttempt(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := dnsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ReconcileRecord(ctx, &dnsv1.ReconcileRecordRequest{
		Context:    meta,
		ProviderId: in.ProviderID,
		ZoneId:     in.ZoneID,
		AttemptId:  in.AttemptID,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(toRecordMutateDTO(resp.GetState(), resp.GetRevision(), resp.GetRecord()))
}

func (i *instance) dnsCheck(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in zoneTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireZoneTarget(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := dnsClientReadOnly(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.CheckDns(ctx, &dnsv1.CheckDnsRequest{
		Context:    meta,
		ProviderId: in.ProviderID,
		ZoneId:     in.ZoneID,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	observations := make([]observationDTO, 0, len(resp.GetObservations()))
	for _, obs := range resp.GetObservations() {
		vals := make([]string, 0, len(obs.GetValues()))
		vals = append(vals, obs.GetValues()...)
		observations = append(observations, observationDTO{
			Source:      obs.GetSource(),
			Kind:        obs.GetKind(),
			Values:      vals,
			CollectedAt: obs.GetCollectedAt(),
			ErrorCode:   obs.GetErrorCode(),
		})
	}
	return marshalResult(struct {
		Propagated   bool             `json:"propagated"`
		RetryAt      string           `json:"retry_at,omitempty"`
		Observations []observationDTO `json:"observations"`
	}{
		Propagated:   resp.GetPropagated(),
		RetryAt:      resp.GetRetryAt(),
		Observations: observations,
	})
}

// ======================== 宿主连接、摘要缓存与错误映射辅助 ========================

func dnsClientReadOnly(ctx context.Context, req pluginsdk.Request) (dnsv1.DnsServiceClient, *platformv1.HostCallContext, error) {
	host := req.Host()
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return nil, nil, err
	}
	return dnsv1.NewDnsServiceClient(host.Conn()), meta, nil
}

func dnsClientWrite(ctx context.Context, req pluginsdk.Request) (dnsv1.DnsServiceClient, *platformv1.HostCallContext, error) {
	host := req.Host()
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return dnsv1.NewDnsServiceClient(host.Conn()), meta, nil
}

func expectedRevision(req pluginsdk.Request, subject string) string {
	if subject != "" {
		if pre, ok := req.Precondition(subject); ok {
			return pre.Revision
		}
	}
	if len(req.Preconditions) > 0 {
		return req.Preconditions[0].Revision
	}
	return ""
}

func protoError(detail *platformv1.ErrorDetail) error {
	if detail == nil || (detail.GetCode() == "" && detail.GetMessage() == "") {
		return nil
	}
	code := detail.GetCode()
	if code == "" {
		code = "INTERNAL"
	}
	return &pluginsdk.Error{
		Code:        code,
		Message:     detail.GetMessage(),
		Retryable:   detail.GetRetryable(),
		DetailsJSON: append([]byte(nil), detail.GetDetailsJson()...),
	}
}

func missingFieldError(pointer, message string) error {
	return pluginsdk.Validation(pluginsdk.FieldViolation{
		Pointer: pointer,
		Code:    "REQUIRED",
		Message: message,
	})
}

func requireZoneTarget(in zoneTargetInput) error {
	if in.ProviderID == "" {
		return missingFieldError("/provider_id", "缺少提供商 ID")
	}
	if in.ZoneID == "" {
		return missingFieldError("/zone_id", "缺少托管域 ID")
	}
	return nil
}

func requireRecordAttempt(in recordAttemptInput) error {
	if in.ProviderID == "" {
		return missingFieldError("/provider_id", "缺少提供商 ID")
	}
	if in.ZoneID == "" {
		return missingFieldError("/zone_id", "缺少托管域 ID")
	}
	if in.AttemptID == "" {
		return missingFieldError("/attempt_id", "缺少幂等 attempt_id")
	}
	return nil
}

func (i *instance) replaceSummary(ctx context.Context, host *pluginsdk.Host, next map[string]cachedProvider) {
	i.mu.Lock()
	i.cache = next
	summary := i.buildSummaryLocked()
	i.mu.Unlock()
	i.persistSummary(ctx, host, summary)
}

func (i *instance) upsertSummary(ctx context.Context, host *pluginsdk.Host, prov providerDTO) {
	if prov.ID == "" {
		return
	}
	i.mu.Lock()
	i.cache[prov.ID] = cachedProvider{Enabled: prov.Enabled, ZoneCount: prov.ZoneCount}
	summary := i.buildSummaryLocked()
	i.mu.Unlock()
	i.persistSummary(ctx, host, summary)
}

func (i *instance) buildSummaryLocked() providerStatusSummary {
	summary := providerStatusSummary{
		Total:     len(i.cache),
		UpdatedAt: i.now().UTC().Format(time.RFC3339),
	}
	for _, entry := range i.cache {
		if entry.Enabled {
			summary.Enabled++
		}
		summary.Zones += int(entry.ZoneCount)
	}
	return summary
}

func (i *instance) persistSummary(ctx context.Context, host *pluginsdk.Host, summary providerStatusSummary) {
	if host == nil || host.Conn() == nil {
		return
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		return
	}
	// 仅写入公开脱敏计数摘要，失败不影响已完成的宿主能力调用。
	_, _ = host.PutState(ctx, providerSummaryKey, raw, pluginsdk.PutOption{})
}

func toProviderDTO(p *dnsv1.ProviderView) providerDTO {
	if p == nil {
		return providerDTO{}
	}
	return providerDTO{
		ID:        p.GetId(),
		Kind:      p.GetKind(),
		Name:      p.GetName(),
		Revision:  p.GetRevision(),
		Enabled:   p.GetEnabled(),
		ZoneCount: p.GetZoneCount(),
		LastError: p.GetLastError(),
	}
}

func toZoneDTO(z *dnsv1.ZoneView) zoneDTO {
	if z == nil {
		return zoneDTO{}
	}
	return zoneDTO{
		ProviderID: z.GetProviderId(),
		ZoneID:     z.GetZoneId(),
		Name:       z.GetName(),
		Revision:   z.GetRevision(),
		Authorized: z.GetAuthorized(),
	}
}

func toZoneDTOs(zones []*dnsv1.ZoneView) []zoneDTO {
	out := make([]zoneDTO, 0, len(zones))
	for _, z := range zones {
		out = append(out, toZoneDTO(z))
	}
	return out
}

func toRecordDTO(r *dnsv1.RecordView) recordDTO {
	if r == nil {
		return recordDTO{}
	}
	return recordDTO{
		ID:               r.GetId(),
		Type:             r.GetType(),
		Name:             r.GetName(),
		Value:            r.GetValue(),
		TTL:              r.GetTtl(),
		Proxied:          r.GetProxied(),
		Revision:         r.GetRevision(),
		ManagedChallenge: r.GetManagedChallenge(),
	}
}

func toRecordMutateDTO(state, revision string, rec *dnsv1.RecordView) any {
	out := struct {
		State    string     `json:"state"`
		Revision string     `json:"revision"`
		Record   *recordDTO `json:"record,omitempty"`
	}{
		State:    state,
		Revision: revision,
	}
	if rec != nil {
		dto := toRecordDTO(rec)
		out.Record = &dto
	}
	return out
}

func marshalResponse(v any) (pluginsdk.Response, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return pluginsdk.Response{}, fmt.Errorf("encode response: %w", err)
	}
	return pluginsdk.Response{Payload: raw}, nil
}

func marshalResult(v any) (pluginsdk.Result, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return pluginsdk.Result{}, fmt.Errorf("encode result: %w", err)
	}
	return pluginsdk.Result{Payload: raw}, nil
}
