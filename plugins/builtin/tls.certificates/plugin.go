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
	"strings"
	"time"

	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 内置清单与插件生命周期 ========================

//go:embed manifest.json
var manifestJSON []byte
var buildVersion string

const (
	certificateSummaryKey = "summary/certificates"
	defaultPollInterval   = 500 * time.Millisecond
	cancelTaskTimeout     = 5 * time.Second
)

// Manifest 返回当前内置 TLS 证书控制器插件的嵌入清单。
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

// Plugin 实现按需启动、无常驻后台的 TLS 证书控制器插件。
type Plugin struct {
	now          func() time.Time
	pollInterval time.Duration
}

// New 构造内置 tls.certificates 插件实例工厂。
func New() *Plugin {
	return &Plugin{now: time.Now, pollInterval: defaultPollInterval}
}

func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	if err := validateConfigJSON(info.Config); err != nil {
		return nil, err
	}
	nowFn := p.now
	if nowFn == nil {
		nowFn = time.Now
	}
	poll := p.pollInterval
	if poll <= 0 {
		poll = defaultPollInterval
	}
	inst := &instance{
		InstanceBase: pluginsdk.NewInstanceBase(info),
		now:          nowFn,
		pollInterval: poll,
	}
	inst.register()
	return inst, nil
}

type instance struct {
	*pluginsdk.InstanceBase
	now          func() time.Time
	pollInterval time.Duration
}

func (i *instance) ValidateConfig(_ context.Context, cfg pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	return pluginsdk.ConfigValidation{}, validateConfigJSON(cfg.JSON)
}

func (i *instance) ApplyConfig(_ context.Context, cfg pluginsdk.Config) error {
	return validateConfigJSON(cfg.JSON)
}

func (i *instance) Health(context.Context) pluginsdk.Health {
	return pluginsdk.Health{Message: "TLS 证书能力就绪"}
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
			Message: "TLS 证书插件配置必须是空 JSON 对象",
		})
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "",
			Code:    "INVALID_CONFIG",
			Message: "TLS 证书插件配置包含多余内容",
		})
	}
	return nil
}

// ======================== 请求/响应 DTO（严禁解码、缓存或输出私钥材料） ========================

type certificateIDInput struct {
	CertificateID string `json:"certificate_id"`
}

type certificateTaskInput struct {
	CertificateID string `json:"certificate_id"`
	AttemptID     string `json:"attempt_id"`
}

type bindingTargetInput struct {
	CertificateID string `json:"certificate_id"`
	BindingRef    string `json:"binding_ref"`
}

type renewalTargetInput struct {
	PolicyID      string `json:"policy_id"`
	CertificateID string `json:"certificate_id"`
}

type certificateSummaryCache struct {
	Total     int    `json:"total"`
	Ready     int    `json:"ready"`
	Attention int    `json:"attention"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type certificateSummaryResponse struct {
	Value     float64   `json:"value"`
	Unit      string    `json:"unit"`
	Percent   float64   `json:"percent"`
	Sub       string    `json:"sub"`
	Level     string    `json:"level"`
	Spark     []float64 `json:"spark"`
	Total     int       `json:"total"`
	Ready     int       `json:"ready"`
	Attention int       `json:"attention"`
	UpdatedAt string    `json:"updated_at,omitempty"`
}

type generationDTO struct {
	Number      uint64 `json:"number"`
	Fingerprint string `json:"fingerprint"`
	Issuer      string `json:"issuer"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	Trust       string `json:"trust"`
}

type bindingDTO struct {
	BindingRef         string `json:"binding_ref"`
	PluginID           string `json:"plugin_id"`
	ProfileID          string `json:"profile_id"`
	NodeID             string `json:"node_id"`
	ServerName         string `json:"server_name"`
	Purpose            string `json:"purpose"`
	Generation         uint64 `json:"generation"`
	RunningGeneration  uint64 `json:"running_generation"`
	PolicyRevision     string `json:"policy_revision"`
	Status             string `json:"status"`
	PreviousGeneration uint64 `json:"previous_generation,omitempty"`
}

type certificateDTO struct {
	ID               string          `json:"id"`
	Revision         string          `json:"revision"`
	SANs             []string        `json:"sans"`
	Purpose          string          `json:"purpose"`
	Status           string          `json:"status"`
	LatestGeneration uint64          `json:"latest_generation"`
	Generations      []generationDTO `json:"generations"`
	Bindings         []bindingDTO    `json:"bindings"`
}

type taskDTO struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	Status        string `json:"status"`
	Stage         string `json:"stage"`
	Percent       uint32 `json:"percent"`
	ErrorCode     string `json:"error_code,omitempty"`
	RetryAt       string `json:"retry_at,omitempty"`
	Revision      string `json:"revision"`
}

type taskResultDTO struct {
	Task        taskDTO         `json:"task"`
	Certificate *certificateDTO `json:"certificate,omitempty"`
}

type renewalDTO struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	Revision      string `json:"revision"`
	Enabled       bool   `json:"enabled"`
	Status        string `json:"status"`
	NextAt        string `json:"next_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	Attempts      uint32 `json:"attempts"`
	LastError     string `json:"last_error,omitempty"`
	Alert         string `json:"alert,omitempty"`
}

// ======================== 16 个受控操作注册与宿主能力转发 ========================

func (i *instance) register() {
	i.HandleInvoke("certificates.summary", i.certificatesSummary)
	i.HandleJob("certificates.list", i.certificatesList)
	i.HandleJob("certificates.get", i.certificatesGet)
	i.HandleJob("certificates.issue", i.certificatesIssue)
	i.HandleJob("certificates.import", i.certificatesImport)
	i.HandleJob("certificates.test", i.certificatesTest)
	i.HandleJob("bindings.bind", i.bindingsBind)
	i.HandleJob("bindings.deploy", i.bindingsDeploy)
	i.HandleJob("bindings.rollback", i.bindingsRollback)
	i.HandleJob("bindings.unbind", i.bindingsUnbind)
	i.HandleJob("generations.remove", i.generationsRemove)
	i.HandleJob("certificates.remove", i.certificatesRemove)
	i.HandleJob("renewal.configure", i.renewalConfigure)
	i.HandleJob("renewal.revoke", i.renewalRevoke)
	i.HandleJob("renewal.get", i.renewalGet)
	i.HandleJob("renew_existing", i.renewExisting)
}

func (i *instance) certificatesSummary(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	host := req.Host()
	if host == nil || host.Conn() == nil {
		return pluginsdk.Response{}, pluginsdk.ErrNoHost
	}
	raw, _, found, err := host.GetState(ctx, certificateSummaryKey)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	var cache certificateSummaryCache
	if found && len(raw) > 0 {
		if json.Unmarshal(raw, &cache) != nil {
			cache = certificateSummaryCache{}
		}
	}
	percent := 0.0
	if cache.Total > 0 {
		percent = math.Round(float64(cache.Ready)*1000/float64(cache.Total)) / 10
	}
	level := "ok"
	sub := "尚未同步证书状态"
	if cache.Total > 0 {
		sub = fmt.Sprintf("共 %d 张证书，%d 张待处理", cache.Total, cache.Attention)
		if cache.Attention > 0 {
			level = "warn"
		}
	}
	return marshalResponse(certificateSummaryResponse{
		Value:     float64(cache.Ready),
		Unit:      "张",
		Percent:   percent,
		Sub:       sub,
		Level:     level,
		Spark:     []float64{float64(cache.Ready)},
		Total:     cache.Total,
		Ready:     cache.Ready,
		Attention: cache.Attention,
		UpdatedAt: cache.UpdatedAt,
	})
}

func (i *instance) certificatesList(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	client, meta, err := certsClientReadOnly(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ListCertificates(ctx, &certificatesv1.ListCertificatesRequest{Context: meta})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	items := make([]certificateDTO, 0, len(resp.GetCertificates()))
	summary := certificateSummaryCache{
		Total:     len(resp.GetCertificates()),
		UpdatedAt: i.now().UTC().Format(time.RFC3339),
	}
	for _, c := range resp.GetCertificates() {
		dto := toCertificateDTO(c)
		items = append(items, dto)
		if dto.Status == "ready" {
			summary.Ready++
		} else {
			summary.Attention++
		}
	}
	i.persistSummary(ctx, req.Host(), summary)
	return marshalResult(struct {
		Certificates []certificateDTO `json:"certificates"`
	}{Certificates: items})
}

func (i *instance) certificatesGet(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in certificateIDInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.CertificateID == "" {
		return pluginsdk.Result{}, missingFieldError("/certificate_id", "缺少证书资源 ID")
	}
	client, meta, err := certsClientReadOnly(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.GetCertificate(ctx, &certificatesv1.GetCertificateRequest{
		Context:       meta,
		CertificateId: in.CertificateID,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Certificate certificateDTO `json:"certificate"`
	}{Certificate: toCertificateDTO(resp.GetCertificate())})
}

func (i *instance) certificatesIssue(ctx context.Context, req pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	var in certificateTaskInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireTaskInput(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.SubmitIssue(ctx, &certificatesv1.SubmitIssueRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		AttemptId:        in.AttemptID,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	out, err := i.awaitTask(ctx, req, client, resp.GetTask(), progress)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(out)
}

func (i *instance) certificatesImport(ctx context.Context, req pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	// 仅解码资源 ID 与 attempt_id；私钥已由宿主提前提取保护，插件不触碰明文。
	var in certificateTaskInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireTaskInput(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.SubmitImport(ctx, &certificatesv1.SubmitImportRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		AttemptId:        in.AttemptID,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	out, err := i.awaitTask(ctx, req, client, resp.GetTask(), progress)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(out)
}

func (i *instance) certificatesTest(ctx context.Context, req pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	var in certificateTaskInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireTaskInput(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.SubmitTestCertificate(ctx, &certificatesv1.SubmitTestCertificateRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		AttemptId:        in.AttemptID,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	out, err := i.awaitTask(ctx, req, client, resp.GetTask(), progress)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(out)
}

func (i *instance) bindingsBind(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in bindingTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.CertificateID == "" {
		return pluginsdk.Result{}, missingFieldError("/certificate_id", "缺少证书资源 ID")
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.BindCertificate(ctx, &certificatesv1.BindCertificateRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Certificate certificateDTO `json:"certificate"`
	}{Certificate: toCertificateDTO(resp.GetCertificate())})
}

func (i *instance) bindingsDeploy(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in bindingTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireBindingTarget(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.DeployBinding(ctx, &certificatesv1.DeployBindingRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		BindingRef:       in.BindingRef,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Certificate certificateDTO `json:"certificate"`
	}{Certificate: toCertificateDTO(resp.GetCertificate())})
}

func (i *instance) bindingsRollback(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in bindingTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireBindingTarget(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RollbackBinding(ctx, &certificatesv1.RollbackBindingRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		BindingRef:       in.BindingRef,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Certificate certificateDTO `json:"certificate"`
	}{Certificate: toCertificateDTO(resp.GetCertificate())})
}

func (i *instance) bindingsUnbind(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in bindingTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := requireBindingTarget(in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.UnbindCertificate(ctx, &certificatesv1.UnbindCertificateRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		BindingRef:       in.BindingRef,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Certificate certificateDTO `json:"certificate"`
	}{Certificate: toCertificateDTO(resp.GetCertificate())})
}

func (i *instance) generationsRemove(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in certificateIDInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.CertificateID == "" {
		return pluginsdk.Result{}, missingFieldError("/certificate_id", "缺少证书资源 ID")
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RemoveGeneration(ctx, &certificatesv1.RemoveGenerationRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Certificate certificateDTO `json:"certificate"`
	}{Certificate: toCertificateDTO(resp.GetCertificate())})
}

func (i *instance) certificatesRemove(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in certificateIDInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.CertificateID == "" {
		return pluginsdk.Result{}, missingFieldError("/certificate_id", "缺少证书资源 ID")
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RemoveCertificate(ctx, &certificatesv1.RemoveCertificateRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		ExpectedRevision: expectedRevision(req, "certificates/"+in.CertificateID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		CertificateID string `json:"certificate_id"`
		Removed       bool   `json:"removed"`
	}{CertificateID: in.CertificateID, Removed: true})
}

func (i *instance) renewalConfigure(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in renewalTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.PolicyID == "" {
		return pluginsdk.Result{}, missingFieldError("/policy_id", "缺少续期策略 ID")
	}
	if in.CertificateID == "" {
		return pluginsdk.Result{}, missingFieldError("/certificate_id", "缺少证书资源 ID")
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ConfigureRenewal(ctx, &certificatesv1.ConfigureRenewalRequest{
		Context:          meta,
		CertificateId:    in.CertificateID,
		ExpectedRevision: expectedRevision(req, "policies/"+in.PolicyID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Renewal renewalDTO `json:"renewal"`
	}{Renewal: toRenewalDTO(resp.GetRenewal())})
}

func (i *instance) renewalRevoke(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in renewalTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.PolicyID == "" {
		return pluginsdk.Result{}, missingFieldError("/policy_id", "缺少续期策略 ID")
	}
	client, meta, err := certsClientWrite(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RevokeRenewal(ctx, &certificatesv1.RevokeRenewalRequest{
		Context:          meta,
		PolicyId:         in.PolicyID,
		ExpectedRevision: expectedRevision(req, "policies/"+in.PolicyID),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Renewal renewalDTO `json:"renewal"`
	}{Renewal: toRenewalDTO(resp.GetRenewal())})
}

func (i *instance) renewalGet(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in renewalTargetInput
	if err := req.Decode(&in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.CertificateID == "" {
		return pluginsdk.Result{}, missingFieldError("/certificate_id", "缺少证书资源 ID")
	}
	client, meta, err := certsClientReadOnly(ctx, req)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.GetRenewal(ctx, &certificatesv1.GetRenewalRequest{
		Context:       meta,
		CertificateId: in.CertificateID,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(struct {
		Renewal renewalDTO `json:"renewal"`
	}{Renewal: toRenewalDTO(resp.GetRenewal())})
}

func (i *instance) renewExisting(_ context.Context, _ pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	return pluginsdk.Result{}, &pluginsdk.Error{
		Code:    "HOST_MANAGED",
		Message: "既有证书自动续期由宿主受控调度器内部执行，不接受直接插件调用",
	}
}

// ======================== 长任务轮询、进度上报与取消联动 CancelTask ========================

func (i *instance) awaitTask(
	ctx context.Context,
	req pluginsdk.Request,
	client certificatesv1.CertificatesServiceClient,
	task *certificatesv1.TaskView,
	progress pluginsdk.Progress,
) (taskResultDTO, error) {
	if task == nil || task.GetId() == "" {
		return taskResultDTO{}, &pluginsdk.Error{Code: "INVALID_RESPONSE", Message: "宿主未返回有效任务标识"}
	}
	lastStage, lastPercent := "", uint32(0)
	emit := func(t *certificatesv1.TaskView) error {
		if progress == nil || t == nil {
			return nil
		}
		if t.GetStage() == lastStage && t.GetPercent() == lastPercent && lastStage != "" {
			return nil
		}
		lastStage, lastPercent = t.GetStage(), t.GetPercent()
		return progress(pluginsdk.ProgressUpdate{
			Percent: clampPercent(t.GetPercent()),
			Step:    t.GetStage(),
			Message: taskStageMessage(t.GetStage()),
		})
	}

	if isTaskActive(task.GetStatus()) {
		if err := emit(task); err != nil {
			cancelHostTask(ctx, req.Host(), client, task.GetId())
			return taskResultDTO{}, err
		}
	}

	for isTaskActive(task.GetStatus()) {
		timer := time.NewTimer(i.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			cancelHostTask(ctx, req.Host(), client, task.GetId())
			return taskResultDTO{}, ctx.Err()
		case <-timer.C:
		}
		roMeta, err := req.Host().CapabilityContextReadOnly(ctx)
		if err != nil {
			if ctx.Err() != nil {
				cancelHostTask(ctx, req.Host(), client, task.GetId())
			}
			return taskResultDTO{}, err
		}
		getResp, err := client.GetTask(ctx, &certificatesv1.GetTaskRequest{
			Context: roMeta,
			TaskId:  task.GetId(),
		})
		if err != nil {
			if ctx.Err() != nil {
				cancelHostTask(ctx, req.Host(), client, task.GetId())
			}
			return taskResultDTO{}, err
		}
		if err := protoError(getResp.GetError()); err != nil {
			return taskResultDTO{}, err
		}
		if getResp.GetTask() == nil {
			return taskResultDTO{}, &pluginsdk.Error{Code: "INVALID_RESPONSE", Message: "宿主任务查询未返回状态"}
		}
		task = getResp.GetTask()
		if isTaskActive(task.GetStatus()) {
			if err := emit(task); err != nil {
				cancelHostTask(ctx, req.Host(), client, task.GetId())
				return taskResultDTO{}, err
			}
		}
	}

	if task.GetStatus() != "succeeded" {
		code := task.GetErrorCode()
		if code == "" {
			code = strings.ToUpper(task.GetStatus())
			if code == "" {
				code = "TASK_FAILED"
			}
		}
		return taskResultDTO{}, &pluginsdk.Error{
			Code:      code,
			Message:   taskFailureMessage(task.GetStatus(), task.GetStage()),
			Retryable: task.GetRetryAt() != "",
		}
	}

	result := taskResultDTO{Task: toTaskDTO(task)}
	// 任务成功后尽力附带最新证书公开视图；若读取失败不覆盖成功结果。
	if certID := task.GetCertificateId(); certID != "" {
		if roMeta, err := req.Host().CapabilityContextReadOnly(ctx); err == nil {
			if certResp, err := client.GetCertificate(ctx, &certificatesv1.GetCertificateRequest{
				Context:       roMeta,
				CertificateId: certID,
			}); err == nil && protoError(certResp.GetError()) == nil && certResp.GetCertificate() != nil {
				dto := toCertificateDTO(certResp.GetCertificate())
				result.Certificate = &dto
			}
		}
	}
	return result, nil
}

// cancelHostTask 使用脱离外层取消的 5 秒独立上下文通知宿主取消任务，触发 30 秒 DNS-01 TXT 清理窗口。
func cancelHostTask(parent context.Context, host *pluginsdk.Host, client certificatesv1.CertificatesServiceClient, taskID string) {
	if host == nil || host.Conn() == nil || taskID == "" {
		return
	}
	cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), cancelTaskTimeout)
	defer cancel()
	meta, err := host.CapabilityContext(cancelCtx)
	if err != nil {
		return
	}
	_, _ = client.CancelTask(cancelCtx, &certificatesv1.CancelTaskRequest{
		Context: meta,
		TaskId:  taskID,
	})
}

func isTaskActive(status string) bool {
	return status == "queued" || status == "running"
}

func clampPercent(p uint32) uint32 {
	if p > 99 {
		return 99
	}
	return p
}

func taskStageMessage(stage string) string {
	switch stage {
	case "queued":
		return "任务已入队等待宿主调度"
	case "starting":
		return "正在初始化证书任务"
	case "validating":
		return "正在校验域名与证书规格"
	case "authorizing":
		return "正在核验受控授权与 CA 订单"
	case "generating_key":
		return "正在宿主加密库生成私钥"
	case "publishing_dns":
		return "正在发布 DNS-01 TXT 校验记录"
	case "waiting_dns":
		return "正在等待 DNS-01 解析传播生效"
	case "verifying":
		return "正在等待受控 CA 完成挑战验证"
	case "issuing":
		return "正在签发并下载证书链"
	case "validating_certificate":
		return "正在校验叶证书与私钥配对"
	case "persisting_generation":
		return "正在写入宿主加密材料库"
	case "cleaning_dns":
		return "正在清理临时 DNS-01 TXT 记录"
	case "deploying":
		return "正在部署并验证消费者证书"
	case "completed":
		return "证书任务已完成"
	default:
		return "正在执行证书任务"
	}
}

func taskFailureMessage(status, stage string) string {
	switch status {
	case "cancelled":
		return "证书任务已取消并触发宿主清理"
	case "outcome_unknown":
		return "证书任务结果未确认，请使用同一 attempt_id 重试或对账"
	default:
		if stage != "" {
			return fmt.Sprintf("证书任务在阶段 %s 失败", stage)
		}
		return "证书任务执行失败"
	}
}

// ======================== 宿主连接、DTO 转换与错误映射辅助 ========================

func certsClientReadOnly(ctx context.Context, req pluginsdk.Request) (certificatesv1.CertificatesServiceClient, *platformv1.HostCallContext, error) {
	host := req.Host()
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return nil, nil, err
	}
	return certificatesv1.NewCertificatesServiceClient(host.Conn()), meta, nil
}

func certsClientWrite(ctx context.Context, req pluginsdk.Request) (certificatesv1.CertificatesServiceClient, *platformv1.HostCallContext, error) {
	host := req.Host()
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return certificatesv1.NewCertificatesServiceClient(host.Conn()), meta, nil
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

func requireTaskInput(in certificateTaskInput) error {
	if in.CertificateID == "" {
		return missingFieldError("/certificate_id", "缺少证书资源 ID")
	}
	if in.AttemptID == "" {
		return missingFieldError("/attempt_id", "缺少幂等 attempt_id")
	}
	return nil
}

func requireBindingTarget(in bindingTargetInput) error {
	if in.CertificateID == "" {
		return missingFieldError("/certificate_id", "缺少证书资源 ID")
	}
	if in.BindingRef == "" {
		return missingFieldError("/binding_ref", "缺少绑定引用 ID")
	}
	return nil
}

func (i *instance) persistSummary(ctx context.Context, host *pluginsdk.Host, summary certificateSummaryCache) {
	if host == nil || host.Conn() == nil {
		return
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		return
	}
	// 仅写入公开脱敏计数摘要，失败不影响已完成的宿主只读查询。
	_, _ = host.PutState(ctx, certificateSummaryKey, raw, pluginsdk.PutOption{})
}

func toCertificateDTO(c *certificatesv1.CertificateView) certificateDTO {
	if c == nil {
		return certificateDTO{
			SANs:        []string{},
			Generations: []generationDTO{},
			Bindings:    []bindingDTO{},
		}
	}
	sans := make([]string, 0, len(c.GetSans()))
	sans = append(sans, c.GetSans()...)
	gens := make([]generationDTO, 0, len(c.GetGenerations()))
	for _, g := range c.GetGenerations() {
		gens = append(gens, generationDTO{
			Number:      g.GetNumber(),
			Fingerprint: g.GetFingerprint(),
			Issuer:      g.GetIssuer(),
			NotBefore:   g.GetNotBefore(),
			NotAfter:    g.GetNotAfter(),
			Trust:       g.GetTrust(),
		})
	}
	bindings := make([]bindingDTO, 0, len(c.GetBindings()))
	for _, b := range c.GetBindings() {
		bindings = append(bindings, bindingDTO{
			BindingRef:         b.GetBindingRef(),
			PluginID:           b.GetPluginId(),
			ProfileID:          b.GetProfileId(),
			NodeID:             b.GetNodeId(),
			ServerName:         b.GetServerName(),
			Purpose:            b.GetPurpose(),
			Generation:         b.GetGeneration(),
			RunningGeneration:  b.GetRunningGeneration(),
			PolicyRevision:     b.GetPolicyRevision(),
			Status:             b.GetStatus(),
			PreviousGeneration: b.GetPreviousGeneration(),
		})
	}
	return certificateDTO{
		ID:               c.GetId(),
		Revision:         c.GetRevision(),
		SANs:             sans,
		Purpose:          c.GetPurpose(),
		Status:           c.GetStatus(),
		LatestGeneration: c.GetLatestGeneration(),
		Generations:      gens,
		Bindings:         bindings,
	}
}

func toTaskDTO(t *certificatesv1.TaskView) taskDTO {
	if t == nil {
		return taskDTO{}
	}
	return taskDTO{
		ID:            t.GetId(),
		CertificateID: t.GetCertificateId(),
		Status:        t.GetStatus(),
		Stage:         t.GetStage(),
		Percent:       t.GetPercent(),
		ErrorCode:     t.GetErrorCode(),
		RetryAt:       t.GetRetryAt(),
		Revision:      t.GetRevision(),
	}
}

func toRenewalDTO(r *certificatesv1.RenewalView) renewalDTO {
	if r == nil {
		return renewalDTO{}
	}
	return renewalDTO{
		ID:            r.GetId(),
		CertificateID: r.GetCertificateId(),
		Revision:      r.GetRevision(),
		Enabled:       r.GetEnabled(),
		Status:        r.GetStatus(),
		NextAt:        r.GetNextAt(),
		ExpiresAt:     r.GetExpiresAt(),
		Attempts:      r.GetAttempts(),
		LastError:     r.GetLastError(),
		Alert:         r.GetAlert(),
	}
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
