// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// ======================== 宿主固定能力路由；不从RPC构造actor或范围 ========================

type ForwardOptions struct {
	Authority       *hostauth.Authority
	DNS             *dns.Manager
	Checker         *dns.Checker
	Certificates    *certificates.Manager
	Renewals        *certificates.RenewalService
	Views           hostsvc.StateStore
	TaskRepository  store.Repository
	Clock           clock.Clock
	MaxJobs         int
	MonitorInterval time.Duration
}

type Forwarder struct {
	authority *hostauth.Authority
	dns       *dns.Manager
	checker   *dns.Checker
	certs     *certificates.Manager
	renewals  *certificates.RenewalService
	views     hostsvc.StateStore
	tasks     *Tasks
	clock     clock.Clock
}

func NewForwarder(options ForwardOptions) (*Forwarder, error) {
	if options.Authority == nil || options.DNS == nil || options.Checker == nil || options.Certificates == nil ||
		options.Renewals == nil || options.Views == nil || options.TaskRepository == nil {
		return nil, fault.New("BACKEND_REQUIRED", "准备能力需要真实授权、执行器、解析、公开目录和续期后端")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	forwarder := &Forwarder{authority: options.Authority, dns: options.DNS, checker: options.Checker, certs: options.Certificates,
		renewals: options.Renewals, views: options.Views, clock: options.Clock}
	var err error
	forwarder.tasks, err = NewTasks(TaskOptions{Authority: options.Authority, Repository: options.TaskRepository, Executor: forwarder,
		Clock: options.Clock, MaxJobs: options.MaxJobs, MonitorInterval: options.MonitorInterval})
	if err != nil {
		return nil, err
	}
	return forwarder, nil
}

type methodRoute struct {
	plugin     string
	operation  string
	capability string
	write      bool
}

var methodRoutes = map[string]methodRoute{
	"dns/RegisterProvider":               {"domain.dns", "providers.register", "system.dns.manage", true},
	"dns/ListProviders":                  {"domain.dns", "providers.list", "dns.read", false},
	"dns/DiscoverZones":                  {"domain.dns", "providers.zones", "dns.read", false},
	"dns/RevokeProvider":                 {"domain.dns", "providers.revoke", "system.dns.manage", true},
	"dns/AuthorizeZone":                  {"domain.dns", "zones.authorize", "system.dns.manage", true},
	"dns/RevokeZone":                     {"domain.dns", "zones.revoke", "system.dns.manage", true},
	"dns/ListRecords":                    {"domain.dns", "records.list", "dns.read", false},
	"dns/ApplyRecord":                    {"domain.dns", "records.apply", "system.dns.manage", true},
	"dns/ReconcileRecord":                {"domain.dns", "records.reconcile", "system.dns.manage", true},
	"dns/CheckDns":                       {"domain.dns", "dns.check", "dns.read", false},
	"certificates/ListCertificates":      {"tls.certificates", "certificates.list", "certificates.read", false},
	"certificates/GetCertificate":        {"tls.certificates", "certificates.get", "certificates.read", false},
	"certificates/SubmitIssue":           {"tls.certificates", "certificates.issue", "system.certificates.manage", true},
	"certificates/SubmitImport":          {"tls.certificates", "certificates.import", "system.certificates.manage", true},
	"certificates/SubmitTestCertificate": {"tls.certificates", "certificates.test", "system.certificates.manage", true},
	"certificates/GetTask":               {"tls.certificates", "tasks.get", "certificates.read", false},
	"certificates/CancelTask":            {"tls.certificates", "tasks.cancel", "system.certificates.manage", true},
	"certificates/ReserveBinding":        {"tls.certificates", "bindings.reserve", "system.certificates.manage", true},
	"certificates/BindCertificate":       {"tls.certificates", "bindings.bind", "system.certificates.manage", true},
	"certificates/UnbindCertificate":     {"tls.certificates", "bindings.unbind", "system.certificates.manage", true},
	"certificates/DeployBinding":         {"tls.certificates", "bindings.deploy", "system.certificates.manage", true},
	"certificates/RollbackBinding":       {"tls.certificates", "bindings.rollback", "system.certificates.manage", true},
	"certificates/RemoveGeneration":      {"tls.certificates", "generations.remove", "system.certificates.manage", true},
	"certificates/RemoveCertificate":     {"tls.certificates", "certificates.remove", "system.certificates.manage", true},
	"certificates/ConfigureRenewal":      {"tls.certificates", "renewal.configure", "system.certificates.manage", true},
	"certificates/RevokeRenewal":         {"tls.certificates", "renewal.revoke", "system.certificates.manage", true},
	"certificates/GetRenewal":            {"tls.certificates", "renewal.get", "certificates.read", false},
}

type contextualRequest interface {
	proto.Message
	GetContext() *platformv1.HostCallContext
}

// Forward按强类型RPC和宿主固定表校验身份、方法、效果及真实operation。
func (f *Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if f == nil || ctx == nil || call.Request == nil || !call.Request.ProtoReflect().IsValid() {
		return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "准备能力请求无效")
	}
	route, found := methodRoutes[call.Service+"/"+call.Method]
	request, contextual := call.Request.(contextualRequest)
	if !found || !contextual || request.GetContext() == nil || call.PluginID != route.plugin || call.InstanceID != "default" ||
		call.Verb != call.Service+"."+call.Method || call.Capability != route.capability || call.Write != route.write || call.Scope != "self" ||
		request.GetContext().GetOperationId() != call.OperationID || len(call.Request.ProtoReflect().GetUnknown()) != 0 {
		return hostsvc.CapabilityResult{}, status.Error(codes.PermissionDenied, "RPC方法或宿主派发元数据不符")
	}
	bound, release, err := f.authority.BeginCapability(ctx, hostauth.Invocation{PluginID: call.PluginID, InstanceID: call.InstanceID, OperationID: call.OperationID}, route.operation)
	if err != nil {
		return hostsvc.CapabilityResult{}, f.admissionError(err)
	}
	defer release()
	var response proto.Message
	if call.Service == "dns" {
		response, err = f.forwardDNS(bound, call.Method, call.Request)
	} else {
		response, err = f.forwardCertificates(bound, call.Method, call.Request)
	}
	if response == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "固定RPC没有强类型响应")
	}
	result := hostsvc.CapabilityResult{Response: response}
	if err != nil {
		code, retry := taskFailure(err, f.clock.Now())
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			code = "CANCELLED"
		}
		detail := []byte(nil)
		if !retry.IsZero() {
			detail, _ = json.Marshal(map[string]string{"retry_at": retry.UTC().Format(time.RFC3339Nano)})
		}
		result.Error = &hostsvc.DomainError{Code: code, Message: "准备操作未完成，请核对当前权限、版本和错误码", Retryable: !retry.IsZero(), DetailsJSON: detail}
	}
	return result, nil
}

// admissionError 保留稳定的宿主错误类别，具体原因不跨RPC泄露。
func (f *Forwarder) admissionError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	code, _ := taskFailure(err, f.clock.Now())
	grpcCode := codes.FailedPrecondition
	switch code {
	case "PERMISSION_DENIED", "POLICY_SCOPE_DENIED", "AUTHENTICATION_REQUIRED", "FORBIDDEN":
		grpcCode = codes.PermissionDenied
	case "NOT_FOUND":
		grpcCode = codes.NotFound
	case "VALIDATION_FAILED", "INVALID_ARGUMENT":
		grpcCode = codes.InvalidArgument
	case "RESOURCE_EXHAUSTED", "RATE_LIMITED":
		grpcCode = codes.ResourceExhausted
	case "BACKEND_REQUIRED", "STATE_UNAVAILABLE", "AUDIT_UNAVAILABLE":
		grpcCode = codes.Unavailable
	case "INTERNAL":
		grpcCode = codes.Internal
	}
	return status.Error(grpcCode, "准备调用未获准，请核对当前原操作与权限")
}

// RunTask只从原CertificateContext构造请求，并调用实际Manager。
func (f *Forwarder) RunTask(ctx context.Context, kind TaskKind, id, attempt, expected string, progress certificates.Progress) (certificates.View, error) {
	bound, _, err := f.authority.CertificateContext(ctx, id, attempt, expected)
	if err != nil {
		return certificates.View{}, err
	}
	if err := f.publishCatalogID(bound, certificateCatalog, id); err != nil {
		return certificates.View{}, err
	}
	var result certificates.Result
	switch kind {
	case IssueTask:
		request, failure := f.authority.AcceptedIssueRequest(bound)
		if failure != nil {
			return certificates.View{}, failure
		}
		result, err = f.certs.Issue(bound, request, progress)
	case ImportTask:
		request, failure := f.authority.AcceptedImportRequest(bound)
		if failure != nil {
			return certificates.View{}, failure
		}
		defer clear(request.ChainPEM)
		result, err = f.certs.ImportCertificate(bound, request)
	case TestTask:
		request, failure := f.authority.AcceptedTestRequest(bound)
		if failure != nil {
			return certificates.View{}, failure
		}
		result, err = f.certs.GenerateTestCertificate(bound, request)
	default:
		return certificates.View{}, fault.New("PERMISSION_DENIED", "任务kind不属于固定证书方法")
	}
	return result.View, err
}

func (f *Forwarder) Close(ctx context.Context) error {
	if f == nil {
		return fault.New("BACKEND_REQUIRED", "准备能力未装配")
	}
	return f.tasks.Close(ctx)
}

var _ hostsvc.CapabilityForwarder = (*Forwarder)(nil)
var _ TaskExecutor = (*Forwarder)(nil)
