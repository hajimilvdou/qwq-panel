// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
)

// ======================== 证书RPC复用原Manager；不接受材料、身份或替代范围 ========================

func (f *Forwarder) certificateTarget(ctx context.Context, id, expected string) (context.Context, certificates.Caller, hostauth.CertificateTargetArgs, error) {
	input, err := hostauth.DecodeArguments[hostauth.CertificateTargetArgs](ctx, f.authority)
	if err != nil {
		return nil, certificates.Caller{}, input, err
	}
	bound, caller, err := f.authority.CertificateContext(ctx, id, input.AttemptID, expected)
	return bound, caller, input, err
}

func (f *Forwarder) bindingRequest(ctx context.Context, id string, bindingID *string, expected string) (context.Context, certificates.BindRequest, string, error) {
	input, err := hostauth.DecodeArguments[hostauth.BindCertificateArgs](ctx, f.authority)
	if err != nil {
		return nil, certificates.BindRequest{}, "", err
	}
	if bindingID != nil && *bindingID != input.BindingRef {
		return nil, certificates.BindRequest{}, "", fault.New("PERMISSION_DENIED", "RPC替换了原稳定绑定引用")
	}
	bound, _, err := f.authority.BindingContext(ctx, id, expected)
	if err != nil {
		return nil, certificates.BindRequest{}, "", err
	}
	accepted, err := f.authority.AcceptedBindRequest(bound)
	return bound, accepted, input.BindingRef, err
}

func (f *Forwarder) publicRenewal(ctx context.Context, policyID, certificateID string) (*certificatesv1.RenewalView, error) {
	registration, err := f.authority.CurrentRenewalPolicy(ctx, policyID, certificateID)
	if err != nil {
		return nil, err
	}
	bound, caller, _, err := f.authority.RenewalCertificateContext(ctx, policyID, certificateID)
	if err != nil {
		return nil, err
	}
	view, err := f.renewals.Get(bound, caller, policyID)
	var runtime *certificates.RenewalView
	if fault.Code(err) != "NOT_FOUND" {
		if err != nil {
			return nil, err
		}
		runtime = &view
	}
	latest, err := f.authority.CurrentRenewalPolicy(ctx, policyID, certificateID)
	if err != nil {
		return nil, err
	}
	if latest.Revision != registration.Revision {
		return nil, fault.New("REVISION_CONFLICT", "公开续期状态读取期间原policy已变化")
	}
	return renewalView(latest, runtime), nil
}

func (f *Forwarder) forwardCertificates(ctx context.Context, method string, request proto.Message) (proto.Message, error) {
	switch method {
	case "ListCertificates":
		response := new(certificatesv1.ListCertificatesResponse)
		if _, err := requestAs[*certificatesv1.ListCertificatesRequest](request); err != nil {
			return response, err
		}
		if err := f.requireCollection(ctx, "tls.certificates", "certificates.list", "certificates"); err != nil {
			return response, err
		}
		ids, err := f.catalogIDs(ctx, certificateCatalog)
		if err != nil {
			return response, err
		}
		for _, id := range ids {
			bound, caller, err := f.authority.PublicCertificateContext(ctx, id)
			if fault.Code(err) == "NOT_FOUND" || fault.Code(err) == "PERMISSION_DENIED" {
				continue
			}
			if err != nil {
				return response, err
			}
			view, err := f.certs.Get(bound, caller, id)
			if fault.Code(err) == "NOT_FOUND" {
				continue
			}
			if err != nil {
				return response, err
			}
			response.Certificates = append(response.Certificates, certificateView(view))
		}
		return response, nil
	case "GetCertificate":
		response := new(certificatesv1.GetCertificateResponse)
		input, err := requestAs[*certificatesv1.GetCertificateRequest](request)
		if err != nil {
			return response, err
		}
		bound, caller, _, err := f.certificateTarget(ctx, input.CertificateId, "")
		if err != nil {
			return response, err
		}
		view, err := f.certs.Get(bound, caller, input.CertificateId)
		if err == nil {
			response.Certificate = certificateView(view)
		}
		return response, err
	case "SubmitIssue":
		response := new(certificatesv1.SubmitIssueResponse)
		input, err := requestAs[*certificatesv1.SubmitIssueRequest](request)
		if err != nil {
			return response, err
		}
		response.Task, err = f.tasks.Submit(ctx, IssueTask, input.CertificateId, input.AttemptId, input.ExpectedRevision)
		return response, err
	case "SubmitImport":
		response := new(certificatesv1.SubmitImportResponse)
		input, err := requestAs[*certificatesv1.SubmitImportRequest](request)
		if err != nil {
			return response, err
		}
		response.Task, err = f.tasks.Submit(ctx, ImportTask, input.CertificateId, input.AttemptId, input.ExpectedRevision)
		return response, err
	case "SubmitTestCertificate":
		response := new(certificatesv1.SubmitTestCertificateResponse)
		input, err := requestAs[*certificatesv1.SubmitTestCertificateRequest](request)
		if err != nil {
			return response, err
		}
		response.Task, err = f.tasks.Submit(ctx, TestTask, input.CertificateId, input.AttemptId, input.ExpectedRevision)
		return response, err
	case "GetTask":
		response := new(certificatesv1.GetTaskResponse)
		input, err := requestAs[*certificatesv1.GetTaskRequest](request)
		if err != nil {
			return response, err
		}
		response.Task, err = f.tasks.Get(ctx, input.TaskId)
		return response, err
	case "CancelTask":
		response := new(certificatesv1.CancelTaskResponse)
		input, err := requestAs[*certificatesv1.CancelTaskRequest](request)
		if err != nil {
			return response, err
		}
		response.Task, err = f.tasks.Cancel(ctx, input.TaskId)
		return response, err
	case "ReserveBinding":
		response := new(certificatesv1.ReserveBindingResponse)
		input, err := requestAs[*certificatesv1.ReserveBindingRequest](request)
		if err != nil {
			return response, err
		}
		res, err := f.authority.ReserveBinding(ctx, input.CertificateId, input.ExpectedRevision)
		if err == nil {
			response.BindingRef = res.BindingRef
			response.CertificateId = res.CertificateID
			response.Revision = res.Revision
			response.Status = res.Status
		}
		return response, err
	case "BindCertificate":
		response := new(certificatesv1.BindCertificateResponse)
		input, err := requestAs[*certificatesv1.BindCertificateRequest](request)
		if err != nil {
			return response, err
		}
		bound, accepted, _, err := f.bindingRequest(ctx, input.CertificateId, nil, input.ExpectedRevision)
		if err != nil {
			return response, err
		}
		result, err := f.certs.BindCertificate(bound, accepted)
		if result.View.ID != "" {
			response.Certificate = certificateView(result.View)
		}
		return response, err
	case "DeployBinding":
		response := new(certificatesv1.DeployBindingResponse)
		input, err := requestAs[*certificatesv1.DeployBindingRequest](request)
		if err != nil {
			return response, err
		}
		bound, accepted, _, err := f.bindingRequest(ctx, input.CertificateId, &input.BindingRef, input.ExpectedRevision)
		if err != nil {
			return response, err
		}
		result, err := f.certs.BindCertificate(bound, accepted)
		if result.View.ID != "" {
			response.Certificate = certificateView(result.View)
		}
		return response, err
	case "RollbackBinding":
		response := new(certificatesv1.RollbackBindingResponse)
		input, err := requestAs[*certificatesv1.RollbackBindingRequest](request)
		if err != nil {
			return response, err
		}
		bound, accepted, bindingID, err := f.bindingRequest(ctx, input.CertificateId, &input.BindingRef, input.ExpectedRevision)
		if err != nil {
			return response, err
		}
		result, err := f.certs.RollbackBinding(bound, accepted.Caller, accepted.CertificateID, bindingID, accepted.AttemptID, accepted.ExpectedRevision)
		if result.View.ID != "" {
			response.Certificate = certificateView(result.View)
		}
		return response, err
	case "UnbindCertificate":
		response := new(certificatesv1.UnbindCertificateResponse)
		input, err := requestAs[*certificatesv1.UnbindCertificateRequest](request)
		if err != nil {
			return response, err
		}
		bound, caller, complete, err := f.authority.CompletedConsumerUnbindContext(ctx, input.CertificateId, input.BindingRef, input.ExpectedRevision)
		if err != nil {
			return response, err
		}
		if complete {
			view, err := f.certs.Get(bound, caller, input.CertificateId)
			if err == nil {
				response.Certificate = certificateView(view)
			}
			return response, err
		}
		bound, caller, err = f.authority.BindingContext(ctx, input.CertificateId, input.ExpectedRevision)
		if err != nil {
			return response, err
		}
		accepted, err := f.authority.AcceptedUnbindTarget(bound)
		if err != nil {
			return response, err
		}
		if accepted.BindingID != input.BindingRef {
			return response, fault.New("PERMISSION_DENIED", "RPC解绑替换了原稳定绑定引用")
		}
		view, err := f.certs.UnbindCertificate(bound, caller, accepted.CertificateID, accepted.BindingID, accepted.AttemptID, accepted.ExpectedRevision)
		if view.ID != "" {
			response.Certificate = certificateView(view)
		}
		if err != nil {
			return response, err
		}
		return response, f.authority.CompleteConsumerUnbind(bound, caller, accepted.BindingID)
	case "RemoveGeneration":
		response := new(certificatesv1.RemoveGenerationResponse)
		input, err := requestAs[*certificatesv1.RemoveGenerationRequest](request)
		if err != nil {
			return response, err
		}
		bound, caller, accepted, err := f.certificateTarget(ctx, input.CertificateId, input.ExpectedRevision)
		if err != nil {
			return response, err
		}
		view, err := f.certs.RemoveGeneration(bound, caller, accepted.CertificateID, accepted.AttemptID, input.ExpectedRevision, accepted.Generation)
		if view.ID != "" {
			response.Certificate = certificateView(view)
		}
		return response, err
	case "RemoveCertificate":
		response := new(certificatesv1.RemoveCertificateResponse)
		input, err := requestAs[*certificatesv1.RemoveCertificateRequest](request)
		if err != nil {
			return response, err
		}
		bound, caller, accepted, err := f.certificateTarget(ctx, input.CertificateId, input.ExpectedRevision)
		if err != nil {
			return response, err
		}
		return response, f.certs.RemoveCertificate(bound, caller, accepted.CertificateID, accepted.AttemptID, input.ExpectedRevision)
	case "ConfigureRenewal":
		response := new(certificatesv1.ConfigureRenewalResponse)
		input, err := requestAs[*certificatesv1.ConfigureRenewalRequest](request)
		if err != nil {
			return response, err
		}
		accepted, err := hostauth.DecodeArguments[hostauth.RenewalPolicyArgs](ctx, f.authority)
		if err != nil {
			return response, err
		}
		if accepted.CertificateID != input.CertificateId {
			return response, fault.New("PERMISSION_DENIED", "RPC续期配置替换了原证书")
		}
		if _, err := f.authority.RegisterRenewalPolicy(ctx, accepted.PolicyID, input.ExpectedRevision); err != nil {
			return response, err
		}
		response.Renewal, err = f.publicRenewal(ctx, accepted.PolicyID, accepted.CertificateID)
		return response, err
	case "RevokeRenewal":
		response := new(certificatesv1.RevokeRenewalResponse)
		input, err := requestAs[*certificatesv1.RevokeRenewalRequest](request)
		if err != nil {
			return response, err
		}
		accepted, err := hostauth.DecodeArguments[hostauth.RenewalTargetArgs](ctx, f.authority)
		if err != nil {
			return response, err
		}
		if accepted.PolicyID != input.PolicyId {
			return response, fault.New("PERMISSION_DENIED", "RPC续期撤销替换了原policy")
		}
		if _, err := f.authority.RevokeRenewalPolicy(ctx, accepted.PolicyID, accepted.CertificateID, input.ExpectedRevision); err != nil {
			return response, err
		}
		bound, caller, _, err := f.authority.RenewalCertificateContext(ctx, accepted.PolicyID, accepted.CertificateID)
		if err != nil {
			return response, err
		}
		runtime, err := f.renewals.Get(bound, caller, accepted.PolicyID)
		if err != nil && fault.Code(err) != "NOT_FOUND" {
			return response, err
		}
		if err == nil && runtime.Enabled {
			// 私有授权先撤销；numeric runtime revision仅从实际账本读取。
			if _, err := f.renewals.Revoke(bound, caller, accepted.PolicyID, runtime.Revision); err != nil {
				return response, err
			}
		}
		response.Renewal, err = f.publicRenewal(ctx, accepted.PolicyID, accepted.CertificateID)
		return response, err
	case "GetRenewal":
		response := new(certificatesv1.GetRenewalResponse)
		input, err := requestAs[*certificatesv1.GetRenewalRequest](request)
		if err != nil {
			return response, err
		}
		accepted, err := hostauth.DecodeArguments[hostauth.RenewalTargetArgs](ctx, f.authority)
		if err != nil {
			return response, err
		}
		if accepted.CertificateID != input.CertificateId {
			return response, fault.New("PERMISSION_DENIED", "RPC续期查询替换了原证书")
		}
		response.Renewal, err = f.publicRenewal(ctx, accepted.PolicyID, accepted.CertificateID)
		return response, err
	}
	return nil, fault.New("PERMISSION_DENIED", "证书方法不在固定表")
}
