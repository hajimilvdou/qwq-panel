// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"slices"
	"strconv"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 固定签发代与消费者部署 ========================

func (s *RenewalService) issueContext(ctx context.Context, caller Caller, policy renewalPolicy) (context.Context, context.CancelFunc, error) {
	if policy.Issue == nil || policy.Job == nil {
		return nil, nil, fault.New("STATE_INVALID", "续期签发缺少原private阶段")
	}
	return s.contexts.Context(ctx, RenewalContextRequest{Caller: caller, Scope: policy.Scope, RunAttemptID: policy.Job.AttemptID,
		IssueAttemptID: policy.Issue.AttemptID, ExpectedRevision: policy.Issue.ExpectedRevision, Access: RenewExisting})
}

func (s *RenewalService) bindingContext(ctx context.Context, caller Caller, policy renewalPolicy, consumer Consumer) (context.Context, context.CancelFunc, error) {
	return s.contexts.Context(ctx, RenewalContextRequest{Caller: caller, Scope: policy.Scope, RunAttemptID: policy.Job.AttemptID,
		Generation: policy.DeployGeneration, Consumer: &consumer, Access: Bind})
}

func (s *RenewalService) perform(ctx context.Context, caller Caller, policy *renewalPolicy) (View, bool, error) {
	view, err := s.manager.Get(ctx, caller, policy.Scope.CertificateID)
	if err != nil {
		return View{}, false, err
	}
	bound := make([]Consumer, 0, len(view.Bindings))
	for _, binding := range view.Bindings {
		bound = append(bound, binding.Host.Consumer)
	}
	slices.SortFunc(bound, stringsCompareConsumer)
	if !sameSpec(view.Spec, policy.Scope.Issuance.Spec) || !slices.Equal(bound, policy.Scope.Consumers) {
		return view, false, fault.New("POLICY_SCOPE_DENIED", "续期证书或消费者集合已改变，需要重新确认范围")
	}
	if policy.DeployGeneration == 0 {
		if policy.Issue == nil {
			if view.Pending != "" {
				return view, false, fault.New("CERTIFICATE_BUSY", "证书已有其他待处理 operation")
			}
			attemptID, err := renewalAttemptID("renewcert", *policy)
			if err != nil {
				return view, false, err
			}
			intent := &renewalIssue{AttemptID: attemptID, ExpectedRevision: view.Revision}
			candidate := *policy
			candidate.Issue = intent
			hash, err := fingerprint(s.issueRequest(caller, candidate))
			if err != nil {
				return view, false, err
			}
			intent.Hash = hash
			next, err := s.checkpoint(ctx, *policy, func(current *renewalPolicy) { current.Issue = intent })
			if err != nil {
				return view, false, err
			}
			*policy = next
		}
		issueCtx, release, err := s.issueContext(ctx, caller, *policy)
		if err != nil {
			return view, false, err
		}
		defer release()
		ctx = issueCtx
		result, generation, err := s.lookupIssue(ctx, caller, *policy)
		if err != nil {
			return result.View, result.Stage == "rejected", err
		}
		var issueErr error
		called := false
		switch result.Stage {
		case "new":
			called = true
			request := s.issueRequest(caller, *policy)
			hash, err := fingerprint(request)
			if err != nil {
				return result.View, false, err
			}
			// 已确认没有 pending/收据且 revision 未变，才能换当前 operation。
			if hash != policy.Issue.Hash {
				intent := *policy.Issue
				intent.Hash = hash
				next, err := s.checkpoint(ctx, *policy, func(current *renewalPolicy) { current.Issue = &intent })
				if err != nil {
					return result.View, false, err
				}
				*policy = next
			}
			result, issueErr = s.manager.Issue(ctx, request, nil)
		case "pending":
			called = true
			result, issueErr = s.manager.Recover(ctx, caller, policy.Scope.CertificateID, result.View.Revision, nil)
		case "issued":
		default:
			return result.View, false, fault.New("STATE_INVALID", "续期签发阶段无效")
		}
		if issueErr != nil && result.Stage != "issued" {
			return result.View, result.Stage == "rejected", issueErr
		}
		if generation == 0 {
			confirmed, number, verifyErr := s.lookupIssue(ctx, caller, *policy)
			if verifyErr != nil {
				return result.View, false, verifyErr
			}
			if confirmed.Stage != "issued" || number == 0 {
				return result.View, false, unknown("续期签发收据未确认，不能选择最新 generation")
			}
			result, generation = confirmed, number
		}
		intent := *policy.Issue
		// 真实 Issue/Recover 返回成功时，其有界 Cancel 已确认 TXT 清理。
		intent.CleanupDone = intent.CleanupDone || (called && issueErr == nil)
		next, saveErr := s.checkpoint(ctx, *policy, func(current *renewalPolicy) { current.DeployGeneration = generation; current.Issue = &intent })
		if saveErr != nil {
			return result.View, false, saveErr
		}
		*policy, view = next, result.View
		if issueErr != nil {
			return view, false, issueErr
		}
	}
	if view.CurrentGeneration != policy.DeployGeneration {
		return view, false, fault.New("REVISION_CONFLICT", "续期目标代已被其他签发替换，需要重新预演")
	}
	if !view.Ready {
		return view, false, fault.New("CERTIFICATE_EXPIRED", "续期目标证书未处于有效期")
	}
	if !policy.Issue.CleanupDone {
		cleanupCtx, release, err := s.issueContext(ctx, caller, *policy)
		if err != nil {
			return view, false, err
		}
		defer release()
		scope := policy.Scope.Issuance
		if err := s.manager.authorize(cleanupCtx, Authorization{Caller: caller, CertificateID: policy.Scope.CertificateID, Spec: scope.Spec, Issuance: &scope, Access: RenewExisting}); err != nil {
			return view, false, err
		}
		if err := s.manager.authority.Cancel(cleanupCtx, caller, policy.Scope.CertificateID, policy.Issue.AttemptID, scope); err != nil {
			return view, false, backendFailure(err, "DNS_CLEANUP_FAILED")
		}
		intent := *policy.Issue
		intent.CleanupDone = true
		next, err := s.checkpoint(ctx, *policy, func(current *renewalPolicy) { current.Issue = &intent })
		if err != nil {
			return view, false, err
		}
		*policy = next
	}
	if view.Pending == "bind" {
		consumer, err := s.ownedPendingBinding(ctx, caller, *policy)
		if err != nil {
			return view, false, err
		}
		boundCtx, release, err := s.bindingContext(ctx, caller, *policy, consumer)
		if err != nil {
			return view, false, err
		}
		result, err := s.manager.Recover(boundCtx, caller, policy.Scope.CertificateID, view.Revision, nil)
		release()
		if result.View.ID == view.ID {
			view = result.View
		}
		if err != nil {
			return view, false, err
		}
	} else if view.Pending != "" {
		return view, false, fault.New("CERTIFICATE_BUSY", "续期不能接管其他资源 operation")
	}
	for index, consumer := range policy.Scope.Consumers {
		boundCtx, release, err := s.bindingContext(ctx, caller, *policy, consumer)
		if err != nil {
			return view, false, err
		}
		if err := s.Authorize(boundCtx, Authorization{Caller: caller, CertificateID: policy.Scope.CertificateID, Generation: policy.DeployGeneration, Spec: view.Spec, Consumer: &consumer, Access: Bind}); err != nil {
			release()
			return view, false, err
		}
		if slices.ContainsFunc(view.Bindings, func(binding Binding) bool {
			return binding.Host.Consumer == consumer && binding.RunningGeneration == policy.DeployGeneration && binding.Verified
		}) {
			release()
			continue
		}
		result, err := s.manager.BindCertificate(boundCtx, BindRequest{Caller: caller, CertificateID: policy.Scope.CertificateID, AttemptID: policy.Job.AttemptID + "-deploy-" + strconv.Itoa(index), ExpectedRevision: view.Revision, Generation: policy.DeployGeneration, Consumer: consumer})
		release()
		if result.View.ID == view.ID {
			view = result.View
		}
		if err != nil {
			return view, false, err
		}
	}
	return view, false, nil
}
