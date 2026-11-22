// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 低频有界 service actor ========================

// Run 与宿主生命周期一同取消，不依赖 TCP/HTTPS 握手触发续期。
func (s *RenewalService) Run(ctx context.Context, report func(error)) {
	for {
		if err := s.Tick(ctx); err != nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.clock.After(s.checkEvery):
		}
	}
}

// Tick 单次最多执行 maxJobs，未到期或已耗尽的策略不创建 operation。
func (s *RenewalService) Tick(ctx context.Context) error {
	ledger, _, err := s.load(ctx)
	if err != nil {
		return backendFailure(err, "RENEWAL_FAILED")
	}
	jobs := 0
	var failures []error
	for _, policy := range ledger.Policies {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if jobs >= s.maxJobs {
			break
		}
		if !policy.Enabled || policy.Exhausted || policy.NextAt.IsZero() || s.clock.Now().Before(policy.NextAt) {
			continue
		}
		if policy.Job != nil && s.clock.Now().Before(policy.Job.LeaseUntil) {
			continue
		}
		if err := s.execute(ctx, policy.ID); err != nil {
			failures = append(failures, backendFailure(err, "RENEWAL_FAILED"))
		}
		jobs++
	}
	return errors.Join(failures...)
}

func (s *RenewalService) claim(ctx context.Context, policyID string, cancel context.CancelFunc) (renewalPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[policyID] != nil || len(s.running) >= s.maxJobs {
		return renewalPolicy{}, fault.New("RENEWAL_NOT_DUE", "本进程续期任务已达上限")
	}
	ledger, revision, err := s.load(ctx)
	if err != nil {
		return renewalPolicy{}, err
	}
	activeJobs := 0
	for _, policy := range ledger.Policies {
		if policy.Job != nil && s.clock.Now().Before(policy.Job.LeaseUntil) {
			activeJobs++
		}
	}
	if activeJobs >= s.maxJobs {
		return renewalPolicy{}, fault.New("RENEWAL_NOT_DUE", "宿主共享账本的续期任务已达上限")
	}
	for index, policy := range ledger.Policies {
		if policy.ID != policyID {
			continue
		}
		if !policy.Enabled || policy.Exhausted || policy.NextAt.IsZero() || s.clock.Now().Before(policy.NextAt) || (policy.Job != nil && s.clock.Now().Before(policy.Job.LeaseUntil)) {
			return renewalPolicy{}, fault.New("RENEWAL_NOT_DUE", "续期策略未到期或已有有效租约")
		}
		if err := s.confirmations.Validate(ctx, policy.Scope); err != nil {
			code := fault.Code(err)
			if code == "REVISION_CONFLICT" || code == "STATE_UNAVAILABLE" {
				return renewalPolicy{}, err
			}
			policy.Enabled, policy.NextAt, policy.LastError = false, time.Time{}, fault.Code(backendFailure(err, "POLICY_REVOKED"))
			if policy.Version < math.MaxUint64 {
				policy.Version++
			}
			ledger.Policies[index] = policy
			if _, saveErr := store.Save(ctx, s.repository, renewalLedgerKey, revision, ledger); saveErr != nil {
				return renewalPolicy{}, saveErr
			}
			return renewalPolicy{}, backendFailure(err, "POLICY_REVOKED")
		}
		if policy.Attempts >= s.maxAttempts || policy.RunNumber == math.MaxUint64 {
			policy.Exhausted, policy.NextAt, policy.LastError = true, time.Time{}, "RENEWAL_EXHAUSTED"
			ledger.Policies[index] = policy
			if _, err := store.Save(ctx, s.repository, renewalLedgerKey, revision, ledger); err != nil {
				return renewalPolicy{}, err
			}
			return renewalPolicy{}, fault.New("RENEWAL_EXHAUSTED", "续期重试已达上限")
		}
		policy.Attempts++
		policy.RunNumber++
		attemptID, err := renewalAttemptID("renewrun", policy)
		if err != nil {
			return renewalPolicy{}, err
		}
		policy.Job = &renewalJob{AttemptID: attemptID, StartedAt: s.clock.Now().UTC(), LeaseUntil: s.clock.Now().Add(s.jobTimeout).UTC()}
		ledger.Policies[index] = policy
		if _, err := store.Save(ctx, s.repository, renewalLedgerKey, revision, ledger); err != nil {
			return renewalPolicy{}, err
		}
		s.running[policyID] = cancel
		return policy, nil
	}
	return renewalPolicy{}, fault.New("NOT_FOUND", "续期策略不存在")
}

func (s *RenewalService) attachOperation(ctx context.Context, policy renewalPolicy, caller Caller) (renewalPolicy, error) {
	if caller.OwnerID != policy.Scope.OwnerID || caller.PolicyID != policy.ID || caller.PolicyRevision != strconv.FormatUint(policy.Version, 10) || validateCaller(caller, true) != nil {
		return renewalPolicy{}, fault.New("POLICY_SCOPE_DENIED", "service operation 身份与确认范围不符")
	}
	return s.checkpoint(ctx, policy, func(current *renewalPolicy) { current.Job.OperationID = caller.OperationID })
}

func (s *RenewalService) execute(ctx context.Context, policyID string) (err error) {
	jobCtx, cancel := context.WithTimeout(ctx, s.jobTimeout)
	defer cancel()
	policy, err := s.claim(jobCtx, policyID, cancel)
	if err != nil {
		if fault.Code(err) == "RENEWAL_NOT_DUE" {
			return nil
		}
		return err
	}
	defer func() { s.mu.Lock(); delete(s.running, policyID); s.mu.Unlock() }()
	var caller Caller
	var view View
	var rejected bool
	defer func() {
		bounded, stop := context.WithTimeout(context.WithoutCancel(ctx), s.manager.cleanupTimeout)
		defer stop()
		status := "succeeded"
		if err != nil {
			status = "failed"
		}
		if caller.OperationID != "" {
			if finishErr := s.operations.Finish(bounded, caller, status); finishErr != nil {
				err = errors.Join(err, backendFailure(finishErr, "RENEWAL_AUDIT_FAILED"))
			}
		}
		err = s.finish(ctx, policy, view, err, rejected)
	}()
	caller, err = s.operations.Begin(jobCtx, policy.ID, strconv.FormatUint(policy.Version, 10), policy.Job.AttemptID, policy.Scope)
	if err != nil {
		return backendFailure(err, "RENEWAL_OPERATION_FAILED")
	}
	next, err := s.attachOperation(jobCtx, policy, caller)
	if err != nil {
		return err
	}
	policy = next
	executionCtx, release, err := s.contexts.Context(jobCtx, RenewalContextRequest{Caller: caller, Scope: policy.Scope,
		RunAttemptID: policy.Job.AttemptID, Access: Read})
	if err != nil {
		return backendFailure(err, "RENEWAL_CONTEXT_FAILED")
	}
	defer release()
	view, rejected, err = s.perform(executionCtx, caller, &policy)
	return err
}

func (s *RenewalService) finish(ctx context.Context, attempted renewalPolicy, view View, failure error, rejected bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.manager.cleanupTimeout)
	defer cancel()
	ledger, revision, err := s.load(bounded)
	if err != nil {
		return errors.Join(failure, err)
	}
	for index, policy := range ledger.Policies {
		if policy.ID != attempted.ID {
			continue
		}
		if policy.Job == nil || policy.Job.AttemptID != attempted.Job.AttemptID {
			return errors.Join(failure, fault.New("POLICY_REVOKED", "续期任务租约已变化"))
		}
		policy.Job = nil
		if view.ID == policy.Scope.CertificateID {
			if expiry := renewalExpiry(view, policy.Scope.Consumers); !expiry.IsZero() {
				policy.ExpiresAt = expiry
			}
		}
		if policy.Version != attempted.Version || !policy.Enabled {
			policy.NextAt, policy.LastError = time.Time{}, "POLICY_REVOKED"
		} else if failure == nil {
			policy.Attempts, policy.LastError, policy.Exhausted, policy.DeployGeneration = 0, "", false, 0
			policy.Issue = nil
			policy.NextAt = s.dueAt(view)
		} else {
			policy.LastError = fault.Code(backendFailure(failure, "RENEWAL_FAILED"))
			if rejected && policy.DeployGeneration == 0 {
				policy.Issue = nil
			}
			if policy.LastError == "POLICY_REVOKED" || policy.LastError == "POLICY_SCOPE_DENIED" || policy.LastError == "CREDENTIAL_REVOKED" || policy.LastError == "PERMISSION_DENIED" || policy.LastError == "NOT_FOUND" {
				policy.Enabled, policy.NextAt = false, time.Time{}
				if policy.Version < math.MaxUint64 {
					policy.Version++
				}
			} else if policy.Attempts >= s.maxAttempts {
				policy.Exhausted, policy.NextAt = true, time.Time{}
			} else {
				delay := s.retryBase * time.Duration(1<<uint(policy.Attempts-1))
				if delay > 7*24*time.Hour {
					delay = 7 * 24 * time.Hour
				}
				policy.NextAt = s.clock.Now().Add(delay)
				if retry := fault.Retry(failure); retry.After(policy.NextAt) {
					policy.NextAt = retry
				}
				if policy.NextAt.After(s.clock.Now().Add(7 * 24 * time.Hour)) {
					policy.Exhausted, policy.NextAt, policy.LastError = true, time.Time{}, "RETRY_BUDGET_EXCEEDED"
				}
			}
		}
		ledger.Policies[index] = policy
		if _, err := store.Save(bounded, s.repository, renewalLedgerKey, revision, ledger); err != nil {
			return errors.Join(failure, err)
		}
		return failure
	}
	return errors.Join(failure, fault.New("POLICY_REVOKED", "续期策略不存在"))
}

func (s *RenewalService) Get(ctx context.Context, caller Caller, policyID string) (RenewalView, error) {
	if err := validateCaller(caller, false); err != nil {
		return RenewalView{}, err
	}
	ledger, _, err := s.load(ctx)
	if err != nil {
		return RenewalView{}, err
	}
	for _, policy := range ledger.Policies {
		if policy.ID != policyID || policy.Scope.OwnerID != caller.OwnerID {
			continue
		}
		view, err := s.manager.Get(ctx, caller, policy.Scope.CertificateID)
		if err != nil {
			return RenewalView{}, err
		}
		if expiry := renewalExpiry(view, policy.Scope.Consumers); !expiry.IsZero() {
			policy.ExpiresAt = expiry
		}
		return s.view(policy), nil
	}
	return RenewalView{}, fault.New("NOT_FOUND", "续期策略不存在")
}

// PolicyRevision只读runtime CAS版本；原policy管理权限必须由当前私有certificate Context确认。
func (s *RenewalService) PolicyRevision(ctx context.Context, caller Caller, policyID string) (string, bool, error) {
	if err := validateCaller(caller, false); err != nil {
		return "", false, err
	}
	ledger, _, err := s.load(ctx)
	if err != nil {
		return "", false, err
	}
	for _, policy := range ledger.Policies {
		if policy.ID != policyID || policy.Scope.OwnerID != caller.OwnerID {
			continue
		}
		if err := s.manager.authorize(ctx, Authorization{Caller: caller, CertificateID: policy.Scope.CertificateID, Access: Read}); err != nil {
			return "", false, err
		}
		return strconv.FormatUint(policy.Version, 10), true, nil
	}
	return "", false, nil
}
