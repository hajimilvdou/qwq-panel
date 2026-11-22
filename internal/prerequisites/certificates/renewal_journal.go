// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 续期阶段与崩溃恢复 ========================

type RenewalRunOptions struct {
	Repository  store.Repository
	Clock       clock.Clock
	MaxPolicies int
	MaxAttempts int
}

// RenewalStart/Run均为候选事实，没有Actor、Args或可序列化运行proof。
type RenewalStart struct {
	PolicyID       string
	PolicyRevision string
	CertificateID  string
	RunAttemptID   string
	IssueAttemptID string
	Scope          RenewalScope
}

type RenewalRun struct {
	RenewalStart
	OperationID      string
	ExpectedRevision string
	DeployGeneration uint64
	LeaseUntil       time.Time
}

func (RenewalStart) String() string { return "certificates.RenewalStart{[REDACTED]}" }
func (RenewalRun) String() string   { return "certificates.RenewalRun{[REDACTED]}" }

type PrivateRenewalRuns struct {
	repository  store.Repository
	clock       clock.Clock
	maxPolicies int
	maxAttempts int
}

func NewPrivateRenewalRuns(options RenewalRunOptions) (*PrivateRenewalRuns, error) {
	if options.Repository == nil {
		return nil, fault.New("BACKEND_REQUIRED", "续期候选需要宿主私有runtime ledger")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.MaxPolicies == 0 {
		options.MaxPolicies = 128
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = 3
	}
	if options.MaxPolicies < 1 || options.MaxPolicies > 128 || options.MaxAttempts < 1 || options.MaxAttempts > 5 {
		return nil, fault.New("VALIDATION_FAILED", "续期候选容量上限无效")
	}
	return &PrivateRenewalRuns{repository: options.Repository, clock: options.Clock, maxPolicies: options.MaxPolicies, maxAttempts: options.MaxAttempts}, nil
}

func (s *PrivateRenewalRuns) policy(ctx context.Context, policyID, revision, runAttempt string, scope RenewalScope) (renewalPolicy, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !names.ID(policyID) || !names.ID(runAttempt) {
		return renewalPolicy{}, fault.New("PERMISSION_DENIED", "续期候选缺少当前固定请求")
	}
	ledger, _, err := readRenewalLedger(ctx, s.repository, s.maxPolicies, s.maxAttempts)
	if err != nil {
		return renewalPolicy{}, err
	}
	for _, policy := range ledger.Policies {
		if policy.ID != policyID {
			continue
		}
		if !policy.Enabled || policy.Exhausted || strconv.FormatUint(policy.Version, 10) != revision || !sameRenewalScope(policy.Scope, scope) ||
			policy.Job == nil || policy.Job.AttemptID != runAttempt || !s.clock.Now().Before(policy.Job.LeaseUntil) {
			return renewalPolicy{}, fault.New("POLICY_REVOKED", "续期候选的原policy/run/Scope已变化")
		}
		return policy, nil
	}
	return renewalPolicy{}, fault.New("NOT_FOUND", "原private续期policy不存在")
}

func renewalStart(policy renewalPolicy) (RenewalStart, error) {
	issue := ""
	if policy.Issue != nil {
		issue = policy.Issue.AttemptID
	} else {
		var err error
		issue, err = renewalAttemptID("renewcert", policy)
		if err != nil {
			return RenewalStart{}, err
		}
	}
	scope, err := canonicalRenewalScope(policy.Scope)
	if err != nil {
		return RenewalStart{}, err
	}
	return RenewalStart{PolicyID: policy.ID, PolicyRevision: strconv.FormatUint(policy.Version, 10), CertificateID: scope.CertificateID,
		RunAttemptID: policy.Job.AttemptID, IssueAttemptID: issue, Scope: scope}, nil
}

// Starting供Root构造真实Operation；候选存在不证明executor已经启动。
func (s *PrivateRenewalRuns) Starting(ctx context.Context, policyID, revision, runAttempt string, scope RenewalScope) (RenewalStart, error) {
	policy, err := s.policy(ctx, policyID, revision, runAttempt, scope)
	if err != nil {
		return RenewalStart{}, err
	}
	return renewalStart(policy)
}

// Current核对真实Begin之后保存的原operation候选；运行权限仍由Authority取得。
func (s *PrivateRenewalRuns) Current(ctx context.Context, caller Caller, scope RenewalScope, runAttempt string) (RenewalRun, error) {
	if validateCaller(caller, true) != nil || caller.PolicyID == "" || caller.OwnerID != scope.OwnerID {
		return RenewalRun{}, fault.New("PERMISSION_DENIED", "续期候选caller不属于原Scope")
	}
	policy, err := s.policy(ctx, caller.PolicyID, caller.PolicyRevision, runAttempt, scope)
	if err != nil {
		return RenewalRun{}, err
	}
	if policy.Job.OperationID != caller.OperationID {
		return RenewalRun{}, fault.New("PERMISSION_DENIED", "续期候选不是当前原operation")
	}
	start, err := renewalStart(policy)
	if err != nil {
		return RenewalRun{}, err
	}
	result := RenewalRun{RenewalStart: start, OperationID: caller.OperationID, DeployGeneration: policy.DeployGeneration, LeaseUntil: policy.Job.LeaseUntil}
	if policy.Issue != nil {
		result.ExpectedRevision = policy.Issue.ExpectedRevision
	}
	return result, nil
}

func sameRenewalScope(one, two RenewalScope) bool {
	return one.OwnerID == two.OwnerID && one.CertificateID == two.CertificateID &&
		one.Issuance.Provider == two.Issuance.Provider && one.Issuance.CA == two.Issuance.CA &&
		sameSpec(one.Issuance.Spec, two.Issuance.Spec) && slices.Equal(one.Consumers, two.Consumers)
}

func renewalExpiry(view View, consumers []Consumer) time.Time {
	expiry := time.Time{}
	numbers := []uint64{view.CurrentGeneration}
	for _, binding := range view.Bindings {
		if slices.Contains(consumers, binding.Host.Consumer) {
			numbers = append(numbers, binding.RunningGeneration)
		}
	}
	for _, generation := range view.Generations {
		if slices.Contains(numbers, generation.Number) && (expiry.IsZero() || generation.Metadata.NotAfter.Before(expiry)) {
			expiry = generation.Metadata.NotAfter
		}
	}
	return expiry
}

func renewalAttemptID(kind string, policy renewalPolicy) (string, error) {
	hash, err := fingerprint(struct {
		Policy   string
		Revision uint64
		Run      uint64
	}{policy.ID, policy.Version, policy.RunNumber})
	if err != nil {
		return "", err
	}
	return kind + "_" + hash[:32], nil
}

// checkpoint 先提交阶段再发送副作用；失去租约或撤权后不更新旧任务。
func (s *RenewalService) checkpoint(ctx context.Context, attempted renewalPolicy, change func(*renewalPolicy)) (renewalPolicy, error) {
	if err := ctx.Err(); err != nil {
		return renewalPolicy{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, revision, err := s.load(ctx)
	if err != nil {
		return renewalPolicy{}, err
	}
	for index, policy := range ledger.Policies {
		if policy.ID != attempted.ID {
			continue
		}
		if !policy.Enabled || policy.Version != attempted.Version || policy.Job == nil || attempted.Job == nil || policy.Job.AttemptID != attempted.Job.AttemptID || !s.clock.Now().Before(policy.Job.LeaseUntil) {
			return renewalPolicy{}, fault.New("POLICY_REVOKED", "续期阶段已失去授权或租约")
		}
		if err := s.confirmations.Validate(ctx, policy.Scope); err != nil {
			return renewalPolicy{}, backendFailure(err, "POLICY_REVOKED")
		}
		change(&policy)
		ledger.Policies[index] = policy
		if _, err := store.Save(ctx, s.repository, renewalLedgerKey, revision, ledger); err != nil {
			return renewalPolicy{}, err
		}
		return policy, nil
	}
	return renewalPolicy{}, fault.New("POLICY_REVOKED", "续期授权不存在")
}

func (s *RenewalService) issueRequest(caller Caller, policy renewalPolicy) IssueRequest {
	return IssueRequest{Caller: caller, CertificateID: policy.Scope.CertificateID, AttemptID: policy.Issue.AttemptID, ExpectedRevision: policy.Issue.ExpectedRevision, Scope: policy.Scope.Issuance}
}

// lookupIssue 只接受原 policy 签发收据，不能用资源当前最新代冒充该次结果。
func (s *RenewalService) lookupIssue(ctx context.Context, caller Caller, policy renewalPolicy) (Result, uint64, error) {
	if policy.Issue == nil {
		return Result{}, 0, fault.New("STATE_INVALID", "续期缺少持久签发意图")
	}
	scope := policy.Scope.Issuance
	if err := s.manager.authorize(ctx, Authorization{Caller: caller, CertificateID: policy.Scope.CertificateID, Spec: scope.Spec, Issuance: &scope, Access: RenewExisting}); err != nil {
		return Result{}, 0, err
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	state, revision, found, err := s.manager.load(ctx, caller, policy.Scope.CertificateID)
	if err != nil {
		return Result{}, 0, err
	}
	if !found {
		return Result{}, 0, fault.New("NOT_FOUND", "续期证书不存在")
	}
	result := Result{View: s.manager.view(state, revision), Stage: "new"}
	if !sameSpec(state.Spec, scope.Spec) {
		return result, 0, fault.New("POLICY_SCOPE_DENIED", "续期证书 SAN 或用途已变化")
	}
	for _, receipt := range state.Receipts {
		if receipt.ID != policy.Issue.AttemptID {
			continue
		}
		if receipt.Hash != policy.Issue.Hash {
			return result, 0, fault.New("ATTEMPT_CONFLICT", "续期原签发收据不匹配")
		}
		if receipt.Stage == "rejected" {
			result.Stage = "rejected"
			return result, 0, &fault.Error{Code: receipt.ErrorCode, Detail: "原续期签发已明确拒绝", RetryAt: receipt.RetryAt}
		}
		generation, present := generationByNumber(state, receipt.Generation)
		trust := tlsmgr.PublicTrust
		if scope.CA == LetsEncryptStaging {
			trust = tlsmgr.StagingTrust
		}
		if receipt.Stage != "issued" || !present || generation.Source != ACME || generation.Metadata.Trust != trust || !sameSpec(Spec{generation.Metadata.SANs, generation.Metadata.Purpose}, scope.Spec) {
			return result, 0, fault.New("STATE_INVALID", "续期 generation 与原授权或 CA 不符")
		}
		result.Stage = "issued"
		return result, generation.Number, nil
	}
	if state.Pending != nil {
		active := state.Pending
		if active.Kind != "issue" || active.ID != policy.Issue.AttemptID || active.Hash != policy.Issue.Hash || active.Caller.PolicyID != policy.ID || active.Caller.PolicyRevision != strconv.FormatUint(policy.Version, 10) || active.Scope == nil || !sameRenewalScope(RenewalScope{OwnerID: state.OwnerID, CertificateID: state.ID, Issuance: *active.Scope, Consumers: policy.Scope.Consumers}, policy.Scope) {
			return result, 0, fault.New("CERTIFICATE_BUSY", "续期不能接管其他签发或消费任务")
		}
		result.Stage = "pending"
		return result, 0, nil
	}
	if revision != policy.Issue.ExpectedRevision {
		return result, 0, fault.New("REVISION_CONFLICT", "原签发尚未提交，但证书状态已变化")
	}
	return result, 0, nil
}

func (s *RenewalService) ownedPendingBinding(ctx context.Context, caller Caller, policy renewalPolicy) (Consumer, error) {
	if err := s.manager.authorize(ctx, Authorization{Caller: caller, CertificateID: policy.Scope.CertificateID, Access: Read}); err != nil {
		return Consumer{}, err
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	state, _, _, err := s.manager.load(ctx, caller, policy.Scope.CertificateID)
	if err != nil {
		return Consumer{}, err
	}
	active := state.Pending
	if active == nil || active.Kind != "bind" || active.Binding == nil || active.Caller.PolicyID != policy.ID || active.Caller.PolicyRevision != strconv.FormatUint(policy.Version, 10) || active.Binding.Generation != policy.DeployGeneration || !slices.Contains(policy.Scope.Consumers, active.Binding.Consumer) {
		return Consumer{}, fault.New("POLICY_SCOPE_DENIED", "续期不能恢复其他 operation 的部署")
	}
	return active.Binding.Consumer, nil
}
