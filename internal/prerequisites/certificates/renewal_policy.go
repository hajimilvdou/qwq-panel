// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 宿主私有续期授权账本 ========================

const renewalLedgerKey = "certificates/renewal-ledger"

// RenewalScope 是初次确认的完整范围，不使用通配节点或权限字符串。
type RenewalScope struct {
	OwnerID       string        `json:"owner_id"`
	CertificateID string        `json:"certificate_id"`
	Issuance      IssuanceScope `json:"issuance"`
	Consumers     []Consumer    `json:"consumers"`
}

// RenewalConfirmations 必须由宿主审核已确认的高敏 operation 和当前资源授权。
// repository 只供宿主使用，不能将插件可自行改写的 KV 当作授权事实。
type RenewalConfirmations interface {
	Confirm(context.Context, Caller, RenewalScope) error
	Validate(context.Context, RenewalScope) error
}

// RenewalOperations 创建可审计、精确范围的 service operation，不授予一般 reveal。
type RenewalOperations interface {
	Begin(context.Context, string, string, string, RenewalScope) (Caller, error)
	Finish(context.Context, Caller, string) error
}

// RenewalContextRequest 只描述当前已保存阶段；Context必须再匹配真实executor/policy/原Args。
type RenewalContextRequest struct {
	Caller           Caller
	Scope            RenewalScope
	RunAttemptID     string
	IssueAttemptID   string
	ExpectedRevision string
	Generation       uint64
	Consumer         *Consumer
	Access           Access
}

type RenewalContexts interface {
	Context(context.Context, RenewalContextRequest) (context.Context, context.CancelFunc, error)
}

type RenewalOptions struct {
	Repository    store.Repository
	Manager       *Manager
	Confirmations RenewalConfirmations
	Operations    RenewalOperations
	Contexts      RenewalContexts
	Clock         clock.Clock
	MaxPolicies   int
	MaxJobs       int
	MaxAttempts   int
	CheckEvery    time.Duration
	JobTimeout    time.Duration
	RenewBefore   time.Duration
	RetryBase     time.Duration
}

type RenewalService struct {
	mu            sync.Mutex
	repository    store.Repository
	manager       *Manager
	confirmations RenewalConfirmations
	operations    RenewalOperations
	contexts      RenewalContexts
	clock         clock.Clock
	maxPolicies   int
	maxJobs       int
	maxAttempts   int
	checkEvery    time.Duration
	jobTimeout    time.Duration
	renewBefore   time.Duration
	retryBase     time.Duration
	running       map[string]context.CancelFunc
}

type renewalJob struct {
	AttemptID   string    `json:"attempt_id"`
	OperationID string    `json:"operation_id,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	LeaseUntil  time.Time `json:"lease_until"`
}

// renewalIssue 在调用 CA 前持久化；换 operation 后仍只对账原签发意图。
type renewalIssue struct {
	AttemptID        string `json:"attempt_id"`
	ExpectedRevision string `json:"expected_revision"`
	Hash             string `json:"hash"`
	CleanupDone      bool   `json:"cleanup_done"`
}

type renewalPolicy struct {
	ID               string        `json:"id"`
	Version          uint64        `json:"version"`
	Scope            RenewalScope  `json:"scope"`
	Enabled          bool          `json:"enabled"`
	Attempts         int           `json:"attempts"`
	RunNumber        uint64        `json:"run_number"`
	NextAt           time.Time     `json:"next_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
	LastError        string        `json:"last_error,omitempty"`
	Exhausted        bool          `json:"exhausted"`
	Issue            *renewalIssue `json:"issue,omitempty"`
	DeployGeneration uint64        `json:"deploy_generation,omitempty"`
	Job              *renewalJob   `json:"job,omitempty"`
}

type renewalLedger struct {
	Policies []renewalPolicy `json:"policies"`
}

// RenewalView 不显示内部 operation、租约或任何秘密引用。
type RenewalView struct {
	ID               string        `json:"id"`
	Revision         string        `json:"revision"`
	CertificateID    string        `json:"certificate_id"`
	Issuance         IssuanceScope `json:"issuance"`
	Consumers        []Consumer    `json:"consumers"`
	Enabled          bool          `json:"enabled"`
	Attempts         int           `json:"attempts"`
	NextAt           time.Time     `json:"next_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
	Status           string        `json:"status"`
	Alert            string        `json:"alert,omitempty"`
	LastError        string        `json:"last_error,omitempty"`
	Exhausted        bool          `json:"exhausted"`
	DeployGeneration uint64        `json:"deploy_generation,omitempty"`
}

func NewRenewalService(options RenewalOptions) (*RenewalService, error) {
	if options.Repository == nil || options.Manager == nil || options.Confirmations == nil || options.Operations == nil || options.Contexts == nil {
		return nil, fault.New("BACKEND_REQUIRED", "续期必须使用宿主私有账本、范围确认和 operation 后端")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.MaxPolicies == 0 {
		options.MaxPolicies = 128
	}
	if options.MaxJobs == 0 {
		options.MaxJobs = 4
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = 3
	}
	if options.CheckEvery == 0 {
		options.CheckEvery = 6 * time.Hour
	}
	if options.JobTimeout == 0 {
		options.JobTimeout = 10 * time.Minute
	}
	if options.RenewBefore == 0 {
		options.RenewBefore = 30 * 24 * time.Hour
	}
	if options.RetryBase == 0 {
		options.RetryBase = time.Hour
	}
	if options.MaxPolicies < 1 || options.MaxPolicies > 128 || options.MaxJobs < 1 || options.MaxJobs > 8 || options.MaxAttempts < 1 || options.MaxAttempts > 5 || options.CheckEvery < time.Second || options.CheckEvery > 24*time.Hour || options.JobTimeout <= 0 || options.JobTimeout > 15*time.Minute || options.RenewBefore < time.Hour || options.RenewBefore > 90*24*time.Hour || options.RetryBase < time.Second || options.RetryBase > 24*time.Hour {
		return nil, fault.New("VALIDATION_FAILED", "续期策略容量或时间上限无效")
	}
	return &RenewalService{repository: options.Repository, manager: options.Manager, confirmations: options.Confirmations, operations: options.Operations, contexts: options.Contexts, clock: options.Clock,
		maxPolicies: options.MaxPolicies, maxJobs: options.MaxJobs, maxAttempts: options.MaxAttempts, checkEvery: options.CheckEvery, jobTimeout: options.JobTimeout,
		renewBefore: options.RenewBefore, retryBase: options.RetryBase, running: map[string]context.CancelFunc{}}, nil
}

func canonicalRenewalScope(scope RenewalScope) (RenewalScope, error) {
	if !names.ID(scope.OwnerID) || !names.ID(scope.CertificateID) || len(scope.Consumers) > 128 {
		return RenewalScope{}, fault.New("POLICY_SCOPE_DENIED", "续期资源范围无效")
	}
	issuance, err := canonicalScope(scope.Issuance)
	if err != nil {
		return RenewalScope{}, err
	}
	scope.Issuance = issuance
	consumers := make([]Consumer, 0, len(scope.Consumers))
	for _, input := range scope.Consumers {
		consumer, err := canonicalConsumer(input)
		if err != nil {
			return RenewalScope{}, err
		}
		consumers = append(consumers, consumer)
	}
	slices.SortFunc(consumers, func(a, b Consumer) int { return stringsCompareConsumer(a, b) })
	for index := 1; index < len(consumers); index++ {
		if consumerKey(consumers[index-1]) == consumerKey(consumers[index]) {
			return RenewalScope{}, fault.New("POLICY_SCOPE_DENIED", "续期消费者重复")
		}
	}
	scope.Consumers = consumers
	return scope, nil
}

// CanonicalRenewalScope 供宿主登记复用完整scope校验、排序与独立切片。
func CanonicalRenewalScope(scope RenewalScope) (RenewalScope, error) {
	return canonicalRenewalScope(scope)
}

func stringsCompareConsumer(a, b Consumer) int {
	one, two := consumerKey(a), consumerKey(b)
	if one < two {
		return -1
	}
	if one > two {
		return 1
	}
	return 0
}

func (s *RenewalService) load(ctx context.Context) (renewalLedger, string, error) {
	return readRenewalLedger(ctx, s.repository, s.maxPolicies, s.maxAttempts)
}

func readRenewalLedger(ctx context.Context, repository store.Repository, maxPolicies, maxAttempts int) (renewalLedger, string, error) {
	ledger := renewalLedger{Policies: []renewalPolicy{}}
	revision, _, err := store.Load(ctx, repository, renewalLedgerKey, &ledger)
	if err != nil {
		return renewalLedger{}, "", err
	}
	if len(ledger.Policies) > maxPolicies {
		return renewalLedger{}, "", fault.New("STATE_INVALID", "续期授权账本超过上限")
	}
	seen := map[string]bool{}
	for _, policy := range ledger.Policies {
		if !names.ID(policy.ID) || policy.Version == 0 || seen[policy.ID] || policy.Attempts < 0 || policy.Attempts > maxAttempts {
			return renewalLedger{}, "", fault.New("STATE_INVALID", "续期授权账本无效")
		}
		seen[policy.ID] = true
		canonical, err := canonicalRenewalScope(policy.Scope)
		if err != nil || !sameRenewalScope(canonical, policy.Scope) || policy.ExpiresAt.IsZero() || (policy.Attempts > 0 && policy.RunNumber == 0) || (policy.Enabled && !policy.Exhausted && policy.NextAt.IsZero()) {
			return renewalLedger{}, "", fault.New("STATE_INVALID", "续期持久范围或时间无效")
		}
		if policy.Job != nil && (!names.ID(policy.Job.AttemptID) || policy.Job.StartedAt.IsZero() || !policy.Job.LeaseUntil.After(policy.Job.StartedAt) || policy.Job.LeaseUntil.Sub(policy.Job.StartedAt) > 15*time.Minute || policy.Attempts == 0 || (policy.Job.OperationID != "" && !names.ID(policy.Job.OperationID))) {
			return renewalLedger{}, "", fault.New("STATE_INVALID", "续期租约无效")
		}
		if policy.Issue != nil {
			_, hashErr := hex.DecodeString(policy.Issue.Hash)
			if !names.ID(policy.Issue.AttemptID) || !names.ID(policy.Issue.ExpectedRevision) || len(policy.Issue.Hash) != 64 || hashErr != nil {
				return renewalLedger{}, "", fault.New("STATE_INVALID", "续期签发日志无效")
			}
		}
		if policy.DeployGeneration != 0 && policy.Issue == nil {
			return renewalLedger{}, "", fault.New("STATE_INVALID", "续期部署缺少原签发日志")
		}
	}
	return ledger, revision, nil
}

func (s *RenewalService) view(policy renewalPolicy) RenewalView {
	issuance := policy.Scope.Issuance
	issuance.Spec.SANs = slices.Clone(issuance.Spec.SANs)
	view := RenewalView{ID: policy.ID, Revision: strconv.FormatUint(policy.Version, 10), CertificateID: policy.Scope.CertificateID, Issuance: issuance,
		Consumers: slices.Clone(policy.Scope.Consumers), Enabled: policy.Enabled, Attempts: policy.Attempts, NextAt: policy.NextAt, ExpiresAt: policy.ExpiresAt, LastError: policy.LastError,
		Exhausted: policy.Exhausted, DeployGeneration: policy.DeployGeneration, Status: "scheduled"}
	switch {
	case !s.clock.Now().Before(policy.ExpiresAt):
		view.Status, view.Alert = "expired", "certificate_expired"
	case !policy.Enabled:
		view.Status, view.Alert = "disabled", "authorization_disabled"
	case policy.Exhausted:
		view.Status, view.Alert = "exhausted", "retries_exhausted"
	case policy.Job != nil:
		view.Status = "renewing"
	case policy.LastError == "RENEWAL_AUDIT_FAILED":
		view.Status, view.Alert = "audit_failed", "audit_failed"
	case policy.DeployGeneration != 0 && policy.LastError != "" && policy.Issue != nil && !policy.Issue.CleanupDone:
		view.Status, view.Alert = "issued_cleanup_failed", "dns_cleanup_failed"
	case policy.DeployGeneration != 0 && policy.LastError != "":
		view.Status, view.Alert = "issued_deployment_failed", "deployment_failed"
	case policy.LastError != "":
		view.Status, view.Alert = "renewal_failed", "renewal_failed"
	}
	if view.Alert == "" && policy.ExpiresAt.Sub(s.clock.Now()) <= 7*24*time.Hour {
		view.Alert = "certificate_expires_soon"
	}
	return view
}

// Enable 首次或重新启用必须经宿主确认完整范围；不从插件的 enabled 布尔值授权。
func (s *RenewalService) Enable(ctx context.Context, caller Caller, policyID, expectedRevision string, input RenewalScope) (RenewalView, error) {
	if err := validateCaller(caller, true); err != nil {
		return RenewalView{}, err
	}
	if caller.PolicyID != "" || !names.ID(policyID) || input.OwnerID != caller.OwnerID || expectedRevision == "" {
		return RenewalView{}, fault.New("POLICY_SCOPE_DENIED", "续期授权必须由当前资源 owner 的确认 operation 设置")
	}
	scope, err := canonicalRenewalScope(input)
	if err != nil {
		return RenewalView{}, err
	}
	view, err := s.manager.Get(ctx, caller, scope.CertificateID)
	if err != nil {
		return RenewalView{}, err
	}
	if !sameSpec(view.Spec, scope.Issuance.Spec) || view.CurrentGeneration == 0 || view.Pending != "" {
		return RenewalView{}, fault.New("POLICY_SCOPE_DENIED", "只能授权既有证书的固定 SAN 和用途")
	}
	bound := make([]Consumer, 0, len(view.Bindings))
	for _, binding := range view.Bindings {
		bound = append(bound, binding.Host.Consumer)
	}
	slices.SortFunc(bound, stringsCompareConsumer)
	if !slices.Equal(bound, scope.Consumers) {
		return RenewalView{}, fault.New("POLICY_SCOPE_DENIED", "续期授权消费者必须与当前绑定集合一致")
	}
	if err := s.confirmations.Confirm(ctx, caller, scope); err != nil {
		return RenewalView{}, backendFailure(err, "POLICY_SCOPE_DENIED")
	}
	if err := s.confirmations.Validate(ctx, scope); err != nil {
		return RenewalView{}, backendFailure(err, "POLICY_REVOKED")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, revision, err := s.load(ctx)
	if err != nil {
		return RenewalView{}, err
	}
	index := -1
	for position, policy := range ledger.Policies {
		if policy.ID == policyID {
			index = position
			break
		}
	}
	policy := renewalPolicy{ID: policyID, Version: 1, Scope: scope, Enabled: true, ExpiresAt: renewalExpiry(view, scope.Consumers)}
	if index >= 0 {
		previous := ledger.Policies[index]
		if previous.Scope.OwnerID != caller.OwnerID || expectedRevision != strconv.FormatUint(previous.Version, 10) || (previous.Job != nil && s.clock.Now().Before(previous.Job.LeaseUntil)) || s.running[policyID] != nil {
			return RenewalView{}, fault.New("REVISION_CONFLICT", "续期策略或进行中任务已变化")
		}
		if previous.Version == math.MaxUint64 {
			return RenewalView{}, fault.New("RESOURCE_EXHAUSTED", "续期策略 revision 已达上限")
		}
		policy.Version, policy.RunNumber = previous.Version+1, previous.RunNumber
	} else if expectedRevision != MissingRevision || len(ledger.Policies) >= s.maxPolicies {
		return RenewalView{}, fault.New("REVISION_CONFLICT", "续期策略已存在或容量不足")
	}
	for _, existing := range ledger.Policies {
		if existing.ID != policyID && existing.Scope.OwnerID == scope.OwnerID && existing.Scope.CertificateID == scope.CertificateID && existing.Enabled {
			return RenewalView{}, fault.New("POLICY_SCOPE_DENIED", "同一证书已有自动续期授权")
		}
	}
	policy.NextAt = s.dueAt(view)
	if index >= 0 {
		ledger.Policies[index] = policy
	} else {
		ledger.Policies = append(ledger.Policies, policy)
	}
	if _, err := store.Save(ctx, s.repository, renewalLedgerKey, revision, ledger); err != nil {
		return RenewalView{}, err
	}
	return s.view(policy), nil
}

// Revoke 更新授权 revision 并取消本进程租约；其他进程每步读取新 revision 后拒绝。
func (s *RenewalService) Revoke(ctx context.Context, caller Caller, policyID, expectedRevision string) (RenewalView, error) {
	if err := validateCaller(caller, true); err != nil {
		return RenewalView{}, err
	}
	if caller.PolicyID != "" {
		return RenewalView{}, fault.New("POLICY_SCOPE_DENIED", "续期 actor 不能改写授权")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, revision, err := s.load(ctx)
	if err != nil {
		return RenewalView{}, err
	}
	for index, policy := range ledger.Policies {
		if policy.ID != policyID {
			continue
		}
		if policy.Scope.OwnerID != caller.OwnerID || expectedRevision == "" || expectedRevision != strconv.FormatUint(policy.Version, 10) {
			return RenewalView{}, fault.New("REVISION_CONFLICT", "续期策略版本不符")
		}
		if err := s.confirmations.Confirm(ctx, caller, policy.Scope); err != nil {
			return RenewalView{}, backendFailure(err, "POLICY_SCOPE_DENIED")
		}
		if policy.Version == math.MaxUint64 {
			return RenewalView{}, fault.New("RESOURCE_EXHAUSTED", "续期策略 revision 已达上限")
		}
		policy.Enabled, policy.NextAt = false, time.Time{}
		policy.Version++
		ledger.Policies[index] = policy
		if _, err := store.Save(ctx, s.repository, renewalLedgerKey, revision, ledger); err != nil {
			return RenewalView{}, err
		}
		if cancel := s.running[policyID]; cancel != nil {
			cancel()
		}
		return s.view(policy), nil
	}
	return RenewalView{}, fault.New("NOT_FOUND", "续期策略不存在")
}

// Authorize 作为宿主 authorizer 的续期分支，每个 CA/DNS/部署原语都必须调用。
func (s *RenewalService) Authorize(ctx context.Context, request Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCaller(request.Caller, request.Access != Read); err != nil {
		return err
	}
	if request.Caller.PolicyID == "" {
		return nil
	}
	ledger, _, err := s.load(ctx)
	if err != nil {
		return err
	}
	for _, policy := range ledger.Policies {
		if policy.ID != request.Caller.PolicyID {
			continue
		}
		if !policy.Enabled || strconv.FormatUint(policy.Version, 10) != request.Caller.PolicyRevision || policy.Scope.OwnerID != request.Caller.OwnerID || policy.Scope.CertificateID != request.CertificateID || policy.Job == nil || policy.Job.OperationID != request.Caller.OperationID || s.clock.Now().Before(policy.Job.StartedAt) || !s.clock.Now().Before(policy.Job.LeaseUntil) {
			return fault.New("POLICY_REVOKED", "续期授权或租约已失效")
		}
		if request.Access != Read && request.Access != RenewExisting && request.Access != Bind {
			return fault.New("POLICY_SCOPE_DENIED", "续期 actor 操作超出固定资源范围")
		}
		if request.Access == RenewExisting {
			if request.Issuance == nil || !sameSpec(request.Spec, policy.Scope.Issuance.Spec) {
				return fault.New("POLICY_SCOPE_DENIED", "续期 SAN 或 CA 范围不符")
			}
			one, err := fingerprint(*request.Issuance)
			if err != nil {
				return err
			}
			two, err := fingerprint(policy.Scope.Issuance)
			if err != nil || one != two {
				return fault.New("POLICY_SCOPE_DENIED", "续期 provider、zone 或 CA 被扩大")
			}
		}
		if request.Access == Bind && (request.Consumer == nil || !slices.Contains(policy.Scope.Consumers, *request.Consumer) || request.Generation == 0 || request.Generation != policy.DeployGeneration) {
			return fault.New("POLICY_SCOPE_DENIED", "续期不能增加消费者或改变已签发的目标代")
		}
		if err := s.confirmations.Validate(ctx, policy.Scope); err != nil {
			return backendFailure(err, "POLICY_REVOKED")
		}
		return nil
	}
	return fault.New("POLICY_REVOKED", "续期授权不存在")
}

func (s *RenewalService) dueAt(view View) time.Time {
	for _, generation := range view.Generations {
		if generation.Number != view.CurrentGeneration {
			continue
		}
		// 稳定抖动至多一天，无 HTTPS 握手或额外常驻轮询依赖。
		digest := sha256.Sum256([]byte(view.ID + "\x00" + strconv.FormatUint(view.CurrentGeneration, 10)))
		jitter := time.Duration(binary.BigEndian.Uint16(digest[:2])) * time.Second
		due := generation.Metadata.NotAfter.Add(-s.renewBefore - jitter)
		if due.Before(s.clock.Now()) {
			return s.clock.Now()
		}
		return due
	}
	return s.clock.Now()
}
