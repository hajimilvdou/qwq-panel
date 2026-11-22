// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 受控写入与持久提交 ========================

// Options 注入宿主能力、KV 与时钟；生产环境不使用默认 fake。
type Options struct {
	Repository       store.Repository
	Providers        Providers
	Authorizer       Authorizer
	Clock            clock.Clock
	Random           io.Reader
	MaxRecords       int
	MaxReceipts      int
	AttemptLifetime  time.Duration
	ReconcileTimeout time.Duration
	MutationTimeout  time.Duration
}

// Manager 的本地锁串行化同实例；KV CAS 保护多实例和进程恢复。
type Manager struct {
	mu               contextLock
	repository       store.Repository
	providers        Providers
	authorizer       Authorizer
	clock            clock.Clock
	random           io.Reader
	maxRecords       int
	maxReceipts      int
	lifetime         time.Duration
	reconcileTimeout time.Duration
	mutationTimeout  time.Duration
}

// New 拒绝缺失的授权与真实后端，避免把内存实现当作生产成功。
func New(options Options) (*Manager, error) {
	if options.Repository == nil || options.Providers == nil || options.Authorizer == nil {
		return nil, fault.New("BACKEND_REQUIRED", "DNS 模块需要受控状态、提供商和授权后端")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.MaxRecords == 0 {
		options.MaxRecords = 2048
	}
	if options.MaxReceipts == 0 {
		options.MaxReceipts = 128
	}
	if options.AttemptLifetime == 0 {
		options.AttemptLifetime = 30 * time.Minute
	}
	if options.ReconcileTimeout == 0 {
		options.ReconcileTimeout = 15 * time.Second
	}
	if options.MutationTimeout == 0 {
		options.MutationTimeout = 30 * time.Second
	}
	if options.MaxRecords < 1 || options.MaxRecords > 4096 || options.MaxReceipts < 1 || options.MaxReceipts > 256 || options.AttemptLifetime < time.Minute || options.AttemptLifetime > 24*time.Hour || options.ReconcileTimeout <= 0 || options.ReconcileTimeout > time.Minute {
		return nil, fault.New("VALIDATION_FAILED", "DNS 模块资源或时间上限无效")
	}
	if options.MutationTimeout <= 0 || options.MutationTimeout > time.Minute {
		return nil, fault.New("VALIDATION_FAILED", "DNS 写入超时无效")
	}
	return &Manager{repository: options.Repository, providers: options.Providers, authorizer: options.Authorizer,
		clock: options.Clock, random: options.Random, maxRecords: options.MaxRecords, maxReceipts: options.MaxReceipts,
		lifetime: options.AttemptLifetime, reconcileTimeout: options.ReconcileTimeout, mutationTimeout: options.MutationTimeout}, nil
}

func (m *Manager) authorize(ctx context.Context, caller Caller, scope Scope, access Access) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateScope(scope); err != nil {
		return err
	}
	if !names.ID(caller.OwnerID) || (access != Read && !names.ID(caller.OperationID)) {
		return fault.New("PERMISSION_DENIED", "调用者或派发 operation 无效")
	}
	return m.authorizer.Authorize(ctx, caller, scope, access)
}

func (m *Manager) snapshot(ctx context.Context, caller Caller, scope Scope) (Snapshot, Provider, error) {
	bounded, cancel := context.WithTimeout(ctx, m.reconcileTimeout)
	defer cancel()
	ctx = bounded
	if err := m.authorize(ctx, caller, scope, Read); err != nil {
		return Snapshot{}, nil, err
	}
	provider, err := m.providers.For(ctx, scope)
	if err != nil || provider == nil {
		return Snapshot{}, nil, providerFailure(err)
	}
	records, err := provider.List(ctx, scope)
	if err != nil {
		return Snapshot{}, nil, providerFailure(err)
	}
	normalized, revision, err := normalizedSnapshot(scope, records, m.maxRecords)
	if err != nil {
		return Snapshot{}, nil, err
	}
	return Snapshot{Scope: scope, Records: normalized, Revision: revision, CollectedAt: m.clock.Now().UTC()}, provider, nil
}

// List 公开首期记录和快照版本；私有归属标记不进入 UI。
func (m *Manager) List(ctx context.Context, caller Caller, scope Scope) (Snapshot, error) {
	snapshot, _, err := m.snapshot(ctx, caller, scope)
	if err != nil {
		return Snapshot{}, err
	}
	visible := make([]Record, 0, len(snapshot.Records))
	for _, record := range snapshot.Records {
		if record.Type.Supported() {
			record.ManagedBy = ""
			visible = append(visible, record)
		}
	}
	snapshot.Records = visible
	return snapshot, nil
}

// PlanChange 只读取真实快照，不写 KV 或提供商。
func (m *Manager) PlanChange(ctx context.Context, input Request) (Plan, error) {
	request, err := validateRequest(input)
	if err != nil {
		return Plan{}, err
	}
	snapshot, _, err := m.snapshot(ctx, request.Caller, request.Scope)
	if err != nil {
		return Plan{}, err
	}
	plan, err := planChange(request, snapshot.Records, snapshot.Revision)
	if plan.Before != nil {
		plan.Before.ManagedBy = ""
	}
	if plan.After != nil {
		plan.After.ManagedBy = ""
	}
	return plan, err
}

// Apply 每个 attempt 只发送一次变更；不确定结果通过读取对账恢复。
func (m *Manager) Apply(ctx context.Context, input Request) (Receipt, error) {
	return m.apply(ctx, input, false)
}

func (m *Manager) apply(ctx context.Context, input Request, challenge bool) (Receipt, error) {
	request, err := validateRequest(input)
	if err != nil {
		return Receipt{}, err
	}
	if challenge != (request.CertificateID != "") {
		return Receipt{}, fault.New("VALIDATION_FAILED", "DNS-01 必须绑定证书资源")
	}
	access := Manage
	if challenge {
		access = Challenge
	}
	if err := m.authorize(ctx, request.Caller, request.Scope, access); err != nil {
		return Receipt{}, err
	}
	if err := m.mu.Lock(ctx); err != nil {
		return Receipt{}, err
	}
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	state, revision, err := m.load(ctx, request.Scope)
	if err != nil {
		return Receipt{}, err
	}
	hash, err := digest(request)
	if err != nil {
		return Receipt{}, err
	}
	for _, saved := range state.Receipts {
		if saved.Request.AttemptID == request.AttemptID {
			if saved.Hash != hash || saved.Challenge != challenge {
				return Receipt{}, fault.New("ATTEMPT_CONFLICT", "attempt 已用于不同请求")
			}
			if saved.State == Rejected {
				return receipt(saved), fault.New(saved.ErrorCode, "上次变更已被明确拒绝，请重新预演")
			}
			return receipt(saved), nil
		}
	}
	if state.Active != nil {
		if state.Active.Hash != hash || state.Active.Challenge != challenge {
			return Receipt{}, fault.New("DNS_BUSY", "zone 存在待对账变更")
		}
		return m.reconcile(ctx, request.Caller, request.Scope, &state, revision)
	}
	state.Receipts = m.trim(state.Receipts)
	if len(state.Receipts) >= m.maxReceipts {
		return Receipt{}, fault.New("RESOURCE_EXHAUSTED", "DNS 收据已达上限，请先清理 challenge 或等待收据到期")
	}
	snapshot, provider, err := m.snapshot(ctx, request.Caller, request.Scope)
	if err != nil {
		return Receipt{}, err
	}
	plan, err := planChange(request, snapshot.Records, snapshot.Revision)
	if err != nil {
		return Receipt{}, err
	}
	marker := make([]byte, 32)
	if _, err := io.ReadFull(m.random, marker); err != nil {
		return Receipt{}, fault.New("INTERNAL", "无法生成记录归属标记")
	}
	active := &attempt{Request: request, Hash: hash, Before: plan.Before, State: Submitted, Challenge: challenge,
		Marker: hex.EncodeToString(marker), CreatedAt: m.clock.Now().UTC(), ExpiresAt: m.clock.Now().Add(m.lifetime).UTC()}
	for _, record := range snapshot.Records {
		active.Baseline = append(active.Baseline, record.ID)
	}
	state.Active = active
	revision, err = store.Save(ctx, m.repository, journalKey(request.Scope), revision, state)
	if err != nil {
		return Receipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return m.reject(ctx, request.Scope, &state, revision, "CANCELED")
	}
	if err := m.authorize(ctx, request.Caller, request.Scope, access); err != nil {
		return m.reject(ctx, request.Scope, &state, revision, fault.Code(err))
	}
	desired := request.Change.Record
	if request.Change.Action == Create {
		desired.ManagedBy = active.Marker
	}
	if active.Before != nil {
		desired.ManagedBy = active.Before.ManagedBy
	}
	var written Record
	var writeErr error
	writeCtx, cancelWrite := context.WithTimeout(ctx, m.mutationTimeout)
	switch request.Change.Action {
	case Create:
		written, writeErr = provider.Create(writeCtx, request.Scope, desired)
	case Update:
		written, writeErr = provider.Update(writeCtx, request.Scope, *active.Before, desired)
	case Delete:
		writeErr = provider.Delete(writeCtx, request.Scope, *active.Before)
	}
	cancelWrite()
	// 提供商返回的 ID 先持久化；即使后续查询或插件 RPC 丢失也不会重新发送。
	if written.ID != "" {
		normalized, parseErr := normalizeRecord(request.Scope, written, false)
		if parseErr == nil && sameContent(normalized, desired) &&
			((request.Change.Action == Create && !slices.Contains(active.Baseline, normalized.ID)) || (active.Before != nil && normalized.ID == active.Before.ID)) {
			active.Record = &normalized
			revision, err = m.saveDetached(ctx, request.Scope, revision, state)
			if err != nil {
				return receipt(*active), uncertain("STATE_UNAVAILABLE", "变更已发送，但记录 ID 未能持久化")
			}
		}
	}
	var failure *fault.Error
	if errors.As(writeErr, &failure) && failure.NotApplied && written.ID == "" {
		result, rejectErr := m.reject(ctx, request.Scope, &state, revision, failure.Code)
		if rejectErr != nil && fault.Code(rejectErr) != failure.Code {
			return result, rejectErr
		}
		return result, providerFailure(writeErr)
	}
	result, err := m.reconcile(ctx, request.Caller, request.Scope, &state, revision)
	if err != nil {
		return result, err
	}
	if cancelErr := ctx.Err(); cancelErr != nil {
		return result, cancelErr
	}
	return result, nil
}

func receipt(saved attempt) Receipt {
	result := Receipt{AttemptID: saved.Request.AttemptID, State: saved.State, ErrorCode: saved.ErrorCode}
	if saved.Record != nil {
		result.RecordID, result.Revision = saved.Record.ID, saved.Record.Revision
	}
	return result
}

func uncertain(code, detail string) error {
	return &fault.Error{Code: code, Detail: detail, Uncertain: true}
}

func providerFailure(err error) error {
	code := fault.Code(err)
	switch code {
	case "RATE_LIMITED", "CREDENTIAL_REVOKED", "ZONE_DENIED", "RECORD_CONFLICT", "CNAME_CONFLICT", "PROVIDER_INVALID", "RESOURCE_EXHAUSTED", "DNS_UNAVAILABLE", "DNS_UNSAFE_SERVER", "DNS_INVALID_RESPONSE", "DNS_NO_SOURCES", "DNS_NOT_PROPAGATED", "CAA_FORBIDDEN":
		return &fault.Error{Code: code, Detail: "DNS 提供商拒绝请求或暂不可用", RetryAt: fault.Retry(err)}
	default:
		return fault.New("PROVIDER_UNAVAILABLE", "DNS 提供商暂不可用")
	}
}
