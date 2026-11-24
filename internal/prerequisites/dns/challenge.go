// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/contextbudget"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

var challengeValuePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ======================== DNS-01 自有记录生命周期 ========================

// ChallengeRequest 的 SAN 与 certificate_id 由受控 CA 订单和资源授权提供。
type ChallengeRequest struct {
	Caller           Caller
	Scope            Scope
	CertificateID    string
	AttemptID        string
	SAN              string
	Value            string
	ExpectedRevision string
}

// ChallengeIntent 保留 DNS 实际目标；wildcard 与普通 SAN 恢复共用原 TXT 名称。
// 当前 caller 来自真实 operation，attempt/内容则必须匹配宿主原 CA 日志。
type ChallengeIntent struct {
	Caller           Caller
	Scope            Scope
	CertificateID    string
	DNSAttemptID     string
	Name             string
	Value            string
	ExpectedRevision string
}

func (ChallengeIntent) String() string   { return "dns.ChallengeIntent{[REDACTED]}" }
func (ChallengeIntent) GoString() string { return "dns.ChallengeIntent{[REDACTED]}" }

// ChallengeAuthorizations 把实际请求绑定到原 CA intent；缺失实现不能默认放行。
// Source 只供私有原记录查询，Cleanup 必须进一步核对已确认的自有记录事实。
type ChallengeAuthorizations interface {
	ChallengeContext(context.Context, ChallengeIntent) (context.Context, error)
	AuthorizeChallengeSource(context.Context, Caller, Scope, string, string) error
	AuthorizeChallengeCleanup(context.Context, OwnedChallenge) error
}

// OwnedChallenge 仅能由 Manager 从已校验私有日志生成，不接受 DTO 或 bearer。
type OwnedChallenge struct {
	manager       *Manager
	caller        Caller
	scope         Scope
	certificateID string
	attemptID     string
	request       Request
	record        Record
}

func (OwnedChallenge) String() string               { return "dns.OwnedChallenge{[REDACTED]}" }
func (OwnedChallenge) GoString() string             { return "dns.OwnedChallenge{[REDACTED]}" }
func (OwnedChallenge) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

func (o OwnedChallenge) Caller() Caller            { return o.caller }
func (o OwnedChallenge) Scope() Scope              { return o.scope }
func (o OwnedChallenge) CertificateID() string     { return o.certificateID }
func (o OwnedChallenge) DNSAttemptID() string      { return o.attemptID }
func (o OwnedChallenge) Record() Record            { return o.record }
func (o OwnedChallenge) BelongsTo(m *Manager) bool { return m != nil && o.manager == m }

func (o OwnedChallenge) Intent() ChallengeIntent {
	return challengeIntent(o.caller, o.request)
}

// SameRecord 只接受同一 Manager 生成的原记录及意图，清理阶段 CAS 变化不扩权。
func (o OwnedChallenge) SameRecord(other OwnedChallenge) bool {
	return o.manager != nil && o.manager == other.manager && o.caller == other.caller && o.scope == other.scope &&
		o.certificateID == other.certificateID && o.attemptID == other.attemptID && o.record == other.record && o.request == other.request
}

func challengeIntent(caller Caller, request Request) ChallengeIntent {
	return ChallengeIntent{Caller: caller, Scope: request.Scope, CertificateID: request.CertificateID, DNSAttemptID: request.AttemptID,
		Name: request.Change.Record.Name, Value: request.Change.Record.Value, ExpectedRevision: request.ExpectedRevision}
}

func (m *Manager) challengeContext(ctx context.Context, intent ChallengeIntent) (context.Context, error) {
	guard, found := m.authorizer.(ChallengeAuthorizations)
	if !found || guard == nil {
		return nil, fault.New("BACKEND_REQUIRED", "DNS-01 需要原 CA 请求授权后端")
	}
	bound, err := guard.ChallengeContext(ctx, intent)
	if err != nil {
		return nil, err
	}
	if bound == nil {
		return nil, fault.New("BACKEND_REQUIRED", "DNS-01 请求授权缺少私有上下文")
	}
	return bound, nil
}

// OwnedChallenge 仅读取指定 owner/certificate/attempt 的已写入 ID 与完整指纹。
// 未确认 ID 或未知写入不能认领同名同值 TXT，也不能用该读取权限访问提供商。
func (m *Manager) OwnedChallenge(ctx context.Context, caller Caller, scope Scope, certificateID, attemptID string) (OwnedChallenge, bool, error) {
	guard, found := m.authorizer.(ChallengeAuthorizations)
	if !found || guard == nil {
		return OwnedChallenge{}, false, fault.New("BACKEND_REQUIRED", "原自有 TXT 读取需要宿主请求授权")
	}
	if validateScope(scope) != nil || !names.ID(caller.OwnerID) || !names.ID(caller.OperationID) || !names.ID(certificateID) || !names.ID(attemptID) {
		return OwnedChallenge{}, false, fault.New("VALIDATION_FAILED", "原自有 TXT 查询目标无效")
	}
	if err := guard.AuthorizeChallengeSource(ctx, caller, scope, certificateID, attemptID); err != nil {
		return OwnedChallenge{}, false, err
	}
	if err := m.mu.Lock(ctx); err != nil {
		return OwnedChallenge{}, false, err
	}
	defer m.mu.Unlock()
	state, _, err := m.load(ctx, scope)
	if err != nil {
		return OwnedChallenge{}, false, err
	}
	var saved *attempt
	if state.Active != nil && state.Active.Request.AttemptID == attemptID {
		saved = state.Active
	}
	for i := range state.Receipts {
		if state.Receipts[i].Request.AttemptID == attemptID {
			saved = &state.Receipts[i]
			break
		}
	}
	if saved == nil {
		return OwnedChallenge{}, false, uncertain("OUTCOME_UNKNOWN", "原 DNS 日志缺失，不能证明没有写入或已经清理")
	}
	if !saved.Challenge || saved.Request.Caller.OwnerID != caller.OwnerID || saved.Request.CertificateID != certificateID {
		return OwnedChallenge{}, false, fault.New("PERMISSION_DENIED", "TXT 查询不能认领其他 owner 或证书的意图")
	}
	if saved.State == Cleaned || saved.State == Rejected {
		return OwnedChallenge{}, false, nil
	}
	owned, err := m.ownedChallenge(caller, scope, *saved)
	if err != nil {
		return OwnedChallenge{}, false, err
	}
	if err := guard.AuthorizeChallengeSource(ctx, caller, scope, certificateID, attemptID); err != nil {
		return OwnedChallenge{}, false, err
	}
	return owned, true, nil
}

func (m *Manager) ownedChallenge(caller Caller, scope Scope, saved attempt) (OwnedChallenge, error) {
	if saved.Record == nil {
		return OwnedChallenge{}, uncertain("OUTCOME_UNKNOWN", "原 TXT 缺少已确认记录 ID，保留写入证据")
	}
	if !saved.Challenge || saved.Request.Caller.OwnerID != caller.OwnerID || saved.Request.Scope != scope ||
		saved.Request.CertificateID == "" || saved.Request.Change.Action != Create || saved.Record.ID == "" ||
		saved.Record.Type != TXT || !sameContent(*saved.Record, saved.Request.Change.Record) {
		return OwnedChallenge{}, fault.New("STATE_INVALID", "原自有 TXT 的记录身份或内容无效")
	}
	return OwnedChallenge{manager: m, caller: caller, scope: scope, certificateID: saved.Request.CertificateID,
		attemptID: saved.Request.AttemptID, request: saved.Request, record: *saved.Record}, nil
}

func (m *Manager) authorizeOwnedCleanup(ctx context.Context, caller Caller, scope Scope, saved attempt) error {
	guard, found := m.authorizer.(ChallengeAuthorizations)
	if !found || guard == nil {
		return fault.New("BACKEND_REQUIRED", "原自有 TXT 清理需要宿主请求授权")
	}
	owned, err := m.ownedChallenge(caller, scope, saved)
	if err != nil {
		return err
	}
	return guard.AuthorizeChallengeCleanup(ctx, owned)
}

func (ChallengeRequest) String() string   { return "dns.ChallengeRequest{[REDACTED]}" }
func (ChallengeRequest) GoString() string { return "dns.ChallengeRequest{[REDACTED]}" }

// PresentChallenge 保存当前 attempt 的归属证据，不认领同名既有 TXT。
func (m *Manager) PresentChallenge(ctx context.Context, request ChallengeRequest) (Receipt, error) {
	san, err := names.SAN(request.SAN)
	if err != nil || !names.ID(request.CertificateID) || !challengeValuePattern.MatchString(request.Value) {
		return Receipt{}, fault.New("VALIDATION_FAILED", "DNS-01 证书、SAN 或 challenge 值无效")
	}
	name := "_acme-challenge." + strings.TrimPrefix(san, "*.")
	ttl := uint32(60)
	if request.Scope.Kind == Aliyun || request.Scope.Kind == DNSPod {
		ttl = 600
	}
	ctx, err = m.challengeContext(ctx, ChallengeIntent{Caller: request.Caller, Scope: request.Scope, CertificateID: request.CertificateID,
		DNSAttemptID: request.AttemptID, Name: name, Value: request.Value, ExpectedRevision: request.ExpectedRevision})
	if err != nil {
		return Receipt{}, err
	}
	return m.apply(ctx, Request{Caller: request.Caller, Scope: request.Scope, AttemptID: request.AttemptID,
		ExpectedRevision: request.ExpectedRevision, CertificateID: request.CertificateID,
		Change: Change{Action: Create, Record: Record{Type: TXT, Name: name, Value: request.Value, TTL: ttl}}}, true)
}

// WithChallenge 的成功、失败与取消路径均执行有界清理；清理失败保留日志告警。
func (m *Manager) WithChallenge(ctx context.Context, request ChallengeRequest, use func(context.Context) error) (err error) {
	if use == nil {
		return fault.New("VALIDATION_FAILED", "DNS-01 缺少受控验证步骤")
	}
	defer func() {
		bounded, cancel := contextbudget.Detached(ctx, m.reconcileTimeout)
		defer cancel()
		cleanupErr := m.CleanupChallenge(bounded, request.Caller, request.Scope, request.CertificateID, request.AttemptID)
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	if _, err = m.PresentChallenge(ctx, request); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return use(ctx)
}

// CleanupChallenge 只删除已确认的本证书 attempt 记录 ID；凭据撤销时保留证据。
func (m *Manager) CleanupChallenge(ctx context.Context, caller Caller, scope Scope, certificateID, attemptID string) error {
	if !names.ID(certificateID) || !names.ID(attemptID) {
		return fault.New("VALIDATION_FAILED", "证书或 attempt 标识无效")
	}
	if err := m.authorize(ctx, caller, scope, Cleanup); err != nil {
		return err
	}
	if err := m.mu.Lock(ctx); err != nil {
		return err
	}
	defer m.mu.Unlock()
	state, revision, err := m.load(ctx, scope)
	if err != nil {
		return err
	}
	owned := func(saved attempt) bool {
		return saved.Challenge && saved.Request.AttemptID == attemptID && saved.Request.CertificateID == certificateID && saved.Request.Caller.OwnerID == caller.OwnerID
	}
	if state.Active != nil {
		if !owned(*state.Active) {
			return fault.New("DNS_BUSY", "zone 存在其他待对账变更")
		}
		if state.Active.Record != nil {
			if err := m.authorizeOwnedCleanup(ctx, caller, scope, *state.Active); err != nil {
				return err
			}
		}
		if state.Active.Cleaning {
			_, err := m.reconcileCleanup(ctx, caller, scope, &state, revision)
			return err
		}
		if _, err := m.reconcile(ctx, caller, scope, &state, revision); err != nil {
			return err
		}
		state, revision, err = m.load(ctx, scope)
		if err != nil {
			return err
		}
	}
	index := -1
	for position, saved := range state.Receipts {
		if saved.Request.AttemptID == attemptID {
			if !owned(saved) {
				return fault.New("PERMISSION_DENIED", "不能清理其他 owner 或证书的 challenge")
			}
			index = position
			break
		}
	}
	if index < 0 {
		return uncertain("OUTCOME_UNKNOWN", "原 TXT 清理收据缺失，不能确认本次写入已经补偿")
	}
	saved := state.Receipts[index]
	if saved.State == Cleaned || saved.State == Rejected {
		return nil
	}
	if saved.Record == nil || saved.Request.Change.Action != Create {
		return fault.New("STATE_INVALID", "DNS-01 缺少自有记录证据")
	}
	if err := m.authorizeOwnedCleanup(ctx, caller, scope, saved); err != nil {
		return err
	}
	snapshot, provider, err := m.snapshot(ctx, caller, scope)
	if err != nil {
		return err
	}
	present := false
	for _, record := range snapshot.Records {
		if record.ID != saved.Record.ID {
			continue
		}
		if record.Revision != saved.Record.Revision {
			return fault.New("RECORD_CONFLICT", "本次 TXT 已被外部修改，不能自动删除")
		}
		present = true
	}
	// 清理也先占用同一 CAS 日志，防止两进程重复发出删除。
	saved.Cleaning, saved.State = true, Submitted
	state.Active = &saved
	state.Receipts = append(state.Receipts[:index], state.Receipts[index+1:]...)
	revision, err = store.Save(ctx, m.repository, journalKey(scope), revision, state)
	if err != nil {
		return err
	}
	if !present {
		_, err := m.finish(ctx, scope, &state, revision, Cleaned)
		return err
	}
	if err := m.authorizeOwnedCleanup(ctx, caller, scope, saved); err != nil {
		return err
	}
	writeCtx, cancelWrite := context.WithTimeout(ctx, m.mutationTimeout)
	deleteErr := provider.Delete(writeCtx, scope, *saved.Record)
	cancelWrite()
	var failure *fault.Error
	if errors.As(deleteErr, &failure) && failure.NotApplied {
		saved.Cleaning, saved.State = false, Applied
		state.Active = nil
		state.Receipts = append(state.Receipts, saved)
		if _, err := m.saveDetached(ctx, scope, revision, state); err != nil {
			return uncertain("STATE_UNAVAILABLE", "TXT 删除被拒绝，清理状态未能保存")
		}
		return providerFailure(deleteErr)
	}
	_, err = m.reconcileCleanup(ctx, caller, scope, &state, revision)
	return err
}

func (m *Manager) reconcileCleanup(ctx context.Context, caller Caller, scope Scope, state *journal, revision string) (Receipt, error) {
	bounded, cancel := contextbudget.Detached(ctx, m.reconcileTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return Receipt{}, err
	}
	if state.Active == nil {
		return Receipt{}, fault.New("STATE_INVALID", "TXT 删除对账缺少原记录证据")
	}
	if err := m.authorizeOwnedCleanup(bounded, caller, scope, *state.Active); err != nil {
		return Receipt{}, err
	}
	snapshot, _, err := m.snapshot(bounded, caller, scope)
	if err != nil {
		state.Active.ErrorCode = fault.Code(err)
		return m.markUnknown(ctx, scope, state, revision, "TXT 删除已发送，等待提供商恢复后确认清理")
	}
	for _, record := range snapshot.Records {
		if record.ID == state.Active.Record.ID {
			return m.markUnknown(ctx, scope, state, revision, "TXT 删除结果未确认；不能重新发送或删除其他记录")
		}
	}
	return m.finish(ctx, scope, state, revision, Cleaned)
}
