// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
)

// ======================== 原 executor 的私有 proof 与单次硬清理窗口 ========================

type runtimeDispatchProof struct {
	service      *Service
	job          *runningJob
	exact        DispatchTarget
	original     *Operation
	limits       Limits
	approved     bool
	confirmation actor.Actor
}

type runtimeCleanupWindow struct {
	deadline     time.Time
	wallDeadline time.Time
}

// CleanupSource 只描述原证书/签发/DNS attempt 的私有事实查询，不提供记录值。
// DNSAttemptID 仅在初始原 ACME journal 读取时可空；mint 与任何请求必须非空。
type CleanupSource struct {
	CertificateID  string
	IssueAttemptID string
	DNSAttemptID   string
}

func (CleanupSource) String() string   { return "operations.CleanupSource{[REDACTED]}" }
func (CleanupSource) GoString() string { return "operations.CleanupSource{[REDACTED]}" }

// CleanupLease 不可由 DTO 构造或序列化；只授权原已确认记录的补偿清理。
// provider/zone/证书范围及自有记录事实由宿主业务授权器再次校验。
type CleanupLease struct {
	proof        *runtimeDispatchProof
	window       *runtimeCleanupWindow
	source       CleanupSource
	recordID     string
	fingerprint  string
	deadline     time.Time
	wallDeadline time.Time
}

func (*runtimeDispatchProof) String() string               { return "operations.runtimeDispatchProof{[REDACTED]}" }
func (*runtimeDispatchProof) GoString() string             { return "operations.runtimeDispatchProof{[REDACTED]}" }
func (*runtimeDispatchProof) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*CleanupLease) String() string                       { return "operations.CleanupLease{[REDACTED]}" }
func (*CleanupLease) GoString() string                     { return "operations.CleanupLease{[REDACTED]}" }
func (*CleanupLease) MarshalJSON() ([]byte, error)         { return []byte(`{"redacted":true}`), nil }

func (s *Service) captureRuntimeProof(exact DispatchTarget, op *Operation) (*runtimeDispatchProof, error) {
	if s == nil || op == nil || op.StartedAt == nil || op.Attempt < 0 {
		return nil, dispatchDenied()
	}
	s.runMu.Lock()
	job := s.running[op.ID]
	alive := cleanupJobAlive(job)
	s.runMu.Unlock()
	if !alive {
		return nil, dispatchDenied()
	}
	original := *op
	original.Args = bytes.Clone(op.Args)
	original.Meta.Capabilities = slices.Clone(op.Meta.Capabilities)
	original.Meta.ArgsSchema = bytes.Clone(op.Meta.ArgsSchema)
	started := *op.StartedAt
	original.StartedAt = &started
	return &runtimeDispatchProof{service: s, job: job, exact: exact, original: &original}, nil
}

func cleanupJobAlive(job *runningJob) bool {
	if job == nil || job.done == nil {
		return false
	}
	select {
	case <-job.done:
		return false
	default:
		return true
	}
}

func (s *Service) cleanupRuntimeAlive(proof *runtimeDispatchProof) bool {
	if s == nil || proof == nil || proof.service != s || proof.original == nil {
		return false
	}
	s.runMu.Lock()
	alive := s.running[proof.original.ID] == proof.job && cleanupJobAlive(proof.job)
	s.runMu.Unlock()
	return alive
}

func sameCleanupIntent(original, current *Operation) bool {
	return original != nil && current != nil && original.StartedAt != nil && current.StartedAt != nil &&
		current.Status == Running && original.ID == current.ID && original.NodeID == current.NodeID &&
		original.Attempt == current.Attempt && original.EffectiveRisk == current.EffectiveRisk &&
		original.Permission == current.Permission && original.Effect == current.Effect && original.Mode == current.Mode &&
		original.ParentOperationID == current.ParentOperationID && reflect.DeepEqual(original.Preconditions, current.Preconditions) &&
		sameDispatch(original, current)
}

func (s *Service) dispatchConfirmation(ctx context.Context, op *Operation) (actor.Actor, error) {
	if op.ApprovalID == "" {
		return actor.Actor{}, nil
	}
	approval, err := loadApproval(ctx, s.db.Reader(), op.ApprovalID)
	if err != nil || approval.Status != ApprovalApproved || approval.OperationID != op.ID || approval.DecidedBy == nil || approval.DecidedAt == nil ||
		approval.DecidedAt.Before(approval.CreatedAt) || !approval.DecidedAt.Before(approval.ExpiresAt) {
		return actor.Actor{}, dispatchDenied()
	}
	who := *approval.DecidedBy
	if who.Kind != actor.Human || who.Valid() != nil || !ids.Valid(who.ID, ids.User) {
		return actor.Actor{}, dispatchDenied()
	}
	// 审批库本来只保存主体；显式丢弃登录标志，不能作为新会话或 mint 权限。
	who.SessionID, who.MFA = "", false
	return who, nil
}

func sameCleanupSnapshot(snapshot DispatchedContext, proof *runtimeDispatchProof) bool {
	if proof == nil || proof.original == nil {
		return false
	}
	op := proof.original
	action := op.Meta
	action.ArgsSchema = nil
	return snapshot.OperationID == op.ID && snapshot.Actor == op.Actor && snapshot.Target == op.Target &&
		reflect.DeepEqual(snapshot.Action, action) && snapshot.ArgsDigest == op.ArgsDigest && bytes.Equal(snapshot.Args, op.Args) &&
		snapshot.ExpectedRevision == op.ExpectedRevision && snapshot.Deadline.Equal(op.StartedAt.Add(op.Timeout)) &&
		snapshot.Limits == proof.limits && snapshot.Approved == proof.approved && snapshot.ConfirmationActor == proof.confirmation
}

// CheckCleanupSource 仅核对原私有执行 proof，供宿主读取精确清理候选事实。
// 它不返回新的普通 DispatchedContext，也不开放任何写入或秘密读取。
func (s *Service) CheckCleanupSource(ctx context.Context, accepted DispatchedContext, source CleanupSource, ttl time.Duration) error {
	proof := accepted.runtimeProof
	if ttl <= 0 || ttl > 30*time.Second || !sameCleanupSnapshot(accepted, proof) || accepted.Action.Effect == EffectRead || accepted.Action.Mode != ModeJob ||
		!acceptedCleanupSource(proof, source) {
		return dispatchDenied()
	}
	if _, err := s.openCleanupWindow(proof, ttl); err != nil {
		return err
	}
	return s.checkCleanupProof(ctx, proof)
}

func acceptedCleanupSource(proof *runtimeDispatchProof, source CleanupSource) bool {
	if proof == nil || proof.original == nil || proof.exact.PluginID != "tls.certificates" || proof.original.Meta.Permission != "system.certificates:manage" ||
		(proof.original.Meta.Operation != "certificates.issue" && proof.original.Meta.Operation != "renew_existing") ||
		!boundedCleanupID(source.CertificateID) || !boundedCleanupID(source.IssueAttemptID) || (source.DNSAttemptID != "" && !boundedCleanupID(source.DNSAttemptID)) {
		return false
	}
	var identifiers struct {
		CertificateID string `json:"certificate_id"`
		AttemptID     string `json:"attempt_id"`
	}
	if json.Unmarshal(proof.original.Args, &identifiers) != nil {
		return false
	}
	return identifiers.CertificateID == source.CertificateID && identifiers.AttemptID == source.IssueAttemptID &&
		proof.exact.Subject == "plugins/tls.certificates/resources/certificates/"+source.CertificateID
}

func boundedCleanupID(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n")
}

func (s *Service) openCleanupWindow(proof *runtimeDispatchProof, ttl time.Duration) (*runtimeCleanupWindow, error) {
	if s == nil || proof == nil || proof.service != s || proof.original == nil {
		return nil, dispatchDenied()
	}
	now, wallNow := s.clock.Now(), time.Now()
	s.runMu.Lock()
	if s.running[proof.original.ID] != proof.job || !cleanupJobAlive(proof.job) {
		s.runMu.Unlock()
		return nil, dispatchDenied()
	}
	window := proof.job.cleanupWindow
	if window == nil {
		window = &runtimeCleanupWindow{deadline: now.Add(ttl), wallDeadline: wallNow.Add(ttl)}
		proof.job.cleanupWindow = window
	}
	alive := now.Before(window.deadline) && wallNow.Before(window.wallDeadline)
	s.runMu.Unlock()
	if !alive {
		return nil, dispatchDenied()
	}
	return window, nil
}

func (s *Service) cleanupWindowValid(proof *runtimeDispatchProof) bool {
	if s == nil || proof == nil || proof.service != s || proof.original == nil {
		return false
	}
	now, wallNow := s.clock.Now(), time.Now()
	s.runMu.Lock()
	alive := s.running[proof.original.ID] == proof.job && cleanupJobAlive(proof.job)
	if alive && proof.job.cleanupWindow != nil {
		window := proof.job.cleanupWindow
		alive = now.Before(window.deadline) && wallNow.Before(window.wallDeadline)
	}
	s.runMu.Unlock()
	return alive
}

func (s *Service) cleanupOperation(ctx context.Context, proof *runtimeDispatchProof) (*Operation, error) {
	if !s.cleanupWindowValid(proof) {
		return nil, dispatchDenied()
	}
	op, err := loadOperation(ctx, s.db.Reader(), proof.original.ID)
	if err != nil || !sameCleanupIntent(proof.original, op) {
		return nil, dispatchDenied()
	}
	return op, nil
}

func (s *Service) checkCleanupProof(ctx context.Context, proof *runtimeDispatchProof) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.authorizer == nil || s.policy == nil {
		return dispatchDenied()
	}
	if !s.cleanupWindowValid(proof) {
		return dispatchDenied()
	}
	s.runMu.Lock()
	window := proof.job.cleanupWindow
	if window == nil {
		s.runMu.Unlock()
		return dispatchDenied()
	}
	deadline, wallDeadline := window.deadline, window.wallDeadline
	s.runMu.Unlock()
	bounded, cancel, err := cleanupBudgetContext(ctx, deadline, wallDeadline, s.clock.Now())
	if err != nil {
		return err
	}
	defer cancel()
	ctx = bounded
	before, err := s.cleanupOperation(ctx, proof)
	if err != nil {
		return err
	}
	limits, err := s.checkCleanupPermissions(ctx, before, proof.confirmation)
	if err != nil {
		return err
	}
	after, err := s.cleanupOperation(ctx, proof)
	if err != nil {
		return err
	}
	latest, err := s.checkCleanupPermissions(ctx, after, proof.confirmation)
	if err != nil {
		return err
	}
	if limits != latest {
		return dispatchDenied()
	}
	_, err = s.cleanupOperation(ctx, proof)
	return err
}

func (s *Service) checkCleanupPermissions(ctx context.Context, op *Operation, confirmation actor.Actor) (Limits, error) {
	if err := s.authorize(ctx, op.Actor, op.Meta, op.Target); err != nil {
		return Limits{}, err
	}
	limits, err := s.limits(ctx, op.Actor, op.Meta, op.Target)
	if err != nil {
		return Limits{}, err
	}
	if _, err := s.checkDispatchPolicy(ctx, op, limits); err != nil {
		return Limits{}, err
	}
	current, err := s.dispatchConfirmation(ctx, op)
	if err != nil || current != confirmation {
		return Limits{}, dispatchDenied()
	}
	if current.ID != "" {
		if err := s.authorize(ctx, current, op.Meta, op.Target); err != nil {
			return Limits{}, err
		}
	}
	return limits, nil
}

func validCleanupRecord(recordID, fingerprint string) bool {
	if !boundedCleanupID(recordID) || len(fingerprint) != 64 {
		return false
	}
	raw, err := hex.DecodeString(fingerprint)
	return err == nil && hex.EncodeToString(raw) == fingerprint
}

// NewCleanupLease 的 ID 和完整指纹只能来自宿主核验的原自有记录。
// 首次窗口固定在 runningJob；fresh snapshot、较长 TTL 或其他记录不能延长它。
func (s *Service) NewCleanupLease(ctx context.Context, accepted DispatchedContext, source CleanupSource, recordID, fingerprint string, ttl time.Duration) (*CleanupLease, error) {
	if ttl <= 0 || ttl > 30*time.Second || !boundedCleanupID(source.DNSAttemptID) || !validCleanupRecord(recordID, fingerprint) {
		return nil, dispatchDenied()
	}
	if err := s.CheckCleanupSource(ctx, accepted, source, ttl); err != nil {
		return nil, err
	}
	proof := accepted.runtimeProof
	now, wallNow := s.clock.Now(), time.Now()
	s.runMu.Lock()
	if s.running[proof.original.ID] != proof.job || !cleanupJobAlive(proof.job) || proof.job.cleanupWindow == nil {
		s.runMu.Unlock()
		return nil, dispatchDenied()
	}
	window := proof.job.cleanupWindow
	deadline, wallDeadline := window.deadline, window.wallDeadline
	s.runMu.Unlock()
	if !now.Before(deadline) || !wallNow.Before(wallDeadline) {
		return nil, dispatchDenied()
	}
	deadline, wallDeadline = earlierTime(deadline, now.Add(ttl)), earlierTime(wallDeadline, wallNow.Add(ttl))
	lease := &CleanupLease{proof: proof, window: window, source: source, recordID: recordID, fingerprint: fingerprint, deadline: deadline, wallDeadline: wallDeadline}
	if err := s.CheckCleanupLease(ctx, lease, source, recordID, fingerprint); err != nil {
		return nil, err
	}
	return lease, nil
}

func earlierTime(one, two time.Time) time.Time {
	if one.Before(two) {
		return one
	}
	return two
}

func cleanupBudgetContext(ctx context.Context, deadline, wallDeadline, now time.Time) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, dispatchDenied()
	}
	remaining := min(deadline.Sub(now), time.Until(wallDeadline))
	if remaining <= 0 {
		return nil, nil, dispatchDenied()
	}
	bounded, cancel := context.WithTimeout(ctx, remaining)
	return bounded, cancel, nil
}

// CheckCleanupLease 每步核对同 Service、原 executor 与同一记录，不复用缓存权限。
func (s *Service) CheckCleanupLease(ctx context.Context, lease *CleanupLease, source CleanupSource, recordID, fingerprint string) error {
	if s == nil || lease == nil || lease.proof == nil || lease.proof.job == nil || lease.proof.service != s || lease.source != source || lease.recordID != recordID || lease.fingerprint != fingerprint ||
		!s.clock.Now().Before(lease.deadline) || !time.Now().Before(lease.wallDeadline) {
		return dispatchDenied()
	}
	s.runMu.Lock()
	window := lease.proof.job.cleanupWindow
	sameWindow := window != nil && window == lease.window
	s.runMu.Unlock()
	if !sameWindow {
		return dispatchDenied()
	}
	bounded, cancel, err := cleanupBudgetContext(ctx, lease.deadline, lease.wallDeadline, s.clock.Now())
	if err != nil {
		return err
	}
	defer cancel()
	if err := s.checkCleanupProof(bounded, lease.proof); err != nil {
		return err
	}
	if !s.clock.Now().Before(lease.deadline) || !time.Now().Before(lease.wallDeadline) {
		return dispatchDenied()
	}
	return nil
}

// Context 只收紧传入的清理上下文；调用方自行在原取消时使用 WithoutCancel。
func (s *Service) CleanupContext(ctx context.Context, lease *CleanupLease, source CleanupSource, recordID, fingerprint string) (context.Context, context.CancelFunc, error) {
	if err := s.CheckCleanupLease(ctx, lease, source, recordID, fingerprint); err != nil {
		return nil, nil, err
	}
	return cleanupBudgetContext(ctx, lease.deadline, lease.wallDeadline, s.clock.Now())
}

// CleanupSourceContext 只把原私有 journal 读取限制到同 window 的剩余预算。
// 无记录字段、凭据或 DNS 请求权限；fresh Source 与较长 TTL 都不能延长它。
func (s *Service) CleanupSourceContext(ctx context.Context, accepted DispatchedContext, source CleanupSource, ttl time.Duration) (context.Context, context.CancelFunc, error) {
	if err := s.CheckCleanupSource(ctx, accepted, source, ttl); err != nil {
		return nil, nil, err
	}
	proof := accepted.runtimeProof
	s.runMu.Lock()
	window := proof.job.cleanupWindow
	if window == nil || s.running[proof.original.ID] != proof.job || !cleanupJobAlive(proof.job) {
		s.runMu.Unlock()
		return nil, nil, dispatchDenied()
	}
	deadline, wallDeadline := window.deadline, window.wallDeadline
	s.runMu.Unlock()
	bounded, cancel, err := cleanupBudgetContext(ctx, deadline, wallDeadline, s.clock.Now())
	if err != nil {
		return nil, nil, err
	}
	s.runMu.Lock()
	same := s.running[proof.original.ID] == proof.job && cleanupJobAlive(proof.job) && proof.job.cleanupWindow == window
	s.runMu.Unlock()
	if !same || !s.cleanupWindowValid(proof) {
		cancel()
		return nil, nil, dispatchDenied()
	}
	return bounded, cancel, nil
}
