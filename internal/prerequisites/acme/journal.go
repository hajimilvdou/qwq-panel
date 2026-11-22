// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/contextbudget"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 构造、精确资源与 CAS 订单日志 ========================

func New(options Options) (*Authority, error) {
	if options.DB == nil || options.Secrets == nil || options.Repository == nil || options.Vault == nil || options.DNS == nil || options.Checker == nil || options.CAA == nil || options.Authorizer == nil || options.DNSContexts == nil || options.CleanupContexts == nil || options.Terms == nil {
		return nil, fault.New("BACKEND_REQUIRED", "ACME 需要真实材料、DNS、授权与账户同意后端")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Timeout == 0 {
		options.Timeout = 5 * time.Minute
	}
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = 15 * time.Second
	}
	if options.Timeout < time.Minute || options.Timeout > 10*time.Minute || options.CleanupTimeout <= 0 || options.CleanupTimeout > time.Minute {
		return nil, fault.New("VALIDATION_FAILED", "ACME 时间预算无效")
	}
	return &Authority{db: options.DB, secrets: options.Secrets, repository: options.Repository, vault: options.Vault, dns: options.DNS, checker: options.Checker, caa: options.CAA, authorizer: options.Authorizer, dnsContexts: options.DNSContexts, cleanupContexts: options.CleanupContexts, terms: options.Terms, client: options.Client, clock: options.Clock, random: &lockedRandom{reader: options.Random}, timeout: options.Timeout, cleanupTimeout: options.CleanupTimeout}, nil
}

type lockedRandom struct {
	mu     sync.Mutex
	reader io.Reader
}

func (r *lockedRandom) Read(buffer []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reader.Read(buffer)
}

func canonicalScope(scope certificates.IssuanceScope) (certificates.IssuanceScope, error) {
	canonical, err := tlsmgr.CanonicalSANs(scope.Spec.SANs)
	if err != nil {
		return certificates.IssuanceScope{}, err
	}
	if scope.Spec.Purpose != tlsmgr.ServerTLS || dns.ValidateScope(scope.Provider) != nil {
		return certificates.IssuanceScope{}, fault.New("SCOPE_INVALID", "ACME 必须使用授权 DNS 与服务端 TLS 用途")
	}
	if _, err := directory(scope.CA); err != nil {
		return certificates.IssuanceScope{}, err
	}
	for _, san := range canonical {
		if !names.InZone(strings.TrimPrefix(san, "*."), scope.Provider.ZoneName) {
			return certificates.IssuanceScope{}, fault.New("ZONE_DENIED", "ACME SAN 超出固定 zone")
		}
	}
	scope.Spec.SANs = canonical
	return scope, nil
}

func journalKey(caller certificates.Caller, certificateID, attemptID string) string {
	sum := sha256.Sum256([]byte(caller.OwnerID + "\x00" + certificateID + "\x00" + attemptID))
	return "acme/attempt/" + hex.EncodeToString(sum[:])
}

func equalScope(a, b certificates.IssuanceScope) bool {
	return a.CA == b.CA && a.Provider == b.Provider && a.Spec.Purpose == b.Spec.Purpose && slices.Equal(a.Spec.SANs, b.Spec.SANs)
}

func (a *Authority) load(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope) (journal, string, bool, error) {
	return loadJournal(ctx, a.repository, a.clock, a.timeout, caller, certificateID, attemptID, scope)
}

func loadJournal(ctx context.Context, repository store.Repository, source clock.Clock, timeout time.Duration, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope) (journal, string, bool, error) {
	state := journal{Version: 1, OwnerID: caller.OwnerID, CertificateID: certificateID, AttemptID: attemptID, Scope: scope, Challenges: []challenge{}}
	// JSON 解码会复用已有 slice，不能让持久状态改写调用方的授权 SAN。
	state.Scope.Spec.SANs = slices.Clone(scope.Spec.SANs)
	revision, found, err := store.Load(ctx, repository, journalKey(caller, certificateID, attemptID), &state)
	if err != nil || !found {
		return state, revision, found, err
	}
	canonical, scopeErr := canonicalScope(state.Scope)
	if scopeErr != nil || !equalScope(canonical, state.Scope) || !equalScope(scope, state.Scope) || state.Version != 1 || state.OwnerID != caller.OwnerID || state.CertificateID != certificateID || state.AttemptID != attemptID || state.CreatedAt.IsZero() || len(state.CSR) == 0 || len(state.CSR) > 16384 || len(state.Challenges) > 16 {
		return journal{}, "", false, fault.New("STATE_INVALID", "ACME 原订单日志归属或范围无效")
	}
	if _, err := secrets.ParseRef(string(state.KeyRef)); err != nil {
		return journal{}, "", false, fault.New("STATE_INVALID", "ACME 原证书密钥引用无效")
	}
	csr, err := x509.ParseCertificateRequest(state.CSR)
	if err != nil || csr.CheckSignature() != nil || !slices.Equal(csr.DNSNames, scope.Spec.SANs) {
		return journal{}, "", false, fault.New("STATE_INVALID", "ACME 原 CSR 与授权 SAN 不符")
	}
	for _, value := range []string{state.AccountURI, state.OrderURI, state.FinalizeURI, state.CertificateURI} {
		if value != "" && !allowedURL(scope.CA, value) {
			return journal{}, "", false, fault.New("STATE_INVALID", "ACME 持久端点不属于受控 CA")
		}
	}
	switch state.Phase {
	case "prepared", "submitting_order", "order_created", "finalizing", "issued", "rejected":
	default:
		return journal{}, "", false, fault.New("STATE_INVALID", "ACME 持久阶段无效")
	}
	if (state.LeaseToken == "") != state.LeaseUntil.IsZero() {
		return journal{}, "", false, fault.New("STATE_INVALID", "ACME 租约格式无效")
	}
	if state.LeaseToken != "" {
		value, err := hex.DecodeString(state.LeaseToken)
		if err != nil || len(value) != 24 || state.LeaseUntil.After(source.Now().Add(timeout)) {
			return journal{}, "", false, fault.New("STATE_INVALID", "ACME 租约超出上限")
		}
	}
	for _, item := range state.Challenges {
		if !allowedURL(scope.CA, item.AuthorizationURI) || !allowedURL(scope.CA, item.URI) || !slices.Contains(scope.Spec.SANs, item.SAN) || item.Token == "" || len(item.Token) > 256 || len(item.Value) != 43 || item.DNSRound > 5 || (item.DNSSubmitted && (!names.ID(item.DNSAttempt) || len(item.DNSRevision) != 64)) || (item.Cleaned && !item.Presented) {
			return journal{}, "", false, fault.New("STATE_INVALID", "ACME challenge 日志无效")
		}
	}
	return state, revision, true, nil
}

func (a *Authority) save(ctx context.Context, caller certificates.Caller, state journal, revision string) (string, error) {
	return store.Save(ctx, a.repository, journalKey(caller, state.CertificateID, state.AttemptID), revision, state)
}

func (a *Authority) saveDetached(ctx context.Context, caller certificates.Caller, state journal, revision string) (string, error) {
	bounded, cancel := contextbudget.Detached(ctx, a.cleanupTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return "", err
	}
	return a.save(bounded, caller, state, revision)
}

func (a *Authority) prepare(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope) (journal, string, error) {
	owner, err := keyOwner(caller, certificateID)
	if err != nil {
		return journal{}, "", err
	}
	ref, key, err := a.ensureKey(ctx, owner, keyPurpose(attemptID))
	if err != nil {
		return journal{}, "", err
	}
	defer clearSigner(key)
	csr, err := x509.CreateCertificateRequest(a.random, &x509.CertificateRequest{DNSNames: slices.Clone(scope.Spec.SANs)}, key)
	if err != nil {
		return journal{}, "", fault.New("KEY_UNAVAILABLE", "ACME 无法生成固定 CSR")
	}
	state := journal{Version: 1, OwnerID: caller.OwnerID, CertificateID: certificateID, AttemptID: attemptID, Scope: scope, KeyRef: ref, CSR: csr, Phase: "prepared", CreatedAt: a.clock.Now().UTC(), Challenges: []challenge{}}
	revision, err := a.save(ctx, caller, state, "")
	return state, revision, err
}

func (a *Authority) lease(ctx context.Context, caller certificates.Caller, state journal, revision string) (journal, string, error) {
	if !state.LeaseUntil.IsZero() && a.clock.Now().Before(state.LeaseUntil) {
		return journal{}, "", fault.New("CERTIFICATE_BUSY", "原 ACME 任务仍有有效租约")
	}
	raw := make([]byte, 24)
	if _, err := io.ReadFull(a.random, raw); err != nil {
		return journal{}, "", fault.New("KEY_UNAVAILABLE", "ACME 无法生成租约标识")
	}
	state.LeaseToken, state.LeaseUntil = hex.EncodeToString(raw), a.clock.Now().Add(a.timeout).UTC()
	next, err := a.save(ctx, caller, state, revision)
	return state, next, err
}

func (a *Authority) release(ctx context.Context, caller certificates.Caller, state journal) error {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cleanupTimeout)
	defer cancel()
	current, revision, found, err := a.load(bounded, caller, state.CertificateID, state.AttemptID, state.Scope)
	if err != nil || !found {
		return err
	}
	if current.LeaseToken != state.LeaseToken {
		return fault.New("CERTIFICATE_BUSY", "ACME 租约已更换")
	}
	current.LeaseToken, current.LeaseUntil = "", time.Time{}
	_, err = a.save(bounded, caller, current, revision)
	return err
}
