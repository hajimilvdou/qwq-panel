// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 原加密 CA journal 的只读请求匹配 ========================

type ChallengeSourceOptions struct {
	Repository *store.EncryptedRepository
	Clock      clock.Clock
	Timeout    time.Duration
}

// ChallengeSource 不创建订单、读取密钥或改写材料，只复用原持久校验核对 intent。
type ChallengeSource struct {
	repository *store.EncryptedRepository
	clock      clock.Clock
	timeout    time.Duration
}

func NewChallengeSource(options ChallengeSourceOptions) (*ChallengeSource, error) {
	if options.Repository == nil {
		return nil, fault.New("BACKEND_REQUIRED", "CA 请求匹配需要真实私有加密 journal")
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	if options.Timeout == 0 {
		options.Timeout = 5 * time.Minute
	}
	if options.Timeout < time.Minute || options.Timeout > 10*time.Minute {
		return nil, fault.New("VALIDATION_FAILED", "CA 请求匹配的原租约上限无效")
	}
	return &ChallengeSource{repository: options.Repository, clock: options.Clock, timeout: options.Timeout}, nil
}

// Match 固定原 certificate/issue/DNS attempt 与 exact scope/Name/TXT/快照版本。
// Name 来自原 SAN，可同时恢复 wildcard 的原 TXT，不能转为其他 challenge。
func (s *ChallengeSource) Match(ctx context.Context, caller certificates.Caller, certificateID, issueAttemptID string, scope certificates.IssuanceScope, intent dns.ChallengeIntent, cleanup bool) error {
	original, err := s.Intent(ctx, caller, certificateID, issueAttemptID, scope, intent.DNSAttemptID, cleanup)
	if err != nil {
		return err
	}
	if intent != original {
		return fault.New("PERMISSION_DENIED", "DNS请求目标、TXT或原快照版本不属于CA意图")
	}
	return nil
}

// Intent 只返回原已保存请求事实；调用方仍须以私有宿主上下文授权实际请求。
func (s *ChallengeSource) Intent(ctx context.Context, caller certificates.Caller, certificateID, issueAttemptID string, scope certificates.IssuanceScope, attemptID string, cleanup bool) (dns.ChallengeIntent, error) {
	if s == nil || s.repository == nil || ctx == nil || ctx.Err() != nil {
		return dns.ChallengeIntent{}, fault.New("BACKEND_REQUIRED", "原 CA 请求匹配后端不可用")
	}
	if !names.ID(caller.OwnerID) || !names.ID(caller.OperationID) || !names.ID(certificateID) || !names.ID(issueAttemptID) ||
		!names.ID(attemptID) {
		return dns.ChallengeIntent{}, fault.New("PERMISSION_DENIED", "DNS 请求不属于原证书和签发意图")
	}
	canonical, err := canonicalScope(scope)
	if err != nil || !equalScope(canonical, scope) {
		return dns.ChallengeIntent{}, fault.New("PERMISSION_DENIED", "原 CA 请求 scope 不完整或发生变化")
	}
	state, _, found, err := loadJournal(ctx, s.repository, s.clock, s.timeout, caller, certificateID, issueAttemptID, scope)
	if err != nil {
		return dns.ChallengeIntent{}, err
	}
	if !found {
		return dns.ChallengeIntent{}, fault.New("PERMISSION_DENIED", "原 CA journal 尚未登记该 DNS 请求")
	}
	matched := 0
	var original dns.ChallengeIntent
	for _, item := range state.Challenges {
		if item.DNSAttempt != attemptID {
			continue
		}
		name := "_acme-challenge." + strings.TrimPrefix(item.SAN, "*.")
		if !item.DNSSubmitted || item.DNSRound == 0 || item.DNSAttempt != dnsAttemptID(issueAttemptID, item.AuthorizationURI, item.DNSRound) ||
			(!cleanup && item.Cleaned) {
			return dns.ChallengeIntent{}, fault.New("PERMISSION_DENIED", "DNS attempt、原 SAN、TXT 或快照版本不匹配")
		}
		original = dns.ChallengeIntent{Caller: dns.Caller{OwnerID: caller.OwnerID, OperationID: caller.OperationID}, Scope: scope.Provider,
			CertificateID: certificateID, DNSAttemptID: item.DNSAttempt, Name: name, Value: item.Value, ExpectedRevision: item.DNSRevision}
		matched++
	}
	if matched != 1 {
		return dns.ChallengeIntent{}, fault.New("PERMISSION_DENIED", "原 CA DNS 请求缺失或存在歧义")
	}
	return original, nil
}
