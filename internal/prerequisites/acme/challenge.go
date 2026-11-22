// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	xacme "golang.org/x/crypto/acme"
)

// ======================== 同一 CA challenge 的 TXT 与对账 ========================

func authorizationSAN(scope certificates.IssuanceScope, authorization *xacme.Authorization) (string, error) {
	if authorization == nil || authorization.Identifier.Type != "dns" {
		return "", fault.New("CA_UNAVAILABLE", "CA 授权不是 DNS 名称")
	}
	san := authorization.Identifier.Value
	if authorization.Wildcard {
		san = "*." + san
	}
	canonical, err := names.SAN(san)
	if err != nil || canonical != san || !slices.Contains(scope.Spec.SANs, san) {
		return "", fault.New("SAN_MISMATCH", "CA 授权 SAN 不属于原订单")
	}
	return san, nil
}

func (a *Authority) authorizations(ctx context.Context, caller certificates.Caller, state *journal, revision *string, client *xacme.Client, guard *guardedTransport, order *xacme.Order, progress certificates.Progress) error {
	for authIndex, uri := range order.AuthzURLs {
		if err := a.authorize(ctx, caller, state.CertificateID, state.Scope); err != nil {
			return err
		}
		authorization, err := client.GetAuthorization(ctx, uri)
		if err != nil {
			return guard.failure(err, false)
		}
		san, err := authorizationSAN(state.Scope, authorization)
		if err != nil {
			return err
		}
		if authorization.Status == xacme.StatusValid {
			continue
		}
		if authorization.Status != xacme.StatusPending {
			return &fault.Error{Code: "CA_REJECTED", Detail: "原 DNS 授权已拒绝或失效", Uncertain: true}
		}
		var selected *xacme.Challenge
		for _, candidate := range authorization.Challenges {
			if candidate != nil && candidate.Type == "dns-01" {
				if selected != nil {
					return fault.New("CA_UNAVAILABLE", "CA 返回多个不确定 DNS-01 challenge")
				}
				selected = candidate
			}
		}
		if selected == nil || !allowedURL(state.Scope.CA, selected.URI) || selected.Token == "" || len(selected.Token) > 256 || strings.ContainsAny(selected.Token, "\x00\r\n") {
			return fault.New("CA_UNAVAILABLE", "CA 缺少受控 DNS-01 challenge")
		}
		index := slices.IndexFunc(state.Challenges, func(item challenge) bool { return item.AuthorizationURI == uri })
		if index < 0 {
			value, err := client.DNS01ChallengeRecord(selected.Token)
			if err != nil || len(value) != 43 {
				return fault.New("CA_UNAVAILABLE", "CA challenge 无法生成 DNS-01 值")
			}
			state.Challenges = append(state.Challenges, challenge{AuthorizationURI: uri, SAN: san, URI: selected.URI, Token: selected.Token, Value: value})
			index = len(state.Challenges) - 1
			*revision, err = a.save(ctx, caller, *state, *revision)
			if err != nil {
				return err
			}
		}
		item := &state.Challenges[index]
		if item.SAN != san || item.URI != selected.URI || item.Token != selected.Token {
			return fault.New("STATE_INVALID", "原 CA challenge 的范围或 token 改变")
		}
		dnsCtx, err := a.dnsContexts.Context(ctx, caller, state.CertificateID, state.AttemptID, state.Scope, false)
		if err != nil {
			return err
		}
		if err := a.ensureDNS(dnsCtx, caller, state, revision, index); err != nil {
			return err
		}
		item = &state.Challenges[index]
		waitingPercent := uint32(30 + authIndex*40/len(order.AuthzURLs))
		if err := report(progress, "waiting_dns", waitingPercent); err != nil {
			return err
		}
		ttl := uint32(60)
		if state.Scope.Provider.Kind == dns.Aliyun {
			ttl = 600
		}
		request := dns.PropagationRequest{Caller: dns.Caller{OwnerID: caller.OwnerID, OperationID: caller.OperationID}, Scope: state.Scope.Provider, Record: dns.Record{Type: dns.TXT, Name: "_acme-challenge." + strings.TrimPrefix(item.SAN, "*."), Value: item.Value, TTL: ttl}}
		if _, err := a.checker.Wait(dnsCtx, request); err != nil {
			return err
		}
		if err := report(progress, "verifying", uint32(30+(authIndex+1)*40/len(order.AuthzURLs))); err != nil {
			return err
		}
		if !item.Accepted {
			// 先记录 ack 意图；响应丢失后只查询原授权，不盲目再次 Accept。
			item.Accepted = true
			*revision, err = a.save(ctx, caller, *state, *revision)
			if err != nil {
				return err
			}
			if _, err := client.Accept(ctx, &xacme.Challenge{Type: "dns-01", URI: item.URI, Token: item.Token}); err != nil {
				return postOrderFailure(guard.failure(err, true))
			}
		}
		verified, err := client.WaitAuthorization(ctx, item.AuthorizationURI)
		if err != nil {
			return guard.failure(err, false)
		}
		verifiedSAN, err := authorizationSAN(state.Scope, verified)
		if err != nil || verifiedSAN != item.SAN || verified.Status != xacme.StatusValid {
			return fault.New("CA_REJECTED", "原 DNS 授权没有验证完成")
		}
		item.Validated = true
		*revision, err = a.saveDetached(ctx, caller, *state, *revision)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Authority) ensureDNS(ctx context.Context, caller certificates.Caller, state *journal, revision *string, index int) error {
	item := &state.Challenges[index]
	dnsCaller := dns.Caller{OwnerID: caller.OwnerID, OperationID: caller.OperationID}
	if item.DNSRound == 0 || item.Cleaned {
		if item.DNSRound >= 5 {
			return fault.New("RENEWAL_EXHAUSTED", "原 challenge 的 TXT 执行预算已耗尽")
		}
		snapshot, err := a.dns.List(ctx, dnsCaller, state.Scope.Provider)
		if err != nil {
			return err
		}
		item.DNSRound++
		item.DNSAttempt, item.DNSRevision = dnsAttemptID(state.AttemptID, item.AuthorizationURI, item.DNSRound), snapshot.Revision
		item.DNSSubmitted, item.Presented, item.Cleaned = true, false, false
		*revision, err = a.save(ctx, caller, *state, *revision)
		if err != nil {
			return err
		}
	}
	result, err := a.dns.RecoverAttempt(ctx, dnsCaller, state.Scope.Provider, state.CertificateID, item.DNSAttempt)
	if fault.Code(err) == "NOT_FOUND" {
		result, err = a.dns.PresentChallenge(ctx, dns.ChallengeRequest{Caller: dnsCaller, Scope: state.Scope.Provider, CertificateID: state.CertificateID, AttemptID: item.DNSAttempt, SAN: item.SAN, Value: item.Value, ExpectedRevision: item.DNSRevision})
	}
	if err != nil {
		return err
	}
	if result.State == dns.Cleaned {
		item.Presented, item.Cleaned = true, true
		*revision, err = a.saveDetached(ctx, caller, *state, *revision)
		if err != nil {
			return err
		}
		return a.ensureDNS(ctx, caller, state, revision, index)
	}
	if result.State != dns.Applied {
		return outcome("原 TXT 写入未确认，不能提交 CA 验证")
	}
	item.Presented = true
	*revision, err = a.saveDetached(ctx, caller, *state, *revision)
	return err
}

func dnsAttemptID(issueAttemptID, authorizationURI string, round uint32) string {
	hash := sha256.Sum256([]byte(issueAttemptID + "\x00" + authorizationURI + "\x00" + strconv.FormatUint(uint64(round), 10)))
	return "acmedns_" + hex.EncodeToString(hash[:])
}

// Cancel 仅清理原订单已登记的自有 TXT；不撤销账户或签发其他订单。
func (a *Authority) Cancel(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, input certificates.IssuanceScope) error {
	bounded, cancel := context.WithTimeout(ctx, a.cleanupTimeout)
	defer cancel()
	ctx = bounded
	scope, err := canonicalScope(input)
	if err != nil {
		return err
	}
	if a.cleanupContexts == nil {
		return fault.New("BACKEND_REQUIRED", "ACME 清理需要原 journal 与自有 TXT 的宿主许可")
	}
	cleanupCtx, stopSource, err := a.cleanupContexts.Source(ctx, caller, certificateID, attemptID, scope)
	if err != nil {
		return err
	}
	if cleanupCtx == nil || stopSource == nil {
		return fault.New("BACKEND_REQUIRED", "ACME 原 journal 清理许可不完整")
	}
	defer stopSource()
	state, revision, found, err := a.load(cleanupCtx, caller, certificateID, attemptID, scope)
	if err != nil || !found {
		return err
	}
	var failures []error
	for index := range state.Challenges {
		item := &state.Challenges[index]
		if !item.DNSSubmitted || item.Cleaned {
			continue
		}
		dnsCaller := dns.Caller{OwnerID: caller.OwnerID, OperationID: caller.OperationID}
		owned, found, err := a.dns.OwnedChallenge(cleanupCtx, dnsCaller, scope.Provider, certificateID, item.DNSAttempt)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if found {
			recordCtx, stopRecord, err := a.cleanupContexts.ForChallenge(cleanupCtx, caller, certificateID, attemptID, scope, owned)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if recordCtx == nil || stopRecord == nil {
				failures = append(failures, fault.New("BACKEND_REQUIRED", "原自有 TXT 清理许可不完整"))
				continue
			}
			cleanupErr := a.dns.CleanupChallenge(recordCtx, dnsCaller, scope.Provider, certificateID, item.DNSAttempt)
			stopRecord()
			if cleanupErr != nil {
				failures = append(failures, cleanupErr)
				continue
			}
		}
		item.Presented, item.Cleaned = true, true
		next, err := a.saveDetached(cleanupCtx, caller, state, revision)
		if err != nil {
			failures = append(failures, err)
			break
		}
		revision = next
	}
	return errors.Join(failures...)
}
