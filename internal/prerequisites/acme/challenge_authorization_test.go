// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 真实加密原 CSR 与私有订单查询 ========================

type originalChallengeFixture struct {
	*authorityFixture
	source   *ChallengeSource
	state    journal
	revision string
}

func newOriginalChallengeFixture(t *testing.T, sans []string) originalChallengeFixture {
	t.Helper()
	f := newAuthorityFixture(t, sans)
	repository, err := store.NewEncrypted(store.EncryptedOptions{DB: f.authority.db, Secrets: f.authority.secrets, Namespace: "certificates"})
	if err != nil {
		t.Fatal(err)
	}
	f.authority.repository = repository
	state, revision, err := f.authority.prepare(context.Background(), f.caller, "certificate-original", "issue-original", f.scope)
	if err != nil {
		t.Fatal(err)
	}
	for index, san := range f.scope.Spec.SANs {
		uri := fixtureCAOrigin + "/acme/authz/" + strings.Repeat("a", index+1)
		state.Challenges = append(state.Challenges, challenge{AuthorizationURI: uri, URI: uri + "/challenge", SAN: san,
			Token: "original-token", Value: strings.Repeat("V", 43), DNSRound: 1, DNSSubmitted: true,
			DNSAttempt: dnsAttemptID(state.AttemptID, uri, 1), DNSRevision: strings.Repeat("a", 64)})
	}
	revision, err = f.authority.save(context.Background(), f.caller, state, revision)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewChallengeSource(ChallengeSourceOptions{Repository: repository, Clock: f.authority.clock})
	if err != nil {
		t.Fatal(err)
	}
	return originalChallengeFixture{authorityFixture: f, source: source, state: state, revision: revision}
}

func (f originalChallengeFixture) intent(t *testing.T, index int, cleanup bool) dns.ChallengeIntent {
	t.Helper()
	intent, err := f.source.Intent(context.Background(), f.caller, f.state.CertificateID, f.state.AttemptID, f.scope, f.state.Challenges[index].DNSAttempt, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestACMEChallengeSourceMatchesOriginalWildcardAndNewAuthorizedOperation(t *testing.T) {
	f := newOriginalChallengeFixture(t, []string{"*.example.com", "proxy.example.com"})
	for index, san := range f.scope.Spec.SANs {
		intent := f.intent(t, index, false)
		if intent.Name != "_acme-challenge."+strings.TrimPrefix(san, "*.") || intent.ExpectedRevision != f.state.Challenges[index].DNSRevision {
			t.Fatal("wildcard 或原快照版本被换成另一个请求")
		}
		caller := f.caller
		caller.OperationID = "operation-recovery"
		intent.Caller.OperationID = caller.OperationID
		if err := f.source.Match(context.Background(), caller, f.state.CertificateID, f.state.AttemptID, f.scope, intent, false); err != nil {
			t.Fatal(err)
		}
	}
	if f.ca.orders != 0 || f.ca.finalizes != 0 {
		t.Fatal("只读原请求匹配创建了 CA 订单或材料")
	}
}

func TestACMEChallengeSourceRejectsChangedRequestAndScope(t *testing.T) {
	f := newOriginalChallengeFixture(t, []string{"proxy.example.com"})
	original := f.intent(t, 0, false)
	for _, mutate := range []func(*dns.ChallengeIntent){
		func(r *dns.ChallengeIntent) { r.Caller.OwnerID = "other-owner" },
		func(r *dns.ChallengeIntent) { r.Caller.OperationID = "other-operation" },
		func(r *dns.ChallengeIntent) { r.CertificateID = "other-certificate" },
		func(r *dns.ChallengeIntent) { r.DNSAttemptID = "other-dns-attempt" },
		func(r *dns.ChallengeIntent) { r.Name = "_acme-challenge.other.example.com" },
		func(r *dns.ChallengeIntent) { r.Value = strings.Repeat("X", 43) },
		func(r *dns.ChallengeIntent) { r.ExpectedRevision = strings.Repeat("b", 64) },
		func(r *dns.ChallengeIntent) { r.Scope.ZoneID = "other-zone" },
	} {
		changed := original
		mutate(&changed)
		if err := f.source.Match(context.Background(), f.caller, f.state.CertificateID, f.state.AttemptID, f.scope, changed, false); err == nil {
			t.Fatal("原请求匹配接受了另一个实际请求")
		}
	}
	for _, mutate := range []func(*certificates.IssuanceScope){
		func(s *certificates.IssuanceScope) { s.CA = certificates.LetsEncrypt },
		func(s *certificates.IssuanceScope) { s.Provider.Revision = strings.Repeat("b", 64) },
		func(s *certificates.IssuanceScope) { s.Spec.SANs = []string{"other.example.com"} },
	} {
		changed := f.scope
		changed.Spec.SANs = slices.Clone(f.scope.Spec.SANs)
		mutate(&changed)
		if _, err := f.source.Intent(context.Background(), f.caller, f.state.CertificateID, f.state.AttemptID, changed, original.DNSAttemptID, false); err == nil {
			t.Fatal("原 CA 查询接受了其他 scope 或 SAN")
		}
	}
}

func TestACMEChallengeSourceRejectsUnsubmittedRoundAndAmbiguousAttempt(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*journal)
	}{
		{"unsubmitted", func(s *journal) { s.Challenges[0].DNSSubmitted = false }},
		{"round", func(s *journal) { s.Challenges[0].DNSRound = 2 }},
		{"duplicate", func(s *journal) { s.Challenges = append(s.Challenges, s.Challenges[0]) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOriginalChallengeFixture(t, []string{"proxy.example.com"})
			attempt := f.state.Challenges[0].DNSAttempt
			test.mutate(&f.state)
			if _, err := f.authority.save(context.Background(), f.caller, f.state, f.revision); err != nil {
				t.Fatal(err)
			}
			if _, err := f.source.Intent(context.Background(), f.caller, f.state.CertificateID, f.state.AttemptID, f.scope, attempt, false); err == nil {
				t.Fatal("私有 journal 中无效或歧义的原请求被授权")
			}
		})
	}
}

func TestACMEChallengeSourceKeepsCleanedEvidenceOnlyForCleanupAndRejectsMissingBackend(t *testing.T) {
	f := newOriginalChallengeFixture(t, []string{"proxy.example.com"})
	original := f.intent(t, 0, false)
	f.state.Challenges[0].Cleaned, f.state.Challenges[0].Presented = true, true
	if _, err := f.authority.save(context.Background(), f.caller, f.state, f.revision); err != nil {
		t.Fatal(err)
	}
	if err := f.source.Match(context.Background(), f.caller, f.state.CertificateID, f.state.AttemptID, f.scope, original, false); err == nil {
		t.Fatal("已清理 challenge 重新获得正常提交权限")
	}
	if err := f.source.Match(context.Background(), f.caller, f.state.CertificateID, f.state.AttemptID, f.scope, original, true); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChallengeSource(ChallengeSourceOptions{}); fault.Code(err) != "BACKEND_REQUIRED" {
		t.Fatal("缺失真实加密后端仍然构造了原请求匹配器")
	}
}

func TestACMEChallengeSourceDoesNotMutateTheRequestedSANs(t *testing.T) {
	f := newOriginalChallengeFixture(t, []string{"proxy.example.com"})
	requested := f.scope
	requested.Spec.SANs = []string{"other.example.com"}
	original := slices.Clone(requested.Spec.SANs)
	_, err := f.source.Intent(context.Background(), f.caller, f.state.CertificateID, f.state.AttemptID, requested, f.state.Challenges[0].DNSAttempt, false)
	if !slices.Equal(requested.Spec.SANs, original) {
		t.Fatal("私有 journal 解码改写了请求的授权 SAN")
	}
	if err == nil {
		t.Fatal("持久 SAN 覆盖了另一个授权范围")
	}
}
