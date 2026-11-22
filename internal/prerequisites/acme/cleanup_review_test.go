// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
)

// ======================== 原 CA 意图尚无 DNS 日志与外部写入后的证据丢失 ========================

func TestACMECleanupMissingDNSReceiptPreservesUnconfirmedJournal(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	state, revision, err := f.authority.prepare(context.Background(), f.caller, "certificate-1", "attempt-not-started", f.scope)
	if err != nil {
		t.Fatal(err)
	}
	uri := fixtureCAOrigin + "/acme/authz/not-started"
	state.Challenges = []challenge{{AuthorizationURI: uri, URI: uri + "/challenge", SAN: "proxy.example.com", Token: "original-token", Value: strings.Repeat("V", 43),
		DNSRound: 1, DNSSubmitted: true, DNSAttempt: dnsAttemptID(state.AttemptID, uri, 1), DNSRevision: strings.Repeat("a", 64)}}
	if _, err := f.authority.save(context.Background(), f.caller, state, revision); err != nil {
		t.Fatal(err)
	}
	err = f.authority.Cancel(context.Background(), f.caller, state.CertificateID, state.AttemptID, f.scope)
	if fault.Code(err) != "OUTCOME_UNKNOWN" {
		t.Fatalf("没有实际 DNS receipt 却声称清理完成：%v", err)
	}
	stored, _, found, err := f.authority.load(context.Background(), f.caller, state.CertificateID, state.AttemptID, f.scope)
	if err != nil || !found || stored.Challenges[0].Cleaned {
		t.Fatal("原未确认 CA 清理证据被标记为完成")
	}
}

func TestACMECleanupMissingPrivateDNSStateDoesNotClaimExistingTXTWasDeleted(t *testing.T) {
	f := newAuthorityFixture(t, []string{"proxy.example.com"})
	if _, err := f.authority.Issue(context.Background(), f.caller, "certificate-1", "attempt-lost-private", f.scope, nil); err != nil {
		t.Fatal(err)
	}
	if f.dns.created != 1 || len(f.dns.records) != 1 {
		t.Fatal("实际受控端没有原 TXT 写入")
	}
	// 新的空私有后端模拟日志丢失，外部提供商仍保留已创建记录。
	manager, err := dns.New(dns.Options{Repository: &testsupport.MemoryStore{}, Providers: f.dns, Authorizer: f.dns, Clock: f.authority.clock})
	if err != nil {
		t.Fatal(err)
	}
	f.authority.dns = manager
	err = f.authority.Cancel(context.Background(), f.caller, "certificate-1", "attempt-lost-private", f.scope)
	if fault.Code(err) != "OUTCOME_UNKNOWN" || f.dns.deleted != 0 || len(f.dns.records) != 1 {
		t.Fatalf("私有证据缺失被当成已删除外部 TXT：%v", err)
	}
	stored, _, found, err := f.authority.load(context.Background(), f.caller, "certificate-1", "attempt-lost-private", f.scope)
	if err != nil || !found || stored.Challenges[0].Cleaned {
		t.Fatal("原外部 TXT 的 CA 对账条目被错误完成")
	}
}
