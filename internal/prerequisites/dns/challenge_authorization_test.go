// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 请求感知 fixture，不替代真实宿主授权 ========================

type originalChallengeKey struct{}
type ownedCleanupKey struct{}

type originalChallengeAuthorization struct {
	*fakeAuthorization
	expected ChallengeIntent
	sources  atomic.Int32
	requests atomic.Int32
}

func (a *originalChallengeAuthorization) Authorize(ctx context.Context, caller Caller, scope Scope, access Access) error {
	if err := a.fakeAuthorization.Authorize(ctx, caller, scope, access); err != nil {
		return err
	}
	switch access {
	case Challenge:
		intent, found := ctx.Value(originalChallengeKey{}).(ChallengeIntent)
		if !found || intent.Caller != caller || intent.Scope != scope {
			return fault.New("PERMISSION_DENIED", "fixture 要求原已绑定请求")
		}
	case Cleanup:
		owned, found := ctx.Value(ownedCleanupKey{}).(OwnedChallenge)
		if !found || owned.Caller() != caller || owned.Scope() != scope {
			return fault.New("PERMISSION_DENIED", "fixture 要求真实原记录")
		}
	}
	return nil
}

func (a *originalChallengeAuthorization) ChallengeContext(ctx context.Context, intent ChallengeIntent) (context.Context, error) {
	if err := a.fakeAuthorization.Authorize(ctx, intent.Caller, intent.Scope, Read); err != nil {
		return nil, err
	}
	expected := a.expected
	expected.Caller = intent.Caller
	if intent != expected {
		return nil, fault.New("PERMISSION_DENIED", "fixture 原 DNS 请求不匹配")
	}
	a.requests.Add(1)
	return context.WithValue(ctx, originalChallengeKey{}, intent), nil
}

func (a *originalChallengeAuthorization) AuthorizeChallengeSource(ctx context.Context, caller Caller, scope Scope, certificateID, attemptID string) error {
	if err := a.fakeAuthorization.Authorize(ctx, caller, scope, Read); err != nil {
		return err
	}
	if caller.OperationID == "" || scope != a.expected.Scope || certificateID != a.expected.CertificateID || attemptID != a.expected.DNSAttemptID {
		return fault.New("PERMISSION_DENIED", "fixture 私有读取不属于原 CA 意图")
	}
	a.sources.Add(1)
	return nil
}

func (a *originalChallengeAuthorization) AuthorizeChallengeCleanup(ctx context.Context, owned OwnedChallenge) error {
	bound, found := ctx.Value(ownedCleanupKey{}).(OwnedChallenge)
	if !found || !bound.SameRecord(owned) {
		return fault.New("PERMISSION_DENIED", "fixture 原完整记录事实不匹配")
	}
	return a.Authorize(ctx, owned.Caller(), owned.Scope(), Cleanup)
}

func requestAwareFixture(t *testing.T) (fixture, ChallengeRequest, *originalChallengeAuthorization) {
	t.Helper()
	f := newFixture(t)
	request := f.challenge(t, "challenge-original")
	guard := &originalChallengeAuthorization{fakeAuthorization: f.authorization, expected: ChallengeIntent{
		Caller: request.Caller, Scope: request.Scope, CertificateID: request.CertificateID, DNSAttemptID: request.AttemptID,
		Name: "_acme-challenge." + strings.TrimPrefix(request.SAN, "*."), Value: request.Value, ExpectedRevision: request.ExpectedRevision}}
	f.manager.authorizer = guard
	return f, request, guard
}

// ======================== 先固定原查询，再绑定真实恢复请求 ========================

func TestDNSChallengeRecoveryBindsOriginalRequestBeforeMutation(t *testing.T) {
	f, request, guard := requestAwareFixture(t)
	applied, err := f.manager.PresentChallenge(context.Background(), request)
	if err != nil || applied.State != Applied {
		t.Fatalf("初次受控提交失败：%v", err)
	}
	caller := request.Caller
	caller.OperationID = "operation-recovery"
	recovered, err := f.manager.RecoverAttempt(context.Background(), caller, request.Scope, request.CertificateID, request.AttemptID)
	if err != nil || recovered.State != Applied || recovered.RecordID != applied.RecordID {
		t.Fatalf("恢复未先绑定原请求：%v", err)
	}
	if guard.sources.Load() == 0 || guard.requests.Load() != 2 {
		t.Fatal("恢复没有核验原私有查询与实际请求")
	}
	if creates, _, _ := f.provider.counts(); creates != 1 {
		t.Fatal("已确认提交的恢复重复写入了提供商")
	}
}

func TestDNSChallengeRecoveryRejectsAnotherCAIntentBeforeProviderAccess(t *testing.T) {
	f, request, _ := requestAwareFixture(t)
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	f.provider.mu.Lock()
	lists := f.provider.lists
	f.provider.mu.Unlock()
	for _, change := range []func(*ChallengeRequest){
		func(r *ChallengeRequest) { r.CertificateID = "another-certificate" },
		func(r *ChallengeRequest) { r.AttemptID = "another-attempt" },
		func(r *ChallengeRequest) { r.Caller.OperationID = "" },
	} {
		foreign := request
		change(&foreign)
		_, err := f.manager.RecoverAttempt(context.Background(), foreign.Caller, foreign.Scope, foreign.CertificateID, foreign.AttemptID)
		requireCode(t, err, "PERMISSION_DENIED")
	}
	f.provider.mu.Lock()
	defer f.provider.mu.Unlock()
	if f.provider.creates != 1 || f.provider.lists != lists {
		t.Fatal("被拒绝的私有读取访问了提供商")
	}
}

func TestDNSOwnedChallengeSourceCannotDeleteOrRestoreSerializedProof(t *testing.T) {
	f, request, _ := requestAwareFixture(t)
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	owned, found, err := f.manager.OwnedChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID)
	if err != nil || !found || !owned.BelongsTo(f.manager) {
		t.Fatalf("未取得真实原自有记录事实：%v", err)
	}
	encoded, err := json.Marshal(owned)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatal("私有记录被序列化为可恢复证明")
	}
	requireCode(t, f.manager.CleanupChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID), "PERMISSION_DENIED")
	ctx := context.WithValue(context.Background(), ownedCleanupKey{}, owned)
	guard := f.manager.authorizer.(ChallengeAuthorizations)
	requireCode(t, guard.AuthorizeChallengeCleanup(ctx, OwnedChallenge{}), "PERMISSION_DENIED")
	if err := f.manager.CleanupChallenge(ctx, request.Caller, request.Scope, request.CertificateID, request.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, _, deletes := f.provider.counts(); deletes != 1 {
		t.Fatal("绑定原完整记录的清理没有且仅有一次删除")
	}
}

func TestDNSOwnedChallengeWithoutConfirmedIDPreservesUnknownEvidence(t *testing.T) {
	f, request, _ := requestAwareFixture(t)
	f.provider.noMarkers, f.provider.lostCreate = true, true
	if _, err := f.manager.PresentChallenge(context.Background(), request); fault.Code(err) != "OUTCOME_UNKNOWN" {
		t.Fatalf("未知写入未保留不确定状态：%v", err)
	}
	_, found, err := f.manager.OwnedChallenge(context.Background(), request.Caller, request.Scope, request.CertificateID, request.AttemptID)
	if found || fault.Code(err) != "OUTCOME_UNKNOWN" {
		t.Fatal("未知 ID 被认领成自有记录")
	}
	if _, _, deletes := f.provider.counts(); deletes != 0 {
		t.Fatal("未知原写入被自动删除")
	}
}
