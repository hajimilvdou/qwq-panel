// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
)

type fakeAuthorization struct {
	mu      sync.Mutex
	scope   Scope
	revoked bool
}

func (a *fakeAuthorization) Authorize(ctx context.Context, caller Caller, scope Scope, _ Access) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.revoked {
		return fault.New("CREDENTIAL_REVOKED", "授权已撤销")
	}
	if scope != a.scope || caller.OwnerID != "tls.certificates" {
		return fault.New("PERMISSION_DENIED", "资源授权不匹配")
	}
	return nil
}

func (a *fakeAuthorization) revoke() { a.mu.Lock(); a.revoked = true; a.mu.Unlock() }

// 显式协议 fixture 复用现有故障授权；不作为真实 CA journal/宿主 owner 事实。
func (a *fakeAuthorization) ChallengeContext(ctx context.Context, intent ChallengeIntent) (context.Context, error) {
	if err := a.Authorize(ctx, intent.Caller, intent.Scope, Challenge); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (a *fakeAuthorization) AuthorizeChallengeSource(ctx context.Context, caller Caller, scope Scope, _, _ string) error {
	return a.Authorize(ctx, caller, scope, Cleanup)
}

func (a *fakeAuthorization) AuthorizeRecoveryAttempt(ctx context.Context, caller Caller, scope Scope, _ string) error {
	return a.Authorize(ctx, caller, scope, Reconcile)
}

func (a *fakeAuthorization) AuthorizeChallengeCleanup(ctx context.Context, owned OwnedChallenge) error {
	return a.Authorize(ctx, owned.Caller(), owned.Scope(), Cleanup)
}

type fakeProviders struct {
	provider *fakeProvider
	scope    Scope
}

func (p fakeProviders) For(_ context.Context, scope Scope) (Provider, error) {
	if scope != p.scope {
		return nil, fault.New("ZONE_DENIED", "未授权 zone")
	}
	return p.provider, nil
}

type fakeProvider struct {
	mu             sync.Mutex
	records        []Record
	next           int
	lists          int
	creates        int
	updates        int
	deletes        []string
	noMarkers      bool
	lostCreate     bool
	lostDelete     bool
	mirrorMarker   bool
	createRejected error
	listFailures   map[int]error
	started        chan struct{}
	release        chan struct{}
	cancelOnCreate context.CancelFunc
}

func (p *fakeProvider) List(ctx context.Context, _ Scope) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lists++
	if failure := p.listFailures[p.lists]; failure != nil {
		return nil, failure
	}
	return slices.Clone(p.records), nil
}

func (p *fakeProvider) Create(ctx context.Context, _ Scope, record Record) (Record, error) {
	p.mu.Lock()
	p.creates++
	rejected, started, release := p.createRejected, p.started, p.release
	p.mu.Unlock()
	if rejected != nil {
		return Record{}, rejected
	}
	if err := ctx.Err(); err != nil {
		return Record{}, &fault.Error{Code: "CANCELED", Detail: "取消", NotApplied: true}
	}
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return Record{}, ctx.Err()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	record.ID, record.Revision = fmt.Sprintf("new-%d", p.next), ""
	if p.noMarkers {
		record.ManagedBy = ""
	}
	p.records = append(p.records, record)
	if p.mirrorMarker {
		mirror := record
		mirror.ID = "external-mirror"
		p.records = append(p.records, mirror)
	}
	if p.cancelOnCreate != nil {
		p.cancelOnCreate()
	}
	if p.lostCreate {
		return Record{}, errors.New("transport contained DO-NOT-EXPOSE-TOKEN")
	}
	return record, nil
}

func (p *fakeProvider) Update(_ context.Context, scope Scope, before, after Record) (Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updates++
	for index, record := range p.records {
		if record.ID != before.ID {
			continue
		}
		current, err := normalizeRecord(scope, record, false)
		if err != nil || current.Revision != before.Revision {
			return Record{}, &fault.Error{Code: "RECORD_CONFLICT", Detail: "前提变化", NotApplied: true}
		}
		after.Revision = ""
		p.records[index] = after
		return after, nil
	}
	return Record{}, &fault.Error{Code: "RECORD_CONFLICT", Detail: "已删除", NotApplied: true}
}

func (p *fakeProvider) Delete(_ context.Context, scope Scope, before Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for index, record := range p.records {
		if record.ID != before.ID {
			continue
		}
		current, err := normalizeRecord(scope, record, false)
		if err != nil || current.Revision != before.Revision {
			return &fault.Error{Code: "RECORD_CONFLICT", Detail: "前提变化", NotApplied: true}
		}
		p.deletes = append(p.deletes, record.ID)
		p.records = append(p.records[:index], p.records[index+1:]...)
		if p.lostDelete {
			return errors.New("delete response lost")
		}
		return nil
	}
	return nil
}

func (p *fakeProvider) counts() (int, int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.creates, p.updates, len(p.deletes)
}

func (p *fakeProvider) edit(id string, apply func(*Record)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for index := range p.records {
		if p.records[index].ID == id {
			apply(&p.records[index])
		}
	}
}

type fixture struct {
	manager       *Manager
	repository    *testsupport.MemoryStore
	provider      *fakeProvider
	clock         *clock.Fake
	authorization *fakeAuthorization
	scope         Scope
	caller        Caller
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	scope := Scope{ProviderID: "provider-1", Kind: Cloudflare, ZoneID: "zone-1", ZoneName: "example.com", Revision: "scope-1"}
	provider := &fakeProvider{}
	repository := &testsupport.MemoryStore{}
	now := clock.NewFake(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	authorization := &fakeAuthorization{scope: scope}
	manager, err := New(Options{Repository: repository, Providers: fakeProviders{provider, scope}, Authorizer: authorization, Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{manager: manager, repository: repository, provider: provider, clock: now, authorization: authorization, scope: scope,
		caller: Caller{OwnerID: "tls.certificates", OperationID: "operation-1"}}
}

func (f fixture) request(t *testing.T, attemptID string, change Change) Request {
	t.Helper()
	snapshot, err := f.manager.List(context.Background(), f.caller, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Caller: f.caller, Scope: f.scope, AttemptID: attemptID, ExpectedRevision: snapshot.Revision, Change: change}
}

func (f fixture) challenge(t *testing.T, attemptID string) ChallengeRequest {
	t.Helper()
	snapshot, err := f.manager.List(context.Background(), f.caller, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	return ChallengeRequest{Caller: f.caller, Scope: f.scope, CertificateID: "certificate-1", AttemptID: attemptID, SAN: "proxy.example.com",
		Value: strings.Repeat("V", 43), ExpectedRevision: snapshot.Revision}
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || fault.Code(err) != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}
