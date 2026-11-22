// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 真实加密KV竞争与私有origin完整性 ========================

func TestHostBindingReservationConcurrentCASNeverCreatesTwoIDs(t *testing.T) {
	f := newReservationFixture(t)
	type outcome struct {
		view BindingReservation
		err  error
	}
	results := make(chan outcome, 2)
	ctx, cancel := context.WithTimeout(f.call.ctx, 5*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		go func() {
			view, err := f.f.authority.ReserveBinding(ctx, fixtureCertificate, stringsDigest('a'))
			results <- outcome{view: view, err: err}
		}()
	}
	var ids []string
	var received []outcome
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			received = append(received, result)
		case <-time.After(10 * time.Second):
			t.Fatal("有界预留线程没有退出")
		}
	}
	for _, result := range received {
		if result.err != nil {
			if fault.Code(result.err) != "REVISION_CONFLICT" {
				t.Fatalf("竞争没有保持CAS边界：%v", result.err)
			}
		} else {
			ids = append(ids, result.view.BindingRef)
		}
	}
	state, _, err := f.f.authority.loadBindingLedger(f.f.ctx)
	if err != nil || len(state.Entries) != 1 || len(ids) == 0 {
		t.Fatalf("竞争产生重复范围或没有原子登记：%v", err)
	}
	for _, id := range ids {
		if id != state.Entries[0].ID {
			t.Fatal("并发返回了未登记的其他稳定ID")
		}
	}
}

func TestHostBindingLedgerRejectsCorruptionAndPreservesExplicitOrigin(t *testing.T) {
	f := newReservationFixture(t)
	reservation := f.reserve(t)
	initial, revision, err := f.f.authority.loadBindingLedger(f.f.ctx)
	if err != nil || len(initial.Entries) != 1 {
		t.Fatal(err)
	}
	raw, err := json.Marshal(initial.Entries[0].Origin)
	defer clear(raw)
	if err != nil || !bytes.Contains(raw, []byte(f.call.invocation.OperationID)) || !bytes.Contains(raw, []byte(`"operation_id"`)) {
		t.Fatal("origin被Invocation的脱敏JSON吞掉，或原operation没有持久化")
	}
	encoded, err := json.Marshal(initial)
	defer clear(encoded)
	if err != nil || bytes.Contains(encoded, []byte(f.f.human.SessionID)) || bytes.Contains(encoded, []byte(`"session_id"`)) || bytes.Contains(encoded, []byte(`"mfa"`)) {
		t.Fatal("私有登记错误持久化了真人session或MFA事实")
	}
	for caseIndex, mutate := range []func(*bindingLedger){
		func(v *bindingLedger) { v.OwnerID = "foreign-owner" },
		func(v *bindingLedger) { v.NodeID = "foreign-node" },
		func(v *bindingLedger) { v.Entries = nil },
		func(v *bindingLedger) { v.Entries[0].Version = 0 },
		func(v *bindingLedger) { v.Entries[0].Origin.OperationID = "not-an-operation" },
		func(v *bindingLedger) { v.Entries[0].Origin.PluginID = "other-plugin" },
		func(v *bindingLedger) { v.Entries[0].AuthorizedBy.ID = "not-a-user" },
		func(v *bindingLedger) { v.Entries[0].Phase = bindingConfirmed },
		func(v *bindingLedger) { v.Entries = append(v.Entries, v.Entries[0]) },
	} {
		invalid := initial
		invalid.Entries = slices.Clone(initial.Entries)
		mutate(&invalid)
		if err := f.f.authority.saveBindingLedger(f.f.ctx, invalid, revision); err != nil {
			t.Fatal(err)
		}
		current := bindingLedgerRevision(t, f.f.authority)
		if _, _, err := f.f.authority.loadBindingLedger(f.f.ctx); fault.Code(err) != "STATE_INVALID" {
			t.Fatalf("损坏的私有scope/origin被接受，case=%d：%v", caseIndex, err)
		}
		if err := f.f.authority.saveBindingLedger(f.f.ctx, initial, current); err != nil {
			t.Fatal(err)
		}
		revision = bindingLedgerRevision(t, f.f.authority)
	}
	if err := f.f.authority.ValidateConsumerConfiguration(f.f.ctx, f.f.human, "local", "core.xray", "0", []ConsumerConfiguration{{BindingRef: reservation.BindingRef, Consumer: f.want}}); err != nil {
		t.Fatal(err)
	}
}

func bindingLedgerRevision(t *testing.T, authority *Authority) string {
	t.Helper()
	key, err := authority.bindingLedgerKey()
	if err != nil {
		t.Fatal(err)
	}
	entry, found, err := authority.repository.Get(context.Background(), key)
	defer clear(entry.Value)
	if err != nil || !found {
		t.Fatal("加密绑定账本不存在")
	}
	return entry.Revision
}
