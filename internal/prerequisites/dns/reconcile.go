// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"slices"

	"github.com/qwq-panel/qwq/internal/platform/contextbudget"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 对账与有界收据 ========================

func (m *Manager) load(ctx context.Context, scope Scope) (journal, string, error) {
	state := journal{Receipts: []attempt{}}
	revision, _, err := store.Load(ctx, m.repository, journalKey(scope), &state)
	if err != nil {
		return journal{}, "", err
	}
	if len(state.Receipts) > m.maxReceipts {
		return journal{}, "", fault.New("STATE_INVALID", "DNS 收据数量无效")
	}
	validate := func(saved attempt, active bool) bool {
		request, err := validateRequest(saved.Request)
		hash, hashErr := digest(request)
		if err != nil || hashErr != nil || request.Scope != scope || saved.Hash != hash || len(saved.Marker) != 64 || saved.CreatedAt.IsZero() || !saved.ExpiresAt.After(saved.CreatedAt) || len(saved.Baseline) > m.maxRecords || !names.ID(request.Caller.OperationID) {
			return false
		}
		if saved.Challenge != (request.CertificateID != "") || (saved.Challenge && (request.Change.Action != Create || request.Change.Record.Type != TXT || !challengeValuePattern.MatchString(request.Change.Record.Value))) {
			return false
		}
		if saved.Cleaning && (!saved.Challenge || saved.Record == nil) {
			return false
		}
		if request.Change.Action != Create && saved.Before == nil {
			return false
		}
		if !active && saved.State == Applied && saved.Record == nil {
			return false
		}
		if active && saved.State != Submitted && saved.State != Unknown {
			return false
		}
		if !active && saved.State != Applied && saved.State != Cleaned && saved.State != Rejected {
			return false
		}
		if saved.Record != nil {
			record, err := normalizeRecord(scope, *saved.Record, false)
			if err != nil || record.ID == "" || record.Revision != saved.Record.Revision {
				return false
			}
		}
		if saved.Before != nil {
			record, err := normalizeRecord(scope, *saved.Before, false)
			if err != nil || record.ID == "" || record.Revision != saved.Before.Revision {
				return false
			}
		}
		return true
	}
	if state.Active != nil && !validate(*state.Active, true) {
		return journal{}, "", fault.New("STATE_INVALID", "DNS 写前日志无效")
	}
	seen := map[string]bool{}
	for _, saved := range state.Receipts {
		if !validate(saved, false) || seen[saved.Request.AttemptID] {
			return journal{}, "", fault.New("STATE_INVALID", "DNS 收据无效")
		}
		seen[saved.Request.AttemptID] = true
	}
	return state, revision, nil
}

func (m *Manager) trim(receipts []attempt) []attempt {
	retained := make([]attempt, 0, len(receipts))
	for _, saved := range receipts {
		// 未清理的 challenge 不因时间到期而丢失归属证据。
		if m.clock.Now().Before(saved.ExpiresAt) || (saved.Challenge && saved.State != Cleaned && saved.State != Rejected) {
			retained = append(retained, saved)
		}
	}
	return retained
}

func (m *Manager) saveDetached(ctx context.Context, scope Scope, revision string, state journal) (string, error) {
	bounded, cancel := contextbudget.Detached(ctx, m.reconcileTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return "", err
	}
	return store.Save(bounded, m.repository, journalKey(scope), revision, state)
}

func (m *Manager) finish(ctx context.Context, scope Scope, state *journal, revision string, status AttemptState) (Receipt, error) {
	active := state.Active
	active.State = status
	active.Baseline = nil
	state.Receipts = append(state.Receipts, *active)
	state.Active = nil
	if _, err := m.saveDetached(ctx, scope, revision, *state); err != nil {
		return Receipt{AttemptID: active.Request.AttemptID, State: Unknown}, uncertain("STATE_UNAVAILABLE", "提供商结果已确认，但收据未能保存")
	}
	return receipt(*active), nil
}

func (m *Manager) reject(ctx context.Context, scope Scope, state *journal, revision, code string) (Receipt, error) {
	state.Active.ErrorCode = code
	result, err := m.finish(ctx, scope, state, revision, Rejected)
	if err != nil {
		return result, err
	}
	return result, fault.New(code, "变更未执行或已被明确拒绝")
}

func (m *Manager) markUnknown(ctx context.Context, scope Scope, state *journal, revision, detail string) (Receipt, error) {
	state.Active.State = Unknown
	result := receipt(*state.Active)
	if _, err := m.saveDetached(ctx, scope, revision, *state); err != nil {
		return result, uncertain("STATE_UNAVAILABLE", "变更已发送，但对账状态未能保存")
	}
	return result, uncertain("OUTCOME_UNKNOWN", detail)
}

func (m *Manager) reconcile(ctx context.Context, caller Caller, scope Scope, state *journal, revision string) (Receipt, error) {
	if state.Active.Cleaning {
		return m.reconcileCleanup(ctx, caller, scope, state, revision)
	}
	bounded, cancel := contextbudget.Detached(ctx, m.reconcileTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return Receipt{}, err
	}
	snapshot, _, err := m.snapshot(bounded, caller, scope)
	if err != nil {
		state.Active.ErrorCode = fault.Code(err)
		return m.markUnknown(ctx, scope, state, revision, "变更已发送，请在 DNS 提供商恢复后对账")
	}
	active := state.Active
	desired := active.Request.Change.Record
	switch active.Request.Change.Action {
	case Delete:
		if !slices.ContainsFunc(snapshot.Records, func(record Record) bool { return record.ID == active.Before.ID }) {
			active.Record = active.Before
			return m.finish(ctx, scope, state, revision, Applied)
		}
	case Update:
		for _, record := range snapshot.Records {
			if record.ID == active.Before.ID && sameContent(record, desired) && record.ManagedBy == active.Before.ManagedBy {
				copy := record
				active.Record = &copy
				return m.finish(ctx, scope, state, revision, Applied)
			}
		}
	case Create:
		candidates := []Record{}
		for _, record := range snapshot.Records {
			if slices.Contains(active.Baseline, record.ID) || !sameContent(record, desired) {
				continue
			}
			// 确认返回的 ID 或提供商持久归属标记才可认领；同名同值不是所有权。
			knownID := active.Record != nil && active.Record.ID == record.ID && active.Record.ManagedBy == record.ManagedBy
			if knownID || record.ManagedBy == active.Marker {
				candidates = append(candidates, record)
			}
		}
		if len(candidates) == 1 {
			active.Record = &candidates[0]
			return m.finish(ctx, scope, state, revision, Applied)
		}
	}
	return m.markUnknown(ctx, scope, state, revision, "DNS 结果尚不能唯一确认；只允许读取对账，不能重发变更")
}
