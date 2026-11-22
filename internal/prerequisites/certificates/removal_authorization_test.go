// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"context"
	"errors"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 精确 generation 授权必须传到实际清理步骤 ========================

func TestGenerationRemovalRechecksExactAuthorizedGeneration(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "exact-remove-issue-one")
	newer := f.issue(t, "exact-remove-issue-two")
	checks := 0
	f.authorization.policyCheck = func(request Authorization) error {
		if request.Access != Remove {
			return nil
		}
		checks++
		if request.Generation != 1 || checks > 1 {
			return fault.New("PERMISSION_DENIED", "原精确代权限已撤销")
		}
		return nil
	}
	view, err := f.manager.RemoveGeneration(context.Background(), f.caller, newer.View.ID, "exact-remove-one", newer.View.Revision, 1)
	requireCode(t, err, "PERMISSION_DENIED")
	if checks != 2 || f.materials.removes != 0 || view.Pending != "remove" || len(view.Generations) != 2 {
		t.Fatal("实际材料清理没有再次检查精确代，或撤权后删除了材料")
	}
}

func TestGenerationRemovalRecoveryRejectsAnotherAuthorizedGeneration(t *testing.T) {
	f := newFixture(t)
	f.issue(t, "recover-exact-issue-one")
	newer := f.issue(t, "recover-exact-issue-two")
	f.materials.removeFailure = errors.New("明确的材料清理故障注入")
	view, err := f.manager.RemoveGeneration(context.Background(), f.caller, newer.View.ID, "recover-exact-remove-one", newer.View.Revision, 1)
	requireCode(t, err, "OUTCOME_UNKNOWN")
	f.materials.removeFailure = nil
	f.authorization.policyCheck = func(request Authorization) error {
		if request.Access == Remove && request.Generation != 2 {
			return fault.New("PERMISSION_DENIED", "当前 operation 仅授权其他代")
		}
		return nil
	}
	_, err = f.manager.RecoverGenerationRemoval(context.Background(), f.caller, view.ID, view.Revision)
	requireCode(t, err, "PERMISSION_DENIED")
	if f.materials.removes != 0 {
		t.Fatal("恢复把另一代的授权套用到原待删除材料")
	}
}
