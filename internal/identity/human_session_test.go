// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 实际password login、SQLite会话与事务内事实 ========================

func humanSessionTxFixture(t *testing.T) (*fixture, actor.Actor) {
	t.Helper()
	f := newFixture(t)
	f.createUser("human-tx", testPassword, RoleAdmin)
	login := f.login("human-tx", testPassword)
	who, _, err := f.svc.AuthenticateSession(f.ctx, login.Token)
	if err != nil {
		t.Fatal(err)
	}
	return f, who
}

func verifyHumanInTx(t *testing.T, f *fixture, who actor.Actor) (actor.Actor, error) {
	t.Helper()
	var verified actor.Actor
	var checkErr error
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		verified, checkErr = f.svc.VerifyHumanSessionTx(f.ctx, tx, who)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return verified, checkErr
}

func TestVerifyHumanSessionTxUsesStoredIdentityAndMFA(t *testing.T) {
	f, who := humanSessionTxFixture(t)
	who.MFA = true
	verified, err := verifyHumanInTx(t, f, who)
	if err != nil || verified.Kind != actor.Human || verified.ID != who.ID || verified.SessionID != who.SessionID || verified.MFA {
		t.Fatal("会话身份丢失或传入布尔值提高了MFA状态")
	}
}

func TestVerifyHumanSessionTxRejectsForeignAndSessionlessActors(t *testing.T) {
	f, who := humanSessionTxFixture(t)
	other := f.createUser("other-tx", testPassword, RoleAdmin)
	for _, changed := range []actor.Actor{
		{Kind: actor.Human, ID: who.ID},
		{Kind: actor.Human, ID: other.ID, SessionID: who.SessionID},
		{Kind: actor.Service, ID: who.ID, SessionID: who.SessionID},
		{Kind: actor.Human, ID: who.ID, SessionID: "ses_invalid"},
		{Kind: actor.Human, ID: who.ID, SessionID: f.gen.New(ids.Session)},
	} {
		if _, err := verifyHumanInTx(t, f, changed); !problem.HasCode(err, problem.Unauthenticated) {
			t.Fatalf("异主或非真实人类会话未拒绝: %v", err)
		}
	}
}

func TestVerifyHumanSessionTxObservesRevocationInCurrentTransaction(t *testing.T) {
	for _, change := range []string{"session", "user"} {
		t.Run(change, func(t *testing.T) {
			f, who := humanSessionTxFixture(t)
			if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
				if change == "session" {
					if _, err := tx.ExecContext(f.ctx, "UPDATE sessions SET revoked_at=? WHERE session_id=?", storage.FormatTime(tx.Now()), who.SessionID); err != nil {
						return err
					}
				} else {
					if _, err := tx.ExecContext(f.ctx, "UPDATE users SET disabled=1 WHERE user_id=?", who.ID); err != nil {
						return err
					}
				}
				if _, err := f.svc.VerifyHumanSessionTx(f.ctx, tx, who); !problem.HasCode(err, problem.Unauthenticated) {
					t.Fatal("同事务撤权未生效，核验可能读取了旧Reader快照")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyHumanSessionTxRejectsExpiredAndCanceledRequests(t *testing.T) {
	for _, boundary := range []string{"idle", "absolute"} {
		f, who := humanSessionTxFixture(t)
		limit := DefaultIdleTimeout
		if boundary == "absolute" {
			limit = DefaultAbsoluteTimeout
			if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
				_, err := tx.ExecContext(f.ctx, "UPDATE sessions SET idle_expires_at=? WHERE session_id=?", storage.FormatTime(tx.Now().Add(2*DefaultAbsoluteTimeout)), who.SessionID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		f.clk.Advance(limit)
		if _, err := verifyHumanInTx(t, f, who); !problem.HasCode(err, problem.Unauthenticated) {
			t.Fatalf("%s截止边界仍允许创建身份", boundary)
		}
	}
	f, who := humanSessionTxFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
		if _, err := f.svc.VerifyHumanSessionTx(ctx, tx, who); !errors.Is(err, context.Canceled) {
			t.Fatalf("取消核验仍读取了会话: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// MFA时间是明确的存储fixture，验证当前事实；既有TOTP回归验证真实协议。
func TestVerifyHumanSessionTxDerivesMFAFromCurrentStoredTimestamp(t *testing.T) {
	for _, offset := range []time.Duration{0, -DefaultMFAFreshness, time.Minute} {
		f, who := humanSessionTxFixture(t)
		if err := f.db.Update(f.ctx, func(tx *storage.Tx) error {
			stamp := storage.FormatTime(tx.Now().Add(offset))
			if _, err := tx.ExecContext(f.ctx, "UPDATE sessions SET mfa_verified_at=? WHERE session_id=?", stamp, who.SessionID); err != nil {
				return err
			}
			verified, err := f.svc.VerifyHumanSessionTx(f.ctx, tx, who)
			if err != nil || verified.MFA != (offset == 0) {
				t.Fatalf("MFA时间边界未按当前事实计算: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
