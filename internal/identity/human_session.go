// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 同事务真实会话；不生成凭据或刷新登录期限 ========================

// VerifyHumanSessionTx 复核当前宿主交互请求的真实session/user关联。
// who必须来自已认证请求；本方法不把知道会话ID当作登录，不处理普通cookie认证。
// 用当前事务读取，保证同事务撤权可见，MFA也只取持久事实的当前状态。
func (s *Service) VerifyHumanSessionTx(ctx context.Context, tx *storage.Tx, who actor.Actor) (actor.Actor, error) {
	if s == nil || ctx == nil || tx == nil {
		return actor.Actor{}, problem.New(problem.Unavailable, "人类会话核验后端不可用。")
	}
	if err := ctx.Err(); err != nil {
		return actor.Actor{}, err
	}
	if !who.IsHumanSession() || who.Valid() != nil ||
		!ids.Valid(who.ID, ids.User) || !ids.Valid(who.SessionID, ids.Session) {
		return actor.Actor{}, unauthenticated()
	}
	sess, err := scanSession(tx.QueryRowContext(ctx,
		"SELECT "+sessionColumns+" FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE s.session_id=? AND s.user_id=?",
		who.SessionID, who.ID))
	if isNoRows(err) {
		return actor.Actor{}, unauthenticated()
	}
	if err != nil {
		return actor.Actor{}, err
	}
	return s.humanSessionActor(sess, tx.Now())
}

func (s *Service) humanSessionActor(sess Session, now time.Time) (actor.Actor, error) {
	if sess.Expired(now) || sess.User.Disabled {
		return actor.Actor{}, unauthenticated()
	}
	return actor.Actor{Kind: actor.Human, ID: sess.User.ID, SessionID: sess.ID,
		MFA: sess.MFAFresh(now, s.mfaFreshness)}, nil
}
