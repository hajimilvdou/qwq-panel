// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// idemState is the state of one idempotency key row.
const (
	idemInProgress = "in_progress"
	idemCompleted  = "completed"
)

// idempotencyKeyRe is the IdempotencyKeyValue schema.
var idempotencyKeyRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

// idemClaim identifies a key this request owns until it completes.
type idemClaim struct {
	keyID       string
	principal   string
	method      string
	route       string
	key         string
	fingerprint string
}

// IdempotencyClaim 是事务内取得的不可伪造声明；字段仅由 operations 管理。
// 目录豁免写入必须在同一事务完成领域变更和脱敏回放。
type IdempotencyClaim = idemClaim

// claimIdempotency binds the request's key or returns the stored response of an
// earlier identical request. It reports (nil, nil, nil) when the request has no
// key, which is only allowed for read actions.
func (s *Service) claimIdempotency(ctx context.Context, a actor.Actor, idem Idempotency, fingerprint string) (*idemClaim, *Response, error) {
	if idem.Key == "" {
		return nil, nil, nil
	}
	var claim *idemClaim
	var replay *Response
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		var err error
		claim, replay, err = s.idempotencyTx(ctx, tx, a, idem, fingerprint, true)
		return err
	})
	if err != nil {
		return nil, nil, problem.From(err)
	}
	return claim, replay, nil
}

// ======================== 复用原幂等存储的事务接缝 ========================

// ClaimIdempotencyTx 在调用方事务中绑定键或读取回放，不打开第二写事务。
// Idempotency.Fingerprint 必须由宿主根据已验证请求计算。
func (s *Service) ClaimIdempotencyTx(ctx context.Context, tx *storage.Tx, a actor.Actor, idem Idempotency) (*IdempotencyClaim, *Response, error) {
	return s.idempotencyTx(ctx, tx, a, idem, idem.Fingerprint, true)
}

// LookupIdempotencyTx 仅检查已有回放，不占键；一次性链接据此跳过重复 MFA。
func (s *Service) LookupIdempotencyTx(ctx context.Context, tx *storage.Tx, a actor.Actor, idem Idempotency) (*Response, error) {
	_, replay, err := s.idempotencyTx(ctx, tx, a, idem, idem.Fingerprint, false)
	return replay, err
}

func (s *Service) idempotencyTx(ctx context.Context, tx *storage.Tx, a actor.Actor, idem Idempotency, fingerprint string, acquire bool) (*idemClaim, *Response, error) {
	if tx == nil {
		return nil, nil, problem.New(problem.Internal, "An idempotency transaction is required.")
	}
	if !idempotencyKeyRe.MatchString(idem.Key) {
		return nil, nil, problem.Validation(problem.Violation{
			Pointer: "/Idempotency-Key", In: "header", Code: "INVALID",
			Message: "An Idempotency-Key is 16 to 128 characters of A-Z a-z 0-9 _ . : -.",
		})
	}
	method := idem.Method
	if method == "" {
		method = "POST"
	}
	route := idem.Route
	if route == "" {
		route = "/api/v1"
	}
	principal := principalKey(a)
	now := tx.Now()

	var (
		claim  *idemClaim
		replay *Response
	)
	err := func() error {
		// 仅删除当前精确 scope 已过期的行，新鲜键不受其他键清理影响。
		if acquire {
			if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_keys
				WHERE principal = ? AND method = ? AND route = ? AND key = ? AND expires_at <= ?`,
				principal, method, route, idem.Key, storage.FormatTime(now)); err != nil {
				return err
			}
		}
		var (
			keyID, storedFingerprint, state string
			operationID                     string
			status                          int
			body                            sql.NullString
			createdAtStr, expiresAtStr      string
		)
		err := tx.QueryRowContext(ctx, `SELECT key_id, fingerprint, state, operation_id, response_status,
				response_body, created_at, expires_at
			FROM idempotency_keys WHERE principal = ? AND method = ? AND route = ? AND key = ? AND expires_at > ?`,
			principal, method, route, idem.Key, storage.FormatTime(now)).
			Scan(&keyID, &storedFingerprint, &state, &operationID, &status, &body, &createdAtStr, &expiresAtStr)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if !acquire {
				return nil
			}
			var live int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM idempotency_keys WHERE principal = ? AND expires_at > ?`,
				principal, storage.FormatTime(now)).Scan(&live); err != nil {
				return err
			}
			if live >= s.cfg.IdempotencyKeysPerPrincipal {
				return &problem.Error{
					Code:   problem.RateLimited,
					Detail: "Too many live idempotency keys for this principal.",
					Limit: &problem.Limit{
						Name: "idempotency_keys_per_principal",
						Max:  int64(s.cfg.IdempotencyKeysPerPrincipal),
					},
					RetryAfterSec: 60,
				}
			}
			claim = &idemClaim{
				keyID: s.ids.New(ids.Idempotency), principal: principal, method: method,
				route: route, key: idem.Key, fingerprint: fingerprint,
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO idempotency_keys
				(key_id, principal, method, route, key, fingerprint, state, created_at, updated_at, expires_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				claim.keyID, principal, method, route, idem.Key, fingerprint, idemInProgress,
				storage.FormatTime(now), storage.FormatTime(now),
				storage.FormatTime(expiresAt(now, s.cfg.IdempotencyTTL)))
			return err
		case err != nil:
			return err
		}

		if storedFingerprint != fingerprint {
			return problem.New(problem.IdempotencyKeyReused,
				"The idempotency key was already used for a different request.")
		}
		if state == idemCompleted {
			replay = &Response{
				Status:      status,
				Body:        json.RawMessage(body.String),
				Replayed:    true,
				OperationID: operationID,
			}
			return nil
		}
		if !acquire {
			return idempotencyInProgress()
		}
		// Still in progress. A claim older than the in-progress TTL belongs to a
		// crashed request. A claim already bound to an operation is never taken
		// over: the retry sees that one operation (OPS-02). An unbound one is
		// taken over, so a retry is not stuck for a day.
		createdAt, parseErr := storage.ParseTime(createdAtStr)
		stale := parseErr == nil && now.Sub(createdAt) > s.cfg.IdempotencyInProgressTTL
		if stale && operationID != "" {
			replay = &Response{Status: 202, Replayed: true, OperationID: operationID}
			return nil
		}
		if stale {
			claim = &idemClaim{
				keyID: keyID, principal: principal, method: method, route: route,
				key: idem.Key, fingerprint: fingerprint,
			}
			_, err := tx.ExecContext(ctx, `UPDATE idempotency_keys
				SET fingerprint = ?, state = ?, created_at = ?, updated_at = ?, expires_at = ?,
					operation_id = '', response_status = 0, response_body = NULL
				WHERE key_id = ?`,
				fingerprint, idemInProgress, storage.FormatTime(now), storage.FormatTime(now),
				storage.FormatTime(expiresAt(now, s.cfg.IdempotencyTTL)), keyID)
			return err
		}
		return idempotencyInProgress()
	}()
	if err != nil {
		return nil, nil, problem.From(err)
	}
	return claim, replay, nil
}

func idempotencyInProgress() error {
	return &problem.Error{Code: problem.IdempotencyInProgress,
		Detail: "A request with this idempotency key is still being processed.", RetryAfterSec: 2}
}

// bindIdempotency 在创建 operation 的事务内绑定幂等键：此后无论请求以何种方式结束，
// 同 key 重试只会看到这一个 operation（at-most-once）。
func bindIdempotency(ctx context.Context, tx *storage.Tx, c *idemClaim, operationID string) error {
	if c == nil {
		return nil
	}
	_, err := tx.ExecContext(ctx,
		`UPDATE idempotency_keys SET operation_id = ?, updated_at = ? WHERE key_id = ?`,
		operationID, storage.FormatTime(tx.Now()), c.keyID)
	return err
}

// finishIdempotency stores the response of a finished request, or releases the
// key when the failure is one the caller should be able to retry (5xx,
// rate limit, authentication) and no operation was created for it: "Only
// responses produced after the key was bound are stored. Authentication
// failures, 429 and 5xx release the key." A key bound to an operation is never
// released, because a retry would execute the action a second time.
func (s *Service) finishIdempotency(ctx context.Context, claim *idemClaim, resp *Response, callErr error,
	requestID, instance string) {
	if claim == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	if callErr != nil {
		perr := problem.From(callErr)
		if perr.OperationID == "" && (perr.Code.Status() >= 500 || perr.Code == problem.RateLimited ||
			perr.Code == problem.Unauthenticated || perr.Code == problem.CSRFFailed) {
			s.releaseIdempotency(ctx, claim)
			return
		}
		rendered := perr.Problem(requestID, instance)
		s.completeIdempotency(ctx, claim, rendered.Status, responseJSON(rendered), perr.OperationID)
		return
	}
	if resp == nil {
		s.releaseIdempotency(ctx, claim)
		return
	}
	s.completeIdempotency(ctx, claim, resp.Status, resp.Body, resp.OperationID)
}

func (s *Service) completeIdempotency(ctx context.Context, claim *idemClaim, status int, body json.RawMessage, operationID string) {
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		return s.CompleteIdempotencyTx(ctx, tx, claim, status, body, operationID)
	})
	if err != nil {
		s.log.ErrorContext(ctx, "operations: store idempotent response",
			"key_id", claim.keyID, "error", err)
	}
}

// CompleteIdempotencyTx 与调用方领域写入原子保存安全回放；body 不能携带
// 只展示一次的凭据。原 operation_id 绑定始终保留，失败由调用方回滚事务。
func (s *Service) CompleteIdempotencyTx(ctx context.Context, tx *storage.Tx, claim *IdempotencyClaim, status int, body json.RawMessage, operationID string) error {
	if claim == nil {
		return nil
	}
	if tx == nil {
		return problem.New(problem.Internal, "An idempotency transaction is required.")
	}
	if len(body) == 0 {
		body = json.RawMessage("null")
	}
	_, err := tx.ExecContext(ctx, `UPDATE idempotency_keys
			SET state = ?, operation_id = CASE WHEN operation_id = '' THEN ? ELSE operation_id END,
			response_status = ?, response_body = ?, updated_at = ?
			WHERE key_id = ?`,
		idemCompleted, operationID, status, string(body), storage.FormatTime(tx.Now()), claim.keyID)
	return err
}

func (s *Service) releaseIdempotency(ctx context.Context, claim *idemClaim) {
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		// 绑定事实以数据库为准，即使上层错误漏带 operation_id 也不释放活键。
		_, err := tx.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE key_id = ? AND operation_id = ''`, claim.keyID)
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "operations: release idempotency key", "key_id", claim.keyID, "error", err)
	}
}

// hydrateReplay fills in the typed fields of a replayed response so callers can
// use them without parsing Body.
func (s *Service) hydrateReplay(ctx context.Context, resp *Response) {
	if resp == nil {
		return
	}
	// 旧版本保存的审批正文可能仍带引用；回放同样经过公开 JSON 边界。
	resp.Body = secrets.RedactRefs(resp.Body)
	if resp.OperationID == "" || resp.Operation != nil {
		return
	}
	if op, err := loadOperation(ctx, s.db.Reader(), resp.OperationID); err == nil {
		resp.Operation = op
		if len(resp.Body) == 0 {
			resp.Body = responseJSON(op)
		}
	}
}
