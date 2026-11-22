// SPDX-License-Identifier: AGPL-3.0-only

package privateexport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

type record struct {
	Grant                         Grant
	binding                       CreateRequest
	owner, sessionID, operationID string
	secretRef                     secrets.Ref
	createdAt                     time.Time
	material                      KeyMaterial
}

func (record) String() string   { return "privateexport.record{[REDACTED]}" }
func (record) GoString() string { return "privateexport.record{[REDACTED]}" }

func (s *Service) load(ctx context.Context, tx *storage.Tx, id string) (record, error) {
	if !ids.Valid(id, exportPrefix) {
		return record{}, notFound()
	}
	var entry record
	var created, expires, material, ref string
	err := tx.QueryRowContext(ctx, `SELECT export_id,owner_user_id,session_id,action,plugin_id,instance_id,node_id,purpose,subject,status,operation_id,secret_ref,material_json,created_at,expires_at
		FROM private_exports WHERE export_id=?`, id).Scan(&entry.Grant.ID, &entry.owner, &entry.sessionID, &entry.binding.Action, &entry.binding.PluginID, &entry.binding.InstanceID, &entry.binding.NodeID, &entry.binding.Purpose, &entry.binding.Subject, &entry.Grant.Status, &entry.operationID, &ref, &material, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return record{}, notFound()
	}
	if err != nil {
		return record{}, err
	}
	entry.createdAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return record{}, err
	}
	entry.Grant.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return record{}, err
	}
	if !s.validBinding(entry.binding) || json.Unmarshal([]byte(material), &entry.material) != nil {
		return record{}, problem.New(problem.Unavailable, "私密导出状态无效")
	}
	entry.secretRef = secrets.Ref(ref)
	return entry, nil
}

func (s *Service) session(ctx context.Context, tx *storage.Tx, user, session string) error {
	var revoked, idle, expires string
	var disabled int
	err := tx.QueryRowContext(ctx, `SELECT u.disabled,s.revoked_at,s.idle_expires_at,s.expires_at FROM sessions s JOIN users u ON u.user_id=s.user_id
		WHERE s.session_id=? AND s.user_id=?`, session, user).Scan(&disabled, &revoked, &idle, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return notFound()
	}
	if err != nil {
		return err
	}
	end, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return problem.New(problem.Unavailable, "人类会话状态无效")
	}
	idleEnd, err := time.Parse(time.RFC3339Nano, idle)
	if err != nil {
		return problem.New(problem.Unavailable, "人类会话状态无效")
	}
	now := s.opts.Clock.Now()
	if disabled != 0 || revoked != "" || !now.Before(end) || !now.Before(idleEnd) {
		return notFound()
	}
	return nil
}

func (s *Service) producer(ctx context.Context, tx *storage.Tx, call Caller) (record, error) {
	if !s.validBinding(call.Binding) || !ids.Valid(call.OperationID, ids.Operation) || call.Actor.Valid() != nil {
		return record{}, notFound()
	}
	entry, err := s.load(ctx, tx, call.ExportID)
	if err != nil {
		return record{}, err
	}
	owner := call.Actor.ID
	if call.Actor.Kind == actor.AIAgent || call.Actor.Kind == actor.Service {
		owner = call.Actor.OnBehalfOf
	}
	if call.Actor.Kind == actor.System || owner == "" || owner != entry.owner || entry.binding != call.Binding || entry.operationID != "" && entry.operationID != call.OperationID {
		return record{}, notFound()
	}
	now := s.opts.Clock.Now()
	if now.Before(entry.createdAt) || !now.Before(entry.Grant.ExpiresAt) {
		return record{}, notFound()
	}
	if err := s.session(ctx, tx, entry.owner, entry.sessionID); err != nil {
		return record{}, err
	}
	// 只用于当前角色/动作权限查询；不会把此 actor 传给 operation 审批或执行入口。
	human := actor.Actor{Kind: actor.Human, ID: entry.owner, SessionID: entry.sessionID}
	if err := s.opts.Authorize(ctx, human, entry.binding); err != nil {
		return record{}, err
	}
	return entry, nil
}

func (s *Service) prune(ctx context.Context, tx *storage.Tx) (int64, error) {
	result, err := tx.ExecContext(ctx, `DELETE FROM private_exports WHERE export_id IN
		(SELECT export_id FROM private_exports WHERE expires_at<=? ORDER BY expires_at LIMIT 128)`, storage.FormatTime(s.opts.Clock.Now()))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Prune 是宿主既有维护循环的有界接缝，不新增常驻任务。
func (s *Service) Prune(ctx context.Context) (int64, error) {
	var count int64
	err := s.opts.DB.Update(ctx, func(tx *storage.Tx) error { var err error; count, err = s.prune(ctx, tx); return err })
	return count, problemResult(err)
}

func secretOwner(id string) string { return "private_exports/" + id }
