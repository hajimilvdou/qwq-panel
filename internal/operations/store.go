// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// queryer is the subset of *sql.DB, *sql.Tx and *storage.Tx this package needs.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type rowsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type scanner interface {
	Scan(dest ...any) error
}

// ======================== 私有操作元数据与创建时 schema ========================

// storedActionMetadata 保持原 flat Action 的存储布局，只在私有 action_meta 中
// 保存操作级秘密所需的创建时 schema。公开 Action 仍忽略 ArgsSchema，旧行没有
// 此字段时不补当前目录；其他操作不增加每行 schema 副本。
type storedActionMetadata struct {
	Action
	ArgsSchema json.RawMessage `json:"args_schema,omitempty"`
}

func marshalStoredAction(action Action) ([]byte, error) {
	stored := storedActionMetadata{Action: action}
	for _, capability := range action.Capabilities {
		if capability.Name == "secret.reveal" && capability.Scope == "operation" {
			stored.ArgsSchema = action.ArgsSchema
			break
		}
	}
	return json.Marshal(stored)
}

func unmarshalStoredAction(raw []byte) (Action, error) {
	var stored storedActionMetadata
	if err := json.Unmarshal(raw, &stored); err != nil {
		return Action{}, err
	}
	action := stored.Action
	action.ArgsSchema = stored.ArgsSchema
	return action, nil
}

// operationColumnList is the column order of every operation query. The
// placeholder list is derived from it so the two can never drift.
var operationColumnList = []string{
	"operation_id", "action", "action_meta", "status", "target", "node_id", "plugin_id", "instance_id", "subject",
	"actor_kind", "actor_id", "actor_on_behalf_of", "effective_risk", "declared_risk", "effect", "mode",
	"idempotent", "permission", "ui_route", "args", "args_digest", "expected_revision", "preconditions",
	"plan_id", "approval_id", "parent_operation_id", "attempt", "cancel_requested", "progress", "result", "error",
	"timeout_ms", "request_id", "trace_id", "created_at", "updated_at", "started_at", "finished_at", "revision",
	"permission_mode",
}

var (
	operationColumns      = strings.Join(operationColumnList, ", ")
	operationPlaceholders = placeholders(len(operationColumnList))
)

// placeholders returns n comma-separated question marks.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

func scanOperation(sc scanner) (*Operation, error) {
	var (
		op                                      Operation
		action, metaJSON, status, targetJSON    string
		nodeID, pluginID, instanceID, subject   string
		actorKind, actorID, onBehalf            string
		effectiveRisk, declaredRisk, effect     string
		mode, permission, uiRoute               string
		idempotent, cancel                      int
		argsJSON, argsDigest, expectedRevision  string
		preconditionsJSON, planID, approval     string
		parentID, progressJSON                  string
		result, opErr                           sql.NullString
		timeoutMS                               int
		requestID, traceID                      string
		createdAt, updatedAt, startedAt, finish string
		revision                                int64
		permissionMode                          string
	)
	if err := sc.Scan(
		&op.ID, &action, &metaJSON, &status, &targetJSON, &nodeID, &pluginID, &instanceID, &subject,
		&actorKind, &actorID, &onBehalf, &effectiveRisk, &declaredRisk, &effect, &mode, &idempotent,
		&permission, &uiRoute, &argsJSON, &argsDigest, &expectedRevision, &preconditionsJSON, &planID,
		&approval, &parentID, &op.Attempt, &cancel, &progressJSON, &result, &opErr, &timeoutMS,
		&requestID, &traceID, &createdAt, &updatedAt, &startedAt, &finish, &revision, &permissionMode,
	); err != nil {
		return nil, err
	}
	op.Action = action
	op.Status = Status(status)
	op.Actor = actor.Actor{Kind: actor.Kind(actorKind), ID: actorID, OnBehalfOf: onBehalf}
	op.EffectiveRisk = effectiveRisk
	op.DeclaredRisk = declaredRisk
	op.Effect = effect
	op.Mode = mode
	op.PermissionMode = PermissionMode(permissionMode)
	op.Idempotent = idempotent != 0
	op.Permission = permission
	op.UIRoute = uiRoute
	op.ExpectedRevision = expectedRevision
	op.PlanID = planID
	op.ApprovalID = approval
	op.ParentOperationID = parentID
	op.CancelRequested = cancel != 0
	op.RequestID = requestID
	op.TraceID = traceID
	op.NodeID = nodeID
	op.Timeout = time.Duration(timeoutMS) * time.Millisecond
	op.ArgsDigest = argsDigest
	op.Revision = strconv.FormatInt(revision, 10)
	op.Args = json.RawMessage(argsJSON)
	if err := unmarshalArray(preconditionsJSON, &op.Preconditions); err != nil {
		return nil, fmt.Errorf("operations: operation %s: preconditions: %w", op.ID, err)
	}
	if targetJSON != "" {
		if err := json.Unmarshal([]byte(targetJSON), &op.Target); err != nil {
			return nil, fmt.Errorf("operations: operation %s: target: %w", op.ID, err)
		}
	}
	if metaJSON != "" {
		meta, err := unmarshalStoredAction([]byte(metaJSON))
		if err != nil {
			return nil, fmt.Errorf("operations: operation %s: action_meta: %w", op.ID, err)
		}
		op.Meta = meta
	}
	if op.Meta.Mode != "" {
		op.Mode = op.Meta.Mode
	}
	if progressJSON != "" && progressJSON != "{}" && progressJSON != "null" {
		var p Progress
		if err := json.Unmarshal([]byte(progressJSON), &p); err != nil {
			return nil, fmt.Errorf("operations: operation %s: progress: %w", op.ID, err)
		}
		op.Progress = &p
	}
	if result.Valid && result.String != "" && result.String != "null" {
		op.Result = json.RawMessage(result.String)
	}
	if opErr.Valid && opErr.String != "" && opErr.String != "null" {
		var p problem.Problem
		if err := json.Unmarshal([]byte(opErr.String), &p); err != nil {
			return nil, fmt.Errorf("operations: operation %s: error: %w", op.ID, err)
		}
		op.Error = &p
	}
	var err error
	if op.CreatedAt, err = storage.ParseTime(createdAt); err != nil {
		return nil, fmt.Errorf("operations: operation %s: created_at: %w", op.ID, err)
	}
	if op.UpdatedAt, err = storage.ParseTime(updatedAt); err != nil {
		return nil, fmt.Errorf("operations: operation %s: updated_at: %w", op.ID, err)
	}
	if op.StartedAt, err = optionalTime(startedAt); err != nil {
		return nil, fmt.Errorf("operations: operation %s: started_at: %w", op.ID, err)
	}
	if op.FinishedAt, err = optionalTime(finish); err != nil {
		return nil, fmt.Errorf("operations: operation %s: finished_at: %w", op.ID, err)
	}
	return &op, nil
}

func loadOperation(ctx context.Context, q queryer, id string) (*Operation, error) {
	row := q.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE operation_id = ?`, id)
	op, err := scanOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("operation")
	}
	if err != nil {
		return nil, problem.Wrap(fmt.Errorf("operations: load %s: %w", id, err))
	}
	return op, nil
}

func insertOperationRow(ctx context.Context, tx *storage.Tx, op *Operation) error {
	metaJSON, err := marshalStoredAction(op.Meta)
	if err != nil {
		return problem.Wrap(err)
	}
	targetJSON, err := json.Marshal(op.Target)
	if err != nil {
		return problem.Wrap(err)
	}
	progressJSON, err := jsonObject(op.Progress)
	if err != nil {
		return problem.Wrap(err)
	}
	argsJSON := "{}"
	if len(op.Args) > 0 {
		argsJSON = string(op.Args)
	}
	preconds, err := jsonArray(op.Preconditions)
	if err != nil {
		return problem.Wrap(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO operations (`+operationColumns+`)
		VALUES (`+operationPlaceholders+`)`,
		op.ID, op.Action, string(metaJSON), string(op.Status), string(targetJSON), op.NodeID, op.Target.PluginID,
		op.Target.InstanceID, op.Target.Subject, string(op.Actor.Kind), op.Actor.ID, op.Actor.OnBehalfOf,
		op.EffectiveRisk, op.DeclaredRisk, op.Effect, op.Mode, boolInt(op.Idempotent), op.Permission, op.UIRoute,
		argsJSON, op.ArgsDigest, op.ExpectedRevision, preconds, op.PlanID, op.ApprovalID, op.ParentOperationID,
		op.Attempt, boolInt(op.CancelRequested), progressJSON, nullJSON(op.Result), nullProblem(op.Error),
		int(op.Timeout/time.Millisecond), op.RequestID, op.TraceID, storage.FormatTime(op.CreatedAt),
		storage.FormatTime(op.UpdatedAt), formatTimePtr(op.StartedAt), formatTimePtr(op.FinishedAt), revisionSeq(op.Revision),
		string(op.PermissionMode),
	)
	if err != nil {
		return problem.Wrap(fmt.Errorf("operations: insert %s: %w", op.ID, err))
	}
	return nil
}

// updateOperationRow writes the mutable columns of an operation.
func updateOperationRow(ctx context.Context, tx *storage.Tx, op *Operation) error {
	progressJSON, err := jsonObject(op.Progress)
	if err != nil {
		return problem.Wrap(err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE operations SET
			status = ?, attempt = ?, cancel_requested = ?, progress = ?, result = ?, error = ?,
			approval_id = ?, plan_id = ?, timeout_ms = ?, started_at = ?, finished_at = ?,
			updated_at = ?, revision = ?
		WHERE operation_id = ?`,
		string(op.Status), op.Attempt, boolInt(op.CancelRequested), progressJSON, nullJSON(op.Result),
		nullProblem(op.Error), op.ApprovalID, op.PlanID, int(op.Timeout/time.Millisecond),
		formatTimePtr(op.StartedAt), formatTimePtr(op.FinishedAt), storage.FormatTime(op.UpdatedAt),
		revisionSeq(op.Revision), op.ID)
	if err != nil {
		return problem.Wrap(fmt.Errorf("operations: update %s: %w", op.ID, err))
	}
	return nil
}

func startAttemptRow(ctx context.Context, tx *storage.Tx, op *Operation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO operation_attempts
		(operation_id, attempt, status, started_at) VALUES (?, ?, 'running', ?)`,
		op.ID, op.Attempt, storage.FormatTime(tx.Now()))
	if err != nil {
		return problem.Wrap(fmt.Errorf("operations: attempt %s/%d: %w", op.ID, op.Attempt, err))
	}
	return nil
}

func finishAttemptRow(ctx context.Context, tx *storage.Tx, op *Operation, status string) error {
	_, err := tx.ExecContext(ctx, `UPDATE operation_attempts SET status = ?, finished_at = ?, error = ?
		WHERE operation_id = ? AND attempt = ?`,
		status, storage.FormatTime(tx.Now()), nullProblem(op.Error), op.ID, op.Attempt)
	if err != nil {
		return problem.Wrap(fmt.Errorf("operations: finish attempt %s/%d: %w", op.ID, op.Attempt, err))
	}
	return nil
}

// queryOperations returns the operations matching f that a may read.
func (s *Service) queryOperations(ctx context.Context, q rowsQuerier, f ListFilter, a actor.Actor) ([]Operation, error) {
	var (
		where []string
		args  []any
	)
	if len(f.Statuses) > 0 {
		placeholders := make([]string, len(f.Statuses))
		for i, st := range f.Statuses {
			placeholders[i] = "?"
			args = append(args, string(st))
		}
		where = append(where, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if f.ActorKind != "" {
		where = append(where, "actor_kind = ?")
		args = append(args, string(f.ActorKind))
	}
	if f.NodeID != "" {
		where = append(where, "node_id = ?")
		args = append(args, f.NodeID)
	}
	if f.PluginID != "" {
		where = append(where, "plugin_id = ?")
		args = append(args, f.PluginID)
	}
	if f.SinceRevision != "" {
		seq, err := revisionInt(f.SinceRevision)
		if err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/since_revision", In: "query", Code: "INVALID", Message: "Not a revision.",
			})
		}
		where = append(where, "revision > ?")
		args = append(args, seq)
	}
	if !canReadAll(a) {
		where = append(where, "actor_kind = ? AND actor_id = ? AND actor_on_behalf_of = ?")
		args = append(args, string(a.Kind), a.ID, a.OnBehalfOf)
	}
	if f.Cursor != "" {
		after, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/cursor", In: "query", Code: "INVALID", Message: "Not a cursor.",
			})
		}
		where = append(where, "operation_id < ?")
		args = append(args, after)
	}
	limit := clampLimit(f.Limit)
	query := `SELECT ` + operationColumns + ` FROM operations`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY operation_id DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, problem.Wrap(fmt.Errorf("operations: list: %w", err))
	}
	defer rows.Close()
	var out []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, problem.Wrap(fmt.Errorf("operations: list: %w", err))
		}
		out = append(out, *op)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(fmt.Errorf("operations: list: %w", err))
	}
	return out, nil
}

// canReadAll reports whether the actor sees every operation. People see the
// whole task list (follow mode shows what an AI is doing, ADR-0004 D9); an AI
// agent or service account sees only its own operations.
func canReadAll(a actor.Actor) bool {
	return a.Kind == actor.Human || a.Kind == actor.System
}

func canRead(a actor.Actor, op *Operation) bool {
	return canReadAll(a) || samePrincipal(a, op.Actor)
}

// ---- approvals ----

var approvalColumnList = []string{
	"approval_id", "operation_id", "plan_id", "status", "facts", "plugin_preview", "requires_mfa",
	"decided_by_kind", "decided_by_id", "decided_by_on_behalf_of", "decided_at", "comment",
	"created_at", "expires_at", "revision",
}

var (
	approvalColumns      = strings.Join(approvalColumnList, ", ")
	approvalPlaceholders = placeholders(len(approvalColumnList))
)

func scanApproval(sc scanner) (*Approval, error) {
	var (
		ap                                    Approval
		status, factsJSON, previewJSON        string
		requiresMFA                           int
		decidedKind, decidedID, decidedBehalf string
		decidedAt, comment, createdAt         string
		expiresAt                             string
		revision                              int64
	)
	if err := sc.Scan(&ap.ID, &ap.OperationID, &ap.PlanID, &status, &factsJSON, &previewJSON, &requiresMFA,
		&decidedKind, &decidedID, &decidedBehalf, &decidedAt, &comment, &createdAt, &expiresAt, &revision); err != nil {
		return nil, err
	}
	ap.Status = ApprovalStatus(status)
	ap.RequiresMFA = requiresMFA != 0
	ap.Comment = comment
	ap.Revision = strconv.FormatInt(revision, 10)
	if err := json.Unmarshal([]byte(factsJSON), &ap.Facts); err != nil {
		return nil, fmt.Errorf("operations: approval %s: facts: %w", ap.ID, err)
	}
	if previewJSON != "" && previewJSON != "{}" && previewJSON != "null" {
		var p PluginPreview
		if err := json.Unmarshal([]byte(previewJSON), &p); err != nil {
			return nil, fmt.Errorf("operations: approval %s: preview: %w", ap.ID, err)
		}
		if p.Changes != nil || p.Warnings != nil {
			ap.PluginPreview = &p
		}
	}
	if decidedKind != "" {
		ap.DecidedBy = &actor.Actor{Kind: actor.Kind(decidedKind), ID: decidedID, OnBehalfOf: decidedBehalf}
	}
	var err error
	if ap.CreatedAt, err = storage.ParseTime(createdAt); err != nil {
		return nil, fmt.Errorf("operations: approval %s: created_at: %w", ap.ID, err)
	}
	if ap.ExpiresAt, err = storage.ParseTime(expiresAt); err != nil {
		return nil, fmt.Errorf("operations: approval %s: expires_at: %w", ap.ID, err)
	}
	if ap.DecidedAt, err = optionalTime(decidedAt); err != nil {
		return nil, fmt.Errorf("operations: approval %s: decided_at: %w", ap.ID, err)
	}
	return &ap, nil
}

func loadApproval(ctx context.Context, q queryer, id string) (*Approval, error) {
	row := q.QueryRowContext(ctx, `SELECT `+approvalColumns+` FROM approvals WHERE approval_id = ?`, id)
	ap, err := scanApproval(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("approval")
	}
	if err != nil {
		return nil, problem.Wrap(fmt.Errorf("operations: load approval %s: %w", id, err))
	}
	return ap, nil
}

func insertApprovalRow(ctx context.Context, tx *storage.Tx, ap *Approval) error {
	factsJSON, err := json.Marshal(ap.Facts)
	if err != nil {
		return problem.Wrap(err)
	}
	previewJSON := "{}"
	if ap.PluginPreview != nil {
		b, err := json.Marshal(ap.PluginPreview)
		if err != nil {
			return problem.Wrap(err)
		}
		previewJSON = string(b)
	}
	decidedKind, decidedID, decidedBehalf, decidedAt := "", "", "", ""
	if ap.DecidedBy != nil {
		decidedKind, decidedID, decidedBehalf = string(ap.DecidedBy.Kind), ap.DecidedBy.ID, ap.DecidedBy.OnBehalfOf
	}
	if ap.DecidedAt != nil {
		decidedAt = storage.FormatTime(*ap.DecidedAt)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO approvals (`+approvalColumns+`)
		VALUES (`+approvalPlaceholders+`)`,
		ap.ID, ap.OperationID, ap.PlanID, string(ap.Status), string(factsJSON), previewJSON,
		boolInt(ap.RequiresMFA), decidedKind, decidedID, decidedBehalf, decidedAt, ap.Comment,
		storage.FormatTime(ap.CreatedAt), storage.FormatTime(ap.ExpiresAt), revisionSeq(ap.Revision))
	if err != nil {
		return problem.Wrap(fmt.Errorf("operations: insert approval %s: %w", ap.ID, err))
	}
	return nil
}

func updateApprovalRow(ctx context.Context, tx *storage.Tx, ap *Approval) error {
	decidedKind, decidedID, decidedBehalf, decidedAt := "", "", "", ""
	if ap.DecidedBy != nil {
		decidedKind, decidedID, decidedBehalf = string(ap.DecidedBy.Kind), ap.DecidedBy.ID, ap.DecidedBy.OnBehalfOf
	}
	if ap.DecidedAt != nil {
		decidedAt = storage.FormatTime(*ap.DecidedAt)
	}
	_, err := tx.ExecContext(ctx, `UPDATE approvals SET status = ?, decided_by_kind = ?, decided_by_id = ?,
			decided_by_on_behalf_of = ?, decided_at = ?, comment = ?, revision = ?
		WHERE approval_id = ?`,
		string(ap.Status), decidedKind, decidedID, decidedBehalf, decidedAt, ap.Comment,
		revisionSeq(ap.Revision), ap.ID)
	if err != nil {
		return problem.Wrap(fmt.Errorf("operations: update approval %s: %w", ap.ID, err))
	}
	return nil
}

// ---- plans ----

var planColumnList = []string{
	"plan_id", "action", "action_meta", "target", "args", "args_digest", "plannable", "changes",
	"changes_truncated", "violations", "warnings", "preconditions", "plugin_preconditions",
	"effective_risk", "requires_approval", "requires_mfa", "executable", "operation_id",
	"actor_kind", "actor_id", "actor_on_behalf_of", "trace_id", "request_id", "created_at",
	"expires_at", "revision",
}

var (
	planColumns      = strings.Join(planColumnList, ", ")
	planPlaceholders = placeholders(len(planColumnList))
)

func scanPlan(sc scanner) (*Plan, error) {
	var (
		p                                           Plan
		metaJSON, targetJSON, argsJSON              string
		changesJSON, violationsJSON, warningsJSON   string
		precondsJSON, pluginPrecondsJSON            string
		plannable, truncated, requiresApproval, mfa int
		executable                                  int
		actorKind, actorID, onBehalf                string
		traceID, requestID, createdAt, expiresAt    string
		revision                                    int64
	)
	if err := sc.Scan(&p.ID, &p.Action, &metaJSON, &targetJSON, &argsJSON, &p.ArgsDigest, &plannable,
		&changesJSON, &truncated, &violationsJSON, &warningsJSON, &precondsJSON, &pluginPrecondsJSON,
		&p.EffectiveRisk, &requiresApproval, &mfa, &executable, &p.OperationID, &actorKind, &actorID,
		&onBehalf, &traceID, &requestID, &createdAt, &expiresAt, &revision); err != nil {
		return nil, err
	}
	p.Plannable = plannable != 0
	p.ChangesTruncated = truncated != 0
	p.RequiresApproval = requiresApproval != 0
	p.RequiresMFA = mfa != 0
	p.Executable = executable != 0
	p.Owner = actor.Actor{Kind: actor.Kind(actorKind), ID: actorID, OnBehalfOf: onBehalf}
	p.TraceID = traceID
	p.RequestID = requestID
	p.Revision = strconv.FormatInt(revision, 10)
	meta, metaErr := unmarshalStoredAction([]byte(metaJSON))
	if metaErr != nil {
		return nil, fmt.Errorf("operations: plan %s: action_meta: %w", p.ID, metaErr)
	}
	p.Meta = meta
	if err := json.Unmarshal([]byte(targetJSON), &p.Target); err != nil {
		return nil, fmt.Errorf("operations: plan %s: target: %w", p.ID, err)
	}
	p.Args = json.RawMessage(argsJSON)
	if err := unmarshalArray(changesJSON, &p.Changes); err != nil {
		return nil, fmt.Errorf("operations: plan %s: changes: %w", p.ID, err)
	}
	if err := unmarshalArray(violationsJSON, &p.Violations); err != nil {
		return nil, fmt.Errorf("operations: plan %s: violations: %w", p.ID, err)
	}
	if err := unmarshalArray(warningsJSON, &p.Warnings); err != nil {
		return nil, fmt.Errorf("operations: plan %s: warnings: %w", p.ID, err)
	}
	if err := unmarshalArray(precondsJSON, &p.Preconditions); err != nil {
		return nil, fmt.Errorf("operations: plan %s: preconditions: %w", p.ID, err)
	}
	if err := unmarshalArray(pluginPrecondsJSON, &p.PluginPreconditions); err != nil {
		return nil, fmt.Errorf("operations: plan %s: plugin preconditions: %w", p.ID, err)
	}
	var err error
	if p.CreatedAt, err = storage.ParseTime(createdAt); err != nil {
		return nil, fmt.Errorf("operations: plan %s: created_at: %w", p.ID, err)
	}
	if p.ExpiresAt, err = storage.ParseTime(expiresAt); err != nil {
		return nil, fmt.Errorf("operations: plan %s: expires_at: %w", p.ID, err)
	}
	return &p, nil
}

func loadPlan(ctx context.Context, q queryer, id string) (*Plan, error) {
	row := q.QueryRowContext(ctx, `SELECT `+planColumns+` FROM plans WHERE plan_id = ?`, id)
	p, err := scanPlan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound("plan")
	}
	if err != nil {
		return nil, problem.Wrap(fmt.Errorf("operations: load plan %s: %w", id, err))
	}
	return p, nil
}

func insertPlanRow(ctx context.Context, tx *storage.Tx, p *Plan) error {
	metaJSON, err := marshalStoredAction(p.Meta)
	if err != nil {
		return problem.Wrap(err)
	}
	targetJSON, err := json.Marshal(p.Target)
	if err != nil {
		return problem.Wrap(err)
	}
	argsJSON := "{}"
	if len(p.Args) > 0 {
		argsJSON = string(p.Args)
	}
	changes, err := jsonArray(p.Changes)
	if err != nil {
		return problem.Wrap(err)
	}
	violations, err := jsonArray(p.Violations)
	if err != nil {
		return problem.Wrap(err)
	}
	warnings, err := jsonArray(p.Warnings)
	if err != nil {
		return problem.Wrap(err)
	}
	preconds, err := jsonArray(p.Preconditions)
	if err != nil {
		return problem.Wrap(err)
	}
	pluginPreconds, err := jsonArray(p.PluginPreconditions)
	if err != nil {
		return problem.Wrap(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO plans (`+planColumns+`)
		VALUES (`+planPlaceholders+`)`,
		p.ID, p.Action, string(metaJSON), string(targetJSON), argsJSON, p.ArgsDigest, boolInt(p.Plannable),
		changes, boolInt(p.ChangesTruncated), violations, warnings, preconds, pluginPreconds,
		p.EffectiveRisk, boolInt(p.RequiresApproval), boolInt(p.RequiresMFA), boolInt(p.Executable),
		p.OperationID, string(p.Owner.Kind), p.Owner.ID, p.Owner.OnBehalfOf, p.TraceID, p.RequestID,
		storage.FormatTime(p.CreatedAt), storage.FormatTime(p.ExpiresAt), revisionSeq(p.Revision))
	if err != nil {
		return problem.Wrap(fmt.Errorf("operations: insert plan %s: %w", p.ID, err))
	}
	return nil
}

// bindPlanOperation marks a plan as executed by an operation. The empty
// operation_id guard makes "a plan executes at most once" hold.
func bindPlanOperation(ctx context.Context, tx *storage.Tx, planID, operationID string) error {
	res, err := tx.ExecContext(ctx, `UPDATE plans SET operation_id = ? WHERE plan_id = ? AND operation_id = ''`,
		operationID, planID)
	if err != nil {
		return problem.Wrap(fmt.Errorf("operations: bind plan %s: %w", planID, err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return problem.Wrap(err)
	}
	if n == 0 {
		// Report which operation won the race (OpenAPI executePlan).
		existing := ""
		_ = tx.QueryRowContext(ctx, `SELECT operation_id FROM plans WHERE plan_id = ?`, planID).Scan(&existing)
		return &problem.Error{
			Code:        problem.StateConflict,
			Detail:      "The plan was already executed.",
			OperationID: existing,
		}
	}
	return nil
}

// ---- small helpers ----

func notFound(kind string) error {
	return problem.New(problem.NotFound, "No such %s.", kind)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

func nullProblem(p *problem.Problem) any {
	if p == nil {
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	return string(b)
}

func jsonObject(v any) (string, error) {
	if v == nil {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if string(b) == "null" {
		return "{}", nil
	}
	return string(b), nil
}

func jsonArray(v any) (string, error) {
	if v == nil {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if string(b) == "null" {
		return "[]", nil
	}
	return string(b), nil
}

func unmarshalArray(s string, dst any) error {
	if s == "" || s == "null" {
		return nil
	}
	return json.Unmarshal([]byte(s), dst)
}

func optionalTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := storage.ParseTime(s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return storage.FormatTime(*t)
}

func revisionSeq(rev string) int64 {
	n, err := strconv.ParseInt(rev, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func revisionInt(rev string) (int64, error) {
	n, err := strconv.ParseInt(rev, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("operations: invalid revision")
	}
	return n, nil
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	return min(limit, 200)
}
