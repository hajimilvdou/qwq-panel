// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// nodeRevision is the revision of the synthetic `local` node.
const nodeRevision = "1"

const (
	nodeHeartbeatOnlineWindow = 90 * time.Second
	defaultEnrollTokenTTL     = 15 * time.Minute
	maxEnrollTokenTTL         = 24 * time.Hour
)

// localNode renders the single node of a standalone installation.
func (a *api) localNode() nodeDTO {
	return nodeDTO{
		NodeID:     a.d.NodeID,
		Name:       a.d.NodeID,
		Status:     "online",
		LastSeenAt: ts(a.d.Clock.Now().UTC()),
		CreatedAt:  ts(a.startedAt),
		Revision:   nodeRevision,
	}
}

func (a *api) loadRemoteNode(ctx context.Context, nodeID string) (nodeDTO, bool, error) {
	var (
		dto          nodeDTO
		state, mode  string
		agentVer     string
		arch         string
		addrsJSON    string
		lastHB, crAt int64
	)
	err := a.d.DB.View(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
SELECT id, name, mode, enrollment_state, agent_version, arch, public_addrs_json,
       last_heartbeat_at, revision, created_at
FROM nodes WHERE id = ?`, nodeID).Scan(
			&dto.NodeID, &dto.Name, &mode, &state, &agentVer, &arch, &addrsJSON,
			&lastHB, &dto.Revision, &crAt,
		)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nodeDTO{}, false, nil
	}
	if err != nil {
		return nodeDTO{}, false, problem.Wrap(err)
	}
	dto.Mode = mode
	dto.EnrollmentState = state
	dto.CreatedAt = ts(time.UnixMilli(crAt).UTC())
	if lastHB > 0 {
		dto.LastSeenAt = ts(time.UnixMilli(lastHB).UTC())
	}
	dto.Status = computeNodeStatus(state, lastHB, a.d.Clock.Now().UTC())
	var addrs []string
	_ = json.Unmarshal([]byte(addrsJSON), &addrs)
	dto.Reported = map[string]any{
		"agent_version": agentVer,
		"arch":          arch,
		"public_addrs":  addrs,
	}
	return dto, true, nil
}

func (a *api) loadAllRemoteNodes(ctx context.Context) ([]nodeDTO, error) {
	now := a.d.Clock.Now().UTC()
	var out []nodeDTO
	err := a.d.DB.View(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
SELECT id, name, mode, enrollment_state, agent_version, arch, public_addrs_json,
       last_heartbeat_at, revision, created_at
FROM nodes ORDER BY created_at ASC, id ASC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				dto          nodeDTO
				state, mode  string
				agentVer     string
				arch         string
				addrsJSON    string
				lastHB, crAt int64
			)
			if err := rows.Scan(&dto.NodeID, &dto.Name, &mode, &state, &agentVer, &arch, &addrsJSON, &lastHB, &dto.Revision, &crAt); err != nil {
				return err
			}
			if dto.NodeID == a.d.NodeID {
				continue
			}
			dto.Mode = mode
			dto.EnrollmentState = state
			dto.CreatedAt = ts(time.UnixMilli(crAt).UTC())
			if lastHB > 0 {
				dto.LastSeenAt = ts(time.UnixMilli(lastHB).UTC())
			}
			dto.Status = computeNodeStatus(state, lastHB, now)
			var addrs []string
			_ = json.Unmarshal([]byte(addrsJSON), &addrs)
			dto.Reported = map[string]any{
				"agent_version": agentVer,
				"arch":          arch,
				"public_addrs":  addrs,
			}
			out = append(out, dto)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return out, nil
}

func computeNodeStatus(state string, lastHBMs int64, now time.Time) string {
	switch state {
	case "revoked":
		return "revoked"
	case "cordoned":
		return "cordoned"
	case "pending":
		return "pending"
	default:
		if lastHBMs > 0 && now.Sub(time.UnixMilli(lastHBMs)) <= nodeHeartbeatOnlineWindow {
			return "online"
		}
		return "offline"
	}
}

// listNodes returns the local host node plus any enrolled remote cluster nodes (P4).
func (a *api) listNodes(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.nodes:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	remotes, err := a.loadAllRemoteNodes(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]any, 0, 1+len(remotes))
	items = append(items, a.localNode())
	for _, n := range remotes {
		items = append(items, n)
	}
	a.writeList(w, r, listResponse{
		Items:    items,
		Revision: a.watermark(),
	}, q.Fields)
}

// getNode returns one node (`local` or an enrolled remote cluster node).
func (a *api) getNode(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	nodeID := r.PathValue("node_id")
	if err := a.authorize(r.Context(), act, "host.nodes:read", nodeID); err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if nodeID == a.d.NodeID {
		a.writeResource(w, r, http.StatusOK, a.localNode(), fields)
		return
	}
	remote, ok, err := a.loadRemoteNode(r.Context(), nodeID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !ok {
		a.fail(w, r, problem.New(problem.NotFound, "The node does not exist."))
		return
	}
	a.writeResource(w, r, http.StatusOK, remote, fields)
}

type createEnrollmentTokenRequest struct {
	PresetName string `json:"preset_name"`
	Mode       string `json:"mode,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type nodeEnrollmentTokenDTO struct {
	ID           string `json:"id"`
	Token        string `json:"token"`
	PresetName   string `json:"preset_name"`
	Mode         string `json:"mode"`
	ExpiresAt    string `json:"expires_at"`
	CASPKISHA256 string `json:"ca_spki_sha256,omitempty"`
}

// createNodeEnrollmentToken 实现 POST /api/v1/nodes/enrollment-tokens（签发 15 分钟单次边缘节点入网令牌）。
func (a *api) createNodeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.nodes:write", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	var req createEnrollmentTokenRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	preset := strings.TrimSpace(req.PresetName)
	if preset == "" || len(preset) > 64 {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/preset_name", Code: "INVALID", Message: "preset_name must be 1..64 characters.",
		}))
		return
	}
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "full"
	}
	if mode != "full" && mode != "probe_512m" {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/mode", Code: "INVALID", Message: "mode must be full or probe_512m.",
		}))
		return
	}
	ttl := defaultEnrollTokenTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl < time.Minute || ttl > maxEnrollTokenTTL {
			a.fail(w, r, problem.Validation(problem.Violation{
				Pointer: "/ttl_seconds", Code: "OUT_OF_RANGE", Message: "ttl_seconds must be between 60 and 86400.",
			}))
			return
		}
	}
	key, err := a.idempotency(r, req)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	var rnd [24]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	plainToken := "qwq_enroll_" + base64.RawURLEncoding.EncodeToString(rnd[:])
	sum := sha256.Sum256([]byte(plainToken))
	hashHex := hex.EncodeToString(sum[:])

	response, err := a.catalogWrite(r, act, key, "host.nodes:enroll_token", http.StatusCreated, "token", func(tx *storage.Tx) (any, error) {
		now := tx.Now()
		exp := now.Add(ttl)
		id := tx.NewID("netok")
		if _, err := tx.ExecContext(r.Context(), `
INSERT INTO node_enrollment_tokens (id, token_sha256, preset_name, mode, expires_at, redeemed_node_id, created_by, created_at)
VALUES (?, ?, ?, ?, ?, '', ?, ?)`,
			id, hashHex, preset, mode, exp.UTC().UnixMilli(), act.ID, now.UTC().UnixMilli(),
		); err != nil {
			return nil, problem.Wrap(err)
		}
		if err := operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor: act, Action: "node.enrollment_token.create", Subject: "nodes/enrollment-tokens/" + id,
			Outcome: operations.AuditSuccess, TraceID: traceID(r), RequestID: requestID(r),
		}); err != nil {
			return nil, err
		}
		caHash := ""
		if a.d.ClusterCAHash != nil {
			caHash = a.d.ClusterCAHash()
		}
		return nodeEnrollmentTokenDTO{
			ID:           id,
			Token:        plainToken,
			PresetName:   preset,
			Mode:         mode,
			ExpiresAt:    ts(exp),
			CASPKISHA256: caHash,
		}, nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeCatalogResponse(w, r, response)
}

// revokeNode 实现 POST /api/v1/nodes/{node_id}/revoke（吊销远端节点证书并立即踢断在线流）。
func (a *api) revokeNode(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	nodeID := r.PathValue("node_id")
	if err := a.authorize(r.Context(), act, "host.nodes:write", nodeID); err != nil {
		a.fail(w, r, err)
		return
	}
	if nodeID == a.d.NodeID {
		a.fail(w, r, problem.New(problem.ValidationFailed, "The local controller node cannot be revoked."))
		return
	}
	key, err := a.idempotency(r, nodeID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	response, err := a.catalogWrite(r, act, key, "host.nodes:revoke", http.StatusOK, "", func(tx *storage.Tx) (any, error) {
		var curState string
		qerr := tx.QueryRowContext(r.Context(), `SELECT enrollment_state FROM nodes WHERE id = ?`, nodeID).Scan(&curState)
		if errors.Is(qerr, sql.ErrNoRows) {
			return nil, problem.New(problem.NotFound, "The node does not exist.")
		}
		if qerr != nil {
			return nil, problem.Wrap(qerr)
		}
		nowMs := tx.Now().UTC().UnixMilli()
		newRev := tx.NewID("nrev")
		if _, err := tx.ExecContext(r.Context(),
			`UPDATE nodes SET enrollment_state = 'revoked', revision = ?, updated_at = ? WHERE id = ?`,
			newRev, nowMs, nodeID,
		); err != nil {
			return nil, problem.Wrap(err)
		}
		if err := operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor: act, Action: "node.revoke", Subject: "nodes/" + nodeID,
			Outcome: operations.AuditSuccess, TraceID: traceID(r), RequestID: requestID(r),
		}); err != nil {
			return nil, err
		}
		return map[string]any{
			"node_id":          nodeID,
			"enrollment_state": "revoked",
			"revision":         newRev,
		}, nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.NodeRevoker != nil {
		a.d.NodeRevoker(nodeID)
	}
	a.writeCatalogResponse(w, r, response)
}
