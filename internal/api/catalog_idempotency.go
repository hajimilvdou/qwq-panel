// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"net/http"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 当前权限、领域写入与安全回放共用一个事务 ========================

// catalogOwnerFact 仅由宿主从真实领域行生成；DELETE 的 204 不输出该私有正文。
type catalogOwnerFact struct {
	OwnerID string `json:"owner_id"`
}

// catalogWrite 只承接目录豁免的本地数据库写入；change 不得调用网络或插件。
// 一次性凭据只进入首个 HTTP 响应，privateMember 在提交前从持久正文移除。
func (a *api) catalogWrite(r *http.Request, who actor.Actor, key operations.Idempotency, permission string,
	status int, privateMember string, change func(*storage.Tx) (any, error)) (*operations.Response, error) {
	var response *operations.Response
	err := a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: who, TraceID: traceID(r), NodeID: a.d.NodeID})
		if err := a.d.Authz.AuthorizeHumanTx(r.Context(), tx, who, permission); err != nil {
			return err
		}
		claim, replay, err := a.d.Ops.ClaimIdempotencyTx(r.Context(), tx, who, key)
		if err != nil {
			return err
		}
		if replay != nil {
			if err := a.authorizeCatalogReplay(r, tx, who, permission, replay.Body); err != nil {
				return err
			}
			response = replay
			return nil
		}
		body, err := change(tx)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		safe := raw
		if privateMember != "" {
			safe = withoutMember(raw, privateMember)
		}
		if err := a.d.Ops.CompleteIdempotencyTx(r.Context(), tx, claim, status, safe, ""); err != nil {
			return err
		}
		response = &operations.Response{Status: status, Body: raw}
		return nil
	})
	if err != nil {
		return nil, problem.From(err)
	}
	return response, nil
}

func (a *api) authorizeCatalogReplay(r *http.Request, tx *storage.Tx, who actor.Actor, permission string, body json.RawMessage) error {
	switch permission {
	case "host.delegations:update", "host.delegations:delete":
		var fact catalogOwnerFact
		if err := json.Unmarshal(body, &fact); err != nil || fact.OwnerID == "" {
			return problem.New(problem.PermissionDenied, "The stored delegation authorization facts are unavailable.")
		}
		return a.d.Authz.AuthorizeDelegationOwnerTx(r.Context(), tx, who, fact.OwnerID)
	default:
		return nil
	}
}

// catalogReplay 在 MFA 消耗前检查回放，当前人类角色仍在同一事务重验。
func (a *api) catalogReplay(r *http.Request, who actor.Actor, key operations.Idempotency, permission string) (*operations.Response, error) {
	var replay *operations.Response
	err := a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		if err := a.d.Authz.AuthorizeHumanTx(r.Context(), tx, who, permission); err != nil {
			return err
		}
		var err error
		replay, err = a.d.Ops.LookupIdempotencyTx(r.Context(), tx, who, key)
		return err
	})
	if err != nil {
		return nil, problem.From(err)
	}
	return replay, nil
}

func (a *api) writeCatalogResponse(w http.ResponseWriter, r *http.Request, response *operations.Response) {
	if response.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if response.Status == http.StatusNoContent {
		w.WriteHeader(response.Status)
		return
	}
	if err := gateway.WriteJSON(w, response.Status, response.Body); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: write response", "error", err)
	}
}
