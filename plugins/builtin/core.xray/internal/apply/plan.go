// SPDX-License-Identifier: AGPL-3.0-only

package apply

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

type plannedConfig struct {
	state.PublicIntentSummary
	Enabled bool `json:"enabled"`
}
type authenticationChange struct {
	TransportIdentity string `json:"transport_identity"`
	UserIdentity      string `json:"user_identity"`
	SessionIDs        string `json:"session_ids"`
}
type plannedRuntime struct {
	DesiredRevision   string   `json:"desired_revision"`
	Enabled           bool     `json:"enabled"`
	ProcessAction     string   `json:"process_action"`
	RollbackAvailable bool     `json:"rollback_available"`
	AddedUsers        []string `json:"added_users"`
	RemovedUsers      []string `json:"removed_users"`
}

// Plan 只读取当前 desired 与已核验元数据；不触碰秘密、进程、端口或状态写入。
func (e *Engine) Plan(ctx context.Context, request Request) (pluginsdk.Plan, error) {
	if ctx.Err() != nil {
		return pluginsdk.Plan{}, failure("CANCELLED", ctx.Err())
	}
	if request.Host == nil || !state.ValidRevision(request.ConfigRevision) {
		return pluginsdk.Plan{}, failure("INVALID_REQUEST", nil)
	}
	desired, err := loadDesiredAny(ctx, request)
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	current, err := e.options.Store.Committed(ctx)
	if err != nil {
		return pluginsdk.Plan{}, stateFailure(err)
	}
	if err := checkRunning(request, current); err != nil {
		return pluginsdk.Plan{}, err
	}
	if desired.v2 != nil {
		return e.planV2(ctx, request, desired.v2, current)
	}
	intent := desired.v1
	afterSummary, err := state.Summarize(intent)
	if err != nil {
		return pluginsdk.Plan{}, failure("INVALID_INTENT", nil)
	}
	var before any
	kind := pluginsdk.ChangeCreate
	revision := ""
	changes := authenticationChange{TransportIdentity: "changed", UserIdentity: "changed", SessionIDs: "changed"}
	runtime := plannedRuntime{DesiredRevision: request.ConfigRevision, Enabled: *intent.Enabled, ProcessAction: "keep_stopped", AddedUsers: slices.Clone(afterSummary.UserIDs), RemovedUsers: []string{}}
	if *intent.Enabled {
		runtime.ProcessAction = "start"
	}
	if current != nil {
		kind, revision = pluginsdk.ChangeUpdate, current.Current.Revision
		runtime.RollbackAvailable = true
		if beforeSummary := current.Current.Summary; beforeSummary != nil {
			before = plannedConfig{PublicIntentSummary: beforeSummary.PublicIntentSummary, Enabled: current.Current.Enabled}
			runtime.AddedUsers, runtime.RemovedUsers = userDifference(beforeSummary.UserIDs, afterSummary.UserIDs)
			changes.TransportIdentity = changeStatus(beforeSummary.PrivateKeyRefDigest != afterSummary.PrivateKeyRefDigest)
			changes.UserIdentity = changeStatus(beforeSummary.UserRefsDigest != afterSummary.UserRefsDigest)
			changes.SessionIDs = changeStatus(beforeSummary.ShortIDsDigest != afterSummary.ShortIDsDigest)
		} else if beforeV2 := current.Current.SummaryV2; beforeV2 != nil {
			before = map[string]any{"enabled": current.Current.Enabled, "summary": beforeV2}
			runtime.AddedUsers, runtime.RemovedUsers = userDifference(beforeV2.AllUserIDs(), afterSummary.UserIDs)
		}
		if current.Current.Enabled {
			runtime.ProcessAction = "stop"
			if *intent.Enabled {
				runtime.ProcessAction = "restart_if_changed"
			}
		}
	}
	beforeJSON, err := planJSON(before)
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	afterJSON, err := planJSON(plannedConfig{PublicIntentSummary: afterSummary.PublicIntentSummary, Enabled: *intent.Enabled})
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	authJSON, err := planJSON(changes)
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	runtimeJSON, err := planJSON(runtime)
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	if ctx.Err() != nil {
		return pluginsdk.Plan{}, failure("CANCELLED", ctx.Err())
	}
	return pluginsdk.Plan{
		Changes: []pluginsdk.PlannedChange{
			{Kind: kind, Subject: "config/current", Before: beforeJSON, After: afterJSON, Reversible: current != nil, Description: "保存完整期望配置；监听、用户与启停变化如下"},
			{Kind: kind, Subject: "config/current", Pointer: "/authentication", After: authJSON, Reversible: current != nil, Description: "认证材料只显示引用是否变更，实际解引用在执行时进行"},
			{Kind: kind, Subject: "runtime/current", After: runtimeJSON, Reversible: current != nil, Description: "按候选摘要决定进程切换；失败恢复上一份有效配置"},
		},
		Preconditions: []pluginsdk.Precondition{{Subject: RunningKey, Revision: revision}},
		Warnings: []pluginsdk.FieldViolation{
			{Code: "NATIVE_PREFLIGHT_NOT_RUN", Message: "本次预演只做静态校验；原生预检和健康检查在 Apply 时执行"},
			{Code: "RESTART_CONDITIONAL", Message: "实际重启由解引用后的候选摘要及当前进程健康决定"},
		},
	}, nil
}

func changeStatus(changed bool) string {
	if changed {
		return "changed"
	}
	return "unchanged"
}
func userDifference(before, after []string) ([]string, []string) {
	added, removed := []string{}, []string{}
	for _, id := range after {
		if !slices.Contains(before, id) {
			added = append(added, id)
		}
	}
	for _, id := range before {
		if !slices.Contains(after, id) {
			removed = append(removed, id)
		}
	}
	return added, removed
}
func planJSON(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, failure("CORE_STATE_UNAVAILABLE", nil)
	}
	return data, nil
}
