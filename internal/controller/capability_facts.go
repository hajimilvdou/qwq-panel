// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/storage"
)

// capabilityAddresses 重新确认派发，读取操作者全部有效人类会话地址。
// operation 未持久化具体 session id，因此不猜测一条记录，而是保守检查全部候选。
func (rt *PluginRuntime) capabilityAddresses(ctx context.Context, call hostsvc.CapabilityCall) ([]string, error) {
	deps, ok := rt.depsSnapshot()
	if !ok || deps.DB == nil || deps.Ops == nil {
		return nil, errors.New("controller: capability facts unavailable")
	}
	operation, ok := dispatchedOperation(ctx, deps.Ops, call.PluginID, call.InstanceID, deps.NodeID, call.OperationID)
	if !ok {
		return nil, hostsvc.ErrOperationNotDispatched
	}
	owner := operation.Actor.ID
	if operation.Actor.Kind == actor.AIAgent || operation.Actor.Kind == actor.Service {
		owner = operation.Actor.OnBehalfOf
	}
	if owner == "" || operation.Actor.Kind == actor.System {
		return nil, errors.New("controller: human owner is unavailable")
	}
	return activeSessionAddresses(ctx, deps.DB, owner, deps.Clock.Now())
}

func activeSessionAddresses(ctx context.Context, db *storage.DB, owner string, at time.Time) ([]string, error) {
	now := storage.FormatTime(at)
	rows, err := db.Reader().QueryContext(ctx, `SELECT DISTINCT s.client_ip FROM sessions s JOIN users u ON u.user_id=s.user_id
		WHERE s.user_id=? AND s.revoked_at='' AND s.idle_expires_at>? AND s.expires_at>? AND u.disabled=0
		ORDER BY s.client_ip LIMIT 65`, owner, now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var addresses []string
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, err
		}
		address, err := netip.ParseAddr(text)
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return nil, errors.New("controller: invalid management session address")
		}
		addresses = append(addresses, address.Unmap().String())
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(addresses) > 64 {
		return nil, errors.New("controller: management session address limit exceeded")
	}
	slices.Sort(addresses)
	return slices.Compact(addresses), nil
}

// capabilityBanProtectedAddresses 合并当前全部活跃人类会话源 IP，防止手动或后台自动封禁锁死管理员。
func (rt *PluginRuntime) capabilityBanProtectedAddresses(ctx context.Context, call hostsvc.CapabilityCall) ([]string, error) {
	deps, ok := rt.depsSnapshot()
	if !ok || deps.DB == nil {
		return nil, errors.New("controller: capability facts unavailable")
	}
	now := storage.FormatTime(deps.Clock.Now())
	rows, err := deps.DB.Reader().QueryContext(ctx, `SELECT DISTINCT s.client_ip FROM sessions s JOIN users u ON u.user_id=s.user_id
		WHERE s.revoked_at='' AND s.idle_expires_at>? AND s.expires_at>? AND u.disabled=0
		ORDER BY s.client_ip LIMIT 129`, now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var addresses []string
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, err
		}
		if addr, perr := netip.ParseAddr(text); perr == nil && addr.Zone() == "" && !addr.IsUnspecified() && !addr.IsMulticast() {
			addresses = append(addresses, addr.Unmap().String())
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.Sort(addresses)
	return slices.Compact(addresses), nil
}

// capabilityRevealOperationSecret 仅按当前已派发 operation 揭示账户口令秘密，插件全程不接触明文。
func (rt *PluginRuntime) capabilityRevealOperationSecret(ctx context.Context, call hostsvc.CapabilityCall, secretRef string) ([]byte, error) {
	deps, ok := rt.depsSnapshot()
	if !ok || deps.DB == nil || deps.Ops == nil || deps.Secrets == nil {
		return nil, errors.New("controller: secret revealer unavailable")
	}
	revealer := &hostSecretRevealer{
		operations: deps.Ops,
		secrets:    deps.Secrets,
		pluginID:   call.PluginID,
		instanceID: call.InstanceID,
		nodeID:     deps.NodeID,
		logger:     deps.Logger,
	}
	return revealer.Reveal(ctx, secretRef, call.OperationID, []string{"operation"})
}
