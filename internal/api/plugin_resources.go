// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
)

type pluginResourcesOverrideRequest struct {
	MemoryMaxMB     int64 `json:"memory_max_mb,omitempty"`
	CPUQuotaPercent int64 `json:"cpu_quota_percent,omitempty"`
	PIDsMax         int64 `json:"pids_max,omitempty"`
	FDsMax          int64 `json:"fds_max,omitempty"`
	DiskMaxMB       int64 `json:"disk_max_mb,omitempty"`
	ResetDefault    bool  `json:"reset_default,omitempty"`
}

func (a *api) loadPluginResourceOverride(ctx context.Context, pluginID string) (*pluginResourcesDTO, bool) {
	if a.d.DB == nil || pluginID == "" {
		return nil, false
	}
	var out pluginResourcesDTO
	err := a.d.DB.Reader().QueryRowContext(ctx,
		`SELECT memory_max_mb, cpu_quota_percent, pids_max, fds_max, disk_max_mb
		   FROM plugin_resource_overrides WHERE plugin_id = ?`,
		pluginID,
	).Scan(&out.MemoryMaxMB, &out.CPUQuotaPercent, &out.PIDsMax, &out.FDsMax, &out.DiskMaxMB)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			a.d.Logger.WarnContext(ctx, "api: load plugin resource override", "plugin_id", pluginID, "error", err)
		}
		return nil, false
	}
	return &out, true
}

func (a *api) mergePluginResourceOverride(ctx context.Context, dto *pluginDTO) {
	if dto == nil {
		return
	}
	ov, ok := a.loadPluginResourceOverride(ctx, dto.PluginID)
	if !ok || ov == nil {
		return
	}
	if dto.Resources == nil {
		dto.Resources = &pluginResourcesDTO{}
	}
	if ov.MemoryMaxMB > 0 {
		dto.Resources.MemoryMaxMB = ov.MemoryMaxMB
	}
	if ov.CPUQuotaPercent > 0 {
		dto.Resources.CPUQuotaPercent = ov.CPUQuotaPercent
	}
	if ov.PIDsMax > 0 {
		dto.Resources.PIDsMax = ov.PIDsMax
	}
	if ov.FDsMax > 0 {
		dto.Resources.FDsMax = ov.FDsMax
	}
	if ov.DiskMaxMB > 0 {
		dto.Resources.DiskMaxMB = ov.DiskMaxMB
	}
}

func resolveValidatedPluginLimits(base *PluginResources, req pluginResourcesOverrideRequest) (sandbox.Limits, int64, error) {
	defaults := sandbox.DefaultLimits()
	var baseMem, baseCPU, basePIDs, baseFDs, baseDisk int64 = defaults.MemoryMaxMB, defaults.CPUQuotaPercent, defaults.PIDsMax, defaults.FDsMax, 64
	if base != nil {
		if base.MemoryMaxMB > 0 {
			baseMem = base.MemoryMaxMB
		}
		if base.CPUQuotaPercent > 0 {
			baseCPU = base.CPUQuotaPercent
		}
		if base.PIDsMax > 0 {
			basePIDs = base.PIDsMax
		}
		if base.FDsMax > 0 {
			baseFDs = base.FDsMax
		}
		if base.DiskMaxMB > 0 {
			baseDisk = base.DiskMaxMB
		}
	}
	lim := sandbox.Limits{
		MemoryMaxMB:     baseMem,
		CPUQuotaPercent: baseCPU,
		PIDsMax:         basePIDs,
		FDsMax:          baseFDs,
	}
	diskMB := baseDisk
	if req.MemoryMaxMB > 0 {
		lim.MemoryMaxMB = req.MemoryMaxMB
	}
	if req.CPUQuotaPercent > 0 {
		lim.CPUQuotaPercent = req.CPUQuotaPercent
	}
	if req.PIDsMax > 0 {
		lim.PIDsMax = req.PIDsMax
	}
	if req.FDsMax > 0 {
		lim.FDsMax = req.FDsMax
	}
	if req.DiskMaxMB > 0 {
		diskMB = req.DiskMaxMB
	}
	if err := lim.Validate(); err != nil {
		return sandbox.Limits{}, 0, problem.Validation(problem.Violation{
			Pointer: "/memory_max_mb",
			Code:    "OUT_OF_RANGE",
			Message: err.Error(),
		})
	}
	if diskMB < 1 || diskMB > 1048576 {
		return sandbox.Limits{}, 0, problem.Validation(problem.Violation{
			Pointer: "/disk_max_mb",
			Code:    "OUT_OF_RANGE",
			Message: "disk_max_mb must be between 1 and 1048576.",
		})
	}
	return lim, diskMB, nil
}

func (a *api) applyAndPersistPluginResources(ctx context.Context, pluginID string, base *PluginResources, req pluginResourcesOverrideRequest) error {
	now := a.d.Clock.Now().UTC()
	if req.ResetDefault {
		if err := a.d.DB.Update(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM plugin_resource_overrides WHERE plugin_id = ?`, pluginID)
			return err
		}); err != nil {
			return problem.Wrap(err)
		}
		a.syncPrivilegedPluginResources(ctx, pluginID, nil, true)
		return nil
	}
	lim, diskMB, err := resolveValidatedPluginLimits(base, req)
	if err != nil {
		return err
	}
	if err := a.d.DB.Update(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO plugin_resource_overrides
			 (plugin_id, memory_max_mb, cpu_quota_percent, pids_max, fds_max, disk_max_mb, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(plugin_id) DO UPDATE SET
			   memory_max_mb = excluded.memory_max_mb,
			   cpu_quota_percent = excluded.cpu_quota_percent,
			   pids_max = excluded.pids_max,
			   fds_max = excluded.fds_max,
			   disk_max_mb = excluded.disk_max_mb,
			   updated_at = excluded.updated_at`,
			pluginID, lim.MemoryMaxMB, lim.CPUQuotaPercent, lim.PIDsMax, lim.FDsMax, diskMB, storage.FormatTime(now),
		)
		return err
	}); err != nil {
		return problem.Wrap(err)
	}
	a.syncPrivilegedPluginResources(ctx, pluginID, &lim, false)
	return nil
}

func (a *api) syncPrivilegedPluginResources(ctx context.Context, pluginID string, lim *sandbox.Limits, reset bool) {
	sock := strings.TrimSpace(a.privilegedSocketPath())
	if sock == "" {
		return
	}
	if _, err := os.Stat(sock); err != nil {
		return
	}
	client := sandbox.NewHelperClient(sock)
	if err := client.UpdateResources(ctx, pluginID, lim, reset); err != nil {
		a.d.Logger.WarnContext(ctx, "api: sync plugin systemd resources failed", "plugin_id", pluginID, "error", err)
	}
}

// putPluginResources implements PUT /api/v1/plugins/{plugin_id}/resources.
// Allows administrators to adjust (or reset) a plugin's memory/CPU/PIDs/FDs/disk
// resource limits after installation and live-apply them via systemd drop-in.
func (a *api) putPluginResources(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pluginID := r.PathValue("plugin_id")
	if err := a.authorize(r.Context(), act, "host.plugins:config", pluginID); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	p, err := a.d.Plugins.Get(r.Context(), pluginID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req pluginResourcesOverrideRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.applyAndPersistPluginResources(r.Context(), pluginID, p.Resources, req); err != nil {
		a.fail(w, r, err)
		return
	}
	// Restart active plugin so new cgroup limits take effect immediately when running.
	if p.Runtime != nil && p.Runtime.State == "running" {
		if restarted, rerr := a.d.Plugins.Restart(lifecycleContext(r), pluginID, "resource limits updated"); rerr == nil {
			p = restarted
		} else {
			a.d.Logger.WarnContext(r.Context(), "api: restart plugin after resource update", "plugin_id", pluginID, "error", rerr)
		}
	}
	details, _ := json.Marshal(req)
	_ = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor:     act,
			Action:    "host.plugins.resources.update",
			Subject:   "plugins/" + pluginID,
			Outcome:   operations.AuditSuccess,
			Details:   details,
			NodeID:    a.d.NodeID,
			TraceID:   gateway.TraceID(r.Context()),
			RequestID: requestID(r),
		})
	})
	dto := a.pluginDTOWithOverrides(r.Context(), p)
	a.writeResource(w, r, http.StatusOK, dto, nil)
}
