// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// registerExtendedOperations 注册用户连接限制、链式代理、TCP Brutal 端口透明接管与 tcpfit 动态调优操作。
func (i *instance) registerExtendedOperations() {
	// 用户连接数与同时在线 IP 限制
	i.HandleInvoke("users.set_limits", i.handleUsersSetLimits)
	i.HandleInvoke("users.connections.status", i.handleUsersConnectionsStatus)

	// 链式代理管理（服务端出口转发 + 客户端订阅 dialer-proxy）
	i.HandleInvoke("chains.list", i.handleChainsList)
	i.HandleInvoke("chains.upsert", i.handleChainsUpsert)
	i.HandleInvoke("chains.delete", i.handleChainsDelete)
	i.HandleInvoke("chains.probe", i.handleChainsProbe)
	i.HandleInvoke("chains.preview", i.handleChainsPreview)

	// TCP Brutal + Brutal Custom 端口透明接管与超发倍率手调
	i.HandleInvoke("brutal.status", i.handleBrutalStatus)
	i.HandleInvoke("brutal.binding.upsert", i.handleBrutalBindingUpsert)
	i.HandlePlan("brutal.binding.upsert", i.planBrutalBindingUpsert)
	i.HandleInvoke("brutal.binding.delete", i.handleBrutalBindingDelete)
	i.HandleInvoke("brutal.apply", i.handleBrutalApply)

	// tcpfit 风格动态机器调优（BDP/内存推导 + iperf3 拐点扫描 + 快照回滚）
	i.HandleInvoke("tuning.status", i.handleTuningStatus)
	i.HandleInvoke("tuning.plan", i.handleTuningPlan)
	i.HandleInvoke("tuning.apply", i.handleTuningApply)
	i.HandlePlan("tuning.apply", i.planTuningApply)
	i.HandleInvoke("tuning.rollback", i.handleTuningRollback)
	i.HandleInvoke("tuning.sweep", i.handleTuningSweep)
}

// ======================== 用户连接数与在线 IP 限制 ========================

func (i *instance) handleUsersSetLimits(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		UserID                 string  `json:"user_id"`
		MaxConnectionsOverride *int    `json:"max_connections_override"`
		MaxIPsOverride         *int    `json:"max_ips_override"`
		ChainID                *string `json:"chain_id"`
		ExpectedRevision       string  `json:"expected_revision"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	if strings.TrimSpace(in.UserID) == "" {
		return pluginsdk.Response{}, invalidField("/user_id", "REQUIRED", "缺少 user_id")
	}
	expectedRev := resolveRevision(in.ExpectedRevision, req, "users/"+in.UserID)
	u, err := i.store.SetUserLimits(ctx, strings.TrimSpace(in.UserID), in.MaxConnectionsOverride, in.MaxIPsOverride, in.ChainID, expectedRev)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	snap := i.connLim.SnapshotUser(u.ID, u.EffectiveMaxConnections, u.EffectiveMaxIPs)
	u.ActiveConnections = snap.ActiveConnections
	u.ActiveIPs = snap.ActiveIPs
	return marshalResponse(map[string]any{"user": u})
}

func (i *instance) handleUsersConnectionsStatus(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		IncludeNftables bool `json:"include_nftables"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	users, err := i.store.ListUsers(ctx, "", "", 256)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	items := make([]userConnSnapshot, 0, len(users))
	for _, u := range users {
		items = append(items, i.connLim.SnapshotUser(u.ID, u.EffectiveMaxConnections, u.EffectiveMaxIPs))
	}
	resp := map[string]any{"items": items}
	if in.IncludeNftables {
		resp["nftables_rules"] = renderConnLimitNftables(users)
	}
	return marshalResponse(resp)
}

// ======================== 链式代理操作 ========================

func (i *instance) handleChainsList(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	chains, err := i.store.ListChains(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(map[string]any{"chains": chains})
}

func (i *instance) handleChainsUpsert(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in chainUpsertRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	in.ExpectedRevision = resolveRevision(in.ExpectedRevision, req, "chains/"+in.ID)
	rec, created, err := i.store.UpsertChain(ctx, in)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(map[string]any{"chain": rec, "created": created})
}

func (i *instance) handleChainsDelete(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return pluginsdk.Response{}, invalidField("/id", "REQUIRED", "缺少链式代理 id")
	}
	deleted, err := i.store.DeleteChain(ctx, id)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(map[string]any{"deleted": deleted, "id": id})
}

func (i *instance) handleChainsProbe(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	id := strings.TrimSpace(in.ID)
	chains, err := i.store.ListChains(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	for _, c := range chains {
		if c.ID == id {
			ok, latencyMS, errMsg := probeChainTCP(ctx, c.Server, c.Port)
			return marshalResponse(map[string]any{
				"id":         c.ID,
				"server":     c.Server,
				"port":       c.Port,
				"reachable":  ok,
				"latency_ms": latencyMS,
				"error":      errMsg,
			})
		}
	}
	return pluginsdk.Response{}, pluginsdk.Errorf("NOT_FOUND", "链式代理节点 %s 不存在", id)
}

func (i *instance) handleChainsPreview(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	chains, err := i.store.ListChainsWithSecrets(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	users, err := i.store.ListUsers(ctx, "", "", 256)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	xrayDoc := renderXrayChainOutbounds(chains, users)
	xrayJSON, _ := json.MarshalIndent(xrayDoc, "", "  ")
	return marshalResponse(map[string]any{
		"xray_server_chain": xrayDoc,
		"xray_json":         string(xrayJSON),
		"total_chains":      len(chains),
	})
}

// ======================== TCP Brutal + Brutal Custom 端口透明接管 ========================

func (i *instance) availableTCPInbounds() []map[string]any {
	cfg := i.configSnapshot()
	out := make([]map[string]any, 0, 2)
	if cfg.VLESSPort > 0 {
		out = append(out, map[string]any{
			"inbound_tag": "vless-tcp",
			"protocol":    "vless",
			"target_port": int(cfg.VLESSPort),
			"label":       fmt.Sprintf("VLESS Vision+REALITY (TCP :%d)", cfg.VLESSPort),
		})
	}
	if cfg.SSPort > 0 {
		out = append(out, map[string]any{
			"inbound_tag": "ss2022-tcp",
			"protocol":    "shadowsocks",
			"target_port": int(cfg.SSPort),
			"label":       fmt.Sprintf("Shadowsocks-2022 (TCP :%d)", cfg.SSPort),
		})
	}
	return out
}

func (i *instance) handleBrutalStatus(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	bindings, err := i.store.ListBrutalBindings(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(map[string]any{
		"env":               detectBrutalEnv(),
		"tcp_inbounds":      i.availableTCPInbounds(),
		"bindings":          bindings,
		"live_listeners":    i.brutalMgr.Metrics(),
		"default_oversend":  defaultOversendPct,
		"default_cwnd_gain": defaultBrutalGain,
	})
}

func (i *instance) planBrutalBindingUpsert(_ context.Context, req pluginsdk.Request) (pluginsdk.Plan, error) {
	var in brutalBindingUpsertRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Plan{}, err
	}
	rec, err := validateBrutalBindingInput(in)
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	plan := pluginsdk.Plan{
		Changes: []pluginsdk.PlannedChange{{
			Kind:       pluginsdk.ChangeUpdate,
			Subject:    "brutal/" + rec.ID,
			Reversible: true,
			Description: fmt.Sprintf("透明接管 %s (:%d -> :%d)，基准 %d Mbps × %d%% 超发 = %.1f Mbps (cwnd_gain=%d)",
				rec.InboundTag, rec.ListenPort, rec.TargetPort, rec.BandwidthMbps, rec.OversendPct, rec.EffectiveMbps, rec.CwndGain),
		}},
	}
	if rec.OversendPct > 160 {
		plan.Warnings = append(plan.Warnings, pluginsdk.FieldViolation{
			Pointer: "/oversend_pct",
			Code:    "HIGH_OVERSEND",
			Message: "超发倍率高于 160% 可能导致高重传或触发上游线路 QoS 限速，建议先从 125%–150% 逐步上调。",
		})
	}
	env := detectBrutalEnv()
	if !env.BrutalAvailable {
		plan.Warnings = append(plan.Warnings, pluginsdk.FieldViolation{
			Pointer: "/enabled",
			Code:    "KERNEL_MODULE_ABSENT",
			Message: "当前宿主机内核未加载 tcp-brutal 模块，启用后透明接管转发仍可工作但拥塞算法将回退至系统默认算法。",
		})
	}
	return plan, nil
}

func (i *instance) handleBrutalBindingUpsert(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in brutalBindingUpsertRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	in.ExpectedRevision = resolveRevision(in.ExpectedRevision, req, "brutal/"+in.ID)
	rec, created, err := i.store.UpsertBrutalBinding(ctx, in)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(map[string]any{"binding": rec, "created": created})
}

func (i *instance) handleBrutalBindingDelete(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return pluginsdk.Response{}, invalidField("/id", "REQUIRED", "缺少 brutal 绑定 id")
	}
	deleted, err := i.store.DeleteBrutalBinding(ctx, id)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	bindings, _ := i.store.ListBrutalBindings(ctx)
	_, _ = i.brutalMgr.Reconcile(bindings)
	return marshalResponse(map[string]any{"deleted": deleted, "id": id})
}

func (i *instance) handleBrutalApply(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	bindings, err := i.store.ListBrutalBindings(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	metrics, runErr := i.brutalMgr.Reconcile(bindings)
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	return marshalResponse(map[string]any{
		"applied":        runErr == nil,
		"error":          errMsg,
		"env":            detectBrutalEnv(),
		"live_listeners": metrics,
	})
}

// ======================== tcpfit 动态网络调优 ========================

func (i *instance) handleTuningStatus(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	snaps, err := i.store.ListTuningSnapshots(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(map[string]any{
		"profile":    detectHostProfile(),
		"brutal_env": detectBrutalEnv(),
		"snapshots":  snaps,
	})
}

func (i *instance) handleTuningPlan(_ context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in tcpfitPlanRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	plan, err := computeTcpfitPlan(detectHostProfile(), detectBrutalEnv(), in)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(plan)
}

func (i *instance) planTuningApply(_ context.Context, req pluginsdk.Request) (pluginsdk.Plan, error) {
	var in struct {
		tcpfitPlanRequest
		DryRun bool `json:"dry_run"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Plan{}, err
	}
	calc, err := computeTcpfitPlan(detectHostProfile(), detectBrutalEnv(), in.tcpfitPlanRequest)
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	plan := pluginsdk.Plan{
		Changes: []pluginsdk.PlannedChange{{
			Kind:       pluginsdk.ChangeUpdate,
			Subject:    "sysctl/99-qwq-tcpfit.conf",
			Reversible: true,
			Description: fmt.Sprintf("应用 tcpfit 动态调优（role=%s, %dMbps/%dms, max_buf=%dMiB, cc=%s，自动保留回滚快照）",
				calc.Role, calc.BandwidthMbps, calc.RTTMs, calc.MaxBufferBytes/(1024*1024), calc.SelectedCC),
		}},
	}
	if calc.SwapRecommendation != "" {
		plan.Warnings = append(plan.Warnings, pluginsdk.FieldViolation{
			Pointer: "/mem_budget_pct",
			Code:    "NO_SWAP",
			Message: calc.SwapRecommendation,
		})
	}
	return plan, nil
}

func (i *instance) handleTuningApply(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		tcpfitPlanRequest
		DryRun bool `json:"dry_run"`
	}
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	profile := detectHostProfile()
	calc, err := computeTcpfitPlan(profile, detectBrutalEnv(), in.tcpfitPlanRequest)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	// 先保存应用前内核当前值的基线快照，保证任何时候都可以一键回滚！
	baselineSnap, err := i.store.SaveTuningSnapshot(ctx, "pre_apply_baseline", calc.Role, calc.BandwidthMbps, calc.RTTMs, profile.CurrentSysctl, false)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	applied, output, applyErr := applySysctlConfig(ctx, i.sysctlTargetPath, calc.RenderedConf, in.DryRun)
	errMsg := ""
	if applyErr != nil {
		errMsg = applyErr.Error()
	}
	appliedSnap, _ := i.store.SaveTuningSnapshot(ctx, fmt.Sprintf("tcpfit:%s:%dM/%dms", calc.Role, calc.BandwidthMbps, calc.RTTMs),
		calc.Role, calc.BandwidthMbps, calc.RTTMs, calc.SysctlMap, applied)
	return marshalResponse(map[string]any{
		"applied":           applied,
		"dry_run":           in.DryRun,
		"target_path":       i.sysctlTargetPath,
		"output":            output,
		"error":             errMsg,
		"baseline_snapshot": baselineSnap,
		"applied_snapshot":  appliedSnap,
		"plan":              calc,
	})
}

func (i *instance) handleTuningRollback(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		SnapshotID string `json:"snapshot_id"`
		Revision   int64  `json:"revision"`
		DryRun     bool   `json:"dry_run"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	if strings.TrimSpace(in.SnapshotID) == "" && in.Revision <= 0 {
		return pluginsdk.Response{}, invalidField("/snapshot_id", "REQUIRED", "必须提供 snapshot_id 或 revision")
	}
	snap, err := i.store.GetTuningSnapshot(ctx, strings.TrimSpace(in.SnapshotID), in.Revision)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	rendered := renderSysctlConf(snap.Role, snap.BandwidthMbps, snap.RTTMs, snap.SysctlMap)
	applied, output, applyErr := applySysctlConfig(ctx, i.sysctlTargetPath, rendered, in.DryRun)
	errMsg := ""
	if applyErr != nil {
		errMsg = applyErr.Error()
	}
	return marshalResponse(map[string]any{
		"rolled_back":   applyErr == nil,
		"applied":       applied,
		"dry_run":       in.DryRun,
		"snapshot":      snap,
		"output":        output,
		"error":         errMsg,
		"rendered_conf": rendered,
	})
}

func (i *instance) handleTuningSweep(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		PeerHost    string `json:"peer_host"`
		PeerPort    int    `json:"peer_port"`
		DurationSec int    `json:"duration_sec"`
	}
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	res, err := runIperf3Sweep(ctx, in.PeerHost, in.PeerPort, in.DurationSec)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(res)
}
