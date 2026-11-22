// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
	trafficv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/traffic/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 后台 30 秒流量采样与跨插件配置/限速同步 ========================

type xrayObserveResponse struct {
	ResetEpoch  string             `json:"reset_epoch"`
	CollectedAt string             `json:"collected_at"`
	Source      string             `json:"source"`
	Series      []xrayObserveEntry `json:"series"`
}

type xrayObserveEntry struct {
	Kind            string `json:"kind"`
	ID              string `json:"id"`
	Present         bool   `json:"present"`
	UplinkPresent   bool   `json:"uplink_present"`
	DownlinkPresent bool   `json:"downlink_present"`
	UplinkBytes     string `json:"uplink_bytes"`
	DownlinkBytes   string `json:"downlink_bytes"`
	ResetEpoch      string `json:"reset_epoch"`
}

type syncResult struct {
	CoreRevision          string
	ShapingDegraded       bool
	ShapingDegradedReason string
}

func (i *instance) syncInterval() time.Duration {
	if i.syncIntervalOverride > 0 {
		return i.syncIntervalOverride
	}
	sec := i.configSnapshot().SyncIntervalSeconds
	if sec < 10 {
		sec = defaultSyncIntervalSeconds
	}
	return time.Duration(sec) * time.Second
}

// syncLoop 绑定在实例 Activate 生命周期内，按周期向 core.xray 采样流量并驱动超额/到期同步。
func (i *instance) syncLoop(ctx context.Context) {
	i.runSyncCycle(ctx)
	for {
		timer := time.NewTimer(i.syncInterval())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			i.runSyncCycle(ctx)
		}
	}
}

func (i *instance) runSyncCycle(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	host := i.Host()
	if host == nil || host.Conn() == nil {
		return
	}

	// 后台 goroutine 中不携带 parent operation_id，走宿主 H3 plugin.invoke.background 鉴权路径。
	obsResp, err := host.InvokePlugin(ctx, pluginsdk.InvokeRequest{
		TargetPluginID: "core.xray",
		Operation:      "core.observe",
		APIVersion:     "v1",
		Payload:        []byte("{}"),
	})
	if err != nil {
		i.setSyncError("采样 core.xray 失败：" + err.Error())
		return
	}
	if err := protoError(obsResp.GetError()); err != nil {
		i.setSyncError("采样 core.xray 返回错误：" + err.Error())
		return
	}

	var obs xrayObserveResponse
	if raw := bytes.TrimSpace(obsResp.GetPayloadJson()); len(raw) > 0 {
		if err := json.Unmarshal(raw, &obs); err != nil {
			i.setSyncError("解析 core.observe 采样失败")
			return
		}
	}

	samples := make([]usageSample, 0, len(obs.Series))
	for _, entry := range obs.Series {
		if entry.Kind != "user" || !entry.Present || entry.ID == "" {
			continue
		}
		var up, down int64
		if entry.UplinkPresent && entry.UplinkBytes != "" {
			if n, parseErr := strconv.ParseInt(entry.UplinkBytes, 10, 64); parseErr == nil && n >= 0 {
				up = n
			}
		}
		if entry.DownlinkPresent && entry.DownlinkBytes != "" {
			if n, parseErr := strconv.ParseInt(entry.DownlinkBytes, 10, 64); parseErr == nil && n >= 0 {
				down = n
			}
		}
		samples = append(samples, usageSample{
			UserID:  entry.ID,
			RawUp:   up,
			RawDown: down,
			HasUp:   entry.UplinkPresent,
			HasDown: entry.DownlinkPresent,
		})
	}

	needsCoreSync, err := i.store.IngestXrayObservation(ctx, obs.ResetEpoch, samples)
	if err != nil {
		i.setSyncError("写入流量统计失败：" + err.Error())
		return
	}
	if needsCoreSync {
		if _, err := i.syncCoreAndTraffic(ctx, host); err != nil {
			i.setSyncError("同步 core.xray/限速失败：" + err.Error())
			return
		}
	}
	i.setSyncError("")
}

// syncCoreAndTraffic 串行将当前活跃用户同步至 core.xray（保留未变更密钥）与 TrafficService HTB 限速。
func (i *instance) syncCoreAndTraffic(ctx context.Context, host *pluginsdk.Host) (syncResult, error) {
	i.syncMu.Lock()
	defer i.syncMu.Unlock()

	coreRev, err := i.syncCoreXrayLocked(ctx, host)
	if err != nil {
		return syncResult{}, err
	}
	degraded, reason, err := i.syncTrafficShapingLocked(ctx, host)
	if err != nil {
		return syncResult{CoreRevision: coreRev}, err
	}
	return syncResult{
		CoreRevision:          coreRev,
		ShapingDegraded:       degraded,
		ShapingDegradedReason: reason,
	}, nil
}

func (i *instance) syncCoreXrayLocked(ctx context.Context, host *pluginsdk.Host) (string, error) {
	if host == nil || host.Conn() == nil {
		return "", pluginsdk.ErrNoHost
	}
	readMeta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return "", err
	}
	client := pluginconfigv1.NewPluginConfigServiceClient(host.Conn())
	getResp, err := client.GetConfig(ctx, &pluginconfigv1.GetConfigRequest{
		Context:        readMeta,
		TargetPluginId: "core.xray",
	})
	if err != nil {
		return "", err
	}
	if err := protoError(getResp.GetError()); err != nil {
		return "", err
	}

	activeUsers, err := i.store.ListUsers(ctx, "active", "", 256)
	if err != nil {
		return "", err
	}
	mergedJSON, err := mergeCoreXrayConfig(getResp.GetRedactedConfigJson(), activeUsers)
	if err != nil {
		return "", err
	}

	writeMeta, err := host.CapabilityContext(ctx)
	if err != nil {
		return "", err
	}
	putResp, err := client.PutConfig(ctx, &pluginconfigv1.PutConfigRequest{
		Context:          writeMeta,
		TargetPluginId:   "core.xray",
		ConfigJson:       mergedJSON,
		ExpectedRevision: getResp.GetRevision(),
		TriggerApply:     true,
	})
	if err != nil {
		return "", err
	}
	if err := protoError(putResp.GetError()); err != nil {
		return "", err
	}
	return putResp.GetRevision(), nil
}

// syncTrafficShapingLocked 将活跃且存在限速要求的流量标记下发给 TrafficService。
// 若节点内核不支持 HTB 限速（如受限容器），优雅降级返回原因而不中断用户操作。
func (i *instance) syncTrafficShapingLocked(ctx context.Context, host *pluginsdk.Host) (bool, string, error) {
	if host == nil || host.Conn() == nil {
		return true, "宿主连接未就绪", nil
	}
	readMeta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return false, "", err
	}
	client := trafficv1.NewTrafficServiceClient(host.Conn())
	stResp, err := client.GetShapingStatus(ctx, &trafficv1.GetShapingStatusRequest{Context: readMeta})
	if err != nil {
		return false, "", err
	}
	if err := protoError(stResp.GetError()); err != nil {
		return false, "", err
	}

	i.mu.Lock()
	i.shapingSupported = stResp.GetSupported()
	i.shapingDegradedReason = stResp.GetDegradedReason()
	i.mu.Unlock()

	if !stResp.GetSupported() {
		reason := strings.TrimSpace(stResp.GetDegradedReason())
		if reason == "" {
			reason = "当前节点内核不支持 HTB 流量整形，已优雅降级为不限速"
		}
		return true, reason, nil
	}

	activeUsers, err := i.store.ListUsers(ctx, "active", "", 256)
	if err != nil {
		return false, "", err
	}
	classes := make([]*trafficv1.UserShapingClass, 0, len(activeUsers))
	for _, u := range activeUsers {
		if u.TrafficMark < trafficMarkMin || u.TrafficMark > trafficMarkMax {
			continue
		}
		if u.DownLimitKbps == 0 && u.UpLimitKbps == 0 {
			continue
		}
		classes = append(classes, &trafficv1.UserShapingClass{
			TrafficMark:   u.TrafficMark,
			DownLimitKbps: u.DownLimitKbps,
			UpLimitKbps:   u.UpLimitKbps,
		})
	}

	writeMeta, err := host.CapabilityContext(ctx)
	if err != nil {
		return false, "", err
	}
	if len(classes) == 0 {
		clrResp, err := client.ClearShapingRules(ctx, &trafficv1.ClearShapingRulesRequest{
			Context:          writeMeta,
			ExpectedRevision: stResp.GetRevision(),
		})
		if err != nil {
			return false, "", err
		}
		if err := protoError(clrResp.GetError()); err != nil {
			return false, "", err
		}
		return false, "", nil
	}

	applyResp, err := client.ApplyShapingRules(ctx, &trafficv1.ApplyShapingRulesRequest{
		Context:          writeMeta,
		Classes:          classes,
		ExpectedRevision: stResp.GetRevision(),
	})
	if err != nil {
		return false, "", err
	}
	if err := protoError(applyResp.GetError()); err != nil {
		return false, "", err
	}
	if applyResp.GetDegradedUplink() {
		return true, "节点不支持 IFB 上行整形，已仅生效下行 HTB 限速", nil
	}
	return false, "", nil
}

// ======================== core.xray 脱敏配置合并（$secret_present -> $keep_secret） ========================

func mergeCoreXrayConfig(redactedRaw []byte, activeUsers []userRecord) ([]byte, error) {
	trimmed := bytes.TrimSpace(redactedRaw)
	if len(trimmed) == 0 {
		return nil, pluginsdk.Errorf("PRECONDITION_FAILED", "目标插件 core.xray 尚未初始化配置")
	}
	var doc map[string]any
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return nil, fmt.Errorf("decode core.xray config: %w", err)
	}
	// 先将所有既有脱敏槽位 {"$secret_present":true} 转换为 {"$keep_secret":true}。
	replaceSecretPresentWithKeep(doc)

	// 支持 Core Intent v2（profiles 数组）与 v1（单 inbound.users）两种形态。
	if profiles, ok := doc["profiles"].([]any); ok {
		if len(activeUsers) == 0 {
			doc["enabled"] = false
		} else {
			doc["enabled"] = true
			for _, item := range profiles {
				prof, ok := item.(map[string]any)
				if !ok {
					continue
				}
				protocol, _ := prof["protocol"].(string)
				existingUsers := indexExistingSecretSlots(prof["users"])
				prof["users"] = buildProfileUsers(protocol, activeUsers, existingUsers)
			}
		}
	} else if inbound, ok := doc["inbound"].(map[string]any); ok {
		if len(activeUsers) == 0 {
			doc["enabled"] = false
		} else {
			doc["enabled"] = true
			existingUsers := indexExistingSecretSlots(inbound["users"])
			inbound["users"] = buildProfileUsers("vless", activeUsers, existingUsers)
		}
	}

	return json.Marshal(doc)
}

func replaceSecretPresentWithKeep(v any) {
	switch cur := v.(type) {
	case map[string]any:
		if present, ok := cur["$secret_present"].(bool); ok && present && len(cur) == 1 {
			delete(cur, "$secret_present")
			cur["$keep_secret"] = true
			return
		}
		for _, child := range cur {
			replaceSecretPresentWithKeep(child)
		}
	case []any:
		for _, child := range cur {
			replaceSecretPresentWithKeep(child)
		}
	}
}

func indexExistingSecretSlots(rawUsers any) map[string]map[string]bool {
	out := make(map[string]map[string]bool)
	slice, ok := rawUsers.([]any)
	if !ok {
		return out
	}
	for _, item := range slice {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if id == "" {
			continue
		}
		slots := make(map[string]bool)
		for _, field := range []string{"uuid", "auth", "psk"} {
			if slot, ok := m[field].(map[string]any); ok {
				if keep, ok := slot["$keep_secret"].(bool); ok && keep {
					slots[field] = true
				}
			}
		}
		out[id] = slots
	}
	return out
}

func buildProfileUsers(protocol string, activeUsers []userRecord, existing map[string]map[string]bool) []any {
	out := make([]any, 0, len(activeUsers))
	for _, u := range activeUsers {
		entry := map[string]any{"id": u.ID}
		if u.TrafficMark >= trafficMarkMin && u.TrafficMark <= trafficMarkMax {
			entry["traffic_mark"] = u.TrafficMark
		}
		slots := existing[u.ID]
		switch protocol {
		case "vless":
			if slots["uuid"] {
				entry["uuid"] = map[string]any{"$keep_secret": true}
			} else {
				entry["uuid"] = u.VLESSUUID
			}
		case "hysteria2":
			if slots["auth"] {
				entry["auth"] = map[string]any{"$keep_secret": true}
			} else {
				entry["auth"] = u.Hy2Password
			}
		case "shadowsocks2022":
			if slots["psk"] {
				entry["psk"] = map[string]any{"$keep_secret": true}
			} else {
				entry["psk"] = u.SS2022UserKey
			}
		default:
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (i *instance) setSyncError(msg string) {
	i.mu.Lock()
	i.lastSyncError = msg
	i.mu.Unlock()
}
