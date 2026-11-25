// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/storage"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ============================================================================
// 修复 R2-BUG-17 与 R2-BUG-20.2：
//  1. 跨插件 PutPluginConfig 同步更新 Updater.ActiveConfig 内存缓存 + 裁剪旧版本触发密文 GC + 校验 core.apply 结果；
//  2. 打通 AnyTLS / VLESS-TLS / VMess-TLS / Trojan-TLS / Hysteria2 五大协议的宿主 TLS 证书消费门禁。
// ============================================================================

// TLSConsumerSpec describes an official host-approved TLS certificate consumer plugin.
type TLSConsumerSpec struct {
	PluginID        string
	ReloadOperation string
	InspectOp       string
}

// SupportedTLSConsumerPlugins lists all builtin plugins authorized to consume
// host-materialized TLS certificates and receive automatic renewal reloads.
var SupportedTLSConsumerPlugins = map[string]TLSConsumerSpec{
	"core.xray": {
		PluginID:        "core.xray",
		ReloadOperation: "tls.reload",
		InspectOp:       "tls.inspect",
	},
	"proxy.advanced": {
		PluginID:        "proxy.advanced",
		ReloadOperation: "tls.reload",
		InspectOp:       "tls.inspect",
	},
	"web.ingress": {
		PluginID:        "web.ingress",
		ReloadOperation: "ingress.tls.reload",
		InspectOp:       "ingress.tls.inspect",
	},
	"server.probe": {
		PluginID:        "server.probe",
		ReloadOperation: "probe.tls.reload",
		InspectOp:       "probe.tls.inspect",
	},
}

// IsValidCertificateConsumerPurpose 定义宿主允许受控消费者使用的证书用途集合（同步更新 certificates/validate.go:66）。
func IsValidCertificateConsumerPurpose(purpose string) bool {
	switch purpose {
	case "panel.https",
		"proxy.hysteria2",
		"proxy.anytls",
		"proxy.vless",
		"proxy.vmess",
		"proxy.trojan",
		"proxy.tls",
		"ingress.https",
		"probe.https":
		return true
	default:
		return false
	}
}

// ExtractProfileTLSBinding 统一提取 Core Intent v2 任一 Profile 中引用的宿主托管 TLSBinding 及其标准用途标识。
// 同时供 prerequisite_consumers.go、prerequisite_configuration.go 与 prerequisite_consumer_runtime.go 复用，
// 彻底解除原先硬编码只认 `hysteria2` 的限制！
func ExtractProfileTLSBinding(p corev2.Profile) (binding *corev2.TLSBinding, defaultPurpose string, ok bool) {
	switch p.Protocol {
	case corev2.ProtocolHysteria2:
		if p.Hysteria2 != nil && p.Hysteria2.TLS != nil {
			return p.Hysteria2.TLS, "proxy.hysteria2", true
		}
	case corev2.ProtocolAnyTLS:
		if p.AnyTLS != nil && p.AnyTLS.TLS != nil {
			return p.AnyTLS.TLS, "proxy.anytls", true
		}
	case corev2.ProtocolVLESS:
		if p.VLESS != nil && p.VLESS.EffectiveSecurityMode() == "tls" && p.VLESS.TLS != nil {
			return p.VLESS.TLS, "proxy.vless", true
		}
	case corev2.ProtocolVMess:
		if p.VMess != nil && p.VMess.SecurityMode == "tls" && p.VMess.TLS != nil {
			return p.VMess.TLS, "proxy.vmess", true
		}
	case corev2.ProtocolTrojan:
		if p.Trojan != nil && p.Trojan.SecurityMode == "tls" && p.Trojan.TLS != nil {
			return p.Trojan.TLS, "proxy.trojan", true
		}
	}
	return nil, "", false
}

// ProfileMatchesConsumerPurpose 允许具体协议用途（如 "proxy.anytls"）或通用代理 TLS 用途（"proxy.tls"）。
func ProfileMatchesConsumerPurpose(p corev2.Profile, wantPurpose string) bool {
	_, defaultPurpose, ok := ExtractProfileTLSBinding(p)
	if !ok {
		return false
	}
	if p.Protocol == corev2.ProtocolHysteria2 {
		return wantPurpose == "proxy.hysteria2"
	}
	return wantPurpose == defaultPurpose || wantPurpose == "proxy.tls"
}

// ProfileUsesBindingRef 供 prerequisite_consumer_runtime.go:InUse 检查任意 TLS 协议是否仍在引用指定证书绑定。
func ProfileUsesBindingRef(intent *corev2.Intent, bindingID string) bool {
	if intent == nil || bindingID == "" {
		return false
	}
	for _, profile := range intent.Profiles {
		if tlsBind, _, ok := ExtractProfileTLSBinding(profile); ok && tlsBind.BindingRef == bindingID {
			return true
		}
	}
	return false
}

// CommitAndSyncPluginConfig 修复 internal/controller/plugin_public.go:PutPluginConfig 的三大生产断路：
//  1. 事务内仅保留最近 5 个历史配置版本，使 SQLite `secret_references_cleanup_after_delete` 触发器自动回收陈旧密文；
//  2. 提交后立即调用 updater.SyncActiveConfig 更新内存快照，杜绝 core.xray/core.apply 报 CONFIG_REVISION_CONFLICT；
//  3. 派发 core.apply 后校验返回状态，绝不静默吞掉同步错误！
func CommitAndSyncPluginConfig(
	ctx context.Context,
	db *storage.DB,
	ops *operations.Service,
	syncMemCache func(pluginID string, rev int64, configBytes []byte),
	targetPluginID string,
	toStore []byte,
	expectedRevision string,
	now time.Time,
	nodeID string,
	triggerApply bool,
	payload []byte,
) (revStr string, applyOpID string, err error) {
	nowStr := now.UTC().Format(time.RFC3339Nano)
	var (
		newRev   int64
		prevRev  int64
		prevJSON string
		hasPrev  bool
	)

	err = db.Update(ctx, func(tx *storage.Tx) error {
		var curRev int64
		if qerr := tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(revision), 0) FROM plugin_configs WHERE plugin_id = ?`,
			targetPluginID,
		).Scan(&curRev); qerr != nil {
			return qerr
		}
		if expectedRevision != "" && strconv.FormatInt(curRev, 10) != expectedRevision {
			return problem.New(problem.RevisionConflict, "target plugin configuration revision mismatch")
		}
		if perr := tx.QueryRowContext(ctx,
			`SELECT revision, config_json FROM plugin_configs WHERE plugin_id = ? AND active = 1 ORDER BY revision DESC LIMIT 1`,
			targetPluginID,
		).Scan(&prevRev, &prevJSON); perr == nil {
			hasPrev = true
		}
		newRev = curRev + 1
		if _, uerr := tx.ExecContext(ctx,
			`UPDATE plugin_configs SET active = 0 WHERE plugin_id = ? AND active = 1`,
			targetPluginID,
		); uerr != nil {
			return uerr
		}
		if _, ierr := tx.ExecContext(ctx,
			`INSERT INTO plugin_configs (plugin_id, revision, config_json, active, created_at, applied_at) VALUES (?, ?, ?, 1, ?, ?)`,
			targetPluginID, newRev, string(toStore), nowStr, nowStr,
		); ierr != nil {
			return ierr
		}
		// 裁剪历史非活跃版本（保留最新 5 版供审计/回退），触发级联释放不再被引用的 secrets 行
		_, perr := tx.ExecContext(ctx, `
			DELETE FROM plugin_configs
			WHERE plugin_id = ? AND active = 0 AND revision NOT IN (
				SELECT revision FROM plugin_configs
				WHERE plugin_id = ?
				ORDER BY revision DESC
				LIMIT 5
			)`, targetPluginID, targetPluginID)
		return perr
	})
	if err != nil {
		return "", "", err
	}

	revStr = strconv.FormatInt(newRev, 10)
	// 立即同步 Updater 内存 ActiveConfig 快照，消除 hostConfigSource 旧版本幻读！
	if syncMemCache != nil {
		syncMemCache(targetPluginID, newRev, append([]byte(nil), toStore...))
	}

	rollbackActiveConfig := func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = db.Update(rbCtx, func(tx *storage.Tx) error {
			if _, uerr := tx.ExecContext(rbCtx,
				`UPDATE plugin_configs SET active = 0 WHERE plugin_id = ? AND revision = ?`,
				targetPluginID, newRev,
			); uerr != nil {
				return uerr
			}
			if hasPrev {
				_, uerr := tx.ExecContext(rbCtx,
					`UPDATE plugin_configs SET active = 1 WHERE plugin_id = ? AND revision = ?`,
					targetPluginID, prevRev,
				)
				return uerr
			}
			return nil
		})
		if syncMemCache != nil && hasPrev {
			syncMemCache(targetPluginID, prevRev, []byte(prevJSON))
		}
	}

	if triggerApply && ops != nil {
		actionID := targetPluginID + "/core.apply"
		opCtx := operations.WithPermissionMode(ctx, operations.PermissionFull)
		resp, rerr := ops.Run(opCtx, operations.RunRequest{
			Actor:  actor.SystemActor("pluginconfig"),
			Action: actionID,
			NodeID: nodeID,
			Target: operations.Target{NodeID: nodeID, PluginID: targetPluginID, InstanceID: DefaultInstanceID},
			Args:   payload,
			Idempotency: operations.Idempotency{
				Key:    "pluginconfig-apply:" + targetPluginID + ":" + revStr,
				Method: "POST",
				Route:  "/internal/pluginconfig/apply",
			},
		})
		if rerr != nil {
			rollbackActiveConfig()
			return revStr, "", fmt.Errorf("dispatch %s failed: %w", actionID, rerr)
		}
		if resp != nil && resp.Operation != nil {
			applyOpID = strings.TrimSpace(resp.Operation.ID)
			if resp.Operation.Status == operations.Failed || resp.Operation.Status == operations.Rejected {
				rollbackActiveConfig()
				msg := "core.apply failed"
				if resp.Operation.Error != nil && resp.Operation.Error.Detail != "" {
					msg = resp.Operation.Error.Detail
				}
				return revStr, applyOpID, problem.New(problem.PluginUnavailable, "%s", msg)
			}
		}
	}
	return revStr, applyOpID, nil
}

// Ensure certificates import is referenced for easy copy-in integration.
var _ = certificates.CanonicalConsumer
