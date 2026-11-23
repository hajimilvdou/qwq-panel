// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ======================== 1. 持久化高熵密封密钥加载器 ========================

// LoadOrCreateProbeSealingSecret 替代不安全的固定 "default" 密封密钥：
// 首次启动时用 CSPRNG 生成 32 字节高熵随机种子并以 0600 权限保存在 dataDir/probe_domain.seal。
func LoadOrCreateProbeSealingSecret(dataDir string) ([]byte, error) {
	if strings.TrimSpace(dataDir) == "" {
		buf := make([]byte, 32)
		_, err := rand.Read(buf)
		return buf, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare probe sealing dir: %w", err)
	}
	sealPath := filepath.Join(dataDir, "probe_domain.seal")
	if raw, err := os.ReadFile(sealPath); err == nil && len(raw) == 32 {
		return raw, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate probe sealing secret: %w", err)
	}
	tmp := sealPath + ".tmp"
	if err := os.WriteFile(tmp, secret, 0o600); err != nil {
		return nil, fmt.Errorf("write probe sealing secret: %w", err)
	}
	if err := os.Rename(tmp, sealPath); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	return secret, nil
}

// ======================== 2. 节点离线状态机、真实 90 天 SLA 宕机扣减与边沿告警 ========================

// NodeLivenessSnapshot 由 ProbeStore 在每轮后台 Tick 导出供离线判定器对账。
type NodeLivenessSnapshot struct {
	ID                string
	Name              string
	RegionCode        string
	IsLocal           bool
	ReportIntervalSec int
	LastSeenUnix      int64
	CurrentState      string // "online" | "offline" | "pending"
}

// OfflineTransition 记录本轮巡检发生的状态边沿跳变（用于触发 probe.alert 离线与恢复通知）。
type OfflineTransition struct {
	NodeID       string
	NodeName     string
	RegionCode   string
	BecameOnline bool // false = 刚发生离线告警；true = 已从离线恢复上线
	OfflineFor   time.Duration
}

// EvaluateNodeLiveness 在 backgroundLoop 每次 Tick 中调用：
//   - 若非本机节点已收到过至少一次上报（LastSeenUnix > 0），且距今超过 max(15s, 4 * ReportIntervalSec)，
//     判定为失联：将 OnlineState 置为 "offline"，并向当日 SLA 记录追加 tickSeconds 的 DowntimeSeconds。
//   - 当失联节点重新上报且回到宽限期内时，切换回 "online" 并产生恢复通知。
func EvaluateNodeLiveness(
	now time.Time,
	tickSeconds int64,
	nodes []NodeLivenessSnapshot,
	recordSLACheck func(nodeID string, up bool, deltaSec int64),
	updateNodeState func(nodeID, nextState string),
) []OfflineTransition {
	nowUnix := now.Unix()
	var transitions []OfflineTransition

	for _, n := range nodes {
		if n.IsLocal || n.LastSeenUnix <= 0 {
			continue
		}
		interval := n.ReportIntervalSec
		if interval <= 0 {
			interval = 2
		}
		graceSec := int64(max(15, interval*4))
		silentSec := nowUnix - n.LastSeenUnix

		if silentSec > graceSec {
			if recordSLACheck != nil {
				recordSLACheck(n.ID, false, max(tickSeconds, 1))
			}
			if n.CurrentState != "offline" {
				if updateNodeState != nil {
					updateNodeState(n.ID, "offline")
				}
				transitions = append(transitions, OfflineTransition{
					NodeID:       n.ID,
					NodeName:     n.Name,
					RegionCode:   n.RegionCode,
					BecameOnline: false,
					OfflineFor:   time.Duration(silentSec) * time.Second,
				})
			}
		} else if n.CurrentState == "offline" {
			if updateNodeState != nil {
				updateNodeState(n.ID, "online")
			}
			transitions = append(transitions, OfflineTransition{
				NodeID:       n.ID,
				NodeName:     n.Name,
				RegionCode:   n.RegionCode,
				BecameOnline: true,
			})
		}
	}
	return transitions
}

// BuildProbeAlertEventPayload 将节点离线/恢复边沿事件编码为宿主 probe.alert 标准告警 JSON。
func BuildProbeAlertEventPayload(tr OfflineTransition, now time.Time) ([]byte, error) {
	sev := "critical"
	title := fmt.Sprintf("探针节点离线告警：%s (%s)", tr.NodeName, tr.RegionCode)
	msg := fmt.Sprintf("节点 %s [%s] 已失联超过 %s，请检查服务器电源、网络或探针进程状态。", tr.NodeName, tr.NodeID, tr.OfflineFor.Round(time.Second))
	dedup := "probe.offline." + tr.NodeID
	if tr.BecameOnline {
		sev = "info"
		title = fmt.Sprintf("探针节点已恢复在线：%s (%s)", tr.NodeName, tr.RegionCode)
		msg = fmt.Sprintf("节点 %s [%s] 遥测心跳已恢复正常。", tr.NodeName, tr.NodeID)
		dedup = "probe.online." + tr.NodeID
	}
	return json.Marshal(map[string]any{
		"source":    "server.probe",
		"severity":  sev,
		"title":     title,
		"message":   msg,
		"dedup_key": dedup,
		"tags": map[string]string{
			"node_id": tr.NodeID,
			"region":  tr.RegionCode,
		},
		"timestamp": now.UTC().Format(time.RFC3339),
	})
}

// ======================== 3. 真实 SQLite 三网延迟时序查询 ========================

// QueryRealCarrierLatencySeries 从 probe_metric_rollups 查询最近 windowMinutes（默认 60 分钟，最多 120 桶）
// 的全网平均电信 CT / 联通 CU / 移动 CM 真实 TCP 拨测延迟曲线；无数据时返回空 points: []，绝不伪造静态数字。
func QueryRealCarrierLatencySeries(ctx context.Context, db *sql.DB, now time.Time, windowMinutes int) ([]byte, error) {
	if windowMinutes <= 0 || windowMinutes > 1440 {
		windowMinutes = 60
	}
	ctPts := make([][]any, 0, 60)
	cuPts := make([][]any, 0, 60)
	cmPts := make([][]any, 0, 60)
	var maxVal float64 = 100

	if db != nil {
		cutoffUnix := now.Add(-time.Duration(windowMinutes) * time.Minute).Unix()
		rows, err := db.QueryContext(ctx, `
			SELECT
				bucket_minute_unix,
				AVG(CASE WHEN ping_ct_ms >= 0 THEN ping_ct_ms END) AS avg_ct,
				AVG(CASE WHEN ping_cu_ms >= 0 THEN ping_cu_ms END) AS avg_cu,
				AVG(CASE WHEN ping_cm_ms >= 0 THEN ping_cm_ms END) AS avg_cm
			FROM probe_metric_rollups
			WHERE bucket_minute_unix >= ?
			GROUP BY bucket_minute_unix
			ORDER BY bucket_minute_unix ASC
			LIMIT 120
		`, cutoffUnix)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var bucketSec int64
			var ct, cu, cm sql.NullFloat64
			if err := rows.Scan(&bucketSec, &ct, &cu, &cm); err != nil {
				return nil, err
			}
			tsMs := bucketSec * 1000
			if ct.Valid {
				v := round1Decimal(ct.Float64)
				ctPts = append(ctPts, []any{tsMs, v})
				maxVal = max(maxVal, v*1.2)
			}
			if cu.Valid {
				v := round1Decimal(cu.Float64)
				cuPts = append(cuPts, []any{tsMs, v})
				maxVal = max(maxVal, v*1.2)
			}
			if cm.Valid {
				v := round1Decimal(cm.Float64)
				cmPts = append(cmPts, []any{tsMs, v})
				maxVal = max(maxVal, v*1.2)
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	return json.Marshal(map[string]any{
		"unit": "ms",
		"max":  int(maxVal),
		"series": []map[string]any{
			{"name": "电信 CT", "color": "teal", "points": ctPts},
			{"name": "联通 CU", "color": "blue", "points": cuPts},
			{"name": "移动 CM", "color": "violet", "points": cmPts},
		},
	})
}

func round1Decimal(v float64) float64 {
	return float64(int(v*10+0.5)) / 10.0
}

// CheckStandaloneAdminStatus 校验代理到 handleStandaloneAdminAction 的内部状态码，
// 防止 >=400 错误被吞掉并伪造成功的 ResourceChange。
func CheckStandaloneAdminStatus(httpStatus int, respBody []byte) error {
	if httpStatus >= 200 && httpStatus < 300 {
		return nil
	}
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(respBody, &parsed)
	msg := parsed.Message
	if msg == "" {
		msg = parsed.Error
	}
	if msg == "" {
		msg = fmt.Sprintf("probe action failed with status %d", httpStatus)
	}
	if httpStatus == 400 || httpStatus == 422 {
		return fmt.Errorf("VALIDATION_FAILED: %s", msg)
	}
	if httpStatus == 409 {
		return fmt.Errorf("PRECONDITION_FAILED: %s", msg)
	}
	return errors.New(msg)
}

// ======================== 4. 宿主托管 TLS 证书热载与观测 (probe.tls.reload / inspect) ========================

type probeTLSBindingObservation struct {
	BindingRef      string `json:"binding_ref"`
	Running         bool   `json:"running"`
	Generation      uint64 `json:"generation"`
	PolicyRevision  string `json:"policy_revision,omitempty"`
	LeafFingerprint string `json:"leaf_fingerprint,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	SNI             string `json:"sni,omitempty"`
}

func (c *DomainBindingCoordinator) ReloadMaterializedTLS(
	now time.Time,
	bindingRef string,
	generation uint64,
	policyRev, wantFullchainSHA, wantKeySHA, sni, endpoint string,
) (probeTLSBindingObservation, error) {
	if c == nil || c.dataDir == "" {
		return probeTLSBindingObservation{}, errors.New("DATA_DIR_UNSET")
	}
	cleanRef := filepath.Base(strings.TrimSpace(bindingRef))
	if cleanRef == "" || cleanRef == "." || cleanRef == ".." {
		return probeTLSBindingObservation{}, errors.New("INVALID_BINDING_REF")
	}
	baseDir := filepath.Join(c.dataDir, "tls", "bindings", cleanRef)
	chainBytes, err := os.ReadFile(filepath.Join(baseDir, "active_fullchain.pem"))
	if err != nil {
		return probeTLSBindingObservation{}, fmt.Errorf("MATERIALIZED_CERT_MISSING: %w", err)
	}
	keyBytes, err := os.ReadFile(filepath.Join(baseDir, "active_privkey.pem"))
	if err != nil {
		return probeTLSBindingObservation{}, fmt.Errorf("MATERIALIZED_KEY_MISSING: %w", err)
	}
	defer clear(keyBytes)

	if wantFullchainSHA != "" {
		sum := sha256.Sum256(chainBytes)
		got := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(wantFullchainSHA)), []byte(got)) != 1 {
			return probeTLSBindingObservation{}, errors.New("TLS_PROOF_MISMATCH: fullchain digest mismatch")
		}
	}
	if wantKeySHA != "" {
		sum := sha256.Sum256(keyBytes)
		got := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(wantKeySHA)), []byte(got)) != 1 {
			return probeTLSBindingObservation{}, errors.New("TLS_PROOF_MISMATCH: private key digest mismatch")
		}
	}

	dom := normalizeFQDN(sni)
	pair, issuer, fp, notAfter, err := ValidateStrictProbePEM(now, dom, chainBytes, keyBytes)
	if err != nil {
		return probeTLSBindingObservation{}, err
	}
	c.activeCert.Store(pair)
	summary := BoundCertSummary{
		Track:         TrackPanelDNC,
		Domain:        dom,
		Issuer:        issuer,
		Fingerprint:   fp,
		NotAfter:      notAfter,
		AutoRenew:     true,
		EffectiveURL:  "https://" + dom + "/",
		AgentEndpoint: "https://" + dom + "/api/probe/v1/report",
	}
	c.activeMeta.Store(&summary)
	obs := probeTLSBindingObservation{
		BindingRef:      cleanRef,
		Running:         true,
		Generation:      generation,
		PolicyRevision:  policyRev,
		LeafFingerprint: fp,
		Endpoint:        endpoint,
		SNI:             dom,
	}
	c.tlsObs.Store(&obs)
	return obs, nil
}

func (c *DomainBindingCoordinator) InspectMaterializedTLS(bindingRef, fallbackEndpoint string) probeTLSBindingObservation {
	cleanRef := filepath.Base(strings.TrimSpace(bindingRef))
	if c != nil {
		if obs := c.tlsObs.Load(); obs != nil && (cleanRef == "" || obs.BindingRef == cleanRef) {
			return *obs
		}
	}
	return probeTLSBindingObservation{
		BindingRef: cleanRef,
		Running:    false,
		Endpoint:   fallbackEndpoint,
	}
}

// deriveScriptBaseURL 根据配置的 public_origin 或上报 URL 推导出可达的脚本基址，绝不硬编码不可达占位域名。
func deriveScriptBaseURL(reportURL string) string {
	trimmed := strings.TrimSpace(reportURL)
	if strings.HasPrefix(trimmed, "https://") || strings.HasPrefix(trimmed, "http://") {
		if u, err := url.Parse(trimmed); err == nil && u.Scheme != "" && u.Host != "" {
			if strings.Contains(u.Path, "/p/server.probe/") {
				return u.Scheme + "://" + u.Host + "/p/server.probe/portal"
			}
			return u.Scheme + "://" + u.Host
		}
	}
	return "/p/server.probe/portal"
}
