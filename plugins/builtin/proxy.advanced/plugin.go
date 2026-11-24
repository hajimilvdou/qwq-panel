// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	trafficv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/traffic/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 内置清单嵌入与插件入口 ========================

//go:embed manifest.json
var manifestJSON []byte
var buildVersion string

// Manifest 返回内嵌的 proxy.advanced 插件清单字节。
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

// Plugin 实现节点级高级代理多用户管理、多格式订阅分发、配额统计、连接限制、链式代理与 TCP Brutal / tcpfit 网络调优插件。
type Plugin struct {
	now              func() time.Time
	syncInterval     time.Duration
	brutalBindHost   string
	sysctlTargetPath string
}

// New 构造默认高级代理插件实例。
func New() *Plugin { return &Plugin{} }

func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg, err := parseConfig(info.Config)
	if err != nil {
		return nil, err
	}
	nowFn := p.now
	if nowFn == nil {
		nowFn = time.Now
	}
	st, err := openStore(info.DataDir, nowFn)
	if err != nil {
		return nil, pluginsdk.Errorf("INTERNAL", "初始化代理本地数据库失败")
	}
	sysctlPath := p.sysctlTargetPath
	if sysctlPath == "" {
		sysctlPath = sysctlDropInPath
	}
	inst := &instance{
		InstanceBase:         pluginsdk.NewInstanceBase(info),
		cfg:                  cfg,
		store:                st,
		connLim:              newConnLimiter(),
		brutalMgr:            newBrutalManager(p.brutalBindHost),
		sysctlTargetPath:     sysctlPath,
		now:                  nowFn,
		syncIntervalOverride: p.syncInterval,
		shapingSupported:     true,
		spark:                make([]float64, 0, 12),
	}
	inst.register()
	return inst, nil
}

// ======================== 插件配置解析与实例生命周期 ========================

const (
	defaultSyncIntervalSeconds = 30
	defaultPublicBasePath      = "/p/proxy.advanced"
)

var validEntityIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

type proxyConfig struct {
	PublicHost          string
	PublicBasePath      string
	VLESSPort           uint16
	RealitySNI          string
	RealityPublicKey    string
	RealityShortID      string
	Hy2Port             uint16
	Hy2SNI              string
	Hy2PublicTrusted    bool
	Hy2CertPinSHA256    string
	SSPort              uint16
	SSMethod            string
	SSServerKey         string
	SSObfsMode          string
	SSObfsHost          string
	SSUDP               bool
	SyncIntervalSeconds uint32
}

type rawProxyConfig struct {
	PublicHost          *string `json:"public_host"`
	PublicBasePath      *string `json:"public_base_path"`
	VLESSPort           *uint32 `json:"vless_port"`
	RealitySNI          *string `json:"reality_sni"`
	RealityPublicKey    *string `json:"reality_public_key"`
	RealityShortID      *string `json:"reality_short_id"`
	Hy2Port             *uint32 `json:"hy2_port"`
	Hy2SNI              *string `json:"hy2_sni"`
	Hy2PublicTrusted    *bool   `json:"hy2_public_trusted"`
	Hy2CertPinSHA256    *string `json:"hy2_cert_pin_sha256"`
	SSPort              *uint32 `json:"ss_port"`
	SSMethod            *string `json:"ss_method"`
	SSServerKey         *string `json:"ss_server_key"`
	SSObfsMode          *string `json:"ss_obfs_mode"`
	SSObfsHost          *string `json:"ss_obfs_host"`
	SSUDP               *bool   `json:"ss_udp"`
	SyncIntervalSeconds *uint32 `json:"sync_interval_seconds"`
}

func defaultProxyConfig() proxyConfig {
	return proxyConfig{
		PublicBasePath:      defaultPublicBasePath,
		Hy2PublicTrusted:    true,
		SSMethod:            "2022-blake3-aes-128-gcm",
		SSObfsMode:          "none",
		SSUDP:               true,
		SyncIntervalSeconds: defaultSyncIntervalSeconds,
	}
}

func parseConfig(raw []byte) (proxyConfig, error) {
	cfg := defaultProxyConfig()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return cfg, nil
	}
	var in rawProxyConfig
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return proxyConfig{}, invalidField("", "INVALID_CONFIG", "高级代理插件配置格式无效")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return proxyConfig{}, invalidField("", "INVALID_CONFIG", "高级代理插件配置包含多余内容")
	}
	if in.PublicHost != nil {
		cfg.PublicHost = strings.TrimSpace(*in.PublicHost)
	}
	if in.PublicBasePath != nil {
		base := strings.TrimRight(strings.TrimSpace(*in.PublicBasePath), "/")
		if base == "" {
			base = defaultPublicBasePath
		}
		cfg.PublicBasePath = base
	}
	if in.VLESSPort != nil {
		if *in.VLESSPort > 65535 {
			return proxyConfig{}, invalidField("/vless_port", "OUT_OF_RANGE", "vless_port 必须在 0..65535 之间")
		}
		cfg.VLESSPort = uint16(*in.VLESSPort)
	}
	if in.RealitySNI != nil {
		cfg.RealitySNI = strings.TrimSpace(*in.RealitySNI)
	}
	if in.RealityPublicKey != nil {
		cfg.RealityPublicKey = strings.TrimSpace(*in.RealityPublicKey)
	}
	if in.RealityShortID != nil {
		cfg.RealityShortID = strings.TrimSpace(*in.RealityShortID)
	}
	if in.Hy2Port != nil {
		if *in.Hy2Port > 65535 {
			return proxyConfig{}, invalidField("/hy2_port", "OUT_OF_RANGE", "hy2_port 必须在 0..65535 之间")
		}
		cfg.Hy2Port = uint16(*in.Hy2Port)
	}
	if in.Hy2SNI != nil {
		cfg.Hy2SNI = strings.TrimSpace(*in.Hy2SNI)
	}
	if in.Hy2PublicTrusted != nil {
		cfg.Hy2PublicTrusted = *in.Hy2PublicTrusted
	}
	if in.Hy2CertPinSHA256 != nil {
		cfg.Hy2CertPinSHA256 = strings.TrimSpace(*in.Hy2CertPinSHA256)
	}
	if in.SSPort != nil {
		if *in.SSPort > 65535 {
			return proxyConfig{}, invalidField("/ss_port", "OUT_OF_RANGE", "ss_port 必须在 0..65535 之间")
		}
		cfg.SSPort = uint16(*in.SSPort)
	}
	if in.SSMethod != nil {
		m := strings.TrimSpace(*in.SSMethod)
		if m != "2022-blake3-aes-128-gcm" && m != "2022-blake3-aes-256-gcm" {
			return proxyConfig{}, invalidField("/ss_method", "INVALID_VALUE", "ss_method 仅支持 2022-blake3-aes-128-gcm 或 2022-blake3-aes-256-gcm")
		}
		cfg.SSMethod = m
	}
	if in.SSServerKey != nil {
		cfg.SSServerKey = strings.TrimSpace(*in.SSServerKey)
	}
	if in.SSObfsMode != nil {
		m := strings.ToLower(strings.TrimSpace(*in.SSObfsMode))
		if m != "" && m != "none" && m != "http" && m != "tls" {
			return proxyConfig{}, invalidField("/ss_obfs_mode", "INVALID_VALUE", "ss_obfs_mode 仅支持 none、http 或 tls")
		}
		cfg.SSObfsMode = m
	}
	if in.SSObfsHost != nil {
		cfg.SSObfsHost = strings.TrimSpace(*in.SSObfsHost)
	}
	if in.SSUDP != nil {
		cfg.SSUDP = *in.SSUDP
	}
	if in.SyncIntervalSeconds != nil {
		if *in.SyncIntervalSeconds < 10 || *in.SyncIntervalSeconds > 300 {
			return proxyConfig{}, invalidField("/sync_interval_seconds", "OUT_OF_RANGE", "sync_interval_seconds 必须在 10..300 之间")
		}
		cfg.SyncIntervalSeconds = *in.SyncIntervalSeconds
	}
	return cfg, nil
}

type instance struct {
	*pluginsdk.InstanceBase

	mu                    sync.RWMutex
	cfg                   proxyConfig
	shapingSupported      bool
	shapingDegradedReason string
	lastSyncError         string
	spark                 []float64
	coreObfsAvail         *bool
	coreObfsCheckedAt     time.Time

	syncMu               sync.Mutex
	store                *proxyStore
	connLim              *connLimiter
	brutalMgr            *brutalManager
	sysctlTargetPath     string
	now                  func() time.Time
	syncIntervalOverride time.Duration
}

func (i *instance) configSnapshot() proxyConfig {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cfg
}

func (i *instance) Activate(ctx context.Context) error {
	if i.brutalMgr != nil {
		if bindings, err := i.store.ListBrutalBindings(ctx); err == nil && len(bindings) > 0 {
			_, _ = i.brutalMgr.Reconcile(bindings)
		}
	}
	return i.Go(i.syncLoop)
}
func (i *instance) Deactivate(context.Context) error {
	if i.brutalMgr != nil {
		i.brutalMgr.CloseAll()
	}
	return nil
}
func (i *instance) Stop(context.Context) error {
	if i.brutalMgr != nil {
		i.brutalMgr.CloseAll()
	}
	return i.store.Close()
}
func (i *instance) Release(context.Context) error {
	if i.brutalMgr != nil {
		i.brutalMgr.CloseAll()
	}
	return i.store.Close()
}

func (i *instance) ValidateConfig(_ context.Context, cfg pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	_, err := parseConfig(cfg.JSON)
	return pluginsdk.ConfigValidation{}, err
}

func (i *instance) ApplyConfig(_ context.Context, cfg pluginsdk.Config) error {
	next, err := parseConfig(cfg.JSON)
	if err != nil {
		return err
	}
	i.mu.Lock()
	i.cfg = next
	i.mu.Unlock()
	return nil
}

func (i *instance) Health(context.Context) pluginsdk.Health {
	i.mu.RLock()
	syncErr := i.lastSyncError
	shapingOK := i.shapingSupported
	reason := i.shapingDegradedReason
	i.mu.RUnlock()
	if syncErr != "" {
		return pluginsdk.Health{Message: "后台流量采样异常：" + syncErr}
	}
	if !shapingOK && reason != "" {
		return pluginsdk.Health{Message: "高级代理运行中（内核限速已降级：" + reason + "）"}
	}
	return pluginsdk.Health{Message: "高级代理管理与订阅分发就绪"}
}

// ======================== 9 项 Operation 注册与 DTO ========================

func (i *instance) register() {
	i.HandleInvoke("proxy.overview", i.handleOverview)
	i.HandleInvoke("plans.list", i.handlePlansList)
	i.HandleJob("plans.upsert", i.handlePlansUpsert)
	i.HandleInvoke("users.list", i.handleUsersList)
	i.HandleJob("users.create", i.handleUsersCreate)
	i.HandleJob("users.rotate_subscription", i.handleUsersRotateSubscription)
	i.HandleJob("users.set_status", i.handleUsersSetStatus)
	i.HandleInvoke("users.usage_history", i.handleUsersUsageHistory)
	i.HandleInvoke("traffic.status", i.handleTrafficStatus)
	i.registerExtendedOperations()
}

type overviewRequest struct {
	IncludeTrafficStatus bool `json:"include_traffic_status"`
}

type overviewResponse struct {
	Value                 float64   `json:"value"`
	Unit                  string    `json:"unit"`
	Percent               float64   `json:"percent"`
	Sub                   string    `json:"sub"`
	Level                 string    `json:"level"`
	Spark                 []float64 `json:"spark"`
	TotalPlans            int       `json:"total_plans"`
	TotalUsers            int       `json:"total_users"`
	ActiveUsers           int       `json:"active_users"`
	SuspendedQuotaUsers   int       `json:"suspended_quota_users"`
	ExpiredUsers          int       `json:"expired_users"`
	DisabledUsers         int       `json:"disabled_users"`
	PeriodUpBytes         int64     `json:"period_up_bytes"`
	PeriodDownBytes       int64     `json:"period_down_bytes"`
	UsedTrafficMarks      int       `json:"used_traffic_marks"`
	ShapingSupported      bool      `json:"shaping_supported"`
	ShapingDegradedReason string    `json:"shaping_degraded_reason"`
	DetectedPublicHost    string    `json:"detected_public_host,omitempty"`
	CoreObfsAvailable     *bool     `json:"core_obfs_available,omitempty"`
}

type plansListRequest struct {
	Limit int `json:"limit"`
}

type plansListResponse struct {
	Plans []planRecord `json:"plans"`
}

type plansUpsertRequest struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	QuotaBytes       int64  `json:"quota_bytes"`
	DownLimitKbps    uint32 `json:"down_limit_kbps"`
	UpLimitKbps      uint32 `json:"up_limit_kbps"`
	MaxConnections   int    `json:"max_connections"`
	MaxIPs           int    `json:"max_ips"`
	BillingResetDay  *int   `json:"billing_reset_day"`
	ValidityDays     int    `json:"validity_days"`
	ExpectedRevision string `json:"expected_revision"`
}

type plansUpsertResponse struct {
	Plan                  planRecord `json:"plan"`
	Created               bool       `json:"created"`
	ShapingDegraded       bool       `json:"shaping_degraded"`
	ShapingDegradedReason string     `json:"shaping_degraded_reason"`
}

type usersListRequest struct {
	Status string `json:"status"`
	PlanID string `json:"plan_id"`
	Limit  int    `json:"limit"`
}

type usersListResponse struct {
	Users []userRecord `json:"users"`
}

type usersCreateRequest struct {
	ID                     string `json:"id"`
	DisplayName            string `json:"display_name"`
	PlanID                 string `json:"plan_id"`
	ExpiresAt              int64  `json:"expires_at"`
	MaxConnectionsOverride *int   `json:"max_connections_override"`
	MaxIPsOverride         *int   `json:"max_ips_override"`
	ChainID                string `json:"chain_id"`
	SkipTrafficMark        bool   `json:"skip_traffic_mark"`
}

type usersCreateResponse struct {
	User                  userRecord `json:"user"`
	SubscriptionToken     string     `json:"subscription_token"`
	SubscriptionPath      string     `json:"subscription_path"`
	CoreRevision          string     `json:"core_revision"`
	ShapingDegraded       bool       `json:"shaping_degraded"`
	ShapingDegradedReason string     `json:"shaping_degraded_reason"`
}

type usersRotateSubscriptionRequest struct {
	UserID           string `json:"user_id"`
	ExpectedRevision string `json:"expected_revision"`
}

type usersRotateSubscriptionResponse struct {
	UserID            string `json:"user_id"`
	SubscriptionToken string `json:"subscription_token"`
	SubscriptionPath  string `json:"subscription_path"`
	Revision          int64  `json:"revision"`
}

type usersSetStatusRequest struct {
	UserID           string `json:"user_id"`
	Status           string `json:"status"`
	ExpectedRevision string `json:"expected_revision"`
}

type usersSetStatusResponse struct {
	User                  userRecord `json:"user"`
	CoreRevision          string     `json:"core_revision"`
	ShapingDegraded       bool       `json:"shaping_degraded"`
	ShapingDegradedReason string     `json:"shaping_degraded_reason"`
}

type usersUsageHistoryRequest struct {
	UserID string `json:"user_id"`
	Hours  int    `json:"hours"`
}

type usersUsageHistoryResponse struct {
	UserID string             `json:"user_id"`
	Hours  int                `json:"hours"`
	Points []usageRollupPoint `json:"points"`
}

type trafficStatusRequest struct {
	IncludeClasses *bool `json:"include_classes"`
}

type trafficClassDTO struct {
	TrafficMark   uint32 `json:"traffic_mark"`
	DownLimitKbps uint32 `json:"down_limit_kbps"`
	UpLimitKbps   uint32 `json:"up_limit_kbps"`
}

type trafficStatusResponse struct {
	Supported          bool              `json:"supported"`
	UplinkIFBSupported bool              `json:"uplink_ifb_supported"`
	DegradedReason     string            `json:"degraded_reason"`
	EgressInterface    string            `json:"egress_interface"`
	Revision           string            `json:"revision"`
	Classes            []trafficClassDTO `json:"classes"`
}

// ======================== 9 项 Operation 处理器实现 ========================

func (i *instance) handleOverview(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in overviewRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	stats, err := i.store.GetOverviewStats(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}

	if in.IncludeTrafficStatus {
		if host := req.Host(); host != nil && host.Conn() != nil {
			if meta, err := host.CapabilityContextReadOnly(ctx); err == nil {
				if resp, err := trafficv1.NewTrafficServiceClient(host.Conn()).GetShapingStatus(ctx, &trafficv1.GetShapingStatusRequest{Context: meta}); err == nil && resp.GetError() == nil {
					i.mu.Lock()
					i.shapingSupported = resp.GetSupported()
					i.shapingDegradedReason = resp.GetDegradedReason()
					i.mu.Unlock()
				}
			}
		}
	}

	i.mu.Lock()
	i.spark = append(i.spark, float64(stats.ActiveUsers))
	if len(i.spark) > 12 {
		i.spark = append([]float64(nil), i.spark[len(i.spark)-12:]...)
	}
	sparkCopy := append([]float64(nil), i.spark...)
	shapingOK := i.shapingSupported
	degradedReason := i.shapingDegradedReason
	i.mu.Unlock()

	pct := float64(stats.UsedTrafficMarks) * 100.0 / 256.0
	if pct > 100 {
		pct = 100
	}
	level := "ok"
	sub := fmt.Sprintf("套餐 %d 个 · 活跃 %d/%d", stats.TotalPlans, stats.ActiveUsers, stats.TotalUsers)
	if stats.SuspendedQuotaUsers > 0 || stats.ExpiredUsers > 0 {
		level = "warn"
		sub = fmt.Sprintf("活跃 %d · 超配额 %d · 已到期 %d", stats.ActiveUsers, stats.SuspendedQuotaUsers, stats.ExpiredUsers)
	} else if !shapingOK && degradedReason != "" {
		level = "warn"
		sub = "内核限速已降级：" + degradedReason
	} else if stats.TotalUsers == 0 {
		level = "muted"
		sub = "尚未创建代理用户"
	}

	var obfsAvail *bool
	now := i.now()
	i.mu.RLock()
	if i.coreObfsAvail != nil && now.Sub(i.coreObfsCheckedAt) < 60*time.Second {
		v := *i.coreObfsAvail
		obfsAvail = &v
	}
	i.mu.RUnlock()
	if obfsAvail == nil {
		if host := req.Host(); host != nil && host.Conn() != nil {
			// proxy.overview is a read-only invoke (unpersisted op.ID); use a
			// fresh background context so host routes it through invokeBackgroundRead
			// authorized by plugin.invoke.background without parent_not_dispatched.
			capCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			capResp, cerr := host.InvokePlugin(capCtx, pluginsdk.InvokeRequest{
				TargetPluginID: "core.xray",
				Operation:      "core.capabilities",
				APIVersion:     "v1",
				Payload:        []byte("{}"),
			})
			cancel()
			if cerr == nil && capResp.GetError() == nil && len(capResp.GetPayloadJson()) > 0 {
				var capDoc struct {
					ObfsAvailable *bool `json:"obfs_available"`
				}
				if json.Unmarshal(capResp.GetPayloadJson(), &capDoc) == nil && capDoc.ObfsAvailable != nil {
					v := *capDoc.ObfsAvailable
					obfsAvail = &v
					i.mu.Lock()
					vCopy := v
					i.coreObfsAvail = &vCopy
					i.coreObfsCheckedAt = now
					i.mu.Unlock()
				}
			}
		}
	}
	detectedHost := detectPrimaryPublicHost(i.configSnapshot().PublicHost, "")

	return marshalResponse(overviewResponse{
		Value:                 float64(stats.ActiveUsers),
		Unit:                  "位活跃用户",
		Percent:               pct,
		Sub:                   sub,
		Level:                 level,
		Spark:                 sparkCopy,
		TotalPlans:            stats.TotalPlans,
		TotalUsers:            stats.TotalUsers,
		ActiveUsers:           stats.ActiveUsers,
		SuspendedQuotaUsers:   stats.SuspendedQuotaUsers,
		ExpiredUsers:          stats.ExpiredUsers,
		DisabledUsers:         stats.DisabledUsers,
		PeriodUpBytes:         stats.PeriodUpBytes,
		PeriodDownBytes:       stats.PeriodDownBytes,
		UsedTrafficMarks:      stats.UsedTrafficMarks,
		ShapingSupported:      shapingOK,
		ShapingDegradedReason: degradedReason,
		DetectedPublicHost:    detectedHost,
		CoreObfsAvailable:     obfsAvail,
	})
}

func (i *instance) handlePlansList(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in plansListRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	plans, err := i.store.ListPlans(ctx, in.Limit)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(plansListResponse{Plans: plans})
}

func (i *instance) handlePlansUpsert(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in plansUpsertRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if !validEntityIDPattern.MatchString(in.ID) {
		return pluginsdk.Result{}, invalidField("/id", "INVALID_ID", "套餐 ID 格式无效")
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 64 {
		return pluginsdk.Result{}, invalidField("/name", "INVALID_VALUE", "套餐名称不能为空且不超过 64 字符")
	}
	if in.QuotaBytes < 0 {
		return pluginsdk.Result{}, invalidField("/quota_bytes", "OUT_OF_RANGE", "配额字节数不能为负数")
	}
	if in.MaxConnections < 0 || in.MaxConnections > 65535 {
		return pluginsdk.Result{}, invalidField("/max_connections", "OUT_OF_RANGE", "max_connections 必须在 0..65535 之间")
	}
	if in.MaxIPs < 0 || in.MaxIPs > 1024 {
		return pluginsdk.Result{}, invalidField("/max_ips", "OUT_OF_RANGE", "max_ips 必须在 0..1024 之间")
	}
	if in.BillingResetDay != nil && (*in.BillingResetDay < 0 || *in.BillingResetDay > 28) {
		return pluginsdk.Result{}, invalidField("/billing_reset_day", "OUT_OF_RANGE", "billing_reset_day 必须在 0..28 之间")
	}
	if in.ValidityDays < 0 || in.ValidityDays > 3650 {
		return pluginsdk.Result{}, invalidField("/validity_days", "OUT_OF_RANGE", "validity_days 必须在 0..3650 之间")
	}

	expectedRev := resolveRevision(in.ExpectedRevision, req, "plans/"+in.ID)
	plan, created, err := i.store.UpsertPlan(ctx, in, expectedRev)
	if err != nil {
		return pluginsdk.Result{}, err
	}

	// 更新套餐限速时同步刷新 core.xray 流量标记与内核 HTB 规则（容器降级不阻塞套餐保存）。
	var degraded bool
	var reason string
	if !created && req.Host() != nil && req.Host().Conn() != nil {
		i.syncMu.Lock()
		_, _ = i.syncCoreXrayLocked(ctx, req.Host())
		degraded, reason, err = i.syncTrafficShapingLocked(ctx, req.Host())
		i.syncMu.Unlock()
		if err != nil {
			return pluginsdk.Result{}, err
		}
	}
	return marshalResult(plansUpsertResponse{
		Plan:                  plan,
		Created:               created,
		ShapingDegraded:       degraded,
		ShapingDegradedReason: reason,
	})
}

func (i *instance) handleUsersList(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in usersListRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	if in.Status != "" && !validUserStatus(in.Status) {
		return pluginsdk.Response{}, invalidField("/status", "INVALID_VALUE", "无效的用户状态过滤值")
	}
	users, err := i.store.ListUsers(ctx, in.Status, strings.TrimSpace(in.PlanID), in.Limit)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	for idx := range users {
		snap := i.connLim.SnapshotUser(users[idx].ID, users[idx].EffectiveMaxConnections, users[idx].EffectiveMaxIPs)
		users[idx].ActiveConnections = snap.ActiveConnections
		users[idx].ActiveIPs = snap.ActiveIPs
	}
	return marshalResponse(usersListResponse{Users: users})
}

func (i *instance) handleUsersCreate(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in usersCreateRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if !validEntityIDPattern.MatchString(in.ID) {
		return pluginsdk.Result{}, invalidField("/id", "INVALID_ID", "用户 ID 格式无效")
	}
	if strings.TrimSpace(in.DisplayName) == "" || len(in.DisplayName) > 64 {
		return pluginsdk.Result{}, invalidField("/display_name", "INVALID_VALUE", "用户显示名称不能为空且不超过 64 字符")
	}
	if !validEntityIDPattern.MatchString(in.PlanID) {
		return pluginsdk.Result{}, invalidField("/plan_id", "INVALID_ID", "套餐 ID 格式无效")
	}
	if in.ExpiresAt < 0 {
		return pluginsdk.Result{}, invalidField("/expires_at", "OUT_OF_RANGE", "到期时间戳不能为负数")
	}

	cfg := i.configSnapshot()
	user, rawToken, err := i.store.CreateUser(ctx, in, cfg.SSMethod)
	if err != nil {
		return pluginsdk.Result{}, err
	}

	syncOut, err := i.syncCoreAndTraffic(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}

	return marshalResult(usersCreateResponse{
		User:                  user,
		SubscriptionToken:     rawToken,
		SubscriptionPath:      cfg.PublicBasePath + "/sub/" + rawToken,
		CoreRevision:          syncOut.CoreRevision,
		ShapingDegraded:       syncOut.ShapingDegraded,
		ShapingDegradedReason: syncOut.ShapingDegradedReason,
	})
}

func (i *instance) handleUsersRotateSubscription(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in usersRotateSubscriptionRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if !validEntityIDPattern.MatchString(in.UserID) {
		return pluginsdk.Result{}, invalidField("/user_id", "INVALID_ID", "用户 ID 格式无效")
	}
	expectedRev := resolveRevision(in.ExpectedRevision, req, "users/"+in.UserID)
	token, nextRev, err := i.store.RotateSubscriptionToken(ctx, in.UserID, expectedRev)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	cfg := i.configSnapshot()
	return marshalResult(usersRotateSubscriptionResponse{
		UserID:            in.UserID,
		SubscriptionToken: token,
		SubscriptionPath:  cfg.PublicBasePath + "/sub/" + token,
		Revision:          nextRev,
	})
}

func (i *instance) handleUsersSetStatus(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in usersSetStatusRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if !validEntityIDPattern.MatchString(in.UserID) {
		return pluginsdk.Result{}, invalidField("/user_id", "INVALID_ID", "用户 ID 格式无效")
	}
	if !validUserStatus(in.Status) {
		return pluginsdk.Result{}, invalidField("/status", "INVALID_VALUE", "状态必须为 active、suspended_quota、expired 或 disabled")
	}
	expectedRev := resolveRevision(in.ExpectedRevision, req, "users/"+in.UserID)
	user, err := i.store.SetUserStatus(ctx, in.UserID, in.Status, expectedRev)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	syncOut, err := i.syncCoreAndTraffic(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(usersSetStatusResponse{
		User:                  user,
		CoreRevision:          syncOut.CoreRevision,
		ShapingDegraded:       syncOut.ShapingDegraded,
		ShapingDegradedReason: syncOut.ShapingDegradedReason,
	})
}

func (i *instance) handleUsersUsageHistory(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in usersUsageHistoryRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	if !validEntityIDPattern.MatchString(in.UserID) {
		return pluginsdk.Response{}, invalidField("/user_id", "INVALID_ID", "用户 ID 格式无效")
	}
	hours := in.Hours
	if hours == 0 {
		hours = 24
	}
	if hours < 1 || hours > 2160 {
		return pluginsdk.Response{}, invalidField("/hours", "OUT_OF_RANGE", "hours 必须在 1..2160 之间")
	}
	points, err := i.store.GetUsageHistory(ctx, in.UserID, hours)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return marshalResponse(usersUsageHistoryResponse{
		UserID: in.UserID,
		Hours:  hours,
		Points: points,
	})
}

func (i *instance) handleTrafficStatus(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in trafficStatusRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	includeClasses := true
	if in.IncludeClasses != nil {
		includeClasses = *in.IncludeClasses
	}
	host := req.Host()
	if host == nil || host.Conn() == nil {
		return pluginsdk.Response{}, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	resp, err := trafficv1.NewTrafficServiceClient(host.Conn()).GetShapingStatus(ctx, &trafficv1.GetShapingStatusRequest{Context: meta})
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Response{}, err
	}

	i.mu.Lock()
	i.shapingSupported = resp.GetSupported()
	i.shapingDegradedReason = resp.GetDegradedReason()
	i.mu.Unlock()

	classes := make([]trafficClassDTO, 0)
	if includeClasses {
		for _, c := range resp.GetClasses() {
			if c == nil {
				continue
			}
			classes = append(classes, trafficClassDTO{
				TrafficMark:   c.GetTrafficMark(),
				DownLimitKbps: c.GetDownLimitKbps(),
				UpLimitKbps:   c.GetUpLimitKbps(),
			})
		}
	}
	return marshalResponse(trafficStatusResponse{
		Supported:          resp.GetSupported(),
		UplinkIFBSupported: resp.GetUplinkIfbSupported(),
		DegradedReason:     resp.GetDegradedReason(),
		EgressInterface:    resp.GetEgressInterface(),
		Revision:           resp.GetRevision(),
		Classes:            classes,
	})
}

// ======================== 编解码、错误透传与校验辅助 ========================

func validUserStatus(s string) bool {
	switch s {
	case "active", "suspended_quota", "expired", "disabled":
		return true
	default:
		return false
	}
}

func resolveRevision(explicit string, req pluginsdk.Request, subject string) string {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return trimmed
	}
	if subject != "" {
		if pre, ok := req.Precondition(subject); ok && pre.Revision != "" {
			return pre.Revision
		}
	}
	if len(req.Preconditions) > 0 {
		return req.Preconditions[0].Revision
	}
	return ""
}

func protoError(detail *platformv1.ErrorDetail) error {
	if detail == nil || (detail.GetCode() == "" && detail.GetMessage() == "") {
		return nil
	}
	code := detail.GetCode()
	if code == "" {
		code = "INTERNAL"
	}
	violations := make([]pluginsdk.FieldViolation, 0, len(detail.GetViolations()))
	for _, v := range detail.GetViolations() {
		if v == nil {
			continue
		}
		violations = append(violations, pluginsdk.FieldViolation{
			Pointer: v.GetPointer(),
			Code:    v.GetCode(),
			Message: v.GetMessage(),
		})
	}
	return &pluginsdk.Error{
		Code:        code,
		Message:     detail.GetMessage(),
		Retryable:   detail.GetRetryable(),
		DetailsJSON: append([]byte(nil), detail.GetDetailsJson()...),
		Violations:  violations,
	}
}

func invalidField(pointer, code, message string) error {
	return pluginsdk.Validation(pluginsdk.FieldViolation{
		Pointer: pointer,
		Code:    code,
		Message: message,
	})
}

func decodeOptionalJSON(raw []byte, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	return decodeStrictJSON(trimmed, dst)
}

func decodeStrictJSON(raw []byte, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return invalidField("", "REQUIRED", "请求体不能为空")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalidField("", "INVALID_JSON", "请求参数 JSON 格式无效或包含未知字段")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return invalidField("", "INVALID_JSON", "请求参数包含多余内容")
	}
	return nil
}

func marshalResponse(v any) (pluginsdk.Response, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return pluginsdk.Response{}, fmt.Errorf("encode response: %w", err)
	}
	return pluginsdk.Response{Payload: raw}, nil
}

func marshalResult(v any) (pluginsdk.Result, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return pluginsdk.Result{}, fmt.Errorf("encode result: %w", err)
	}
	return pluginsdk.Result{Payload: raw}, nil
}
