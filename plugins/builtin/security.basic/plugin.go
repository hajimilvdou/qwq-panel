// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	accountv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/account/v1"
	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 内置清单嵌入与插件入口 ========================

//go:embed manifest.json
var manifestJSON []byte
var buildVersion string

// Manifest 返回内嵌的 security.basic 插件清单字节。
func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

// Plugin 实现节点级基础安全插件（防火墙、SSHD、密钥口令与轻量防爆破）。
type Plugin struct {
	now               func() time.Time
	banScanInterval   time.Duration
	sagaCheckInterval time.Duration
}

// New 构造默认配置的基础安全插件。
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
	inst := &instance{
		InstanceBase:         pluginsdk.NewInstanceBase(info),
		cfg:                  cfg,
		now:                  nowFn,
		banIntervalOverride:  p.banScanInterval,
		sagaIntervalOverride: p.sagaCheckInterval,
		failureBuckets:       make(map[string][]failureRecord),
	}
	inst.register()
	return inst, nil
}

// ======================== 配置解析与实例生命周期 ========================

const (
	defaultBanThreshold          = 5
	defaultBanWindowSeconds      = 600
	defaultBanTTLSeconds         = 3600
	defaultBanUnit               = "sshd.service"
	defaultBanScanInterval       = 30
	defaultPortSagaTimeout       = 600
	maxBanWindowSeconds          = 3600
	maxBanEntries                = 4096
	maxWhitelistEntries          = 128
	maxFailureBucketIPs          = 8192
	kvKeyBanCursor               = "ban/cursor"
	kvKeyOverviewCache           = "security/overview_cache"
	kvKeyPortSaga                = "sshd/port_saga"
	defaultSagaWatchPollInterval = 5 * time.Second
)

var validUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

type securityConfig struct {
	BanEnabled             bool
	BanThreshold           uint32
	BanWindowSeconds       uint32
	BanTTLSeconds          uint32
	BanUnit                string
	BanScanIntervalSeconds uint32
	BanWhitelist           []string
	WhitelistPrefixes      []netip.Prefix
	PortSagaTimeoutSeconds uint32
}

type rawSecurityConfig struct {
	BanEnabled             *bool    `json:"ban_enabled"`
	BanThreshold           *uint32  `json:"ban_threshold"`
	BanWindowSeconds       *uint32  `json:"ban_window_seconds"`
	BanTTLSeconds          *uint32  `json:"ban_ttl_seconds"`
	BanUnit                *string  `json:"ban_unit"`
	BanScanIntervalSeconds *uint32  `json:"ban_scan_interval_seconds"`
	BanWhitelist           []string `json:"ban_whitelist"`
	PortSagaTimeoutSeconds *uint32  `json:"port_saga_timeout_seconds"`
}

func defaultConfig() securityConfig {
	return securityConfig{
		BanEnabled:             true,
		BanThreshold:           defaultBanThreshold,
		BanWindowSeconds:       defaultBanWindowSeconds,
		BanTTLSeconds:          defaultBanTTLSeconds,
		BanUnit:                defaultBanUnit,
		BanScanIntervalSeconds: defaultBanScanInterval,
		BanWhitelist:           make([]string, 0),
		WhitelistPrefixes:      make([]netip.Prefix, 0),
		PortSagaTimeoutSeconds: defaultPortSagaTimeout,
	}
}

func parseConfig(raw []byte) (securityConfig, error) {
	cfg := defaultConfig()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return cfg, nil
	}
	var in rawSecurityConfig
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return securityConfig{}, pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "",
			Code:    "INVALID_CONFIG",
			Message: "基础安全插件配置格式无效",
		})
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return securityConfig{}, pluginsdk.Validation(pluginsdk.FieldViolation{
			Pointer: "",
			Code:    "INVALID_CONFIG",
			Message: "基础安全插件配置包含多余内容",
		})
	}
	if in.BanEnabled != nil {
		cfg.BanEnabled = *in.BanEnabled
	}
	if in.BanThreshold != nil {
		if *in.BanThreshold < 1 || *in.BanThreshold > 1000 {
			return securityConfig{}, invalidField("/ban_threshold", "OUT_OF_RANGE", "ban_threshold 必须在 1..1000 之间")
		}
		cfg.BanThreshold = *in.BanThreshold
	}
	if in.BanWindowSeconds != nil {
		if *in.BanWindowSeconds < 60 || *in.BanWindowSeconds > maxBanWindowSeconds {
			return securityConfig{}, invalidField("/ban_window_seconds", "OUT_OF_RANGE", "ban_window_seconds 必须在 60..3600 之间")
		}
		cfg.BanWindowSeconds = *in.BanWindowSeconds
	}
	if in.BanTTLSeconds != nil {
		if *in.BanTTLSeconds < 60 || *in.BanTTLSeconds > 604800 {
			return securityConfig{}, invalidField("/ban_ttl_seconds", "OUT_OF_RANGE", "ban_ttl_seconds 必须在 60..604800 之间")
		}
		cfg.BanTTLSeconds = *in.BanTTLSeconds
	}
	if in.BanUnit != nil {
		if *in.BanUnit != "ssh.service" && *in.BanUnit != "sshd.service" {
			return securityConfig{}, invalidField("/ban_unit", "INVALID_VALUE", "ban_unit 仅支持 ssh.service 或 sshd.service")
		}
		cfg.BanUnit = *in.BanUnit
	}
	if in.BanScanIntervalSeconds != nil {
		if *in.BanScanIntervalSeconds < 10 || *in.BanScanIntervalSeconds > 300 {
			return securityConfig{}, invalidField("/ban_scan_interval_seconds", "OUT_OF_RANGE", "ban_scan_interval_seconds 必须在 10..300 之间")
		}
		cfg.BanScanIntervalSeconds = *in.BanScanIntervalSeconds
	}
	if len(in.BanWhitelist) > maxWhitelistEntries {
		return securityConfig{}, invalidField("/ban_whitelist", "TOO_MANY", "ban_whitelist 最多包含 128 项")
	}
	if len(in.BanWhitelist) > 0 {
		cfg.BanWhitelist = make([]string, 0, len(in.BanWhitelist))
		cfg.WhitelistPrefixes = make([]netip.Prefix, 0, len(in.BanWhitelist))
		for idx, item := range in.BanWhitelist {
			prefix, norm, err := parseIPOrCIDR(item)
			if err != nil {
				return securityConfig{}, invalidField(fmt.Sprintf("/ban_whitelist/%d", idx), "INVALID_IP", "白名单项必须是合法 IP 或 CIDR")
			}
			cfg.BanWhitelist = append(cfg.BanWhitelist, norm)
			cfg.WhitelistPrefixes = append(cfg.WhitelistPrefixes, prefix)
		}
	}
	if in.PortSagaTimeoutSeconds != nil {
		if *in.PortSagaTimeoutSeconds < 30 || *in.PortSagaTimeoutSeconds > 3600 {
			return securityConfig{}, invalidField("/port_saga_timeout_seconds", "OUT_OF_RANGE", "port_saga_timeout_seconds 必须在 30..3600 之间")
		}
		cfg.PortSagaTimeoutSeconds = *in.PortSagaTimeoutSeconds
	}
	return cfg, nil
}

type failureRecord struct {
	OccurredAt int64
	Count      uint32
}

type overviewCache struct {
	ActiveBanCount   int       `json:"active_ban_count"`
	Fail2banObserver bool      `json:"fail2ban_observer"`
	PortSagaPending  bool      `json:"port_saga_pending"`
	ActiveConflicts  []string  `json:"active_conflicts"`
	Spark            []float64 `json:"spark"`
	UpdatedAt        string    `json:"updated_at"`
}

type instance struct {
	*pluginsdk.InstanceBase

	mu                   sync.RWMutex
	cfg                  securityConfig
	fail2banObserver     bool
	activeBanCount       int
	activeConflicts      []string
	spark                []float64
	lastBanError         string
	ingestedBanCursor    string
	failureBuckets       map[string][]failureRecord
	sagaMu               sync.Mutex
	now                  func() time.Time
	banIntervalOverride  time.Duration
	sagaIntervalOverride time.Duration
}

func (i *instance) nowTime() time.Time {
	if i.now != nil {
		return i.now()
	}
	return time.Now()
}

func (i *instance) configSnapshot() securityConfig {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cfg
}

func (i *instance) Activate(context.Context) error {
	if err := i.Go(i.banLoop); err != nil {
		return err
	}
	return i.Go(i.sagaWatchLoop)
}

func (i *instance) Deactivate(context.Context) error { return nil }

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
	observer := i.fail2banObserver
	bans := i.activeBanCount
	lastErr := i.lastBanError
	i.mu.RUnlock()
	if lastErr != "" {
		return pluginsdk.Health{Message: "防爆破巡检降级：" + lastErr}
	}
	if observer {
		return pluginsdk.Health{Message: "检测到 fail2ban 活跃，防爆破已切入只读旁观模式"}
	}
	return pluginsdk.Health{Message: fmt.Sprintf("基础安全就绪，当前活跃封禁 %d 项", bans)}
}

// ======================== 18 项 Operation 注册 ========================

func (i *instance) register() {
	// 读操作（invoke）
	i.HandleInvoke("security.overview", i.handleOverview)
	i.HandleInvoke("security.firewall.status", i.handleFirewallStatus)
	i.HandleInvoke("security.sshd.status", i.handleSSHDStatus)
	i.HandleInvoke("security.keys.list", i.handleKeysList)
	i.HandleInvoke("security.bans.list", i.handleBansList)
	i.HandleInvoke("security.conflicts.detect", i.handleConflictsDetect)

	// 写操作（job）
	i.HandleJob("security.firewall.apply", i.handleFirewallApply)
	i.HandleJob("security.firewall.reset", i.handleFirewallReset)
	i.HandleJob("security.sshd.change_port_prepare", i.handleSSHDChangePortPrepare)
	i.HandleJob("security.sshd.change_port_commit", i.handleSSHDChangePortCommit)
	i.HandleJob("security.sshd.change_port_rollback", i.handleSSHDChangePortRollback)
	i.HandleJob("security.sshd.set_login_policy", i.handleSSHDSetLoginPolicy)
	i.HandleJob("security.keys.import", i.handleKeysImport)
	i.HandleJob("security.keys.generate_fallback", i.handleKeysGenerateFallback)
	i.HandleJob("security.keys.remove", i.handleKeysRemove)
	i.HandleJob("security.account.set_password", i.handleAccountSetPassword)
	i.HandleJob("security.bans.add", i.handleBansAdd)
	i.HandleJob("security.bans.remove", i.handleBansRemove)
}

// ======================== 请求/响应 DTO ========================

type overviewResponse struct {
	Value            float64   `json:"value"`
	Unit             string    `json:"unit"`
	Percent          float64   `json:"percent"`
	Sub              string    `json:"sub"`
	Level            string    `json:"level"`
	Spark            []float64 `json:"spark"`
	ActiveBanCount   int       `json:"active_ban_count"`
	Fail2banObserver bool      `json:"fail2ban_observer"`
	PortSagaPending  bool      `json:"port_saga_pending"`
	ActiveConflicts  []string  `json:"active_conflicts"`
	UpdatedAt        string    `json:"updated_at"`
}

type firewallStatusResponse struct {
	Ruleset            json.RawMessage `json:"ruleset"`
	Revision           string          `json:"revision"`
	PreservedPorts     []uint32        `json:"preserved_ports"`
	PersistencePending bool            `json:"persistence_pending"`
}

type firewallApplyRequest struct {
	Ruleset          json.RawMessage `json:"ruleset"`
	PreservedPorts   []uint32        `json:"preserved_ports"`
	ExpectedRevision string          `json:"expected_revision"`
}

type revisionRequest struct {
	ExpectedRevision string `json:"expected_revision"`
}

type revisionResponse struct {
	Revision string `json:"revision"`
}

type managerDTO struct {
	Kind   string `json:"kind"`
	Active bool   `json:"active"`
	Detail string `json:"detail"`
}

type conflictsDetectResponse struct {
	Managers                  []managerDTO `json:"managers"`
	HasActiveFirewallConflict bool         `json:"has_active_firewall_conflict"`
	Fail2banActive            bool         `json:"fail2ban_active"`
}

type sshdStatusRequest struct {
	MatchUser    string `json:"match_user"`
	MatchAddress string `json:"match_address"`
}

type sshdSettingDTO struct {
	Key          string `json:"key"`
	Value        string `json:"value"`
	SourceFile   string `json:"source_file"`
	OverriddenBy string `json:"overridden_by"`
}

type sshdDropInDTO struct {
	Exists             bool   `json:"exists"`
	Revision           string `json:"revision"`
	Content            string `json:"content"`
	TransactionPending bool   `json:"transaction_pending"`
	TransactionRef     string `json:"transaction_ref,omitempty"`
	TransactionStage   string `json:"transaction_stage,omitempty"`
	TransactionPort    uint32 `json:"transaction_port,omitempty"`
	TransactionKind    string `json:"transaction_kind,omitempty"`
}

type portSagaPublicView struct {
	TransactionRef             string `json:"transaction_ref"`
	OldPort                    uint32 `json:"old_port"`
	NewPort                    uint32 `json:"new_port"`
	DeadlineUnix               int64  `json:"deadline_unix"`
	FirewallManaged            bool   `json:"firewall_managed"`
	ExternalConnectionDetected bool   `json:"external_connection_detected,omitempty"`
}

type sshdStatusResponse struct {
	Revision       string              `json:"revision"`
	ListeningPorts []uint32            `json:"listening_ports"`
	Settings       []sshdSettingDTO    `json:"settings"`
	DropIn         sshdDropInDTO       `json:"drop_in"`
	PortSaga       *portSagaPublicView `json:"port_saga"`
}

type sshdSetLoginPolicyRequest struct {
	PasswordAuth     *bool  `json:"password_auth"`
	PermitRootLogin  *bool  `json:"permit_root_login"`
	RootLoginMode    string `json:"root_login_mode"`
	RecoveryUser     string `json:"recovery_user"`
	ExpectedRevision string `json:"expected_revision"`
}

type sshdSetLoginPolicyResponse struct {
	Revision  string           `json:"revision"`
	Effective []sshdSettingDTO `json:"effective"`
}

type keysListRequest struct {
	User string `json:"user"`
}

type accountKeyDTO struct {
	Type              string `json:"type"`
	Bits              uint32 `json:"bits"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Comment           string `json:"comment"`
	LineIndex         uint32 `json:"line_index"`
}

type keysListResponse struct {
	User     string          `json:"user"`
	Revision string          `json:"revision"`
	Keys     []accountKeyDTO `json:"keys"`
}

type keysImportRequest struct {
	User             string `json:"user"`
	PublicKey        string `json:"public_key"`
	ExpectedRevision string `json:"expected_revision"`
}

type keysImportResponse struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Type              string `json:"type"`
	Bits              uint32 `json:"bits"`
	Comment           string `json:"comment"`
	Revision          string `json:"revision"`
}

type keysGenerateRequest struct {
	User             string `json:"user"`
	Type             string `json:"type"`
	ExpectedRevision string `json:"expected_revision"`
}

type keysGenerateResponse struct {
	PublicKey         string `json:"public_key"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	PrivateKeyPEM     string `json:"private_key_pem"`
	Revision          string `json:"revision"`
}

type keysRemoveRequest struct {
	User              string `json:"user"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	ExpectedRevision  string `json:"expected_revision"`
}

type accountSetPasswordRequest struct {
	User             string                `json:"user"`
	Password         pluginsdk.SecretField `json:"password"`
	SecretRef        pluginsdk.SecretField `json:"secret_ref"`
	ExpectedRevision string                `json:"expected_revision"`
}

func extractSecretRefField(f pluginsdk.SecretField) string {
	if ref := strings.TrimSpace(f.SecretRef); ref != "" {
		return ref
	}
	return strings.TrimSpace(f.Plain)
}

type activeBanDTO struct {
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at"`
}

type bansListResponse struct {
	Revision         string         `json:"revision"`
	Bans             []activeBanDTO `json:"bans"`
	Fail2banObserver bool           `json:"fail2ban_observer"`
	Cursor           string         `json:"cursor"`
}

type banEntryInput struct {
	IP         string `json:"ip"`
	TTLSeconds uint32 `json:"ttl_seconds"`
}

type bansAddRequest struct {
	IP               string          `json:"ip"`
	TTLSeconds       uint32          `json:"ttl_seconds"`
	Entries          []banEntryInput `json:"entries"`
	ExpectedRevision string          `json:"expected_revision"`
}

type bansAddResponse struct {
	Revision    string `json:"revision"`
	ActiveCount uint32 `json:"active_count"`
}

type bansRemoveRequest struct {
	IP               string `json:"ip"`
	ExpectedRevision string `json:"expected_revision"`
}

// ======================== 只读查询操作（invoke） ========================

// handleOverview 仅读取插件本地 KV 缓存与挂起事务，保障首页微件零高危调用且低开销。
func (i *instance) handleOverview(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	if err := decodeEmptyJSON(req.Payload); err != nil {
		return pluginsdk.Response{}, err
	}
	cache := overviewCache{
		ActiveConflicts: make([]string, 0),
		Spark:           make([]float64, 0),
	}
	if host := req.Host(); host != nil && host.Conn() != nil {
		if raw, _, found, err := host.GetState(ctx, kvKeyOverviewCache); err == nil && found && len(raw) > 0 {
			_ = json.Unmarshal(raw, &cache)
		}
		if _, _, found, err := host.GetState(ctx, kvKeyPortSaga); err == nil {
			cache.PortSagaPending = found
		}
	}
	if cache.ActiveConflicts == nil {
		cache.ActiveConflicts = make([]string, 0)
	}
	if cache.Spark == nil {
		cache.Spark = make([]float64, 0)
	}
	pct := float64(cache.ActiveBanCount) * 100.0 / float64(maxBanEntries)
	if pct > 100 {
		pct = 100
	}
	level := "ok"
	sub := fmt.Sprintf("轻量防爆破运行中，活跃封禁 %d 项", cache.ActiveBanCount)
	switch {
	case cache.PortSagaPending:
		level = "warn"
		sub = "存在待确认的 SSH 双端口切换事务"
	case cache.Fail2banObserver:
		level = "ok"
		sub = "检测到 fail2ban 活跃，防爆破处于只读旁观模式"
	case len(cache.ActiveConflicts) > 0:
		level = "warn"
		sub = "存在活跃外部管理器：" + strings.Join(cache.ActiveConflicts, ", ")
	case cache.UpdatedAt == "":
		level = "muted"
		sub = "等待首次安全巡检同步"
	}
	return marshalResponse(overviewResponse{
		Value:            float64(cache.ActiveBanCount),
		Unit:             "项封禁",
		Percent:          pct,
		Sub:              sub,
		Level:            level,
		Spark:            cache.Spark,
		ActiveBanCount:   cache.ActiveBanCount,
		Fail2banObserver: cache.Fail2banObserver,
		PortSagaPending:  cache.PortSagaPending,
		ActiveConflicts:  cache.ActiveConflicts,
		UpdatedAt:        cache.UpdatedAt,
	})
}

func (i *instance) handleFirewallStatus(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	if err := decodeEmptyJSON(req.Payload); err != nil {
		return pluginsdk.Response{}, err
	}
	client, meta, err := firewallClientReadOnly(ctx, req.Host())
	if err != nil {
		return pluginsdk.Response{}, err
	}
	resp, err := client.GetRuleset(ctx, &firewallv1.GetRulesetRequest{Context: meta})
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Response{}, err
	}
	ruleset := json.RawMessage(`{}`)
	if raw := bytes.TrimSpace(resp.GetRulesetJson()); len(raw) > 0 {
		if json.Valid(raw) {
			ruleset = json.RawMessage(append([]byte(nil), raw...))
		}
	}
	ports := make([]uint32, 0, len(resp.GetPreservedPorts()))
	ports = append(ports, resp.GetPreservedPorts()...)
	return marshalResponse(firewallStatusResponse{
		Ruleset:            ruleset,
		Revision:           resp.GetRevision(),
		PreservedPorts:     ports,
		PersistencePending: resp.GetPersistencePending(),
	})
}

func (i *instance) handleConflictsDetect(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	if err := decodeEmptyJSON(req.Payload); err != nil {
		return pluginsdk.Response{}, err
	}
	client, meta, err := firewallClientReadOnly(ctx, req.Host())
	if err != nil {
		return pluginsdk.Response{}, err
	}
	resp, err := client.DetectManagers(ctx, &firewallv1.DetectManagersRequest{Context: meta})
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Response{}, err
	}
	managers := make([]managerDTO, 0, len(resp.GetManagers()))
	hasConflict := false
	fail2banActive := false
	for _, m := range resp.GetManagers() {
		if m == nil {
			continue
		}
		dto := managerDTO{Kind: m.GetKind(), Active: m.GetActive(), Detail: m.GetDetail()}
		managers = append(managers, dto)
		if !dto.Active {
			continue
		}
		if strings.EqualFold(dto.Kind, "fail2ban") {
			fail2banActive = true
		} else {
			hasConflict = true
		}
	}
	return marshalResponse(conflictsDetectResponse{
		Managers:                  managers,
		HasActiveFirewallConflict: hasConflict,
		Fail2banActive:            fail2banActive,
	})
}

func (i *instance) handleSSHDStatus(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in sshdStatusRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	client, meta, err := sshdClientReadOnly(ctx, req.Host())
	if err != nil {
		return pluginsdk.Response{}, err
	}
	effResp, err := client.GetEffectiveConfig(ctx, &sshdv1.GetEffectiveConfigRequest{
		Context:      meta,
		MatchUser:    strings.TrimSpace(in.MatchUser),
		MatchAddress: strings.TrimSpace(in.MatchAddress),
	})
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if err := protoError(effResp.GetError()); err != nil {
		return pluginsdk.Response{}, err
	}
	dropResp, err := client.GetDropIn(ctx, &sshdv1.GetDropInRequest{Context: meta})
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if err := protoError(dropResp.GetError()); err != nil {
		return pluginsdk.Response{}, err
	}
	var sagaView *portSagaPublicView
	if saga, found, err := i.loadPortSaga(ctx, req.Host()); err == nil && found {
		extConn := false
		if saga.NewPort >= 1 && saga.NewPort <= 65535 {
			if vr, vErr := client.VerifyPort(ctx, &sshdv1.VerifyPortRequest{
				Context: meta,
				Port:    saga.NewPort,
			}); vErr == nil && vr.GetError() == nil {
				extConn = vr.GetHasExternalConnection()
			}
		}
		sagaView = &portSagaPublicView{
			TransactionRef:             saga.TransactionRef,
			OldPort:                    saga.OldPort,
			NewPort:                    saga.NewPort,
			DeadlineUnix:               saga.DeadlineUnix,
			FirewallManaged:            saga.FirewallManaged,
			ExternalConnectionDetected: extConn,
		}
	}
	return marshalResponse(sshdStatusResponse{
		Revision:       effResp.GetRevision(),
		ListeningPorts: extractListeningPorts(effResp.GetSettings()),
		Settings:       toSSHDSettings(effResp.GetSettings()),
		DropIn: sshdDropInDTO{
			Exists:             dropResp.GetExists(),
			Revision:           dropResp.GetRevision(),
			Content:            dropResp.GetContent(),
			TransactionPending: dropResp.GetTransactionPending(),
			TransactionRef:     dropResp.GetTransactionRef(),
			TransactionStage:   dropResp.GetTransactionStage(),
			TransactionPort:    dropResp.GetTransactionPort(),
			TransactionKind:    dropResp.GetTransactionKind(),
		},
		PortSaga: sagaView,
	})
}

func (i *instance) handleKeysList(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in keysListRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Response{}, err
	}
	if err := validateUser(in.User); err != nil {
		return pluginsdk.Response{}, err
	}
	client, meta, err := accountClientReadOnly(ctx, req.Host())
	if err != nil {
		return pluginsdk.Response{}, err
	}
	resp, err := client.ListKeys(ctx, &accountv1.ListKeysRequest{Context: meta, User: in.User})
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Response{}, err
	}
	keys := make([]accountKeyDTO, 0, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		if k == nil {
			continue
		}
		keys = append(keys, accountKeyDTO{
			Type:              k.GetType(),
			Bits:              k.GetBits(),
			FingerprintSHA256: k.GetFingerprintSha256(),
			Comment:           k.GetComment(),
			LineIndex:         k.GetLineIndex(),
		})
	}
	return marshalResponse(keysListResponse{
		User:     in.User,
		Revision: resp.GetRevision(),
		Keys:     keys,
	})
}

func (i *instance) handleBansList(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	if err := decodeEmptyJSON(req.Payload); err != nil {
		return pluginsdk.Response{}, err
	}
	client, meta, err := banClientReadOnly(ctx, req.Host())
	if err != nil {
		return pluginsdk.Response{}, err
	}
	resp, err := client.ListBans(ctx, &banv1.ListBansRequest{Context: meta})
	if err != nil {
		return pluginsdk.Response{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Response{}, err
	}
	bans := make([]activeBanDTO, 0, len(resp.GetBans()))
	for _, b := range resp.GetBans() {
		if b == nil {
			continue
		}
		bans = append(bans, activeBanDTO{IP: b.GetIp(), ExpiresAt: b.GetExpiresAt()})
	}
	i.mu.RLock()
	observer := i.fail2banObserver
	i.mu.RUnlock()
	cursor := ""
	if host := req.Host(); host != nil && host.Conn() != nil {
		if raw, _, found, err := host.GetState(ctx, kvKeyOverviewCache); err == nil && found && len(raw) > 0 {
			var cache overviewCache
			if json.Unmarshal(raw, &cache) == nil {
				observer = cache.Fail2banObserver
			}
		}
		if raw, _, found, err := host.GetState(ctx, kvKeyBanCursor); err == nil && found && len(raw) > 0 {
			var cur banCursorState
			if json.Unmarshal(raw, &cur) == nil {
				cursor = cur.Cursor
			}
		}
	}
	return marshalResponse(bansListResponse{
		Revision:         resp.GetRevision(),
		Bans:             bans,
		Fail2banObserver: observer,
		Cursor:           cursor,
	})
}

// ======================== 防火墙、SSHD、账号与封禁写操作（job） ========================

func (i *instance) handleFirewallApply(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in firewallApplyRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	ruleset := bytes.TrimSpace(in.Ruleset)
	if len(ruleset) == 0 || !json.Valid(ruleset) {
		return pluginsdk.Result{}, invalidField("/ruleset", "REQUIRED", "ruleset 必须是合法的 nftables JSON 对象")
	}
	preserved := append([]uint32(nil), in.PreservedPorts...)
	if len(preserved) == 0 {
		readClient, readMeta, err := firewallClientReadOnly(ctx, req.Host())
		if err != nil {
			return pluginsdk.Result{}, err
		}
		cur, err := readClient.GetRuleset(ctx, &firewallv1.GetRulesetRequest{Context: readMeta})
		if err != nil {
			return pluginsdk.Result{}, err
		}
		if err := protoError(cur.GetError()); err != nil {
			return pluginsdk.Result{}, err
		}
		preserved = append(preserved, cur.GetPreservedPorts()...)
	}
	client, meta, err := firewallClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ApplyRuleset(ctx, &firewallv1.ApplyRulesetRequest{
		Context:          meta,
		RulesetJson:      ruleset,
		ExpectedRevision: resolveRevision(in.ExpectedRevision, req, "firewall/ruleset"),
		PreservedPorts:   preserved,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(revisionResponse{Revision: resp.GetRevision()})
}

func (i *instance) handleFirewallReset(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in revisionRequest
	if err := decodeOptionalJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := firewallClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ResetRuleset(ctx, &firewallv1.ResetRulesetRequest{
		Context:          meta,
		ExpectedRevision: resolveRevision(in.ExpectedRevision, req, "firewall/ruleset"),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(revisionResponse{Revision: resp.GetRevision()})
}

func (i *instance) handleSSHDSetLoginPolicy(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in sshdSetLoginPolicyRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if in.PermitRootLogin != nil && in.RootLoginMode != "" {
		return pluginsdk.Result{}, invalidField("/root_login_mode", "CONFLICT", "permit_root_login 与 root_login_mode 不可同时设置")
	}
	if in.PasswordAuth == nil && in.PermitRootLogin == nil && in.RootLoginMode == "" {
		return pluginsdk.Result{}, invalidField("", "REQUIRED", "至少需指定 password_auth、permit_root_login 或 root_login_mode 之一")
	}
	if in.RecoveryUser != "" {
		if err := validateUser(in.RecoveryUser); err != nil {
			return pluginsdk.Result{}, invalidField("/recovery_user", "INVALID_USER", "recovery_user 格式无效")
		}
	}
	mode, err := parseRootLoginMode(in.RootLoginMode)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	client, meta, err := sshdClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.SetLoginPolicy(ctx, &sshdv1.SetLoginPolicyRequest{
		Context:          meta,
		PasswordAuth:     in.PasswordAuth,
		PermitRootLogin:  in.PermitRootLogin,
		ExpectedRevision: resolveRevision(in.ExpectedRevision, req, "sshd/config"),
		RecoveryUser:     in.RecoveryUser,
		RootLoginMode:    mode,
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(sshdSetLoginPolicyResponse{
		Revision:  resp.GetRevision(),
		Effective: toSSHDSettings(resp.GetEffective()),
	})
}

func (i *instance) handleKeysImport(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in keysImportRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := validateUser(in.User); err != nil {
		return pluginsdk.Result{}, err
	}
	pub := strings.TrimSpace(in.PublicKey)
	if pub == "" || strings.ContainsAny(pub, "\r\n") {
		return pluginsdk.Result{}, invalidField("/public_key", "INVALID_VALUE", "public_key 必须是非空单行公钥")
	}
	client, meta, err := accountClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ImportKey(ctx, &accountv1.ImportKeyRequest{
		Context:          meta,
		User:             in.User,
		PublicKey:        pub,
		ExpectedRevision: resolveRevision(in.ExpectedRevision, req, "account/"+in.User+"/keys"),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(keysImportResponse{
		FingerprintSHA256: resp.GetFingerprintSha256(),
		Type:              resp.GetType(),
		Bits:              resp.GetBits(),
		Comment:           resp.GetComment(),
		Revision:          resp.GetRevision(),
	})
}

func (i *instance) handleKeysGenerateFallback(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in keysGenerateRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := validateUser(in.User); err != nil {
		return pluginsdk.Result{}, err
	}
	keyType := strings.TrimSpace(in.Type)
	if keyType == "" {
		keyType = "ed25519"
	}
	if keyType != "ed25519" && keyType != "rsa" {
		return pluginsdk.Result{}, invalidField("/type", "INVALID_VALUE", "密钥类型仅支持 ed25519 或 rsa")
	}
	client, meta, err := accountClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.GenerateKey(ctx, &accountv1.GenerateKeyRequest{
		Context:          meta,
		User:             in.User,
		Type:             keyType,
		ExpectedRevision: resolveRevision(in.ExpectedRevision, req, "account/"+in.User+"/keys"),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	// 私钥仅一次性返回，立即擦除底层切片，绝不写入日志或状态存储。
	rawPriv := resp.GetPrivateKeyPem()
	defer clear(rawPriv)
	return marshalResult(keysGenerateResponse{
		PublicKey:         resp.GetPublicKey(),
		FingerprintSHA256: resp.GetFingerprintSha256(),
		PrivateKeyPEM:     string(rawPriv),
		Revision:          resp.GetRevision(),
	})
}

func (i *instance) handleKeysRemove(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in keysRemoveRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := validateUser(in.User); err != nil {
		return pluginsdk.Result{}, err
	}
	fp := strings.TrimSpace(in.FingerprintSHA256)
	if fp == "" {
		return pluginsdk.Result{}, invalidField("/fingerprint_sha256", "REQUIRED", "缺少待移除公钥指纹")
	}
	client, meta, err := accountClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RemoveKey(ctx, &accountv1.RemoveKeyRequest{
		Context:           meta,
		User:              in.User,
		FingerprintSha256: fp,
		ExpectedRevision:  resolveRevision(in.ExpectedRevision, req, "account/"+in.User+"/keys"),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(revisionResponse{Revision: resp.GetRevision()})
}

func (i *instance) handleAccountSetPassword(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in accountSetPasswordRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	if err := validateUser(in.User); err != nil {
		return pluginsdk.Result{}, err
	}
	// 优先读取显式 secret_ref；若调用方填写的是 x-secret password，宿主 OperationProtector 已将其封存为 {"$secret":"..."} 引用信封。
	secretRef := extractSecretRefField(in.SecretRef)
	if secretRef == "" {
		secretRef = extractSecretRefField(in.Password)
	}
	if secretRef == "" {
		return pluginsdk.Result{}, invalidField("/password", "REQUIRED", "必须提供由宿主注入的口令密文引用")
	}
	client, meta, err := accountClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.SetPassword(ctx, &accountv1.SetPasswordRequest{
		Context:          meta,
		User:             in.User,
		SecretRef:        secretRef,
		ExpectedRevision: resolveRevision(in.ExpectedRevision, req, "account/"+in.User+"/password"),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	return marshalResult(revisionResponse{Revision: resp.GetRevision()})
}

func (i *instance) handleBansAdd(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in bansAddRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	cfg := i.configSnapshot()
	defaultTTL := cfg.BanTTLSeconds
	entries := make([]*banv1.BanEntry, 0, len(in.Entries)+1)
	if len(in.Entries) > 0 {
		for idx, item := range in.Entries {
			addr, err := parseStrictIP(item.IP)
			if err != nil {
				return pluginsdk.Result{}, invalidField(fmt.Sprintf("/entries/%d/ip", idx), "INVALID_IP", "封禁 IP 地址无效")
			}
			ttl := item.TTLSeconds
			if ttl == 0 {
				ttl = defaultTTL
			}
			entries = append(entries, &banv1.BanEntry{Ip: addr.String(), TtlSeconds: ttl})
		}
	} else if strings.TrimSpace(in.IP) != "" {
		addr, err := parseStrictIP(in.IP)
		if err != nil {
			return pluginsdk.Result{}, invalidField("/ip", "INVALID_IP", "封禁 IP 地址无效")
		}
		ttl := in.TTLSeconds
		if ttl == 0 {
			ttl = defaultTTL
		}
		entries = append(entries, &banv1.BanEntry{Ip: addr.String(), TtlSeconds: ttl})
	} else {
		return pluginsdk.Result{}, invalidField("/ip", "REQUIRED", "必须提供待封禁 IP 或 entries 列表")
	}
	client, meta, err := banClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.ApplyBans(ctx, &banv1.ApplyBansRequest{
		Context:          meta,
		Entries:          entries,
		ExpectedRevision: resolveRevision(in.ExpectedRevision, req, "ban/set"),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	i.recordActiveBanCount(ctx, req.Host(), int(resp.GetActiveCount()))
	return marshalResult(bansAddResponse{
		Revision:    resp.GetRevision(),
		ActiveCount: resp.GetActiveCount(),
	})
}

func (i *instance) handleBansRemove(ctx context.Context, req pluginsdk.Request, _ pluginsdk.Progress) (pluginsdk.Result, error) {
	var in bansRemoveRequest
	if err := decodeStrictJSON(req.Payload, &in); err != nil {
		return pluginsdk.Result{}, err
	}
	addr, err := parseStrictIP(in.IP)
	if err != nil {
		return pluginsdk.Result{}, invalidField("/ip", "INVALID_IP", "待解封 IP 地址无效")
	}
	// 先检查该 IP 是否确实存在于活跃封禁集合，避免对不存在条目重复递减 activeBanCount。
	var (
		checkedBefore bool
		wasPresent    bool
		beforeCount   int
	)
	if banRead, banReadMeta, rErr := banClientReadOnly(ctx, req.Host()); rErr == nil {
		if listResp, lErr := banRead.ListBans(ctx, &banv1.ListBansRequest{Context: banReadMeta}); lErr == nil && listResp.GetError() == nil {
			checkedBefore = true
			beforeCount = len(listResp.GetBans())
			for _, b := range listResp.GetBans() {
				if b != nil && b.GetIp() == addr.String() {
					wasPresent = true
					break
				}
			}
		}
	}

	client, meta, err := banClientWrite(ctx, req.Host())
	if err != nil {
		return pluginsdk.Result{}, err
	}
	resp, err := client.RemoveBan(ctx, &banv1.RemoveBanRequest{
		Context:          meta,
		Ip:               addr.String(),
		ExpectedRevision: resolveRevision(in.ExpectedRevision, req, "ban/set"),
	})
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if err := protoError(resp.GetError()); err != nil {
		return pluginsdk.Result{}, err
	}
	i.mu.Lock()
	if checkedBefore {
		if wasPresent && beforeCount > 0 {
			i.activeBanCount = beforeCount - 1
		} else {
			i.activeBanCount = beforeCount
		}
	}
	nextCount := i.activeBanCount
	i.mu.Unlock()
	i.recordActiveBanCount(ctx, req.Host(), nextCount)
	return marshalResult(revisionResponse{Revision: resp.GetRevision()})
}

// ======================== 宿主客户端、参数校验与错误映射辅助 ========================

func firewallClientReadOnly(ctx context.Context, host *pluginsdk.Host) (firewallv1.FirewallServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return nil, nil, err
	}
	return firewallv1.NewFirewallServiceClient(host.Conn()), meta, nil
}

func firewallClientWrite(ctx context.Context, host *pluginsdk.Host) (firewallv1.FirewallServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return firewallv1.NewFirewallServiceClient(host.Conn()), meta, nil
}

func firewallClientWriteAutonomous(ctx context.Context, host *pluginsdk.Host, reason string) (firewallv1.FirewallServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextAutonomous(ctx, reason)
	if err != nil {
		return nil, nil, err
	}
	return firewallv1.NewFirewallServiceClient(host.Conn()), meta, nil
}

func sshdClientReadOnly(ctx context.Context, host *pluginsdk.Host) (sshdv1.SshdServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return nil, nil, err
	}
	return sshdv1.NewSshdServiceClient(host.Conn()), meta, nil
}

func sshdClientWrite(ctx context.Context, host *pluginsdk.Host) (sshdv1.SshdServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return sshdv1.NewSshdServiceClient(host.Conn()), meta, nil
}

func sshdClientWriteAutonomous(ctx context.Context, host *pluginsdk.Host, reason string) (sshdv1.SshdServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextAutonomous(ctx, reason)
	if err != nil {
		return nil, nil, err
	}
	return sshdv1.NewSshdServiceClient(host.Conn()), meta, nil
}

func accountClientReadOnly(ctx context.Context, host *pluginsdk.Host) (accountv1.AccountServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return nil, nil, err
	}
	return accountv1.NewAccountServiceClient(host.Conn()), meta, nil
}

func accountClientWrite(ctx context.Context, host *pluginsdk.Host) (accountv1.AccountServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return accountv1.NewAccountServiceClient(host.Conn()), meta, nil
}

func banClientReadOnly(ctx context.Context, host *pluginsdk.Host) (banv1.BanServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return nil, nil, err
	}
	return banv1.NewBanServiceClient(host.Conn()), meta, nil
}

func banClientWrite(ctx context.Context, host *pluginsdk.Host) (banv1.BanServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return banv1.NewBanServiceClient(host.Conn()), meta, nil
}

func banClientWriteAutonomous(ctx context.Context, host *pluginsdk.Host, reason string) (banv1.BanServiceClient, *platformv1.HostCallContext, error) {
	if host == nil || host.Conn() == nil {
		return nil, nil, pluginsdk.ErrNoHost
	}
	meta, err := host.CapabilityContextAutonomous(ctx, reason)
	if err != nil {
		return nil, nil, err
	}
	return banv1.NewBanServiceClient(host.Conn()), meta, nil
}

type securityAlertPayload struct {
	Source    string            `json:"source"`
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	DedupKey  string            `json:"dedup_key,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

func (i *instance) publishSecurityAlert(ctx context.Context, host *pluginsdk.Host, severity, subject, title, message, dedupKey string, tags map[string]string) {
	if host == nil || host.Conn() == nil {
		return
	}
	raw, err := json.Marshal(securityAlertPayload{
		Source:    "security.basic",
		Severity:  severity,
		Title:     title,
		Message:   message,
		DedupKey:  dedupKey,
		Tags:      tags,
		Timestamp: i.nowTime().UTC(),
	})
	if err != nil {
		return
	}
	if _, err := host.PublishEvent(ctx, pluginsdk.EventDraft{
		Type:          "security.alert",
		SchemaVersion: "1",
		Subject:       subject,
		Payload:       raw,
	}); err != nil {
		i.Logger().Warn("发布 security.alert 告警事件失败", "subject", subject, "error", err.Error())
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

func validateUser(user string) error {
	if !validUserPattern.MatchString(user) {
		return invalidField("/user", "INVALID_USER", "系统用户名格式无效")
	}
	return nil
}

func parseStrictIP(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid ip")
	}
	return addr.Unmap(), nil
}

func parseIPOrCIDR(raw string) (netip.Prefix, string, error) {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" {
			return netip.Prefix{}, "", fmt.Errorf("invalid cidr")
		}
		masked := p.Masked()
		return masked, masked.String(), nil
	}
	addr, err := parseStrictIP(s)
	if err != nil {
		return netip.Prefix{}, "", err
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	return prefix, addr.String(), nil
}

func parseRootLoginMode(raw string) (sshdv1.RootLoginMode, error) {
	switch strings.TrimSpace(raw) {
	case "":
		return sshdv1.RootLoginMode_ROOT_LOGIN_MODE_UNSPECIFIED, nil
	case "allow":
		return sshdv1.RootLoginMode_ROOT_LOGIN_MODE_ALLOW, nil
	case "deny":
		return sshdv1.RootLoginMode_ROOT_LOGIN_MODE_DENY, nil
	case "keys_only":
		return sshdv1.RootLoginMode_ROOT_LOGIN_MODE_KEYS_ONLY, nil
	default:
		return sshdv1.RootLoginMode_ROOT_LOGIN_MODE_UNSPECIFIED, invalidField("/root_login_mode", "INVALID_VALUE", "root_login_mode 仅支持 allow、deny 或 keys_only")
	}
}

func toSSHDSettings(in []*sshdv1.Setting) []sshdSettingDTO {
	out := make([]sshdSettingDTO, 0, len(in))
	for _, s := range in {
		if s == nil {
			continue
		}
		out = append(out, sshdSettingDTO{
			Key:          s.GetKey(),
			Value:        s.GetValue(),
			SourceFile:   s.GetSourceFile(),
			OverriddenBy: s.GetOverriddenBy(),
		})
	}
	return out
}

func decodeEmptyJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	var empty struct{}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&empty); err != nil {
		return invalidField("", "INVALID_JSON", "请求体必须是空 JSON 对象")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return invalidField("", "INVALID_JSON", "请求体包含多余内容")
	}
	return nil
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
