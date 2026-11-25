// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
	"github.com/qwq-panel/qwq/internal/xraycore/anytls"
	"github.com/qwq-panel/qwq/internal/xraycore/coreproc"
	"github.com/qwq-panel/qwq/internal/xraycore/metrics"
	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/internal/xraycore/xraybin"
	"github.com/qwq-panel/qwq/internal/xraycore/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// embeddedSyntheticSecretRef 仅用于满足 corev2.Validate 的结构引用检查；真实密钥由本进程从 proxy.db 解密到短期 V2Materials 内存缓冲并立即清零。
const embeddedSyntheticSecretRef = "sec_00000000000000000000000000"

type embeddedXrayStatus struct {
	State          string `json:"state"`
	CoreVersion    string `json:"core_version"`
	BinaryTrusted  bool   `json:"binary_trusted"`
	ProcessState   string `json:"process_state"`
	APIState       string `json:"api_state"`
	ProxyAvailable bool   `json:"proxy_available"`
	ActiveProfiles int    `json:"active_profiles"`
	ObfsAvailable  bool   `json:"obfs_available"`
	AnyTLSActive   bool   `json:"anytls_active"`
	ResetEpoch     string `json:"reset_epoch,omitempty"`
	Revision       string `json:"revision,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

type embeddedTLSStatus struct {
	Running         bool   `json:"running"`
	BindingRef      string `json:"binding_ref"`
	ProfileID       string `json:"-"`
	PublicTrusted   bool   `json:"-"`
	Generation      uint64 `json:"generation"`
	PolicyRevision  string `json:"policy_revision"`
	FullchainSHA256 string `json:"fullchain_sha256"`
	LeafFingerprint string `json:"leaf_fingerprint"`
	SNI             string `json:"sni"`
	Endpoint        string `json:"endpoint"`
}

// embeddedXrayEngine 把原 core.xray 代理数据面与 AnyTLS 监管器深度合并到 proxy.advanced 进程内，
// 消除跨插件 RPC 与重复安装门槛，做到单插件即装即用。
type embeddedXrayEngine struct {
	mu            sync.Mutex
	dataDir       string
	xrayDir       string
	socket        string
	store         *state.Store
	binary        *xraybin.Binary
	trusted       bool
	coreVersion   string
	process       *coreproc.Manager
	obfs          *coreproc.ObfsSupervisor
	anytls        *anytls.Supervisor
	anytlsAligner *anytls.LosslessEpochAligner

	active         bool
	lifetime       context.Context
	lifetimeCancel context.CancelFunc
	revSeq         int64
	lastDigest     string
	lastSummary    *state.V2IntentSummary
	lastError      string
	activeProfiles int
	obfsPlans      []xrayconfig.ObfsPlan
	anytlsSpecs    []anytls.ProfileSpec
	tlsBindings    map[string]embeddedTLSStatus
}

func locateOptionalProxyObfsBinary() *coreproc.ObfsSupervisor {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	candidate := filepath.Join(filepath.Dir(exe), "obfs-server")
	if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
		return coreproc.NewObfsSupervisor(candidate, "")
	}
	return nil
}

func newEmbeddedXrayEngine(dataDir string, track func(func(context.Context)) error) *embeddedXrayEngine {
	if strings.TrimSpace(dataDir) == "" || track == nil {
		return nil
	}
	binary, err := xraybin.Locate()
	trusted := err == nil && binary != nil
	xrayDir := filepath.Join(dataDir, "xray")
	socket := filepath.Join(xrayDir, "runtime", "api.sock")
	e := &embeddedXrayEngine{
		dataDir:       dataDir,
		xrayDir:       xrayDir,
		socket:        socket,
		store:         state.NewStore(xrayDir),
		binary:        binary,
		trusted:       trusted,
		obfs:          locateOptionalProxyObfsBinary(),
		anytls:        anytls.NewSupervisor(),
		anytlsAligner: anytls.NewLosslessEpochAligner(),
		tlsBindings:   make(map[string]embeddedTLSStatus),
	}
	if trusted {
		e.coreVersion = state.CoreVersion
	}
	proc, perr := coreproc.New(coreproc.Options{
		Socket: socket,
		Command: func(ctx context.Context, configPath string) (*exec.Cmd, error) {
			if e.binary == nil || !e.trusted {
				return nil, xraybin.ErrBinary
			}
			return e.binary.Command(ctx, configPath, false)
		},
		Track: track,
	})
	if perr == nil {
		e.process = proc
	}
	return e
}

func (e *embeddedXrayEngine) Available() bool {
	return e != nil && e.trusted && e.binary != nil && e.process != nil
}

func (e *embeddedXrayEngine) ObfsAvailable() bool {
	return e != nil && e.obfs != nil
}

func (e *embeddedXrayEngine) Activate(ctx context.Context) error {
	if !e.Available() {
		return nil
	}
	if err := os.MkdirAll(e.xrayDir, 0o700); err != nil {
		return err
	}
	e.mu.Lock()
	if e.lifetimeCancel != nil {
		e.lifetimeCancel()
	}
	e.lifetime, e.lifetimeCancel = context.WithCancel(context.Background())
	e.active = true
	e.mu.Unlock()
	return nil
}

func (e *embeddedXrayEngine) Shutdown(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	e.active = false
	cancel := e.lifetimeCancel
	e.lifetimeCancel = nil
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if e.anytls != nil {
		e.anytls.StopAll(3 * time.Second)
	}
	if e.obfs != nil {
		e.obfs.StopAll(3 * time.Second)
	}
	if e.process != nil {
		return e.process.Stop(ctx)
	}
	return nil
}

// Sync 直接基于 proxy.db 中的托管节点、多用户凭据与 WARP 配置，在进程内完成 Xray v26.11.9 + AnyTLS 原生渲染、预检、原子切换与回滚。
func (e *embeddedXrayEngine) Sync(
	ctx context.Context,
	managedNodes []proxyNodeRecord,
	activeUsers []userRecord,
	warpCfg *warpWithSecrets,
) (bool, string, string, error) {
	if !e.Available() {
		return false, "", "内置 Xray 核心二进制未就绪", errors.New("embedded xray binary unavailable")
	}
	if err := os.MkdirAll(e.xrayDir, 0o700); err != nil {
		return false, "", "无法创建 Xray 运行目录", err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.active {
		if e.lifetime == nil {
			e.lifetime, e.lifetimeCancel = context.WithCancel(context.Background())
		}
		e.active = true
	}

	intent, materials, loadedTLS, skippedTLS, activeProfileCount, err := e.buildDirectIntentAndMaterials(ctx, managedNodes, activeUsers, warpCfg)
	if err != nil {
		e.lastError = err.Error()
		return false, "", "构建代理核心配置失败：" + err.Error(), err
	}
	defer materials.Clear()

	if intent == nil || len(intent.Profiles) == 0 || !*intent.Enabled || activeProfileCount == 0 {
		if e.anytls != nil {
			e.anytls.StopAll(3 * time.Second)
		}
		if e.obfs != nil {
			e.obfs.StopAll(3 * time.Second)
		}
		if e.process != nil {
			_ = e.process.Stop(ctx)
		}
		e.lastDigest = ""
		e.lastSummary = nil
		e.activeProfiles = 0
		e.lastError = ""
		e.revSeq++
		rev := fmt.Sprintf("embedded-r%d", e.revSeq)
		note := "当前无已启用的托管入站节点，内置 Xray 核心处于待命状态"
		if skippedTLS > 0 {
			note = fmt.Sprintf("另有 %d 个 TLS 节点尚未绑定宿主证书 binding_ref，绑定证书后将自动启动", skippedTLS)
		}
		return true, rev, note, nil
	}

	v2Opts := xrayconfig.V2Options{
		Options:        xrayconfig.Options{APISocket: e.socket},
		Now:            time.Now().UTC(),
		ObfsTargets:    xrayconfig.AllocateObfsTargets(intent),
		SkipSocketMark: !probeProxySocketMarkPermitted(),
	}
	obfsPlans, err := xrayconfig.PlanObfs(intent, v2Opts)
	if err != nil {
		e.lastError = "OBFS_PLAN_INVALID"
		return false, "", "规划 SS2022 混淆端口失败", err
	}
	if len(obfsPlans) > 0 && e.obfs == nil {
		e.lastError = "OBFS_UNAVAILABLE"
		return false, "", "当前未附带 obfs-server，无法开启 SS2022 混淆模式", errors.New("obfs unavailable")
	}

	anytlsSpecs := buildEmbeddedAnyTLSSpecs(intent, materials)
	native, err := xrayconfig.RenderV2(intent, materials, v2Opts)
	if err != nil {
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		e.lastError = "CORE_CONFIG_INVALID"
		return false, "", "渲染 Xray 原生配置失败：" + err.Error(), err
	}
	defer clear(native)

	summaryV2, err := state.SummarizeV2(intent)
	if err != nil {
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		e.lastError = "INVALID_INTENT"
		return false, "", "生成配置摘要失败", err
	}

	e.revSeq++
	rev := fmt.Sprintf("embedded-r%d", e.revSeq)
	workID := fmt.Sprintf("sync-%d", e.revSeq)
	work, err := e.store.Stage(ctx, workID, 1, native)
	if err != nil {
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		e.lastError = "STATE_STAGE_FAILED"
		return false, "", "写入 Xray 候选配置失败", err
	}
	defer func() { _ = e.store.CleanWork(context.WithoutCancel(ctx), workID, 1) }()

	// 若新配置摘要与当前健康运行进程完全一致，零中断幂等返回。
	observed := e.process.Snapshot(ctx)
	if e.lastDigest == work.Digest && observed.State == "RUNNING" && observed.APIState == "READY" && observed.Digest == work.Digest {
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		e.lastSummary = summaryV2
		e.activeProfiles = activeProfileCount
		e.lastError = ""
		return true, rev, skippedTLSNote(skippedTLS), nil
	}

	if err := e.binary.Preflight(ctx, work.Path); err != nil {
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		e.lastError = "CORE_CONFIG_INVALID"
		return false, "", "Xray 原生配置预检未通过，请检查节点参数或端口设置", err
	}
	if err := e.store.Install(ctx, work); err != nil {
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		e.lastError = "STATE_INSTALL_FAILED"
		return false, "", "安装 Xray 配置代次失败", err
	}

	oldMeta, _ := e.store.Committed(ctx)
	oldObfs := append([]xrayconfig.ObfsPlan(nil), e.obfsPlans...)
	oldAnyTLS := cloneEmbeddedAnyTLSSpecs(e.anytlsSpecs)

	genPath, err := e.store.GenerationPath(ctx, work.Digest)
	if err != nil {
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		clearEmbeddedAnyTLSSpecs(oldAnyTLS)
		e.lastError = "DATA_DIR_UNAVAILABLE"
		return false, "", "无法读取已安装的 Xray 配置代次", err
	}

	rollback := func() {
		rbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = e.process.Stop(rbCtx)
		if oldMeta != nil && oldMeta.Current != nil && oldMeta.Current.Enabled {
			if oldPath, perr := e.store.GenerationPath(rbCtx, oldMeta.Current.Digest); perr == nil {
				oldInbound := firstEnabledProfileID(oldMeta.Current.SummaryV2)
				if oldInbound != "" {
					if serr := e.process.Start(rbCtx, coreproc.StartSpec{ConfigPath: oldPath, Digest: oldMeta.Current.Digest, InboundID: oldInbound}); serr == nil {
						if werr := e.process.WaitHealthy(rbCtx); werr == nil {
							_ = e.process.MarkCommitted()
						}
					}
				}
			}
			if e.obfs != nil && len(oldObfs) > 0 && e.lifetime != nil {
				_ = e.obfs.StartAll(e.lifetime, oldObfs)
			}
			if e.anytls != nil && len(oldAnyTLS) > 0 && e.lifetime != nil {
				_ = e.anytls.StartAll(e.lifetime, oldAnyTLS)
			}
		}
	}

	if err := e.process.Stop(ctx); err != nil {
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		clearEmbeddedAnyTLSSpecs(oldAnyTLS)
		e.lastError = "CORE_STOP_FAILED"
		return false, "", "停止旧 Xray 进程失败", err
	}

	primaryInbound := firstEnabledProfileID(summaryV2)
	if primaryInbound == "" {
		primaryInbound = intent.Profiles[0].ID
	}
	if err := e.process.Start(ctx, coreproc.StartSpec{ConfigPath: genPath, Digest: work.Digest, InboundID: primaryInbound}); err != nil {
		rollback()
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		clearEmbeddedAnyTLSSpecs(oldAnyTLS)
		e.lastError = "CORE_START_FAILED"
		return false, "", "启动内置 Xray 核心失败（请检查端口是否被占用）", err
	}
	if err := e.process.WaitHealthy(ctx); err != nil {
		rollback()
		clearEmbeddedAnyTLSSpecs(anytlsSpecs)
		clearEmbeddedAnyTLSSpecs(oldAnyTLS)
		e.lastError = "CORE_API_UNAVAILABLE"
		return false, "", "内置 Xray 核心未通过健康检查，已自动回滚至上一个可用版本", err
	}
	if e.obfs != nil && len(obfsPlans) > 0 {
		if err := e.obfs.StartAll(e.lifetime, obfsPlans); err != nil {
			rollback()
			clearEmbeddedAnyTLSSpecs(anytlsSpecs)
			clearEmbeddedAnyTLSSpecs(oldAnyTLS)
			e.lastError = "OBFS_START_FAILED"
			return false, "", "启动 SS2022 混淆转发失败，已回滚", err
		}
	} else if e.obfs != nil {
		e.obfs.StopAll(2 * time.Second)
	}
	if e.anytls != nil {
		if err := e.anytls.StartAll(e.lifetime, anytlsSpecs); err != nil {
			rollback()
			clearEmbeddedAnyTLSSpecs(anytlsSpecs)
			clearEmbeddedAnyTLSSpecs(oldAnyTLS)
			e.lastError = "ANYTLS_START_FAILED"
			return false, "", "启动 AnyTLS 监听失败，已回滚", err
		}
	}

	observed = e.process.Snapshot(ctx)
	nextMeta := &state.Metadata{
		SchemaVersion: "1",
		State:         "RUNNING",
		ResetEpoch:    observed.Epoch,
		Current: &state.Generation{
			Digest:    work.Digest,
			Revision:  rev,
			Version:   state.CoreVersion,
			Enabled:   true,
			SummaryV2: summaryV2,
		},
	}
	if oldMeta != nil {
		nextMeta.Previous = oldMeta.Current
	}
	_ = e.store.Commit(ctx, nextMeta)
	_ = e.process.MarkCommitted()
	_ = e.store.Prune(ctx, nextMeta)

	clearEmbeddedAnyTLSSpecs(e.anytlsSpecs)
	clearEmbeddedAnyTLSSpecs(oldAnyTLS)
	e.anytlsSpecs = anytlsSpecs
	e.obfsPlans = obfsPlans
	e.lastDigest = work.Digest
	e.lastSummary = summaryV2
	e.activeProfiles = activeProfileCount
	e.lastError = ""
	for k, v := range loadedTLS {
		e.tlsBindings[k] = v
	}

	return true, rev, skippedTLSNote(skippedTLS), nil
}

func skippedTLSNote(skippedTLS int) string {
	if skippedTLS <= 0 {
		return ""
	}
	return fmt.Sprintf("内置 Xray 核心已生效；另有 %d 个需要 TLS 证书的节点尚未绑定 binding_ref", skippedTLS)
}

func firstEnabledProfileID(summary *state.V2IntentSummary) string {
	if summary == nil {
		return ""
	}
	for _, p := range summary.Profiles {
		if p.Enabled && p.Protocol != corev2.ProtocolAnyTLS {
			return p.ID
		}
	}
	for _, p := range summary.Profiles {
		if p.Enabled {
			return p.ID
		}
	}
	return ""
}

func (e *embeddedXrayEngine) Status(ctx context.Context) embeddedXrayStatus {
	if e == nil {
		return embeddedXrayStatus{State: "UNAVAILABLE", ProcessState: "STOPPED", APIState: "UNAVAILABLE"}
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	st := embeddedXrayStatus{
		State:          "UNCONFIGURED",
		CoreVersion:    e.coreVersion,
		BinaryTrusted:  e.trusted,
		ProcessState:   "STOPPED",
		APIState:       "UNAVAILABLE",
		ActiveProfiles: e.activeProfiles,
		ObfsAvailable:  e.obfs != nil,
		AnyTLSActive:   len(e.anytlsSpecs) > 0,
		LastError:      e.lastError,
	}
	if e.revSeq > 0 {
		st.Revision = fmt.Sprintf("embedded-r%d", e.revSeq)
	}
	if !e.trusted {
		st.State = "UNAVAILABLE"
		if st.LastError == "" {
			st.LastError = "CORE_BINARY_UNAVAILABLE"
		}
		return st
	}
	if e.process != nil {
		snap := e.process.Snapshot(ctx)
		if snap.State != "" {
			st.ProcessState = snap.State
		}
		if snap.APIState != "" {
			st.APIState = snap.APIState
		}
		st.ResetEpoch = snap.Epoch
	}
	if e.activeProfiles == 0 && e.lastDigest == "" {
		st.State = "STOPPED"
		if e.lastError != "" {
			st.State = "FAILED"
		}
		return st
	}
	if st.ProcessState == "RUNNING" && st.APIState == "READY" {
		st.State = "RUNNING"
		st.ProxyAvailable = true
	} else if st.ProcessState == "RUNNING" {
		st.State = "DEGRADED"
	} else if e.lastError != "" {
		st.State = "FAILED"
	} else {
		st.State = "STOPPED"
	}
	return st
}

// ObserveUsers 从进程内 Xray 私有 UDS 统计服务与 AnyTLS 监管器直接读取用户实时流量计数器，零跨插件开销。
func (e *embeddedXrayEngine) ObserveUsers(ctx context.Context) (string, []usageSample, bool, error) {
	if !e.Available() {
		return "", nil, false, nil
	}
	e.mu.Lock()
	summary := e.lastSummary
	digest := e.lastDigest
	e.mu.Unlock()
	if summary == nil || digest == "" {
		return "", nil, false, nil
	}

	readCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	snap, err := e.process.ReadCounters(readCtx)
	if err != nil {
		return "", nil, false, err
	}
	if snap.Digest != digest || snap.Epoch == "" {
		return "", nil, false, nil
	}

	values := snap.Values
	if e.anytls != nil {
		if extra := e.anytlsAligner.ProjectForEpoch(snap.Epoch, e.anytls.Counters()); len(extra) > 0 {
			merged := make(map[string]int64, len(values)+len(extra))
			for k, v := range values {
				merged[k] = v
			}
			for k, v := range extra {
				merged[k] += v
			}
			values = merged
		}
	}
	res, err := metrics.NormalizeV2(summary, values, metrics.Filter{Kind: "user"}, snap.Epoch, time.Now())
	if err != nil {
		return "", nil, false, err
	}
	samples := make([]usageSample, 0, len(res.Series))
	for _, entry := range res.Series {
		if entry.Kind != "user" || !entry.Present || entry.ID == "" {
			continue
		}
		var up, down int64
		if entry.UplinkPresent && entry.UplinkBytes != nil {
			if n, perr := strconv.ParseInt(*entry.UplinkBytes, 10, 64); perr == nil && n >= 0 {
				up = n
			}
		}
		if entry.DownlinkPresent && entry.DownlinkBytes != nil {
			if n, perr := strconv.ParseInt(*entry.DownlinkBytes, 10, 64); perr == nil && n >= 0 {
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
	return res.ResetEpoch, samples, true, nil
}

// ======================== 直接构建 corev2.Intent + xrayconfig.V2Materials ========================

func (e *embeddedXrayEngine) buildDirectIntentAndMaterials(
	ctx context.Context,
	managedNodes []proxyNodeRecord,
	activeUsers []userRecord,
	warpCfg *warpWithSecrets,
) (*corev2.Intent, xrayconfig.V2Materials, map[string]embeddedTLSStatus, int, int, error) {
	materials := xrayconfig.V2Materials{Profiles: make(map[string]xrayconfig.ProfileMaterials)}
	loadedTLS := make(map[string]embeddedTLSStatus)
	profiles := make([]corev2.Profile, 0, len(managedNodes))
	existingProfileIDs := make(map[string]bool, len(managedNodes))
	skippedTLS := 0
	activeCount := 0

	ref := coreapi.SecretRef{ID: embeddedSyntheticSecretRef}
	refPtr := func() *coreapi.SecretRef { r := ref; return &r }

	for _, n := range managedNodes {
		needTLS := (n.Protocol == corev2.ProtocolHysteria2 || n.Protocol == corev2.ProtocolAnyTLS) ||
			((n.Protocol == corev2.ProtocolVLESS || n.Protocol == corev2.ProtocolVMess || n.Protocol == corev2.ProtocolTrojan) && n.SecurityMode == "tls")
		var tlsMat *xrayconfig.TLSMaterials
		var tlsStatus *embeddedTLSStatus
		if needTLS {
			if strings.TrimSpace(n.Config.BindingRef) == "" {
				skippedTLS++
				continue
			}
			sni := firstNonEmpty(n.Config.SNI, n.Server)
			loaded, st, terr := e.loadConsumerTLS(ctx, n.ID, n.Config.BindingRef, sni)
			if terr != nil {
				skippedTLS++
				continue
			}
			tlsMat = &loaded
			tlsStatus = &st
		}

		users, userSecrets := buildDirectUsersAndSecrets(n, activeUsers)
		if len(users) == 0 {
			if tlsMat != nil {
				tlsMat.Material.Clear()
			}
			continue
		}
		if n.Protocol == corev2.ProtocolShadowsocks2022 && n.Config.Method == corev2.MethodChaCha20 && len(users) > 1 {
			users = users[:1]
			kept := users[0].ID
			for k, v := range userSecrets {
				if k != kept {
					clear(v)
					delete(userSecrets, k)
				}
			}
		}

		enabled := n.Enabled
		prof := corev2.Profile{
			ID:       n.ID,
			Enabled:  &enabled,
			Listen:   n.Listen,
			Port:     n.Port,
			Protocol: n.Protocol,
			Users:    users,
		}
		var pm xrayconfig.ProfileMaterials
		valid := true

		switch n.Protocol {
		case corev2.ProtocolVLESS:
			v := &corev2.VLESS{
				Transport:    n.Transport,
				Flow:         n.Config.Flow,
				SecurityMode: n.SecurityMode,
				Path:         n.Config.Path,
				Host:         n.Config.Host,
				ServiceName:  n.Config.ServiceName,
				XHTTPMode:    n.Config.XHTTPMode,
				Encryption:   n.Config.Encryption,
				Sniffing:     n.Config.Sniffing,
			}
			vlessMat := &xrayconfig.Secrets{UUIDs: userSecrets}
			switch n.SecurityMode {
			case "reality":
				sni := firstNonEmpty(n.Config.SNI, defaultRealitySNICandidates[0])
				v.Security = &corev2.Reality{
					Mode:        "reality",
					Target:      firstNonEmpty(n.Config.Target, sni+":443"),
					ServerNames: []string{sni},
					PrivateKey:  ref,
					ShortIDs:    []string{firstNonEmpty(n.Config.ShortID, "01234567")},
				}
				vlessMat.PrivateKey = []byte(n.Config.PrivateKey)
			case "tls":
				v.TLS = &corev2.TLSBinding{BindingRef: n.Config.BindingRef, ServerName: firstNonEmpty(n.Config.SNI, n.Server)}
				pm.VLESSTLS = tlsMat
			}
			if n.Config.Decryption != "" && n.Config.Decryption != "none" {
				v.Decryption = refPtr()
				pm.VLESSDecryption = []byte(n.Config.Decryption)
			}
			prof.VLESS = v
			pm.VLESS = vlessMat

		case corev2.ProtocolVMess:
			v := &corev2.VMess{
				Transport:    n.Transport,
				SecurityMode: n.SecurityMode,
				Path:         n.Config.Path,
				Host:         n.Config.Host,
				ServiceName:  n.Config.ServiceName,
				Sniffing:     n.Config.Sniffing,
			}
			vm := &xrayconfig.VMessMaterials{UUIDs: userSecrets}
			if n.SecurityMode == "tls" {
				v.TLS = &corev2.TLSBinding{BindingRef: n.Config.BindingRef, ServerName: firstNonEmpty(n.Config.SNI, n.Server)}
				vm.TLS = tlsMat
			}
			prof.VMess = v
			pm.VMess = vm

		case corev2.ProtocolTrojan:
			v := &corev2.Trojan{
				Transport:    n.Transport,
				SecurityMode: n.SecurityMode,
				Path:         n.Config.Path,
				Host:         n.Config.Host,
				ServiceName:  n.Config.ServiceName,
				Sniffing:     n.Config.Sniffing,
			}
			tr := &xrayconfig.TrojanMaterials{Auth: userSecrets}
			if n.SecurityMode == "tls" {
				v.TLS = &corev2.TLSBinding{BindingRef: n.Config.BindingRef, ServerName: firstNonEmpty(n.Config.SNI, n.Server)}
				tr.TLS = tlsMat
			} else {
				sni := firstNonEmpty(n.Config.SNI, defaultRealitySNICandidates[0])
				v.Reality = &corev2.Reality{
					Mode:        "reality",
					Target:      firstNonEmpty(n.Config.Target, sni+":443"),
					ServerNames: []string{sni},
					PrivateKey:  ref,
					ShortIDs:    []string{firstNonEmpty(n.Config.ShortID, "01234567")},
				}
				tr.PrivateKey = []byte(n.Config.PrivateKey)
			}
			prof.Trojan = v
			pm.Trojan = tr

		case corev2.ProtocolShadowsocks:
			udpOn := n.Config.UDP == nil || *n.Config.UDP
			prof.Shadowsocks = &corev2.Shadowsocks{Method: n.Config.Method, UDP: udpOn, Sniffing: n.Config.Sniffing}
			pm.Shadowsocks = &xrayconfig.ShadowsocksMaterials{Auth: userSecrets}

		case corev2.ProtocolShadowsocks2022:
			obfsMode := firstNonEmpty(n.Config.ObfsMode, corev2.ObfsNone)
			obfs := &corev2.Obfs{Mode: obfsMode}
			if obfsMode == corev2.ObfsHTTP || obfsMode == corev2.ObfsTLS {
				obfs.Host = n.Config.ObfsHost
			}
			udpOn := (n.Config.UDP == nil || *n.Config.UDP) && obfsMode == corev2.ObfsNone
			prof.Shadowsocks2022 = &corev2.Shadowsocks2022{
				Method:    n.Config.Method,
				ServerKey: ref,
				Obfs:      obfs,
				UDP:       udpOn,
				Sniffing:  n.Config.Sniffing,
			}
			pm.Shadowsocks2022 = &xrayconfig.SS2022Materials{
				ServerKey: []byte(n.Config.ServerKey),
				PSKs:      userSecrets,
			}

		case corev2.ProtocolHysteria2:
			h := &corev2.Hysteria2{
				TLS:         &corev2.TLSBinding{BindingRef: n.Config.BindingRef, ServerName: firstNonEmpty(n.Config.SNI, n.Server)},
				PortHopping: n.Config.PortHopping,
				Sniffing:    n.Config.Sniffing,
			}
			h2 := &xrayconfig.HysteriaMaterials{Auth: userSecrets, TLS: *tlsMat}
			if n.Config.ObfsPassword != "" {
				h.ObfsPassword = refPtr()
				h2.ObfsPassword = []byte(n.Config.ObfsPassword)
			}
			prof.Hysteria2 = h
			pm.Hysteria2 = h2

		case corev2.ProtocolAnyTLS:
			prof.AnyTLS = &corev2.AnyTLS{
				TLS:           &corev2.TLSBinding{BindingRef: n.Config.BindingRef, ServerName: firstNonEmpty(n.Config.SNI, n.Server)},
				PaddingScheme: normalizePaddingScheme(n.Config.PaddingScheme),
			}
			pm.AnyTLS = &xrayconfig.AnyTLSMaterials{Auth: userSecrets, TLS: *tlsMat}

		case corev2.ProtocolSOCKS5:
			udpOn := n.Config.UDP == nil || *n.Config.UDP
			prof.SOCKS5 = &corev2.SOCKS5{UDP: udpOn, Sniffing: n.Config.Sniffing}
			pm.SOCKS5 = &xrayconfig.AccountMaterials{Auth: userSecrets}

		case corev2.ProtocolHTTP:
			prof.HTTP = &corev2.HTTP{Sniffing: n.Config.Sniffing}
			pm.HTTP = &xrayconfig.AccountMaterials{Auth: userSecrets}

		default:
			valid = false
		}

		if !valid {
			for _, b := range userSecrets {
				clear(b)
			}
			if tlsMat != nil {
				tlsMat.Material.Clear()
			}
			continue
		}
		profiles = append(profiles, prof)
		materials.Profiles[n.ID] = pm
		existingProfileIDs[n.ID] = true
		if n.Enabled {
			activeCount++
		}
		if tlsStatus != nil {
			tlsStatus.Running = n.Enabled
			tlsStatus.Endpoint = net.JoinHostPort(n.Listen, strconv.Itoa(n.Port))
			loadedTLS[n.Config.BindingRef] = *tlsStatus
		}
	}

	if len(profiles) == 0 {
		return nil, materials, loadedTLS, skippedTLS, 0, nil
	}

	topEnabled := activeCount > 0
	intent := &corev2.Intent{
		SchemaVersion: "2",
		Enabled:       &topEnabled,
		Profiles:      profiles,
		Outbound:      &corev2.Outbound{Type: "direct"},
	}

	if warpCfg != nil && warpCfg.Registered && warpCfg.PrivateKey != "" {
		bound := make([]string, 0, len(warpCfg.BoundProfileIDs))
		for _, pid := range warpCfg.BoundProfileIDs {
			if existingProfileIDs[pid] {
				bound = append(bound, pid)
			}
		}
		mtu := warpCfg.MTU
		if mtu < 1200 || mtu > 1500 {
			mtu = defaultWARPMTU
		}
		intent.WARP = &corev2.WARPOutbound{
			Enabled:         warpCfg.Enabled,
			PrivateKey:      ref,
			PeerPublicKey:   warpCfg.PeerPublicKey,
			Endpoint:        warpCfg.Endpoint,
			AddressV4:       ensureWARPCIDR(warpCfg.AddressV4, "/32"),
			AddressV6:       ensureWARPCIDR(warpCfg.AddressV6, "/128"),
			Reserved:        slices.Clone(warpCfg.Reserved),
			MTU:             mtu,
			RoutingMode:     warpCfg.RoutingMode,
			BoundProfileIDs: bound,
			Domains:         slices.Clone(warpCfg.Domains),
		}
		materials.WARP = &xrayconfig.WARPMaterials{PrivateKey: []byte(warpCfg.PrivateKey)}
	}

	return intent, materials, loadedTLS, skippedTLS, activeCount, nil
}

func buildDirectUsersAndSecrets(n proxyNodeRecord, activeUsers []userRecord) ([]corev2.User, map[string][]byte) {
	ref := coreapi.SecretRef{ID: embeddedSyntheticSecretRef}
	refPtr := func() *coreapi.SecretRef { r := ref; return &r }

	users := make([]corev2.User, 0, len(activeUsers)+1)
	secrets := make(map[string][]byte, len(activeUsers)+1)
	seenSecret := make(map[string]bool, len(activeUsers)+1)

	addOne := func(id, username, secret string, mark uint32) {
		if id == "" || secret == "" {
			return
		}
		dedupKey := secret
		if n.Protocol == corev2.ProtocolVLESS || n.Protocol == corev2.ProtocolVMess {
			dedupKey = strings.ToLower(secret)
		} else if n.Protocol == corev2.ProtocolSOCKS5 || n.Protocol == corev2.ProtocolHTTP {
			dedupKey = "acct:" + firstNonEmpty(username, id)
		}
		if seenSecret[dedupKey] {
			return
		}
		seenSecret[dedupKey] = true

		u := corev2.User{ID: id, TrafficMark: mark}
		switch n.Protocol {
		case corev2.ProtocolVLESS, corev2.ProtocolVMess:
			u.UUID = refPtr()
		case corev2.ProtocolShadowsocks2022:
			u.PSK = refPtr()
		case corev2.ProtocolSOCKS5, corev2.ProtocolHTTP:
			u.Username = firstNonEmpty(username, id)
			u.Auth = refPtr()
		default:
			u.Auth = refPtr()
		}
		users = append(users, u)
		secrets[id] = []byte(secret)
	}

	// 1. 节点自身凭据
	nodeUserID := "u-" + n.ID
	if len(nodeUserID) > 32 {
		nodeUserID = nodeUserID[:32]
	}
	switch n.Protocol {
	case corev2.ProtocolVLESS, corev2.ProtocolVMess:
		addOne(nodeUserID, "", n.Config.UUID, 0)
	case corev2.ProtocolShadowsocks2022:
		effKey := n.Config.UserKey
		if derived, err := DeriveSS2022UserPSKForCipher(n.Config.UserKey, n.Config.Method, n.ID); err == nil {
			effKey = derived
		}
		addOne(nodeUserID, "", effKey, 0)
	case corev2.ProtocolSOCKS5, corev2.ProtocolHTTP:
		addOne(nodeUserID, firstNonEmpty(n.Config.Username, "user"), n.Config.Password, 0)
	default:
		addOne(nodeUserID, "", n.Config.Password, 0)
	}

	// 2. 多用户订阅中心所有活跃用户
	for _, u := range activeUsers {
		if u.ID == nodeUserID {
			continue
		}
		var mark uint32
		if shouldAttachUserTrafficMark(u.TrafficMark, u.UpLimitKbps, u.DownLimitKbps) {
			mark = u.TrafficMark
		}
		switch n.Protocol {
		case corev2.ProtocolVLESS, corev2.ProtocolVMess:
			addOne(u.ID, "", u.VLESSUUID, mark)
		case corev2.ProtocolShadowsocks2022:
			effKey := u.SS2022UserKey
			if derived, err := DeriveSS2022UserPSKForCipher(u.SS2022UserKey, n.Config.Method, n.ID); err == nil {
				effKey = derived
			}
			addOne(u.ID, "", effKey, mark)
		case corev2.ProtocolSOCKS5, corev2.ProtocolHTTP:
			addOne(u.ID, u.ID, u.Hy2Password, mark)
		default:
			addOne(u.ID, "", u.Hy2Password, mark)
		}
	}
	return users, secrets
}

func (e *embeddedXrayEngine) loadConsumerTLS(ctx context.Context, profileID, bindingRef, serverName string) (xrayconfig.TLSMaterials, embeddedTLSStatus, error) {
	root, err := os.OpenRoot(e.dataDir)
	if err != nil {
		return xrayconfig.TLSMaterials{}, embeddedTLSStatus{}, err
	}
	defer root.Close()
	store, err := consumerfiles.New(root)
	if err != nil {
		return xrayconfig.TLSMaterials{}, embeddedTLSStatus{}, err
	}
	defer store.Close()

	proof, err := store.Current(ctx, bindingRef)
	if err != nil || proof == nil {
		return xrayconfig.TLSMaterials{}, embeddedTLSStatus{}, errors.New("tls binding not materialized")
	}
	mat, err := store.Load(ctx, *proof)
	if err != nil {
		return xrayconfig.TLSMaterials{}, embeddedTLSStatus{}, err
	}
	roots, _ := x509.SystemCertPool()
	meta, verr := tlsmgr.ValidateMaterial(mat, tlsmgr.MaterialOptions{
		SANs:    []string{serverName},
		Now:     time.Now().UTC(),
		Purpose: tlsmgr.ServerTLS,
		Trust:   tlsmgr.PublicTrust,
		Roots:   roots,
	})
	trust := tlsmgr.PublicTrust
	purpose := tlsmgr.ServerTLS
	if verr != nil {
		mat.Clear()
		return xrayconfig.TLSMaterials{}, embeddedTLSStatus{}, verr
	}
	fp := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(meta.Fingerprint), ":", ""))
	st := embeddedTLSStatus{
		BindingRef:      bindingRef,
		ProfileID:       profileID,
		PublicTrusted:   trust == tlsmgr.PublicTrust,
		Generation:      proof.Binding.Generation,
		PolicyRevision:  proof.Binding.PolicyRevision,
		FullchainSHA256: proof.FullchainSHA256,
		LeafFingerprint: fp,
		SNI:             serverName,
	}
	return xrayconfig.TLSMaterials{
		BindingRef:     proof.Binding.ID,
		Generation:     proof.Binding.Generation,
		PolicyRevision: proof.Binding.PolicyRevision,
		SANs:           []string{serverName},
		Material:       mat,
		Purpose:        purpose,
		Trust:          trust,
		Roots:          roots,
	}, st, nil
}

func buildEmbeddedAnyTLSSpecs(intent *corev2.Intent, materials xrayconfig.V2Materials) []anytls.ProfileSpec {
	if intent == nil || !*intent.Enabled {
		return nil
	}
	var specs []anytls.ProfileSpec
	for _, p := range intent.Profiles {
		if p.Protocol != corev2.ProtocolAnyTLS || p.Enabled == nil || !*p.Enabled || p.AnyTLS == nil {
			continue
		}
		pm, ok := materials.Profiles[p.ID]
		if !ok || pm.AnyTLS == nil {
			continue
		}
		users := make(map[string][]byte, len(p.Users))
		userMarks := make(map[string]uint32, len(p.Users))
		for _, u := range p.Users {
			pw := pm.AnyTLS.Auth[u.ID]
			if len(pw) == 0 {
				continue
			}
			users[u.ID] = append([]byte(nil), pw...)
			if u.TrafficMark > 0 {
				userMarks[u.ID] = u.TrafficMark
			}
		}
		if len(users) == 0 {
			continue
		}
		certPEM := pm.AnyTLS.TLS.Material.CertificatePEM()
		keyPEM := pm.AnyTLS.TLS.Material.PrivateKeyPEM()
		specs = append(specs, anytls.ProfileSpec{
			ProfileID:     p.ID,
			Listen:        p.Listen,
			Port:          p.Port,
			BindingRef:    p.AnyTLS.TLS.BindingRef,
			ServerName:    p.AnyTLS.TLS.ServerName,
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			Users:         users,
			UserMarks:     userMarks,
			PaddingScheme: slices.Clone(p.AnyTLS.PaddingScheme),
		})
	}
	return specs
}

func cloneEmbeddedAnyTLSSpecs(in []anytls.ProfileSpec) []anytls.ProfileSpec {
	if len(in) == 0 {
		return nil
	}
	out := make([]anytls.ProfileSpec, len(in))
	for i, s := range in {
		cp := s
		cp.CertPEM = append([]byte(nil), s.CertPEM...)
		cp.KeyPEM = append([]byte(nil), s.KeyPEM...)
		if len(s.Users) > 0 {
			cp.Users = make(map[string][]byte, len(s.Users))
			for k, v := range s.Users {
				cp.Users[k] = append([]byte(nil), v...)
			}
		} else {
			cp.Users = nil
		}
		if len(s.UserMarks) > 0 {
			cp.UserMarks = make(map[string]uint32, len(s.UserMarks))
			for k, v := range s.UserMarks {
				cp.UserMarks[k] = v
			}
		} else {
			cp.UserMarks = nil
		}
		cp.PaddingScheme = slices.Clone(s.PaddingScheme)
		out[i] = cp
	}
	return out
}

func clearEmbeddedAnyTLSSpecs(specs []anytls.ProfileSpec) {
	for idx := range specs {
		clear(specs[idx].CertPEM)
		clear(specs[idx].KeyPEM)
		for k, v := range specs[idx].Users {
			clear(v)
			delete(specs[idx].Users, k)
		}
		specs[idx].CertPEM = nil
		specs[idx].KeyPEM = nil
		specs[idx].Users = nil
	}
}

// ======================== 新增统一引擎与 TLS 操作处理器 ========================

func (i *instance) handleXrayStatus(ctx context.Context, _ pluginsdk.Request) (pluginsdk.Response, error) {
	st := embeddedXrayStatus{State: "UNAVAILABLE", ProcessState: "STOPPED", APIState: "UNAVAILABLE"}
	if i.xray != nil {
		st = i.xray.Status(ctx)
	}
	return marshalResponse(st)
}

func (i *instance) handleTLSReload(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		BindingRef       string `json:"binding_ref"`
		ProfileID        string `json:"profile_id"`
		Generation       uint64 `json:"generation"`
		PolicyRevision   string `json:"policy_revision"`
		FullchainSHA256  string `json:"fullchain_sha256"`
		PrivateKeySHA256 string `json:"private_key_sha256"`
		SNI              string `json:"sni"`
	}
	if err := json.Unmarshal(req.Payload, &in); err != nil || in.BindingRef == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_REQUEST", "无效的 TLS 重载请求")
	}
	if i.xray != nil && i.xray.Available() {
		managedNodes, _ := i.store.ListNodes(ctx, "managed", "", "", "", false)
		activeUsers, _ := i.store.ListUsers(ctx, "active", "", 10000)
		warpCfg, _ := i.store.GetWARP(ctx)
		if _, _, _, err := i.xray.Sync(ctx, managedNodes, activeUsers, warpCfg); err != nil {
			return pluginsdk.Response{}, pluginsdk.Errorf("TLS_RELOAD_FAILED", "重新加载代理 TLS 证书失败：%v", err)
		}
		i.xray.mu.Lock()
		st, ok := i.xray.tlsBindings[in.BindingRef]
		i.xray.mu.Unlock()
		if ok {
			return marshalResponse(st)
		}
	}
	return marshalResponse(embeddedTLSStatus{
		BindingRef:      in.BindingRef,
		ProfileID:       in.ProfileID,
		Generation:      in.Generation,
		PolicyRevision:  in.PolicyRevision,
		FullchainSHA256: in.FullchainSHA256,
		SNI:             in.SNI,
	})
}

func (i *instance) handleTLSInspect(_ context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
	var in struct {
		BindingRef string `json:"binding_ref"`
		ProfileID  string `json:"profile_id"`
	}
	if err := json.Unmarshal(req.Payload, &in); err != nil || in.BindingRef == "" {
		return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_REQUEST", "无效的 TLS 观测请求")
	}
	if i.xray != nil {
		i.xray.mu.Lock()
		st, ok := i.xray.tlsBindings[in.BindingRef]
		i.xray.mu.Unlock()
		if ok {
			return marshalResponse(st)
		}
	}
	return marshalResponse(embeddedTLSStatus{
		BindingRef: in.BindingRef,
		ProfileID:  in.ProfileID,
	})
}
