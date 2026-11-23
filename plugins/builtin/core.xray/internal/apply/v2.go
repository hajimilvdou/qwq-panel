// SPDX-License-Identifier: AGPL-3.0-only

package apply

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/anytls"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== v1/v2 统一解码与消费者 TLS 热加载 ========================

type desiredIntent struct {
	v1 *coreapi.Intent
	v2 *corev2.Intent
}

func (d desiredIntent) enabled() bool {
	if d.v1 != nil && d.v1.Enabled != nil {
		return *d.v1.Enabled
	}
	if d.v2 != nil && d.v2.Enabled != nil {
		return *d.v2.Enabled
	}
	return false
}

// TLSReloadRequest 对齐 controller.ConsumerTLSReloadPayload，仅传摘要与绑定身份，不含 PEM。
type TLSReloadRequest struct {
	BindingRef       string
	ProfileID        string
	Generation       uint64
	PolicyRevision   string
	FullchainSHA256  string
	PrivateKeySHA256 string
	SNI              string
}

// TLSBindingStatus 对齐 controller.ConsumerTLSInspectResult，诚实回报运行状态与监听端点。
type TLSBindingStatus struct {
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

// TLSBindingInfo 返回已提交运行中的指定 TLS 绑定信任与指纹摘要（只读）；
// 若内存缓存未命中（如进程重启后），自动从私有 consumerfiles 落盘目录校验并回填，避免导出误加 allowInsecure=1。
func (e *Engine) TLSBindingInfo(bindingRef string) (TLSBindingStatus, bool) {
	if bindingRef == "" {
		return TLSBindingStatus{}, false
	}
	e.mu.Lock()
	if e.tlsBindings != nil {
		if st, ok := e.tlsBindings[bindingRef]; ok {
			e.mu.Unlock()
			return st, true
		}
	}
	dataDir := e.options.DataDir
	e.mu.Unlock()

	if dataDir == "" {
		return TLSBindingStatus{}, false
	}
	store, closeStore, err := openConsumerStore(dataDir)
	if err != nil {
		return TLSBindingStatus{}, false
	}
	defer closeStore()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	proof, err := store.Current(ctx, bindingRef)
	if err != nil || proof == nil {
		return TLSBindingStatus{}, false
	}
	mat, err := store.Load(ctx, *proof)
	if err != nil {
		return TLSBindingStatus{}, false
	}
	defer mat.Clear()

	roots, _ := e.roots()
	trust, _, meta, verr := validateConsumerMaterial(mat, proof.Binding.Consumer.SNI, e.now(), roots, e.options.PermitTestCertificates)
	if verr != nil {
		return TLSBindingStatus{}, false
	}
	st := TLSBindingStatus{
		BindingRef:      bindingRef,
		ProfileID:       proof.Binding.Consumer.ProfileID,
		PublicTrusted:   trust == tlsmgr.PublicTrust,
		Generation:      proof.Binding.Generation,
		PolicyRevision:  proof.Binding.PolicyRevision,
		FullchainSHA256: proof.FullchainSHA256,
		LeafFingerprint: meta.Fingerprint,
		SNI:             proof.Binding.Consumer.SNI,
	}
	e.mu.Lock()
	if e.tlsBindings == nil {
		e.tlsBindings = make(map[string]TLSBindingStatus)
	}
	e.tlsBindings[bindingRef] = st
	e.mu.Unlock()
	return st, true
}

func loadDesiredAny(ctx context.Context, request Request) (desiredIntent, error) {
	call, cancel := boundedHostContext(ctx)
	data, revision, err := request.Host.GetConfig(call, "")
	cancel()
	if err != nil {
		return desiredIntent{}, failure("CONFIG_UNAVAILABLE", contextCause(ctx))
	}
	if revision != request.ConfigRevision {
		return desiredIntent{}, failure("CONFIG_REVISION_CONFLICT", nil)
	}
	return decodeDesiredAny(data)
}

func decodeDesiredAny(data []byte) (desiredIntent, error) {
	var head struct {
		SchemaVersion string `json:"schema_version"`
	}
	if json.Unmarshal(data, &head) != nil {
		return desiredIntent{}, failure("INVALID_INTENT", nil)
	}
	switch head.SchemaVersion {
	case "1":
		intent, err := coreapi.Decode(data)
		if err != nil || coreapi.Validate(intent) != nil {
			return desiredIntent{}, failure("INVALID_INTENT", nil)
		}
		return desiredIntent{v1: intent}, nil
	case "2":
		intent, err := corev2.Decode(data)
		if err != nil || corev2.Validate(intent) != nil {
			return desiredIntent{}, failure("INVALID_INTENT", nil)
		}
		return desiredIntent{v2: intent}, nil
	default:
		return desiredIntent{}, failure("INVALID_INTENT", nil)
	}
}

func (e *Engine) now() time.Time {
	if e.options.Now != nil {
		return e.options.Now()
	}
	return time.Now().UTC()
}

func (e *Engine) roots() (*x509.CertPool, error) {
	if e.options.Roots != nil {
		return e.options.Roots, nil
	}
	return x509.SystemCertPool()
}

// consumerDirTLSLoader 从本实例私有 StateDirectory（consumerfiles）读取并验证宿主部署的 TLS 材料。
type consumerDirTLSLoader struct {
	engine  *Engine
	loaded  map[string]TLSBindingStatus
	dataDir string
}

func openConsumerStore(dataDir string) (*consumerfiles.Store, func(), error) {
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return nil, nil, err
	}
	store, err := consumerfiles.New(root)
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	return store, func() {
		_ = store.Close()
		_ = root.Close()
	}, nil
}

func (l *consumerDirTLSLoader) LoadTLS(ctx context.Context, profileID, bindingRef, serverName string) (xrayconfig.TLSMaterials, error) {
	if l.engine.options.TLSLoader != nil {
		return l.engine.options.TLSLoader.LoadTLS(ctx, profileID, bindingRef, serverName)
	}
	if l.dataDir == "" {
		return xrayconfig.TLSMaterials{}, failure("TLS_MATERIAL_UNAVAILABLE", nil)
	}
	store, closeStore, err := openConsumerStore(l.dataDir)
	if err != nil {
		return xrayconfig.TLSMaterials{}, failure("TLS_MATERIAL_UNAVAILABLE", err)
	}
	defer closeStore()

	proof, err := store.Current(ctx, bindingRef)
	if err != nil || proof == nil {
		return xrayconfig.TLSMaterials{}, failure("TLS_MATERIAL_UNAVAILABLE", err)
	}
	if proof.Binding.ID != bindingRef || proof.Binding.Consumer.ProfileID != profileID || proof.Binding.Consumer.SNI != serverName {
		return xrayconfig.TLSMaterials{}, failure("TLS_BINDING_MISMATCH", nil)
	}
	mat, err := store.Load(ctx, *proof)
	if err != nil {
		return xrayconfig.TLSMaterials{}, failure("TLS_MATERIAL_UNAVAILABLE", err)
	}
	roots, rootErr := l.engine.roots()
	trust, purpose, meta, verr := validateConsumerMaterial(mat, serverName, l.engine.now(), roots, l.engine.options.PermitTestCertificates)
	if verr != nil || (trust != tlsmgr.TestTrust && rootErr != nil) {
		mat.Clear()
		return xrayconfig.TLSMaterials{}, failure("TLS_MATERIAL_INVALID", verr)
	}
	if l.loaded != nil {
		l.loaded[bindingRef] = TLSBindingStatus{
			BindingRef:      bindingRef,
			ProfileID:       profileID,
			PublicTrusted:   trust == tlsmgr.PublicTrust,
			Generation:      proof.Binding.Generation,
			PolicyRevision:  proof.Binding.PolicyRevision,
			FullchainSHA256: proof.FullchainSHA256,
			LeafFingerprint: meta.Fingerprint,
			SNI:             serverName,
		}
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
	}, nil
}

func validateConsumerMaterial(mat tlsmgr.Material, serverName string, now time.Time, roots *x509.CertPool, permitTest bool) (tlsmgr.TrustClass, tlsmgr.MaterialPurpose, tlsmgr.CertificateMetadata, error) {
	if roots != nil {
		meta, err := tlsmgr.ValidateMaterial(mat, tlsmgr.MaterialOptions{
			SANs:    []string{serverName},
			Now:     now,
			Purpose: tlsmgr.ServerTLS,
			Trust:   tlsmgr.PublicTrust,
			Roots:   roots,
		})
		if err == nil && tlsmgr.Covers(meta, serverName) == nil {
			return tlsmgr.PublicTrust, tlsmgr.ServerTLS, meta, nil
		}
	}
	if permitTest {
		meta, err := tlsmgr.ValidateMaterial(mat, tlsmgr.MaterialOptions{
			SANs:    []string{serverName},
			Now:     now,
			Purpose: tlsmgr.TestServerTLS,
			Trust:   tlsmgr.TestTrust,
		})
		if err == nil && tlsmgr.Covers(meta, serverName) == nil {
			return tlsmgr.TestTrust, tlsmgr.TestServerTLS, meta, nil
		}
		return "", "", tlsmgr.CertificateMetadata{}, err
	}
	return "", "", tlsmgr.CertificateMetadata{}, errors.New("apply: certificate trust verification failed")
}

// ======================== v2 端口预检（覆盖 TCP 与 UDP） ========================

func (e *Engine) preflightPortsV2(ctx context.Context, intent *corev2.Intent, old *state.Metadata) error {
	if !*intent.Enabled {
		return nil
	}
	for _, profile := range intent.Profiles {
		if !*profile.Enabled {
			continue
		}
		addr, err := netip.ParseAddr(profile.Listen)
		if err != nil {
			return err
		}
		target := netip.AddrPortFrom(addr.Unmap(), uint16(profile.Port))
		switch profile.Protocol {
		case corev2.ProtocolHysteria2:
			if err := e.preflightUDPPort(ctx, target, old); err != nil {
				return err
			}
		case corev2.ProtocolShadowsocks:
			if err := e.preflightTCPPort(ctx, target, old); err != nil {
				return err
			}
			if profile.Shadowsocks != nil && profile.Shadowsocks.UDP {
				if err := e.preflightUDPPort(ctx, target, old); err != nil {
					return err
				}
			}
		case corev2.ProtocolShadowsocks2022:
			if err := e.preflightTCPPort(ctx, target, old); err != nil {
				return err
			}
			if profile.Shadowsocks2022 != nil && profile.Shadowsocks2022.UDP {
				if err := e.preflightUDPPort(ctx, target, old); err != nil {
					return err
				}
			}
		default:
			if err := e.preflightTCPPort(ctx, target, old); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Engine) preflightTCPPort(ctx context.Context, target netip.AddrPort, old *state.Metadata) error {
	var listen net.ListenConfig
	probe, err := listen.Listen(ctx, "tcp", target.String())
	if err == nil {
		return probe.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) || old == nil || old.Current == nil {
		return err
	}
	original := e.options.Process.Snapshot(ctx)
	if !runtimeMatches(old, original) || original.PID <= 0 {
		return errPortIdentity
	}
	prevAddrs := previousTCPListeners(old)
	scope, serr := tcpBindingScope(ctx, target)
	if serr != nil {
		return serr
	}
	owned := e.ownedPIDs(original.PID)
	for _, previous := range prevAddrs {
		if verifyOwnedPortConflict(ctx, netip.AddrPortFrom(scope, target.Port()), previous, owned...) == nil {
			if current := e.options.Process.Snapshot(ctx); current != original {
				return errPortIdentity
			}
			return ctx.Err()
		}
	}
	return errPortIdentity
}

func (e *Engine) preflightUDPPort(ctx context.Context, target netip.AddrPort, old *state.Metadata) error {
	var listen net.ListenConfig
	probe, err := listen.ListenPacket(ctx, "udp", target.String())
	if err == nil {
		return probe.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) || old == nil || old.Current == nil || old.Current.SummaryV2 == nil {
		return err
	}
	original := e.options.Process.Snapshot(ctx)
	if !runtimeMatches(old, original) || original.PID <= 0 {
		return errPortIdentity
	}
	// 同进程已声明持有该 UDP 端口时允许受控重启切换。
	for _, p := range old.Current.SummaryV2.Profiles {
		if !p.Enabled {
			continue
		}
		if p.Protocol != corev2.ProtocolHysteria2 && !(p.Protocol == corev2.ProtocolShadowsocks2022 && p.UDP) && !(p.Protocol == corev2.ProtocolShadowsocks && p.UDP) {
			continue
		}
		if p.Port == int(target.Port()) {
			return ctx.Err()
		}
	}
	return errPortIdentity
}

func previousTCPListeners(old *state.Metadata) []netip.AddrPort {
	var out []netip.AddrPort
	if old.Current.Summary != nil {
		if addr, err := netip.ParseAddr(old.Current.Summary.Listen); err == nil {
			out = append(out, netip.AddrPortFrom(addr.Unmap(), uint16(old.Current.Summary.Port)))
		}
	}
	if old.Current.SummaryV2 != nil {
		for _, p := range old.Current.SummaryV2.Profiles {
			if !p.Enabled || p.Protocol == corev2.ProtocolHysteria2 {
				continue
			}
			if addr, err := netip.ParseAddr(p.Listen); err == nil {
				out = append(out, netip.AddrPortFrom(addr.Unmap(), uint16(p.Port)))
			}
		}
	}
	return out
}

func sameDesiredV2(old *state.Metadata, revision string, intent *corev2.Intent, summary *state.V2IntentSummary) bool {
	return old != nil && old.State != "FAILED" && old.Current.Revision == revision && old.Current.Enabled == *intent.Enabled && reflect.DeepEqual(old.Current.SummaryV2, summary)
}

// ======================== v2 Plan 预演 ========================

func (e *Engine) planV2(ctx context.Context, request Request, intent *corev2.Intent, current *state.Metadata) (pluginsdk.Plan, error) {
	afterSummary, err := state.SummarizeV2(intent)
	if err != nil {
		return pluginsdk.Plan{}, failure("INVALID_INTENT", nil)
	}
	var before any
	kind := pluginsdk.ChangeCreate
	revision := ""
	authStatus := "changed"
	afterUsers := afterSummary.AllUserIDs()
	runtime := plannedRuntime{
		DesiredRevision: request.ConfigRevision,
		Enabled:         *intent.Enabled,
		ProcessAction:   "keep_stopped",
		AddedUsers:      slices.Clone(afterUsers),
		RemovedUsers:    []string{},
	}
	if *intent.Enabled {
		runtime.ProcessAction = "start"
	}
	if current != nil {
		kind, revision = pluginsdk.ChangeUpdate, current.Current.Revision
		runtime.RollbackAvailable = true
		var beforeUsers []string
		if current.Current.SummaryV2 != nil {
			before = map[string]any{"enabled": current.Current.Enabled, "summary": current.Current.SummaryV2}
			beforeUsers = current.Current.SummaryV2.AllUserIDs()
			authStatus = changeStatus(current.Current.SummaryV2.RefsDigest != afterSummary.RefsDigest)
		} else if current.Current.Summary != nil {
			before = plannedConfig{PublicIntentSummary: current.Current.Summary.PublicIntentSummary, Enabled: current.Current.Enabled}
			beforeUsers = current.Current.Summary.UserIDs
		}
		runtime.AddedUsers, runtime.RemovedUsers = userDifference(beforeUsers, afterUsers)
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
	afterJSON, err := planJSON(map[string]any{"enabled": *intent.Enabled, "summary": afterSummary})
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	authJSON, err := planJSON(map[string]string{"material_refs": authStatus})
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
			{Kind: kind, Subject: "config/current", Before: beforeJSON, After: afterJSON, Reversible: current != nil, Description: "保存 Core Intent v2 期望配置；协议 profile、监听与用户变化如下"},
			{Kind: kind, Subject: "config/current", Pointer: "/authentication", After: authJSON, Reversible: current != nil, Description: "认证与 TLS 绑定仅显示引用是否变更，材料在执行期解引用"},
			{Kind: kind, Subject: "runtime/current", After: runtimeJSON, Reversible: current != nil, Description: "按候选摘要决定进程切换；失败恢复上一份有效配置"},
		},
		Preconditions: []pluginsdk.Precondition{{Subject: RunningKey, Revision: revision}},
		Warnings: []pluginsdk.FieldViolation{
			{Code: "NATIVE_PREFLIGHT_NOT_RUN", Message: "本次预演只做静态校验；原生预检和健康检查在 Apply 时执行"},
			{Code: "RESTART_CONDITIONAL", Message: "实际重启由解引用后的候选摘要及当前进程健康决定"},
		},
	}, nil
}

// ======================== 宿主驱动的 TLS 热重载与实时状态观测 ========================

// ReloadTLS 从本插件私有 StateDirectory 读取宿主已验证部署的证书代际；
// 若当前运行着引用该绑定的 Hysteria2 配置，则原地替换其原生配置中的证书段、预检并重启（失败自动回滚）。
func (e *Engine) ReloadTLS(parent context.Context, req TLSReloadRequest) (TLSBindingStatus, error) {
	if req.BindingRef == "" || req.ProfileID == "" || req.Generation == 0 || req.PolicyRevision == "" ||
		req.FullchainSHA256 == "" || req.PrivateKeySHA256 == "" || req.SNI == "" {
		return TLSBindingStatus{}, failure("INVALID_REQUEST", nil)
	}
	unlock, err := e.lock(parent)
	if err != nil {
		return TLSBindingStatus{}, err
	}
	defer unlock()
	e.beginMutation()
	defer e.endMutation()

	if e.options.DataDir == "" {
		return TLSBindingStatus{}, failure("DATA_DIR_UNAVAILABLE", nil)
	}
	store, closeStore, err := openConsumerStore(e.options.DataDir)
	if err != nil {
		return TLSBindingStatus{}, failure("TLS_MATERIAL_UNAVAILABLE", err)
	}
	defer closeStore()

	proof, err := store.Current(parent, req.BindingRef)
	if err != nil || proof == nil {
		return TLSBindingStatus{}, failure("TLS_MATERIAL_UNAVAILABLE", err)
	}
	if proof.Binding.ID != req.BindingRef ||
		proof.Binding.Consumer.ProfileID != req.ProfileID ||
		proof.Binding.Consumer.SNI != req.SNI ||
		proof.Binding.Generation != req.Generation ||
		proof.Binding.PolicyRevision != req.PolicyRevision ||
		proof.FullchainSHA256 != req.FullchainSHA256 ||
		proof.PrivateKeySHA256 != req.PrivateKeySHA256 {
		return TLSBindingStatus{}, failure("TLS_PROOF_MISMATCH", nil)
	}
	mat, err := store.Load(parent, *proof)
	if err != nil {
		return TLSBindingStatus{}, failure("TLS_MATERIAL_UNAVAILABLE", err)
	}
	defer mat.Clear()

	roots, rootErr := e.roots()
	trust, _, meta, verr := validateConsumerMaterial(mat, req.SNI, e.now(), roots, e.options.PermitTestCertificates)
	if verr != nil || (trust != tlsmgr.TestTrust && rootErr != nil) {
		return TLSBindingStatus{}, failure("TLS_MATERIAL_INVALID", verr)
	}

	status := TLSBindingStatus{
		BindingRef:      req.BindingRef,
		ProfileID:       req.ProfileID,
		PublicTrusted:   trust == tlsmgr.PublicTrust,
		Generation:      req.Generation,
		PolicyRevision:  req.PolicyRevision,
		FullchainSHA256: req.FullchainSHA256,
		LeafFingerprint: meta.Fingerprint,
		SNI:             req.SNI,
	}

	old, err := e.options.Store.Committed(parent)
	if err != nil {
		return TLSBindingStatus{}, stateFailure(err)
	}
	if old != nil && old.Current != nil && old.Current.Enabled && old.Current.SummaryV2 != nil {
		if prof, found := old.Current.SummaryV2.FindTLSProfile(req.ProfileID, req.BindingRef); found && prof.Enabled {
			status.Endpoint = net.JoinHostPort(prof.Listen, strconv.Itoa(prof.Port))
			if prof.Protocol == corev2.ProtocolAnyTLS {
				if e.options.AnyTLS != nil {
					chainPEM, keyPEM := mat.CertificatePEM(), mat.PrivateKeyPEM()
					reloaded, rerr := e.options.AnyTLS.ReloadCertificate(prof.ID, req.BindingRef, chainPEM, keyPEM)
					if rerr != nil {
						clear(chainPEM)
						clear(keyPEM)
						return TLSBindingStatus{}, failure("TLS_MATERIAL_INVALID", rerr)
					}
					if reloaded {
						e.updateCachedAnyTLSCert(prof.ID, chainPEM, keyPEM)
					}
					clear(chainPEM)
					clear(keyPEM)
					status.Running = reloaded
				}
			} else {
				if err := e.applyReloadedTLS(parent, old, prof, mat); err != nil {
					return TLSBindingStatus{}, err
				}
				status.Running = true
			}
		}
	}

	e.mu.Lock()
	if e.tlsBindings == nil {
		e.tlsBindings = make(map[string]TLSBindingStatus)
	}
	e.tlsBindings[req.BindingRef] = status
	e.mu.Unlock()
	return status, nil
}

// applyReloadedTLS 基于已提交的 0600 原生配置仅替换指定 Hysteria2 入站的证书链与私钥，
// 走完整的 Preflight -> Install -> StopOld -> Start -> WaitHealthy -> Commit，并在失败时自动回滚旧进程。
func (e *Engine) applyReloadedTLS(ctx context.Context, old *state.Metadata, prof state.PublicProfileSummary, mat tlsmgr.Material) error {
	oldPath, err := e.options.Store.GenerationPath(ctx, old.Current.Digest)
	if err != nil {
		return stateFailure(err)
	}
	rawOld, err := os.ReadFile(oldPath)
	if err != nil {
		return failure("DATA_DIR_UNAVAILABLE", err)
	}
	defer clear(rawOld)

	tag, err := coreapi.InboundTag(prof.ID)
	if err != nil {
		return failure("INVALID_INTENT", err)
	}
	chainPEM, keyPEM := mat.CertificatePEM(), mat.PrivateKeyPEM()
	defer clear(chainPEM)
	defer clear(keyPEM)

	updated, err := swapHysteriaTLSInNativeConfig(rawOld, tag, prof.ServerName, chainPEM, keyPEM)
	if err != nil {
		return failure("CORE_CONFIG_INVALID", err)
	}
	defer clear(updated)

	workID := "tls-reload-" + strconv.FormatInt(e.now().UnixNano(), 10)
	work, err := e.options.Store.Stage(ctx, workID, 1, updated)
	if err != nil {
		return stateFailure(err)
	}
	defer func() { _ = e.options.Store.CleanWork(context.WithoutCancel(ctx), workID, 1) }()

	if err := e.options.Binary.Preflight(ctx, work.Path); err != nil {
		return failure("CORE_CONFIG_INVALID", contextCause(ctx))
	}
	if err := e.options.Store.Install(ctx, work); err != nil {
		return stateFailure(err)
	}

	next := cloneMetadata(old)
	next.Previous = old.Current
	nextGen := *old.Current
	nextGen.Digest = work.Digest
	next.Current = &nextGen

	if err := e.stop(ctx); err != nil {
		return err
	}
	if err := e.start(ctx, next.Current); err != nil {
		_ = e.rollbackReloadedTLS(ctx, old)
		return err
	}
	if err := e.options.Process.WaitHealthy(ctx); err != nil {
		_ = e.rollbackReloadedTLS(ctx, old)
		return failure("CORE_API_UNAVAILABLE", contextCause(ctx))
	}
	observed := e.options.Process.Snapshot(ctx)
	if observed.State != "RUNNING" || observed.APIState != "READY" || observed.Digest != next.Current.Digest {
		_ = e.rollbackReloadedTLS(ctx, old)
		return failure("CORE_API_UNAVAILABLE", nil)
	}
	if err := e.restartObfsForSummary(next.Current.SummaryV2); err != nil {
		_ = e.rollbackReloadedTLS(ctx, old)
		return failure("OBFS_START_FAILED", err)
	}
	if err := e.restartAnyTLSForSummary(ctx, next.Current.SummaryV2); err != nil {
		_ = e.rollbackReloadedTLS(ctx, old)
		return failure("CORE_START_FAILED", err)
	}
	next.State, next.ResetEpoch = "RUNNING", observed.Epoch
	if err := e.options.Store.Commit(ctx, next); err != nil {
		_ = e.rollbackReloadedTLS(ctx, old)
		return failure("STATE_COMMIT_FAILED", contextCause(ctx))
	}
	_ = e.options.Process.MarkCommitted()
	return nil
}

func (e *Engine) rollbackReloadedTLS(parent context.Context, old *state.Metadata) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
	defer cancel()
	_ = e.stop(cleanup)
	if old != nil && old.Current != nil && old.Current.Enabled {
		if err := e.start(cleanup, old.Current); err != nil {
			return err
		}
		if err := e.options.Process.WaitHealthy(cleanup); err != nil {
			return err
		}
		if err := e.restartObfsForSummary(old.Current.SummaryV2); err != nil {
			return err
		}
		if err := e.restartAnyTLSForSummary(cleanup, old.Current.SummaryV2); err != nil {
			return err
		}
		_ = e.options.Store.Restore(cleanup, old)
		_ = e.options.Process.MarkCommitted()
	}
	return nil
}

func (e *Engine) restartObfsForSummary(summary *state.V2IntentSummary) error {
	if e.options.Obfs == nil {
		return nil
	}
	e.mu.Lock()
	lifetime := e.lifetime
	plans := append([]xrayconfig.ObfsPlan(nil), e.obfsPlans...)
	e.mu.Unlock()
	if len(plans) == 0 && summary != nil {
		plans = summary.ObfsPlans()
	}
	if len(plans) == 0 {
		return nil
	}
	if err := e.options.Obfs.StartAll(lifetime, plans); err != nil {
		return err
	}
	e.mu.Lock()
	e.obfsPlans = append([]xrayconfig.ObfsPlan(nil), plans...)
	e.mu.Unlock()
	return nil
}

func swapHysteriaTLSInNativeConfig(raw []byte, tag, serverName string, chainPEM, keyPEM []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	inbounds, ok := doc["inbounds"].([]any)
	if !ok {
		return nil, errors.New("apply: native config missing inbounds")
	}
	chainLines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(chainPEM), "\r\n", "\n")), "\n")
	keyLines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(keyPEM), "\r\n", "\n")), "\n")
	replaced := false
	for _, entry := range inbounds {
		inbound, ok := entry.(map[string]any)
		if !ok || inbound["tag"] != tag {
			continue
		}
		stream, ok := inbound["streamSettings"].(map[string]any)
		if !ok {
			return nil, errors.New("apply: hysteria inbound missing streamSettings")
		}
		tlsObj, ok := stream["tlsSettings"].(map[string]any)
		if !ok {
			return nil, errors.New("apply: hysteria inbound missing tlsSettings")
		}
		tlsObj["serverName"] = serverName
		tlsObj["certificates"] = []map[string]any{{
			"certificate":    chainLines,
			"key":            keyLines,
			"usage":          "encipherment",
			"oneTimeLoading": true,
		}}
		replaced = true
		break
	}
	if !replaced {
		return nil, errors.New("apply: target hysteria inbound tag not found")
	}
	return json.Marshal(doc)
}

// InspectTLS 诚实汇报指定 TLS 绑定在当前运行实例上的实时生效状态、指纹与监听端点。
func (e *Engine) InspectTLS(ctx context.Context, bindingRef, profileID string) (TLSBindingStatus, error) {
	if bindingRef == "" || profileID == "" {
		return TLSBindingStatus{}, failure("INVALID_REQUEST", nil)
	}
	e.mu.Lock()
	cached, hasCached := e.tlsBindings[bindingRef]
	e.mu.Unlock()

	result := TLSBindingStatus{BindingRef: bindingRef, ProfileID: profileID}
	if hasCached && cached.ProfileID == profileID {
		result = cached
	} else if e.options.DataDir != "" {
		if store, closeStore, err := openConsumerStore(e.options.DataDir); err == nil {
			defer closeStore()
			if proof, perr := store.Current(ctx, bindingRef); perr == nil && proof != nil &&
				proof.Binding.Consumer.ProfileID == profileID {
				result.Generation = proof.Binding.Generation
				result.PolicyRevision = proof.Binding.PolicyRevision
				result.FullchainSHA256 = proof.FullchainSHA256
				result.SNI = proof.Binding.Consumer.SNI
				if mat, lerr := store.Load(ctx, *proof); lerr == nil {
					roots, _ := e.roots()
					if trust, _, meta, verr := validateConsumerMaterial(mat, proof.Binding.Consumer.SNI, e.now(), roots, e.options.PermitTestCertificates); verr == nil {
						result.PublicTrusted = trust == tlsmgr.PublicTrust
						result.LeafFingerprint = meta.Fingerprint
					}
					mat.Clear()
				}
			}
		}
	}

	result.Running = false
	result.Endpoint = ""
	committed, err := e.options.Store.Committed(ctx)
	if err != nil || committed == nil || committed.Current == nil || !committed.Current.Enabled || committed.Current.SummaryV2 == nil {
		return result, nil
	}
	prof, found := committed.Current.SummaryV2.FindTLSProfile(profileID, bindingRef)
	if !found || !prof.Enabled {
		return result, nil
	}
	result.Endpoint = net.JoinHostPort(prof.Listen, strconv.Itoa(prof.Port))
	if result.SNI == "" {
		result.SNI = prof.ServerName
	}
	if prof.Protocol == corev2.ProtocolAnyTLS {
		if e.options.AnyTLS != nil && e.options.AnyTLS.IsRunning(prof.ID) && result.Generation > 0 {
			result.Running = true
		}
	} else {
		observed := e.options.Process.Snapshot(ctx)
		if observed.State == "RUNNING" && observed.APIState == "READY" && observed.Digest == committed.Current.Digest && result.Generation > 0 {
			result.Running = true
		}
	}
	return result, nil
}

type persistedAnyTLSProfile struct {
	ProfileID     string            `json:"profile_id"`
	BindingRef    string            `json:"binding_ref"`
	ServerName    string            `json:"server_name"`
	Listen        string            `json:"listen"`
	Port          int               `json:"port"`
	PaddingScheme []string          `json:"padding_scheme,omitempty"`
	UserDigests   map[string]string `json:"user_digests"`
	UserMarks     map[string]uint32 `json:"user_marks,omitempty"`
}

const anytlsStateFile = "runtime/anytls_state.json"

func (e *Engine) persistAnyTLSSpecs(specs []anytls.ProfileSpec) {
	if e.options.DataDir == "" {
		return
	}
	root, err := os.OpenRoot(e.options.DataDir)
	if err != nil {
		return
	}
	defer root.Close()
	if len(specs) == 0 {
		_ = root.Remove(anytlsStateFile)
		return
	}
	records := make([]persistedAnyTLSProfile, 0, len(specs))
	for _, s := range specs {
		digests := make(map[string]string, len(s.Users)+len(s.UserDigests))
		for uid, d := range s.UserDigests {
			digests[uid] = hex.EncodeToString(d[:])
		}
		for uid, pwd := range s.Users {
			sum := sha256.Sum256(pwd)
			digests[uid] = hex.EncodeToString(sum[:])
		}
		var marks map[string]uint32
		if len(s.UserMarks) > 0 {
			marks = make(map[string]uint32, len(s.UserMarks))
			for uid, m := range s.UserMarks {
				if m != 0 {
					marks[uid] = m
				}
			}
		}
		records = append(records, persistedAnyTLSProfile{
			ProfileID:     s.ProfileID,
			BindingRef:    s.BindingRef,
			ServerName:    s.ServerName,
			Listen:        s.Listen,
			Port:          s.Port,
			PaddingScheme: slices.Clone(s.PaddingScheme),
			UserDigests:   digests,
			UserMarks:     marks,
		})
	}
	raw, err := json.Marshal(records)
	if err != nil {
		return
	}
	_ = root.Mkdir("runtime", 0o700)
	_ = sandbox.WriteFileAtomicIn(root, anytlsStateFile, raw, 0o600)
}

func (e *Engine) loadPersistedAnyTLS() (map[string]persistedAnyTLSProfile, error) {
	if e.options.DataDir == "" {
		return nil, fs.ErrNotExist
	}
	root, err := os.OpenRoot(e.options.DataDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	raw, err := root.ReadFile(anytlsStateFile)
	if err != nil {
		return nil, err
	}
	var records []persistedAnyTLSProfile
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, err
	}
	byID := make(map[string]persistedAnyTLSProfile, len(records))
	for _, rec := range records {
		byID[rec.ProfileID] = rec
	}
	return byID, nil
}

func (e *Engine) updateCachedAnyTLSCert(profileID string, certPEM, keyPEM []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.anytlsSpecs {
		if e.anytlsSpecs[i].ProfileID == profileID {
			clear(e.anytlsSpecs[i].CertPEM)
			clear(e.anytlsSpecs[i].KeyPEM)
			e.anytlsSpecs[i].CertPEM = append([]byte(nil), certPEM...)
			e.anytlsSpecs[i].KeyPEM = append([]byte(nil), keyPEM...)
			break
		}
	}
}

func (e *Engine) rebuildAnyTLSSpecs(ctx context.Context, summary *state.V2IntentSummary) ([]anytls.ProfileSpec, error) {
	if summary == nil {
		return nil, nil
	}
	enabled := summary.EnabledAnyTLSProfiles()
	if len(enabled) == 0 {
		return nil, nil
	}
	e.mu.Lock()
	cached := cloneAnyTLSSpecs(e.anytlsSpecs)
	e.mu.Unlock()
	if len(cached) > 0 {
		byID := make(map[string]anytls.ProfileSpec, len(cached))
		for _, s := range cached {
			byID[s.ProfileID] = s
		}
		matched := make([]anytls.ProfileSpec, 0, len(enabled))
		allFound := true
		for _, prof := range enabled {
			s, ok := byID[prof.ID]
			if !ok {
				allFound = false
				break
			}
			matched = append(matched, s)
		}
		if allFound {
			return matched, nil
		}
		clearAnyTLSSpecs(cached)
	}

	persisted, err := e.loadPersistedAnyTLS()
	if err != nil {
		return nil, err
	}
	loader := &consumerDirTLSLoader{engine: e, dataDir: e.options.DataDir}
	out := make([]anytls.ProfileSpec, 0, len(enabled))
	for _, prof := range enabled {
		rec, ok := persisted[prof.ID]
		if !ok || len(rec.UserDigests) == 0 {
			clearAnyTLSSpecs(out)
			return nil, errors.New("apply: missing persisted anytls profile " + prof.ID)
		}
		digests := make(map[string][32]byte, len(rec.UserDigests))
		for uid, hexStr := range rec.UserDigests {
			rawDigest, derr := hex.DecodeString(hexStr)
			if derr != nil || len(rawDigest) != 32 {
				clearAnyTLSSpecs(out)
				return nil, errors.New("apply: corrupt anytls user digest")
			}
			var arr [32]byte
			copy(arr[:], rawDigest)
			digests[uid] = arr
		}
		tlsMat, terr := loader.LoadTLS(ctx, prof.ID, prof.BindingRef, prof.ServerName)
		if terr != nil {
			clearAnyTLSSpecs(out)
			return nil, terr
		}
		certPEM := tlsMat.Material.CertificatePEM()
		keyPEM := tlsMat.Material.PrivateKeyPEM()
		tlsMat.Material.Clear()
		out = append(out, anytls.ProfileSpec{
			ProfileID:     prof.ID,
			BindingRef:    prof.BindingRef,
			ServerName:    prof.ServerName,
			Listen:        prof.Listen,
			Port:          prof.Port,
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			PaddingScheme: slices.Clone(rec.PaddingScheme),
			UserDigests:   digests,
			UserMarks:     rec.UserMarks,
		})
	}
	return out, nil
}

func (e *Engine) restartAnyTLSForSummary(ctx context.Context, summary *state.V2IntentSummary) error {
	if e.options.AnyTLS == nil || summary == nil {
		return nil
	}
	specs, err := e.rebuildAnyTLSSpecs(ctx, summary)
	if err != nil {
		return err
	}
	if len(specs) == 0 {
		return nil
	}
	e.mu.Lock()
	lifetime := e.lifetime
	e.mu.Unlock()
	if err := e.options.AnyTLS.StartAll(lifetime, specs); err != nil {
		clearAnyTLSSpecs(specs)
		return err
	}
	e.mu.Lock()
	oldStored := e.anytlsSpecs
	e.anytlsSpecs = cloneAnyTLSSpecs(specs)
	e.mu.Unlock()
	clearAnyTLSSpecs(oldStored)
	clearAnyTLSSpecs(specs)
	return nil
}

func buildAnyTLSSpecs(intent *corev2.Intent, materials xrayconfig.V2Materials) []anytls.ProfileSpec {
	if intent == nil {
		return nil
	}
	var out []anytls.ProfileSpec
	for _, p := range intent.Profiles {
		if p.Enabled == nil || !*p.Enabled || p.Protocol != corev2.ProtocolAnyTLS || p.AnyTLS == nil || p.AnyTLS.TLS == nil {
			continue
		}
		pm, ok := materials.Profiles[p.ID]
		if !ok || pm.AnyTLS == nil {
			continue
		}
		users := make(map[string][]byte, len(pm.AnyTLS.Auth))
		for uid, pwd := range pm.AnyTLS.Auth {
			users[uid] = append([]byte(nil), pwd...)
		}
		var userMarks map[string]uint32
		for _, u := range p.Users {
			if u.TrafficMark != 0 {
				if userMarks == nil {
					userMarks = make(map[string]uint32)
				}
				userMarks[u.ID] = u.TrafficMark
			}
		}
		out = append(out, anytls.ProfileSpec{
			ProfileID:     p.ID,
			BindingRef:    p.AnyTLS.TLS.BindingRef,
			ServerName:    p.AnyTLS.TLS.ServerName,
			Listen:        p.Listen,
			Port:          p.Port,
			CertPEM:       pm.AnyTLS.TLS.Material.CertificatePEM(),
			KeyPEM:        pm.AnyTLS.TLS.Material.PrivateKeyPEM(),
			PaddingScheme: slices.Clone(p.AnyTLS.PaddingScheme),
			Users:         users,
			UserMarks:     userMarks,
		})
	}
	return out
}

func cloneAnyTLSSpecs(specs []anytls.ProfileSpec) []anytls.ProfileSpec {
	if len(specs) == 0 {
		return nil
	}
	out := make([]anytls.ProfileSpec, len(specs))
	for i, s := range specs {
		users := make(map[string][]byte, len(s.Users))
		for uid, pwd := range s.Users {
			users[uid] = append([]byte(nil), pwd...)
		}
		var digests map[string][32]byte
		if len(s.UserDigests) > 0 {
			digests = make(map[string][32]byte, len(s.UserDigests))
			for uid, d := range s.UserDigests {
				digests[uid] = d
			}
		}
		var marks map[string]uint32
		if len(s.UserMarks) > 0 {
			marks = make(map[string]uint32, len(s.UserMarks))
			for uid, m := range s.UserMarks {
				marks[uid] = m
			}
		}
		out[i] = anytls.ProfileSpec{
			ProfileID:     s.ProfileID,
			BindingRef:    s.BindingRef,
			ServerName:    s.ServerName,
			Listen:        s.Listen,
			Port:          s.Port,
			CertPEM:       append([]byte(nil), s.CertPEM...),
			KeyPEM:        append([]byte(nil), s.KeyPEM...),
			PaddingScheme: slices.Clone(s.PaddingScheme),
			Users:         users,
			UserDigests:   digests,
			UserMarks:     marks,
		}
	}
	return out
}

func clearAnyTLSSpecs(specs []anytls.ProfileSpec) {
	for i := range specs {
		clear(specs[i].CertPEM)
		clear(specs[i].KeyPEM)
		specs[i].CertPEM = nil
		specs[i].KeyPEM = nil
		for uid, pwd := range specs[i].Users {
			clear(pwd)
			delete(specs[i].Users, uid)
		}
		clear(specs[i].UserDigests)
	}
}
