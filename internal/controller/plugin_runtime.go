// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/capability"
	"github.com/qwq-panel/qwq/internal/capability/account"
	"github.com/qwq-panel/qwq/internal/capability/ban"
	"github.com/qwq-panel/qwq/internal/capability/firewall"
	"github.com/qwq-panel/qwq/internal/capability/metrics"
	"github.com/qwq-panel/qwq/internal/capability/pluginconfig"
	"github.com/qwq-panel/qwq/internal/capability/sshd"
	"github.com/qwq-panel/qwq/internal/capability/traffic"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/events"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/pluginpublic"
	"github.com/qwq-panel/qwq/internal/privateexport"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// This file is the integration seam between the plugin runtime
// (internal/pluginhost/supervisor, internal/pluginhost/hostsvc,
// internal/sandbox) and the host services (storage, operations, secrets). It
// adds no policy of its own: every decision is delegated to the owner of the
// concerned domain, and every adapter is small enough to review on its own
// (ADR-0008 §1).
//
// The runtime is assembled in cmd/qwq/serve.go:
//
//	rt, err := controller.NewPluginRuntime(controller.PluginRuntimeOptions{
//		Units:     controller.UnitManagerAdapter{Systemctl: systemd},
//		PluginDir: controller.PluginDirResolver("/var/lib/qwq-plugins"),
//		RunDir:    cfg.RunDir,
//		StateDir:  filepath.Join(cfg.DataDir, "plugin-state"),
//		Logger:    logger,
//	})
//	c, err := controller.New(ctx, controller.Options{Config: cfg, PluginRuntime: rt})
//	err = rt.Start(ctx, c.HostDeps())
//
// A host without plugin units (tests, a build without systemd, a non-standalone
// role) passes a nil PluginRuntime; operations then reports UNAVAILABLE for
// every plugin action instead of pretending to dispatch it.

const (
	// DefaultInstanceID is the single instance of a plugin this release runs
	// per node (ADR-0002 allows several; P2 runs one).
	DefaultInstanceID = "default"

	// DefaultPluginsDir is where the privileged installer places plugin
	// package versions: <dir>/<plugin_id>/<version>/.
	DefaultPluginsDir = "/var/lib/qwq-plugins"

	// hostStopTimeout bounds how long the host channel waits for hostsvc to
	// finish in-flight calls when the supervisor stops an instance.
	hostStopTimeout = 5 * time.Second

	// hostStartTimeout bounds how long an attach waits for the host socket to
	// appear. hostsvc creates the listener at the start of Serve, so a longer
	// wait only happens when the socket directory is unusable.
	hostStartTimeout = 5 * time.Second

	// hostStartPoll is the socket poll interval of hostStartTimeout.
	hostStartPoll = 5 * time.Millisecond

	// peerMainPIDTimeout bounds the systemd lookup the peer verifier falls
	// back to while the instance is not registered yet.
	peerMainPIDTimeout = 3 * time.Second

	// pluginSecretPurpose is the purpose the host records for the secrets of a
	// plugin instance's config snapshot (internal/secrets: ExtractOptions uses
	// "plugin.config" for plugin references). A reveal with another purpose is
	// refused by the store (X3: plugin.operation secrets are revealed only by
	// host capability forwarders, never by the plugin process itself).
	pluginSecretPurpose = "plugin.config"
)

// --- supervisor.UnitManager -------------------------------------------------

// UnitManagerAdapter adapts internal/sandbox's systemctl client to
// supervisor.UnitManager. It maps a plugin id to the concrete
// qwq-plugin@<id>.service unit (ADR-0003 §1) and never caches unit state:
// systemd is asked every time, because MainPID changes whenever the unit
// restarts out of band.
type UnitManagerAdapter struct {
	// Systemctl runs systemctl as the unprivileged agent user; polkit decides
	// whether the action is allowed (deployments/polkit/qwq-plugin.rules).
	Systemctl sandbox.Systemctl
	// NodeID is not used for policy; it labels the adapter for logs.
	NodeID string
}

// Unit returns the service unit of pluginID.
func (u UnitManagerAdapter) Unit(pluginID string) (string, error) {
	if u.Systemctl == nil {
		return "", problem.New(problem.Unavailable,
			"The systemd unit manager is not configured on this host.")
	}
	service, _, err := sandbox.UnitNames(pluginID)
	if err != nil {
		return "", problem.New(problem.ValidationFailed,
			"Plugin %q cannot be managed as a systemd unit.", pluginID)
	}
	return service, nil
}

// Start starts the plugin unit.
func (u UnitManagerAdapter) Start(ctx context.Context, pluginID string) error {
	unit, err := u.Unit(pluginID)
	if err != nil {
		return err
	}
	return u.Systemctl.Start(ctx, unit)
}

// Stop stops the plugin unit. KillMode=control-group cleans the whole cgroup.
func (u UnitManagerAdapter) Stop(ctx context.Context, pluginID string) error {
	unit, err := u.Unit(pluginID)
	if err != nil {
		return err
	}
	return u.Systemctl.Stop(ctx, unit)
}

// Kill sends SIGKILL to the unit's main process.
func (u UnitManagerAdapter) Kill(ctx context.Context, pluginID string) error {
	unit, err := u.Unit(pluginID)
	if err != nil {
		return err
	}
	return u.Systemctl.Kill(ctx, unit)
}

// Show reads the unit state from systemd. StartTime is systemd's
// ExecMainStartTimestamp, which together with the unit name and MainPID
// identifies the process generation.
func (u UnitManagerAdapter) Show(ctx context.Context, pluginID string) (supervisor.UnitState, error) {
	unit, err := u.Unit(pluginID)
	if err != nil {
		return supervisor.UnitState{}, err
	}
	st, err := u.Systemctl.Show(ctx, unit)
	if err != nil {
		return supervisor.UnitState{}, err
	}
	return supervisor.UnitState{
		MainPID:      st.MainPID,
		ControlGroup: st.ControlGroup,
		ActiveState:  st.ActiveState,
		SubState:     st.SubState,
		StartTime:    st.StartTime,
	}, nil
}

// --- peer identity ---------------------------------------------------------

// InstanceInfo is the host-side identity of one attached plugin process
// generation. Every field comes from systemd or the supervisor, never from the
// plugin: MainPID from systemd, Generation and Owner derived from it.
type InstanceInfo struct {
	PluginID   string
	MainPID    int
	Generation string
	Owner      string
}

// InstanceSource reports the live instance of pluginID, if any.
type InstanceSource func(pluginID string) (InstanceInfo, bool)

// SupervisorInstances returns the InstanceSource backed by sup. Only a running
// instance is reported: a degraded or detached plugin has no process a peer
// could legitimately belong to.
func SupervisorInstances(sup *supervisor.Supervisor) InstanceSource {
	if sup == nil {
		return nil
	}
	return func(pluginID string) (InstanceInfo, bool) {
		for _, st := range sup.Instances() {
			if st.PluginID != pluginID || st.State != supervisor.StateRunning {
				continue
			}
			return InstanceInfo{
				PluginID:   st.PluginID,
				MainPID:    st.MainPID,
				Generation: st.Generation,
				Owner:      st.Owner,
			}, true
		}
		return InstanceInfo{}, false
	}
}

// PeerVerifier is the production hostsvc.PeerVerifier of one plugin instance. It
// decides whether the process on the other end of the host socket is the main
// process of that plugin's unit, using only kernel and systemd facts:
//
//   - the unit name in /proc/<pid>/cgroup must equal qwq-plugin@<id>.service;
//   - the peer pid must be the unit's main process (systemd's current MainPID,
//     or the supervisor's cached instance);
//   - the peer must not run as root, and when ExpectedUID resolves the plugin's
//     service user, the uid must match it as well.
//
// systemd is asked first because the host channel is resident: the updater may
// restart the unit while the supervisor still caches the previous process. The
// unit check and the peer uid check apply in both paths.
type PeerVerifier struct {
	// PluginID is the plugin the protected host socket belongs to.
	PluginID string
	// Unit is the systemd unit of the plugin (qwq-plugin@<id>.service).
	Unit string
	// Instances reports the supervisor's current instance of PluginID.
	Instances InstanceSource
	// MainPID reads the unit's current main process from systemd. It is
	// consulted first; Instances is the fallback.
	MainPID func(pluginID string) (int, error)
	// ExpectedUID resolves the uid of the plugin's service user. A resolver
	// that does not know returns ok=false, which skips only the uid equality
	// check (the unit and pid checks still apply).
	ExpectedUID func(pluginID string) (uid int, ok bool)
	// ProcRoot is the procfs mount; "/proc" when empty. Tests override it.
	ProcRoot string
	// Logger receives rejections at debug level; the server logs and closes
	// the connection itself.
	Logger *slog.Logger
}

// Verify implements hostsvc.PeerVerifier. Every failure is returned as an error
// and closes the connection: there is no anonymous fallback.
func (v *PeerVerifier) Verify(pid, uid int) error {
	if v == nil || v.PluginID == "" || v.Unit == "" {
		return errors.New("controller: the peer verifier is not configured for a plugin")
	}
	if pid <= 0 {
		return fmt.Errorf("controller: peer pid %d is not usable", pid)
	}
	// Plugins run with DynamicUser=yes (deployments/systemd/qwq-plugin@.service),
	// so a root peer is a wiring error, not a plugin.
	if uid == 0 {
		return errors.New("controller: the plugin peer runs as root")
	}
	inst, err := v.matchMainPID(pid)
	if err != nil {
		return err
	}
	unit, err := ReadCgroupUnit(v.procRoot(), pid)
	if err != nil {
		return fmt.Errorf("controller: read the cgroup of peer pid %d: %w", pid, err)
	}
	if unit != v.Unit {
		return fmt.Errorf("controller: peer pid %d belongs to unit %q, not %q", pid, unit, v.Unit)
	}
	if v.ExpectedUID != nil {
		if want, known := v.ExpectedUID(v.PluginID); known && uid != want {
			return fmt.Errorf("controller: peer of plugin %q has uid %d, want %d", v.PluginID, uid, want)
		}
	}
	if v.Logger != nil && inst.Generation != "" {
		v.Logger.Debug("verified plugin peer",
			"plugin_id", v.PluginID, "pid", pid, "generation", inst.Generation, "owner", inst.Owner)
	}
	return nil
}

// matchMainPID checks pid against the unit's main process. systemd is asked
// first: after the updater restarted the unit the supervisor may still cache
// the previous process. The supervisor's instance is the fallback, and the
// peer is rejected only when it matches neither.
func (v *PeerVerifier) matchMainPID(pid int) (InstanceInfo, error) {
	known := false
	if v.MainPID != nil {
		if mainPID, err := v.MainPID(v.PluginID); err == nil && mainPID > 0 {
			if pid == mainPID {
				return InstanceInfo{}, nil
			}
			known = true
		}
	}
	if v.Instances != nil {
		if inst, ok := v.Instances(v.PluginID); ok && inst.MainPID > 0 {
			if pid == inst.MainPID {
				return inst, nil
			}
			known = true
		}
	}
	if !known {
		return InstanceInfo{}, fmt.Errorf("controller: no running instance of plugin %q to match peer pid %d", v.PluginID, pid)
	}
	return InstanceInfo{}, fmt.Errorf("controller: peer pid %d is not the main process of plugin %q", pid, v.PluginID)
}

// procRoot returns the configured procfs mount.
func (v *PeerVerifier) procRoot() string {
	if v.ProcRoot == "" {
		return "/proc"
	}
	return v.ProcRoot
}

// ReadCgroupUnit returns the systemd unit name found in the cgroup path of pid.
// It reads /proc/<pid>/cgroup, which the plugin cannot influence from inside its
// own namespace, and returns "" when no unit component is present.
func ReadCgroupUnit(procRoot string, pid int) (string, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	return CgroupUnit(string(data)), nil
}

// CgroupUnit extracts the unit name from the content of a cgroup file. It
// understands both the unified hierarchy ("0::/system.slice/...") and the v1
// lines ("4:name=systemd:/system.slice/...") and unescapes the \xNN sequences
// systemd uses for "-" in slice names.
func CgroupUnit(data string) string {
	return sandbox.CgroupUnit(data)
}

// --- runtime assembly ------------------------------------------------------

// HostDeps are the host services a plugin host channel uses. A nil field
// disables the affected Host RPC with UNAVAILABLE: an agent process that has no
// database still starts its channel but cannot publish events, reveal secrets,
// invoke other plugins or write host audits.
type HostDeps struct {
	DB             *storage.DB
	Ops            *operations.Service
	Secrets        *secrets.Store
	PrivateExports *privateexport.Service
	// Config 为受保护的插件通道绑定只读配置源；nil 时 GetConfig 不可用。
	Config func(pluginID string) hostsvc.ConfigSource
	// SyncActiveConfig 同步跨插件 PutPluginConfig 写入后的内存配置快照。
	SyncActiveConfig func(pluginID string, rev int64, raw []byte)
	// Catalog supplies the verified manifest grants a plugin-to-plugin call is
	// checked against; nil refuses every such call.
	Catalog *catalog.Catalog
	// Lossy routes high-frequency realtime plugin telemetry samples in memory
	// without writing to SQLite event_journal (OPT-08).
	Lossy  *events.Lossy
	IDs    *ids.Generator
	Clock  clock.Clock
	Logger *slog.Logger
	// NodeID scopes resource subjects and the operation target check; "local"
	// when empty.
	NodeID string
}

// PluginRuntimeOptions configure NewPluginRuntime. Units and PluginDir are
// required; the rest fills in production defaults.
type PluginRuntimeOptions struct {
	// Units manages the systemd units of plugin instances.
	Units supervisor.UnitManager
	// PluginDir resolves the installed version directory of a plugin.
	PluginDir func(pluginID string) (versionDir string, err error)
	// RunDir is the runtime root (default supervisor.DefaultRunDir).
	RunDir string
	// StateDir holds the per-plugin KV state, <StateDir>/<id>/state.json. It
	// must be on persistent storage; serve passes <DataDir>/plugin-state. It is
	// required: /run is a tmpfs, so there is no fallback below RunDir (PLG-06).
	StateDir string
	// Clock defaults to clock.System.
	Clock clock.Clock
	// Logger defaults to a discard logger.
	Logger *slog.Logger
	// NodeID labels lifecycle records; "local" when empty.
	NodeID string
	// PluginsRoot is the installed package root (<root>/<id>/<version>). When
	// set, Start serves the host channel of every installed plugin so that a
	// plugin systemd restarts on its own finds it (pluginsdk waits only 5s).
	PluginsRoot string
	// Host overrides the per-plugin host channel mux. Nil builds the
	// production mux over hostsvc; tests substitute a fake.
	Host func(pluginID string) (supervisor.HostServer, error)
	// CapabilityForwarder 是能力执行/宿主事实注入的组合适配器；未接线时拒绝调用。
	CapabilityForwarder hostsvc.CapabilityForwarder
	// ManagementPorts 来自宿主实际监听配置，插件消息不能修改。
	ManagementPorts []uint32
	// ManagementPortsFunc 可选动态返回宿主当前管理监听端口（如 panelaccess 热换端口后）。
	ManagementPortsFunc func() []uint32
}

// PluginRuntime owns the plugin supervisor and the adapters that connect it to
// the host services. It is safe for concurrent use; Start and Stop are
// idempotent and a stopped runtime refuses new work.
type PluginRuntime struct {
	opts       PluginRuntimeOptions
	sup        *supervisor.Supervisor
	dispatcher *pluginDispatcher

	mu       sync.Mutex
	deps     HostDeps
	lifetime context.Context
	started  bool
	stopped  bool

	// hostFactory builds one plugin's host channel; hosts holds the resident
	// ones by plugin id. hostMu serializes their creation and teardown.
	hostFactory func(pluginID string) (supervisor.HostServer, error)
	hostMu      sync.Mutex
	hosts       map[string]func()
	// hostCapabilities 只保存宿主验签后供启动/恢复使用的授权快照。
	hostCapabilitiesMu sync.RWMutex
	hostCapabilities   map[string][]manifest.Capability

	// restore brings a plugin's ACTIVE version to a ready, active instance
	// (serve binds updater.EnsureActive). While it is bound the supervisor
	// only attaches: starting units and the ABI bootstrap belong to it.
	restore atomic.Pointer[func(ctx context.Context, pluginID string) error]

	// managementPortsFn 返回宿主当前活跃管理端口，未绑定时回退静态 ManagementPorts。
	managementPortsFn atomic.Pointer[func() []uint32]

	// publicGateway 负责 ADR-0024 /p/{plugin_id}/{route}/ 公开 HTTP 路由转发。
	publicGateway *pluginpublic.Gateway
}

// NewPluginRuntime validates opts and builds the supervisor. It performs no I/O
// and starts no plugin: Start binds the host services, Ensure (via the
// dispatcher) attaches plugins on demand.
func NewPluginRuntime(opts PluginRuntimeOptions) (*PluginRuntime, error) {
	switch {
	case opts.Units == nil:
		return nil, problem.New(problem.ValidationFailed, "controller: a plugin unit manager is required")
	case opts.PluginDir == nil:
		return nil, problem.New(problem.ValidationFailed, "controller: a plugin directory resolver is required")
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	defaultCapabilities := opts.CapabilityForwarder == nil
	if defaultCapabilities {
		collector, err := metrics.New(metrics.Options{Clock: opts.Clock})
		if err != nil {
			return nil, problem.New(problem.Unavailable, "The host metrics collector could not be configured.")
		}
		opts.CapabilityForwarder = capability.Forwarder{Services: map[string]hostsvc.CapabilityForwarder{
			"metrics":  metrics.Forwarder{Collector: collector},
			"firewall": firewall.Forwarder{Helper: sandbox.NewCapabilityClient(sandbox.DefaultCapabilitySocket), HostPorts: append([]uint32(nil), opts.ManagementPorts...)},
		}}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.NodeID == "" {
		opts.NodeID = "local"
	}
	runDir := filepath.Clean(opts.RunDir)
	if runDir == "." || runDir == "" {
		runDir = supervisor.DefaultRunDir
	}
	opts.RunDir = runDir
	if opts.StateDir == "" || !filepath.IsAbs(opts.StateDir) {
		return nil, problem.New(problem.ValidationFailed,
			"controller: the plugin state directory must be an absolute path on persistent storage")
	}
	opts.StateDir = filepath.Clean(opts.StateDir)
	migrateLegacyState(filepath.Join(runDir, "state"), opts.StateDir, opts.Logger)

	rt := &PluginRuntime{opts: opts, hosts: make(map[string]func())}
	if opts.ManagementPortsFunc != nil {
		fn := opts.ManagementPortsFunc
		rt.managementPortsFn.Store(&fn)
	}
	if defaultCapabilities {
		router := rt.opts.CapabilityForwarder.(capability.Forwarder)
		capClient := sandbox.NewCapabilityClient(sandbox.DefaultCapabilitySocket)
		router.Services["firewall"] = firewall.Forwarder{
			Helper:        capClient,
			HostPorts:     append([]uint32(nil), opts.ManagementPorts...),
			HostPortsFunc: rt.liveManagementPorts,
		}
		router.Services["sshd"] = sshd.Forwarder{
			Helper:        capClient,
			HostPorts:     append([]uint32(nil), opts.ManagementPorts...),
			HostPortsFunc: rt.liveManagementPorts,
			Addresses:     rt.capabilityAddresses,
		}
		router.Services["account"] = account.Forwarder{Helper: capClient, RevealSecret: rt.capabilityRevealOperationSecret}
		router.Services["ban"] = ban.Forwarder{Helper: capClient, Protected: rt.capabilityBanProtectedAddresses}
		router.Services["traffic"] = traffic.Forwarder{Helper: capClient}
		router.Services["pluginconfig"] = pluginconfig.Forwarder{Backend: &runtimePluginConfigBackend{rt: rt}}
	}
	rt.hostFactory = opts.Host
	if rt.hostFactory == nil {
		rt.hostFactory = rt.HostServer
	}
	sup, err := supervisor.New(supervisor.Options{
		Units: attachOnlyUnits{UnitManager: opts.Units, rt: rt},
		// The supervisor only makes sure the resident channel exists; its
		// per-generation stop is a no-op, so a drop does not remove host.sock.
		Host:      residentHost{rt: rt},
		PluginDir: opts.PluginDir,
		Clock:     opts.Clock,
		Logger:    opts.Logger,
		NodeID:    opts.NodeID,
		RunDir:    opts.RunDir,
		// A crashed plugin that systemd restarted has no instance; restore it
		// before the supervisor adopts the new generation.
		OnNewGeneration: rt.runRestore,
	})
	if err != nil {
		return nil, fmt.Errorf("controller: plugin supervisor: %w", err)
	}
	rt.sup = sup
	rt.dispatcher = &pluginDispatcher{clients: rt}
	return rt, nil
}

// SetManagementPortsFunc 绑定实时管理端口查询器（供防火墙与 SSH 能力防失联保留使用）。
func (rt *PluginRuntime) SetManagementPortsFunc(fn func() []uint32) {
	if rt == nil {
		return
	}
	if fn == nil {
		rt.managementPortsFn.Store(nil)
		return
	}
	rt.managementPortsFn.Store(&fn)
}

func (rt *PluginRuntime) liveManagementPorts() []uint32 {
	if rt == nil {
		return nil
	}
	if ptr := rt.managementPortsFn.Load(); ptr != nil && *ptr != nil {
		if ports := (*ptr)(); len(ports) > 0 {
			return ports
		}
	}
	return append([]uint32(nil), rt.opts.ManagementPorts...)
}

// RenewalJobHandler 处理宿主内部发起的 tls.certificates/renew_existing 作业。
type RenewalJobHandler func(ctx context.Context, req operations.PluginRunJobRequest) (bool, error)

// SetCapabilityService 在插件宿主通道启动前注册额外能力转发服务（例如 dns、certificates）。
func (rt *PluginRuntime) SetCapabilityService(name string, svc hostsvc.CapabilityForwarder) error {
	if rt == nil {
		return problem.New(problem.Unavailable, "controller: the plugin runtime is not enabled")
	}
	if name == "" || svc == nil {
		return problem.New(problem.ValidationFailed, "controller: capability service name and forwarder are required")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.started || rt.stopped {
		return problem.New(problem.PreconditionFailed, "controller: capability services must be registered before start")
	}
	router, ok := rt.opts.CapabilityForwarder.(capability.Forwarder)
	if !ok || router.Services == nil {
		return problem.New(problem.PreconditionFailed, "controller: custom capability forwarder does not support service registration")
	}
	if _, exists := router.Services[name]; exists {
		return problem.New(problem.StateConflict, "controller: capability service is already registered")
	}
	router.Services[name] = svc
	return nil
}

// HasCapabilityService 报告默认宿主能力路由器中是否已登记指定服务名。
func (rt *PluginRuntime) HasCapabilityService(name string) bool {
	if rt == nil || name == "" {
		return false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	router, ok := rt.opts.CapabilityForwarder.(capability.Forwarder)
	if !ok || router.Services == nil {
		return false
	}
	_, exists := router.Services[name]
	return exists
}

// SetRenewalJobHandler 绑定宿主续期作业协调器；仅在 RunJob 收到已登记续期任务时生效。
func (rt *PluginRuntime) SetRenewalJobHandler(handler RenewalJobHandler) {
	if rt == nil || rt.dispatcher == nil {
		return
	}
	if handler == nil {
		rt.dispatcher.renewalJob.Store(nil)
		return
	}
	rt.dispatcher.renewalJob.Store(&handler)
}

// Start binds the host services and fixes the supervisor's lifetime. It must be
// called once, after the controller built them and before requests are served.
func (rt *PluginRuntime) Start(ctx context.Context, deps HostDeps) error {
	if rt == nil {
		return problem.New(problem.Unavailable, "controller: the plugin runtime is not enabled")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.Clock == nil {
		deps.Clock = rt.opts.Clock
	}
	if deps.Logger == nil {
		deps.Logger = rt.opts.Logger
	}
	if deps.NodeID == "" {
		deps.NodeID = rt.opts.NodeID
	}

	started, err := rt.start(ctx, deps)
	if err != nil || !started {
		return err
	}
	rt.serveInstalled()
	rt.SyncPublicRoutes()
	return nil
}

// start performs Start under rt.mu; started reports a first start.
func (rt *PluginRuntime) start(ctx context.Context, deps HostDeps) (bool, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.stopped {
		return false, problem.New(problem.Unavailable, "controller: the plugin runtime is closed")
	}
	if rt.started {
		return false, nil
	}
	if err := rt.sup.Start(ctx); err != nil {
		return false, err
	}
	rt.deps = deps
	rt.lifetime = ctx
	rt.started = true
	rt.opts.Logger.Info("plugin runtime started",
		"node_id", deps.NodeID, "run_dir", rt.opts.RunDir,
		"journal", deps.DB != nil, "operations", deps.Ops != nil, "secrets", deps.Secrets != nil)
	return true, nil
}

// serveInstalled serves the host channel of every installed plugin. A failure
// is logged and skipped: one broken plugin must not keep the host down.
func (rt *PluginRuntime) serveInstalled() {
	if rt.opts.PluginsRoot == "" {
		return
	}
	entries, err := os.ReadDir(rt.opts.PluginsRoot)
	if err != nil {
		rt.opts.Logger.Warn("installed plugins could not be listed for their host channels",
			"plugins_root", rt.opts.PluginsRoot, "error", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() || sandbox.ValidateID(e.Name()) != nil {
			continue
		}
		if err := rt.EnsureHostChannel(e.Name()); err != nil {
			rt.opts.Logger.Warn("plugin host channel could not be served",
				"plugin_id", e.Name(), "error", err)
		}
	}
}

// Stop closes the supervisor: plugin connections and host channels end, the
// plugin processes stay with systemd and the next agent process reattaches.
// Stop is idempotent and safe to call before Start.
func (rt *PluginRuntime) Stop() {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	if rt.stopped {
		rt.mu.Unlock()
		return
	}
	rt.stopped = true
	rt.started = false
	rt.mu.Unlock()
	if rt.sup != nil {
		rt.sup.Close()
	}
	rt.hostMu.Lock()
	hosts := rt.hosts
	rt.hosts = make(map[string]func())
	rt.hostMu.Unlock()
	for _, stop := range hosts {
		stop()
	}
}

// Dispatcher returns the operations.Dispatcher of this runtime, nil when the
// runtime is nil so that operations reports UNAVAILABLE for plugin actions.
func (rt *PluginRuntime) Dispatcher() operations.Dispatcher {
	if rt == nil || rt.dispatcher == nil {
		return nil
	}
	return rt.dispatcher
}

// Supervisor returns the underlying supervisor. The agent process passes it to
// agent.New so both wrap the same instance.
func (rt *PluginRuntime) Supervisor() *supervisor.Supervisor {
	if rt == nil {
		return nil
	}
	return rt.sup
}

// HostServer builds the host channel of one plugin. It has the shape of
// agent.HostMux's factory; EnsureHostChannel serves it once per plugin.
func (rt *PluginRuntime) HostServer(pluginID string) (supervisor.HostServer, error) {
	if rt == nil {
		return nil, problem.New(problem.Unavailable, "controller: the plugin runtime is not enabled")
	}
	if err := sandbox.ValidateID(pluginID); err != nil {
		return nil, problem.New(problem.ValidationFailed, "controller: %q is not a valid plugin id", pluginID)
	}
	return &hostChannel{rt: rt, pluginID: pluginID}, nil
}

// attach ensures the plugin unit runs, attaches to its socket and returns the
// RPC client of the current generation.
func (rt *PluginRuntime) attach(ctx context.Context, pluginID string) (PluginClient, error) {
	if err := rt.startedError(); err != nil {
		return nil, err
	}
	if err := rt.EnsureHostChannel(pluginID); err != nil {
		return nil, problem.From(err)
	}
	// Without an attached instance (host restart, stopped unit) restore first:
	// it waits for a saga holding the plugin and fails fast when the plugin
	// cannot run, before the supervisor spends its retry budget. A crash of an
	// attached plugin is restored through OnNewGeneration instead, so a
	// healthy dispatch costs no extra RPC.
	if _, err := rt.sup.Client(pluginID); err != nil {
		if err := rt.runRestore(ctx, pluginID); err != nil {
			return nil, problem.From(err)
		}
		// 若此前因瞬时故障处于 degraded 冷却期，而本次 runRestore 已确认将单元恢复在线，
		// 立即清除陈旧冷却锁，避免 Ensure 在读取新 PID 前被旧 retryAt 拦截。
		rt.sup.ResetDegraded(pluginID)
	}
	if _, err := rt.sup.Ensure(ctx, pluginID); err != nil {
		return nil, problem.From(err)
	}
	return rt.live(pluginID)
}

// live returns the RPC client of an already attached plugin. It never starts a
// unit: a cancellation or an inspection must not resurrect a stopped plugin.
func (rt *PluginRuntime) live(pluginID string) (PluginClient, error) {
	if err := rt.startedError(); err != nil {
		return nil, err
	}
	client, err := rt.sup.Client(pluginID)
	if err != nil {
		return nil, problem.From(err)
	}
	return client, nil
}

// startedError reports whether the runtime can serve requests.
func (rt *PluginRuntime) startedError() error {
	if rt == nil {
		return problem.New(problem.Unavailable, "controller: the plugin runtime is not enabled")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	switch {
	case rt.stopped:
		return problem.New(problem.Unavailable, "controller: the plugin runtime is closed")
	case !rt.started:
		return problem.New(problem.Unavailable, "controller: the plugin runtime is not started")
	}
	return nil
}

// depsSnapshot returns the host dependencies bound by Start.
func (rt *PluginRuntime) depsSnapshot() (HostDeps, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.deps, rt.started && !rt.stopped
}

// --- host channel ----------------------------------------------------------

// ---------------------------------------------------------------------------
// 宿主通道按插件常驻：插件进程启动前必须已存在（pluginsdk 只等 5s），
// 与进程代际无关；对端身份由 PeerVerifier 按连接逐次校验。
// ---------------------------------------------------------------------------

// EnsureHostChannel serves pluginID's host channel unless it already runs. It
// must be called before the plugin's unit is started.
func (rt *PluginRuntime) EnsureHostChannel(pluginID string) error {
	if err := sandbox.ValidateID(pluginID); err != nil {
		return problem.New(problem.ValidationFailed, "controller: %q is not a valid plugin id", pluginID)
	}
	rt.hostMu.Lock()
	defer rt.hostMu.Unlock()
	return rt.ensureHostChannelLocked(pluginID)
}

// ensureHostChannelLocked 与授权重建共用通道创建路径，调用方持有 hostMu。
func (rt *PluginRuntime) ensureHostChannelLocked(pluginID string) error {
	// Checked under hostMu: Stop marks the runtime stopped before it drains
	// hosts, so no channel can be added after the drain.
	if err := rt.startedError(); err != nil {
		return err
	}
	if _, ok := rt.hosts[pluginID]; ok {
		return nil
	}
	host, err := rt.hostFactory(pluginID)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	lifetime := rt.lifetime
	rt.mu.Unlock()
	ctx, cancel := context.WithCancel(lifetime)
	stop, err := host.Serve(ctx, pluginID)
	if err != nil {
		cancel()
		return err
	}
	rt.hosts[pluginID] = func() { cancel(); stop() }
	return nil
}

// ReleaseHostChannel closes pluginID's host channel; the installer calls it
// once the plugin's last version is removed. Releasing an absent channel is a
// no-op.
func (rt *PluginRuntime) ReleaseHostChannel(pluginID string) {
	if rt == nil {
		return
	}
	rt.hostMu.Lock()
	defer rt.hostMu.Unlock()
	rt.releaseHostChannelLocked(pluginID)
}

// releaseHostChannelLocked 阻止关闭期间出现第二个注册旧授权的 listener。
func (rt *PluginRuntime) releaseHostChannelLocked(pluginID string) {
	stop, ok := rt.hosts[pluginID]
	delete(rt.hosts, pluginID)
	if ok {
		stop()
	}
	rt.hostCapabilitiesMu.Lock()
	delete(rt.hostCapabilities, pluginID)
	rt.hostCapabilitiesMu.Unlock()
}

// ---------------------------------------------------------------------------
// unit 单一所有者：绑定 restore（updater）后，启动 unit 与 ABI bootstrap 只由
// updater 在插件锁内完成；supervisor 只附着/停止，不再与 saga 争抢 unit。
// ---------------------------------------------------------------------------

// SetRestore binds the desired-state restore (updater.EnsureActive). From then
// on every attach restores first and the supervisor no longer starts units.
func (rt *PluginRuntime) SetRestore(f func(ctx context.Context, pluginID string) error) {
	rt.restore.Store(&f)
}

// runRestore runs the bound restore; without one (serve-agent, no updater) the
// supervisor starts units itself and there is nothing to do.
func (rt *PluginRuntime) runRestore(ctx context.Context, pluginID string) error {
	if f := rt.restore.Load(); f != nil {
		return (*f)(ctx, pluginID)
	}
	return nil
}

// attachOnlyUnits is the supervisor's UnitManager. Once a restore is bound it
// refuses Start: a unit the supervisor finds stopped is the updater's to start
// (with the ABI bootstrap and under the plugin lock), never the dispatcher's.
type attachOnlyUnits struct {
	supervisor.UnitManager
	rt *PluginRuntime
}

func (u attachOnlyUnits) Start(ctx context.Context, pluginID string) error {
	if u.rt != nil && u.rt.restore.Load() != nil {
		// 空闲休眠（QWQ_PLUGIN_IDLE_TTL）或单元停止后的按需唤醒：
		// 直接驱动宿主幂等恢复流程（在插件锁内启动 systemd 单元并执行 ABI Initialize/Start/Activate）。
		if err := u.rt.runRestore(ctx, pluginID); err != nil {
			return problem.From(err)
		}
		return nil
	}
	return u.UnitManager.Start(ctx, pluginID)
}

// residentHost is the supervisor's view of the resident host channels: Serve
// ensures the channel and the returned stop leaves it running.
type residentHost struct{ rt *PluginRuntime }

func (h residentHost) Serve(_ context.Context, pluginID string) (func(), error) {
	if err := h.rt.EnsureHostChannel(pluginID); err != nil {
		return nil, err
	}
	return func() {}, nil
}

// hostChannel serves the hostsvc listener of one plugin instance.
type hostChannel struct {
	rt       *PluginRuntime
	pluginID string
}

// Serve implements supervisor.HostServer: it creates the host service, serves it
// in the background and returns a stop function that tears the listener down and
// waits for in-flight calls.
func (h *hostChannel) Serve(ctx context.Context, pluginID string) (func(), error) {
	if h == nil || h.rt == nil {
		return nil, problem.New(problem.Unavailable, "controller: the plugin host channel is not wired")
	}
	if pluginID != h.pluginID {
		return nil, problem.New(problem.ValidationFailed,
			"controller: the host channel of plugin %q was asked to serve %q", h.pluginID, pluginID)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	srv, err := h.rt.newHostService(pluginID)
	if err != nil {
		return nil, err
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx) }()
	if err := waitForHostSocket(ctx, supervisor.HostSocketPath(h.rt.opts.RunDir, pluginID), errCh); err != nil {
		_ = srv.Close()
		return nil, err
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = srv.Close()
			select {
			case <-errCh:
			case <-time.After(hostStopTimeout):
				h.rt.opts.Logger.Warn("plugin host channel did not stop in time", "plugin_id", pluginID)
			}
		})
	}
	return stop, nil
}

// waitForHostSocket waits until hostsvc created the socket or Serve failed.
func waitForHostSocket(ctx context.Context, socket string, errCh <-chan error) error {
	deadline := time.Now().Add(hostStartTimeout)
	ticker := time.NewTicker(hostStartPoll)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(socket); err == nil {
			return nil
		}
		select {
		case err := <-errCh:
			if err == nil {
				err = errors.New("the host service stopped before it served")
			}
			return &problem.Error{
				Code:   problem.PluginUnavailable,
				Detail: "The plugin host channel could not be served.",
				Cause:  err,
			}
		case <-ctx.Done():
			return ctxError(ctx.Err(), "serving the plugin host channel")
		case <-ticker.C:
			if time.Now().After(deadline) {
				return problem.New(problem.PluginUnavailable,
					"The plugin host channel did not start on %s.", socket)
			}
		}
	}
}

// ctxError maps a context error to a host error.
func ctxError(err error, doing string) *problem.Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &problem.Error{Code: problem.Timeout, Detail: "The host gave up " + doing + ".", Cause: err}
	}
	return &problem.Error{Code: problem.Unavailable, Detail: "The host stopped " + doing + ".", Cause: err}
}

// newHostService builds the hostsvc server of one plugin instance.
func (rt *PluginRuntime) newHostService(pluginID string) (*hostsvc.Server, error) {
	deps, ok := rt.depsSnapshot()
	if !ok {
		return nil, problem.New(problem.Unavailable, "controller: the plugin runtime is not started")
	}
	runDir := rt.opts.RunDir
	cfg := hostsvc.Config{
		PluginID:   pluginID,
		InstanceID: DefaultInstanceID,
		SocketPath: supervisor.HostSocketPath(runDir, pluginID),
		StateDir:   filepath.Join(rt.opts.StateDir, pluginID),
		Clock:      deps.Clock,
		Logger:     deps.Logger,
		// State is nil: hostsvc owns the built-in file store below StateDir.
		Peer: &PeerVerifier{
			PluginID:  pluginID,
			Unit:      supervisor.UnitName(pluginID),
			Instances: SupervisorInstances(rt.sup),
			MainPID:   rt.unitMainPID,
			Logger:    deps.Logger,
		},
		Limits:              hostsvc.DefaultLimits(),
		GrantedCapabilities: rt.hostCapabilityGrants(deps, pluginID),
		CapabilityForwarder: rt.opts.CapabilityForwarder,
	}
	if deps.DB != nil {
		// Every host call must present the token issued at install time
		// (ADR-0013). The digest is read per call, so a reinstall's fresh
		// token applies without rebuilding this server.
		tokens := PluginTokens{DB: deps.DB}
		cfg.TokenDigests = func(ctx context.Context) ([][]byte, error) { return tokens.Digests(ctx, pluginID) }
		// The journal, the audit log and the applied config snapshot are host
		// state; an agent process without a database leaves them unavailable
		// instead of pretending to record them.
		var reader operationReader
		if deps.Ops != nil {
			reader = deps.Ops
		}
		cfg.Events = &hostEventSink{
			db:         deps.DB,
			lossy:      deps.Lossy,
			ids:        deps.IDs,
			operations: reader,
			pluginID:   pluginID,
			instanceID: DefaultInstanceID,
			nodeID:     deps.NodeID,
		}
		cfg.Audit = &hostAuditSink{
			db:         deps.DB,
			operations: reader,
			pluginID:   pluginID,
			instanceID: DefaultInstanceID,
			nodeID:     deps.NodeID,
		}
	}
	if deps.Config != nil {
		cfg.Config = deps.Config(pluginID)
	}
	if deps.DB != nil && deps.Ops != nil && deps.Secrets != nil {
		cfg.Secrets = &hostSecretRevealer{
			operations: deps.Ops,
			secrets:    deps.Secrets,
			pluginID:   pluginID,
			instanceID: DefaultInstanceID,
			nodeID:     deps.NodeID,
			logger:     deps.Logger,
		}
	}
	if deps.Ops != nil {
		cfg.Invoke = rt.newHostInvoker(deps, pluginID)
		cfg.OperationResolver = &hostCapabilityResolver{operations: deps.Ops, pluginID: pluginID, instanceID: DefaultInstanceID, nodeID: deps.NodeID}
	}
	srv, err := hostsvc.New(cfg)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The host channel of plugin %q could not be created.", pluginID),
			Cause:  err,
		}
	}
	return srv, nil
}

// newHostInvoker builds the Invoker of one plugin instance; deps.Ops must be set.
func (rt *PluginRuntime) newHostInvoker(deps HostDeps, pluginID string) *hostInvoker {
	clk := deps.Clock
	if clk == nil {
		clk = rt.opts.Clock
	}
	if clk == nil {
		clk = clock.System{}
	}
	h := &hostInvoker{
		reader:     deps.Ops,
		waiter:     deps.Ops,
		canceler:   deps.Ops,
		runner:     deps.Ops,
		db:         deps.DB,
		clock:      clk,
		logger:     rt.opts.Logger,
		pluginID:   pluginID,
		instanceID: DefaultInstanceID,
		nodeID:     deps.NodeID,
		bgTokens:   backgroundInvokeBurst,
	}
	if rt.dispatcher != nil && rt.dispatcher.clients != nil {
		clients := rt.dispatcher.clients
		h.isLive = func(targetPluginID string) bool {
			_, err := clients.live(targetPluginID)
			return err == nil
		}
	}
	if deps.Catalog != nil {
		h.grants = deps.Catalog
	}
	return h
}

// unitMainPID reads the unit's main process from systemd. It is the peer
// verifier's fallback while the supervisor has not registered the instance yet.
func (rt *PluginRuntime) unitMainPID(pluginID string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), peerMainPIDTimeout)
	defer cancel()
	st, err := rt.opts.Units.Show(ctx, pluginID)
	if err != nil {
		return 0, err
	}
	return st.MainPID, nil
}

// --- hostsvc.EventSink -----------------------------------------------------

// hostEventSink writes plugin events and plugin-owned resource changes to the
// host journal. The plugin namespace is fixed by the instance identity, so a
// plugin cannot publish into another plugin's subjects or impersonate the host.
type hostEventSink struct {
	db    *storage.DB
	lossy *events.Lossy
	ids   *ids.Generator
	// operations verifies the operation id the plugin reports; nil verifies
	// nothing, so every reported id is dropped.
	operations operationReader
	pluginID   string
	instanceID string
	nodeID     string
}

// isLossyRealtimeTopic 判定插件事件是否属于高频实时有损遥测主题（OPT-08），
// 此类采样只走内存最新值覆盖通道，绝不写入 SQLite event_journal。
func isLossyRealtimeTopic(eventType string) bool {
	return strings.HasSuffix(eventType, ".sample") ||
		strings.HasPrefix(eventType, "telemetry.") ||
		strings.HasPrefix(eventType, "metrics.")
}

// LossySample 是经由内存有损通道派发给在线订阅者的实时采样结构。
type LossySample struct {
	EventID       string          `json:"event_id"`
	Type          string          `json:"type"`
	SchemaVersion string          `json:"schema_version"`
	Subject       string          `json:"subject"`
	PluginID      string          `json:"plugin_id"`
	NodeID        string          `json:"node_id"`
	Payload       json.RawMessage `json:"payload"`
}

// verifiedOperationID is the reported operation id when it names an operation
// running for this instance, and "" otherwise (EXT-01).
func (s *hostEventSink) verifiedOperationID(ctx context.Context, reported string) string {
	return verifiedOperationID(ctx, s.operations, s.pluginID, s.instanceID, s.nodeID, reported)
}

// namespace is the full subject prefix of this instance.
func (s *hostEventSink) namespace() string {
	return "nodes/" + s.nodeID + "/plugins/" + s.pluginID + "/instances/" + s.instanceID
}

// resourcePrefix is the subject prefix of plugin-owned resources (ADR-0004 D3).
func (s *hostEventSink) resourcePrefix() string { return s.namespace() + "/resources" }

// eventTypePrefix is the topic namespace of the plugin's events.
func (s *hostEventSink) eventTypePrefix() string { return s.pluginID + "." }

// Publish appends one event to the journal and returns its identity.
// High-frequency realtime telemetry topics are dispatched through the bounded
// in-memory Lossy fanout without touching SQLite (OPT-08).
func (s *hostEventSink) Publish(ctx context.Context, draft hostsvc.EventDraft) (hostsvc.EventRef, error) {
	if s == nil || (s.db == nil && s.lossy == nil) {
		return hostsvc.EventRef{}, problem.New(problem.Unavailable, "controller: the event journal is not available")
	}
	schema := draft.SchemaVersion
	if schema == "" {
		schema = "1"
	}
	fullType := s.eventTypePrefix() + draft.Type
	fullSubject := s.namespace() + "/" + draft.Subject
	if s.lossy != nil && isLossyRealtimeTopic(draft.Type) {
		evID := "ev_lossy"
		if s.ids != nil {
			evID = s.ids.New(ids.Event)
		}
		payload := append([]byte(nil), draft.PayloadJSON...)
		if len(payload) == 0 {
			payload = []byte("{}")
		}
		s.lossy.Publish(fullType, fullSubject, LossySample{
			EventID:       evID,
			Type:          fullType,
			SchemaVersion: schema,
			Subject:       fullSubject,
			PluginID:      s.pluginID,
			NodeID:        s.nodeID,
			Payload:       json.RawMessage(payload),
		})
		return hostsvc.EventRef{EventID: evID, Sequence: 0}, nil
	}
	if s.db == nil {
		return hostsvc.EventRef{}, problem.New(problem.Unavailable, "controller: the event journal is not available")
	}
	var ref hostsvc.EventRef
	operationID := s.verifiedOperationID(ctx, draft.OperationID)
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		seq, err := tx.AppendEvent(ctx, storage.Event{
			Type:          fullType,
			SchemaVersion: schema,
			Subject:       fullSubject,
			OccurredAt:    tx.Now(),
			ActorKind:     string(actor.System),
			ActorID:       "plugin:" + s.pluginID,
			NodeID:        s.nodeID,
			TraceID:       draft.TraceID,
			OperationID:   operationID,
			Payload:       draft.PayloadJSON,
		})
		if err != nil {
			return err
		}
		if seq <= 0 {
			return errors.New("controller: the journal returned no sequence")
		}
		ref.Sequence = uint64(seq)
		return tx.QueryRowContext(ctx, `SELECT event_id FROM event_journal WHERE seq = ?`, seq).Scan(&ref.EventID)
	})
	if err != nil {
		return hostsvc.EventRef{}, problem.From(err)
	}
	return ref, nil
}

// ReportChanges turns plugin-reported resource changes into resource.changed
// events. The subject is prefixed with the instance's resource namespace; the
// revision is the journal sequence of the change, so the host owns it.
func (s *hostEventSink) ReportChanges(ctx context.Context, set hostsvc.ChangeSet) error {
	if s == nil || s.db == nil {
		return problem.New(problem.Unavailable, "controller: the event journal is not available")
	}
	if len(set.Changes) == 0 {
		return nil
	}
	operationID := s.verifiedOperationID(ctx, set.OperationID)
	return s.db.Update(ctx, func(tx *storage.Tx) error {
		// The origin carries the caller's operation and trace into every
		// resource.changed event, so a UI can follow the changes of one job.
		tx.SetOrigin(storage.Origin{
			Actor:       actor.SystemActor("plugin:" + s.pluginID),
			OperationID: operationID,
			TraceID:     set.TraceID,
			NodeID:      s.nodeID,
		})
		for _, change := range set.Changes {
			kind := storage.Updated
			switch {
			case change.Deleted:
				kind = storage.Deleted
			}
			if _, err := tx.Changed(ctx, storage.Change{
				Subject:  s.resourcePrefix() + "/" + change.Subject,
				Kind:     kind,
				Pointers: change.ChangedPointers,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Ack acknowledges the subscription cursor of a plugin. The journal is the
// durable source of truth and hostsvc keeps the cursor in memory; a durable
// per-subscription cursor needs a storage migration and is tracked in
// REPORT-PLUGIN-RUNTIME.md as a P2 gap.
func (s *hostEventSink) Ack(context.Context, string, uint64) error { return nil }

// --- hostsvc.SecretRevealer ------------------------------------------------

// operationReader reads one operation by id; *operations.Service implements it.
type operationReader interface {
	Get(ctx context.Context, a actor.Actor, id string) (*operations.Operation, error)
}

// secretRevealer 只按宿主计算的 owner 与精确 purpose 白名单解密一个引用。
// 两层 scope、真实派发与原参数成员先于解密，不提供无归属 Reveal 旁路。
type secretRevealer interface {
	RevealOwnedAnyPurpose(ctx context.Context, ref secrets.Ref, owner string, purposes ...string) (secrets.Secret, error)
}

type secretDispatchResolver interface {
	ResolveDispatchedInstance(ctx context.Context, pluginID, instanceID, nodeID, operationID string) (operations.DispatchedContext, error)
	RevalidateDispatched(ctx context.Context, accepted operations.DispatchedContext) error
}

// hostSecretRevealer reveals a secret reference only for an operation that is
// currently dispatched to this exact plugin instance. The operation id is not
// proof by itself: it arrives in HostCallContext, which the plugin controls, so
// it is checked against the host's own operation record.
type hostSecretRevealer struct {
	operations secretDispatchResolver
	secrets    secretRevealer
	pluginID   string
	instanceID string
	nodeID     string
	logger     *slog.Logger
}

// Reveal implements hostsvc.SecretRevealer.
func (h *hostSecretRevealer) Reveal(ctx context.Context, ref, operationID string, grantedScopes []string) ([]byte, error) {
	if h == nil || h.operations == nil || h.secrets == nil {
		return nil, hostsvc.ErrOperationNotDispatched
	}
	if operationID == "" {
		return nil, hostsvc.ErrOperationNotDispatched
	}
	accepted, err := h.operations.ResolveDispatchedInstance(ctx, h.pluginID, h.instanceID, h.nodeID, operationID)
	if err != nil {
		h.debug("plugin secret reveal refused: unknown operation", "operation_id", operationID, "error", err)
		return nil, hostsvc.ErrOperationNotDispatched
	}
	defer accepted.Clear()
	var purposes []string
	for _, capability := range accepted.Action.Capabilities {
		if capability.Name != "secret.reveal" {
			continue
		}
		granted := false
		for _, scope := range grantedScopes {
			granted = granted || scope == capability.Scope
		}
		if !granted {
			continue
		}
		switch capability.Scope {
		case "config":
			purposes = append(purposes, pluginSecretPurpose)
		case "operation":
			schema := accepted.ArgumentSchema()
			member, err := secrets.SensitiveArgumentReference(schema, accepted.Args, secrets.Ref(ref))
			clear(schema)
			if err == nil && member {
				purposes = append(purposes, "plugin.operation")
			}
		}
	}
	if len(purposes) == 0 {
		return nil, hostsvc.ErrSecretDenied
	}
	secret, err := h.secrets.RevealOwnedAnyPurpose(ctx, secrets.Ref(ref), "plugins/"+h.pluginID, purposes...)
	if err != nil {
		// The concrete error stays in the host log; a plugin learns nothing
		// about whether the reference exists.
		h.debug("plugin secret reveal failed", "operation_id", operationID, "error", err)
		return nil, hostsvc.ErrSecretDenied
	}
	defer secret.Clear()
	if err := h.operations.RevalidateDispatched(ctx, accepted); err != nil {
		return nil, hostsvc.ErrSecretDenied
	}
	return secret.Bytes(), nil
}

// dispatchedTo reports whether op is currently running for the given plugin
// instance. It is the single check behind every operation id a plugin reports
// in HostCallContext: that id is chosen by the plugin, so it is only believed
// when the host's own record says the operation is dispatched to the caller.
func dispatchedTo(op *operations.Operation, pluginID, instanceID, nodeID string) bool {
	return op != nil && op.Status == operations.Running && targetsInstance(op, pluginID, instanceID, nodeID)
}

// targetsInstance reports whether op's target is the given plugin instance. A
// controller-placement operation has no instance and no node.
func targetsInstance(op *operations.Operation, pluginID, instanceID, nodeID string) bool {
	if op == nil || op.Target.PluginID != pluginID {
		return false
	}
	if op.Target.InstanceID != "" && op.Target.InstanceID != instanceID {
		return false
	}
	if nodeID != "" && op.Target.NodeID != "" && op.Target.NodeID != nodeID {
		return false
	}
	return true
}

// dispatchedOperation loads the operation a plugin reported and reports
// whether it is dispatched to that plugin instance. A missing reader, an
// unknown id and a failed lookup are all "not dispatched".
func dispatchedOperation(ctx context.Context, reader operationReader, pluginID, instanceID, nodeID, id string) (*operations.Operation, bool) {
	if reader == nil || id == "" {
		return nil, false
	}
	op, err := reader.Get(ctx, actor.SystemActor("controller"), id)
	if err != nil || !dispatchedTo(op, pluginID, instanceID, nodeID) {
		return nil, false
	}
	return op, true
}

// verifiedOperationID returns the host's id of the reported operation, or ""
// when the report does not hold. Journal events and audit rows then carry no
// operation link rather than a forged one.
func verifiedOperationID(ctx context.Context, reader operationReader, pluginID, instanceID, nodeID, reported string) string {
	op, ok := dispatchedOperation(ctx, reader, pluginID, instanceID, nodeID, reported)
	if !ok {
		return ""
	}
	return op.ID
}

// debug logs a refusal when a logger is configured.
func (h *hostSecretRevealer) debug(msg string, args ...any) {
	if h.logger != nil {
		h.logger.Debug(msg, args...)
	}
}

// --- hostsvc.AuditSink -----------------------------------------------------

// hostAuditSink writes plugin audit records through operations.Audit. The
// record's host fields are host facts (plugin, instance, operation, trace); the
// plugin's own details are nested under "plugin" so they can never overwrite
// them.
type hostAuditSink struct {
	db *storage.DB
	// operations verifies the reported operation id, like hostEventSink.
	operations operationReader
	pluginID   string
	instanceID string
	nodeID     string
}

// Write implements hostsvc.AuditSink.
func (s *hostAuditSink) Write(ctx context.Context, record hostsvc.AuditRecord) error {
	if s == nil || s.db == nil {
		return problem.New(problem.Unavailable, "controller: the audit log is not available")
	}
	record.OperationID = verifiedOperationID(ctx, s.operations, s.pluginID, s.instanceID, s.nodeID, record.OperationID)
	details, err := auditDetails(s.pluginID, s.instanceID, record)
	if err != nil {
		return problem.From(err)
	}
	subject := s.namespace()
	if record.Subject != "" {
		subject += "/" + record.Subject
	}
	auditErr := s.db.Update(ctx, func(tx *storage.Tx) error {
		return operations.Audit(ctx, tx, operations.AuditRecord{
			Actor:       actor.SystemActor("plugin:" + s.pluginID),
			Action:      record.Action,
			Subject:     subject,
			Outcome:     auditOutcome(record.Outcome),
			Details:     details,
			OperationID: record.OperationID,
			NodeID:      s.nodeID,
			TraceID:     record.TraceID,
			Source:      "plugin",
			At:          record.OccurredAt,
		})
	})
	if auditErr != nil {
		return problem.From(auditErr)
	}
	return nil
}

// namespace is the audit subject prefix of this instance.
func (s *hostAuditSink) namespace() string {
	return "nodes/" + s.nodeID + "/plugins/" + s.pluginID + "/instances/" + s.instanceID
}

// auditOutcome maps the ABI outcome. An unspecified outcome is recorded as a
// failure: the audit log must never overstate what happened.
func auditOutcome(outcome hostsvc.AuditOutcome) string {
	switch outcome {
	case hostsvc.AuditSuccess:
		return operations.AuditSuccess
	case hostsvc.AuditDenied:
		return operations.AuditDenied
	default:
		return operations.AuditFailure
	}
}

// auditDetails renders the audit details: host-known identifiers first, the
// plugin's own JSON under "plugin". No secret material is added.
func auditDetails(pluginID, instanceID string, record hostsvc.AuditRecord) (json.RawMessage, error) {
	host := map[string]any{"plugin_id": pluginID, "instance_id": instanceID}
	if record.Action != "" {
		host["action"] = record.Action
	}
	if record.OperationID != "" {
		host["operation_id"] = record.OperationID
	}
	if record.TraceID != "" {
		host["trace_id"] = record.TraceID
	}
	details := map[string]any{"host": host}
	if len(record.DetailsJSON) > 0 {
		details["plugin"] = json.RawMessage(record.DetailsJSON)
	}
	return json.Marshal(details)
}

// --- hostsvc.Invoker -------------------------------------------------------

// operationWaiter waits for one operation; *operations.Service implements it.
type operationWaiter interface {
	Wait(ctx context.Context, a actor.Actor, id string, timeout time.Duration) (*operations.Operation, error)
}

// operationCanceler cancels one operation; *operations.Service implements it.
type operationCanceler interface {
	Cancel(ctx context.Context, req operations.CancelRequest) (*operations.Response, error)
}

// hostInvoker is the host side of HostInvokeService for one plugin instance.
// InvokePlugin turns a call into a child operation of the caller's dispatched
// operation through operations.Run (ADR-0011, plugin_invoke.go). WaitOperation
// and CancelOperation go through the operation manager and only ever touch an
// operation this instance created.
type hostInvoker struct {
	reader   operationReader
	waiter   operationWaiter
	canceler operationCanceler
	runner   operationRunner
	grants   pluginGrantSource
	db       *storage.DB // audit rows of refused calls; nil refuses every call
	clock    clock.Clock // rate limit clock for ADR-0023 H3 background reads
	isLive   func(string) bool
	logger   *slog.Logger // nil discards; records storage failures of the ownership check

	pluginID   string
	instanceID string
	nodeID     string

	bgMu     sync.Mutex
	bgTokens float64
	bgLast   time.Time
}

// WaitOperation waits for an operation this instance created.
func (h *hostInvoker) WaitOperation(ctx context.Context, call hostsvc.WaitCall) (hostsvc.OperationSnapshot, error) {
	if h == nil || h.reader == nil || h.waiter == nil {
		return hostsvc.OperationSnapshot{}, problem.New(problem.Unavailable, "controller: the operation manager is not available")
	}
	if err := h.requireOwned(ctx, call.OperationID); err != nil {
		return hostsvc.OperationSnapshot{}, err
	}
	op, err := h.waiter.Wait(ctx, actor.SystemActor("controller"), call.OperationID, call.Timeout)
	if err != nil {
		return hostsvc.OperationSnapshot{}, statusFromProblem(err)
	}
	snapshot := hostsvc.OperationSnapshot{
		State:      hostOperationState(op.Status),
		ResultJSON: op.Result,
	}
	if op.Error != nil {
		snapshot.Error = &hostsvc.DomainError{
			Code: string(op.Error.Code), Message: op.Error.Detail, Retryable: op.Error.Retryable,
		}
	}
	if op.Progress != nil {
		snapshot.Progress = &hostsvc.Progress{
			Step:      op.Progress.Step,
			StepIndex: op.Progress.StepIndex,
			StepCount: op.Progress.StepCount,
			Message:   op.Progress.Message,
		}
		if op.Progress.Percent != nil {
			snapshot.Progress.Percent = *op.Progress.Percent
		}
	}
	return snapshot, nil
}

// CancelOperation cancels an operation this instance created.
func (h *hostInvoker) CancelOperation(ctx context.Context, call hostsvc.CancelCall) (hostsvc.OperationState, error) {
	if h == nil || h.reader == nil || h.canceler == nil {
		return hostsvc.OperationUnspecified, problem.New(problem.Unavailable, "controller: the operation manager is not available")
	}
	if err := h.requireOwned(ctx, call.OperationID); err != nil {
		return hostsvc.OperationUnspecified, err
	}
	op, err := h.canceler.Cancel(ctx, operations.CancelRequest{
		Actor:       actor.SystemActor("plugin:" + h.pluginID),
		OperationID: call.OperationID,
		Reason:      "the plugin requested cancellation",
		Idempotency: operations.Idempotency{
			Key:    "plugin-cancel:" + call.OperationID,
			Method: "POST",
			Route:  "/internal/plugin/cancel",
		},
	})
	if err != nil {
		return hostsvc.OperationUnspecified, statusFromProblem(err)
	}
	if op != nil && op.Operation != nil {
		return hostOperationState(op.Operation.Status), nil
	}
	return hostsvc.OperationPending, nil
}

// requireOwned refuses an operation this instance does not own. It runs before
// any wait or cancel, because by the time either has returned the plugin has
// already held a call open on, or stopped, someone else's work. A foreign
// operation, an unknown id and a failed lookup get the same answer, so the
// refusal does not reveal which operations exist.
func (h *hostInvoker) requireOwned(ctx context.Context, operationID string) error {
	op, err := h.reader.Get(ctx, actor.SystemActor("controller"), operationID)
	if err != nil && !errors.Is(err, problem.Sentinel(problem.NotFound)) {
		// A storage failure is no refusal: like hostsvc's sinkError, the plugin
		// gets a retryable UNAVAILABLE that says nothing about the operation and
		// the cause stays in the host log.
		if h.logger != nil {
			h.logger.Error("plugin operation ownership check failed",
				"plugin_id", h.pluginID, "operation_id", operationID, "error", err)
		}
		return status.Error(codes.Unavailable, "a host dependency is unavailable")
	}
	if err != nil || !h.owns(ctx, op) {
		return status.Error(codes.NotFound, "the operation was not created by this plugin instance")
	}
	return nil
}

// owns reports whether this plugin instance created op with InvokePlugin: op is
// a child, and its parent is an operation dispatched to this instance
// (ADR-0011 §6). Both links are host records that never change. The cancel and
// wait calls run as a system actor, which may read every operation, so this
// check is what keeps one plugin away from work it did not start, including
// work merely dispatched to it.
func (h *hostInvoker) owns(ctx context.Context, op *operations.Operation) bool {
	if op == nil || op.ParentOperationID == "" {
		return false
	}
	parent, err := h.reader.Get(ctx, actor.SystemActor("controller"), op.ParentOperationID)
	if err != nil {
		return false
	}
	return targetsInstance(parent, h.pluginID, h.instanceID, h.nodeID)
}

// hostOperationState maps an operation status to the ABI enum name.
func hostOperationState(state operations.Status) hostsvc.OperationState {
	switch state {
	case operations.Pending:
		return hostsvc.OperationPending
	case operations.AwaitingApproval:
		return hostsvc.OperationAwaiting
	case operations.Approved:
		return hostsvc.OperationApproved
	case operations.Rejected:
		return hostsvc.OperationRejected
	case operations.Expired:
		return hostsvc.OperationExpired
	case operations.Running:
		return hostsvc.OperationRunning
	case operations.Succeeded:
		return hostsvc.OperationSucceeded
	case operations.Failed:
		return hostsvc.OperationFailed
	case operations.Canceled:
		return hostsvc.OperationCanceled
	}
	return hostsvc.OperationUnspecified
}

// statusFromProblem maps a host error to a gRPC status so hostsvc passes a
// meaningful code to the plugin instead of an opaque INTERNAL.
func statusFromProblem(err error) error {
	if err == nil {
		return nil
	}
	var e *problem.Error
	if !errors.As(err, &e) {
		if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
			return st.Err()
		}
		return status.Error(codes.Internal, "the host failed to complete the call")
	}
	code := codes.Internal
	switch e.Code {
	case problem.Unauthenticated:
		code = codes.Unauthenticated
	case problem.PermissionDenied, problem.ApprovalRequired, problem.MFARequired, problem.CSRFFailed:
		code = codes.PermissionDenied
	case problem.NotFound:
		code = codes.NotFound
	case problem.ValidationFailed, problem.UnsupportedMediaType:
		code = codes.InvalidArgument
	case problem.PayloadTooLarge, problem.RateLimited:
		code = codes.ResourceExhausted
	case problem.PreconditionFailed, problem.StateConflict, problem.PlanExpired:
		code = codes.FailedPrecondition
	case problem.RevisionConflict, problem.IdempotencyInProgress, problem.IdempotencyKeyReused:
		code = codes.Aborted
	case problem.Timeout:
		code = codes.DeadlineExceeded
	case problem.Unavailable, problem.PluginUnavailable, problem.NodeOffline, problem.PluginError:
		code = codes.Unavailable
	}
	message := e.Detail
	if code == codes.Internal {
		message = "the host failed to complete the call"
	}
	return status.Error(code, message)
}

// --- operations.Dispatcher -------------------------------------------------

// PluginClient is the part of *supervisor.Client the dispatcher uses. It is an
// interface so the mapping can be tested without a plugin process.
type PluginClient interface {
	Plan(ctx context.Context, req *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error)
	Invoke(ctx context.Context, req *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error)
	RunJob(ctx context.Context, req *platformv1.RunJobRequest, progress func(*platformv1.JobProgress) error) error
	Cancel(ctx context.Context, operationID string) error
}

// pluginClients resolves the RPC client of a plugin instance.
type pluginClients interface {
	// attach ensures the plugin runs and returns its client.
	attach(ctx context.Context, pluginID string) (PluginClient, error)
	// live returns the client of an already attached plugin.
	live(pluginID string) (PluginClient, error)
}

// pluginDispatcher implements operations.Dispatcher on top of the supervisor.
// Every call happens outside a host transaction; the mapping is a pure type
// translation and adds no policy.
type pluginDispatcher struct {
	clients    pluginClients
	renewalJob atomic.Pointer[RenewalJobHandler]
}

// Plan previews a plugin operation.
func (d *pluginDispatcher) Plan(ctx context.Context, req operations.PluginPlanRequest) (operations.Preview, error) {
	client, err := d.clients.attach(ctx, req.PluginID)
	if err != nil {
		return operations.Preview{}, problem.From(err)
	}
	resp, err := client.Plan(ctx, &platformv1.PlanOperationRequest{
		Context: requestContext(req.NodeID, req.InstanceID, req.RequestID, req.OperationID,
			req.TraceID, req.Locale, req.Actor),
		Operation:   req.Operation,
		ApiVersion:  req.APIVersion,
		PayloadJson: req.Payload,
	})
	if err != nil {
		return operations.Preview{}, problem.From(err)
	}
	return previewFromProto(resp, req.PluginID), nil
}

// Invoke runs a synchronous plugin operation.
func (d *pluginDispatcher) Invoke(ctx context.Context, req operations.PluginInvokeRequest) (operations.PluginInvokeResponse, error) {
	client, err := d.client(ctx, req.PluginID, req.ParentOperationID)
	if err != nil {
		return operations.PluginInvokeResponse{}, problem.From(err)
	}
	resp, err := client.Invoke(ctx, &platformv1.InvokeRequest{
		Context: requestContext(req.NodeID, req.InstanceID, req.RequestID, req.OperationID,
			req.TraceID, req.Locale, req.Actor),
		Operation:     req.Operation,
		ApiVersion:    req.APIVersion,
		PayloadJson:   req.Payload,
		Preconditions: preconditionsProto(req.Preconditions),
		Attempt:       attemptProto(req.Attempt),
	})
	if err != nil {
		return operations.PluginInvokeResponse{}, problem.From(err)
	}
	return operations.PluginInvokeResponse{
		Result:  resp.GetPayloadJson(),
		Changes: changesFromProto(resp.GetChanges()),
	}, nil
}

// RunJob runs a long plugin operation and forwards its progress stream.
func (d *pluginDispatcher) RunJob(ctx context.Context, req operations.PluginRunJobRequest, progress func(operations.JobProgress) error) error {
	if req.PluginID == "tls.certificates" && req.Operation == "renew_existing" {
		if handler := d.renewalJob.Load(); handler != nil && *handler != nil {
			handled, err := (*handler)(ctx, req)
			if handled {
				if err == nil && progress != nil {
					if perr := progress(operations.JobProgress{Completed: true}); perr != nil {
						return perr
					}
				}
				return err
			}
		}
	}
	client, err := d.client(ctx, req.PluginID, req.ParentOperationID)
	if err != nil {
		return problem.From(err)
	}
	err = client.RunJob(ctx, &platformv1.RunJobRequest{
		Context: requestContext(req.NodeID, req.InstanceID, req.RequestID, req.OperationID,
			req.TraceID, req.Locale, req.Actor),
		Operation:     req.Operation,
		ApiVersion:    req.APIVersion,
		PayloadJson:   req.Payload,
		Attempt:       attemptProto(req.Attempt),
		Preconditions: preconditionsProto(req.Preconditions),
	}, func(p *platformv1.JobProgress) error {
		return progress(jobProgressFromProto(p))
	})
	if err != nil {
		return problem.From(err)
	}
	return nil
}

// client resolves the plugin an operation runs on. A child of a
// plugin-to-plugin call is routed only to a plugin that already runs: a plugin
// must not be able to start another one (ADR-0011 §1, ARCH §5.4).
func (d *pluginDispatcher) client(ctx context.Context, pluginID, parentOperationID string) (PluginClient, error) {
	if parentOperationID == "" {
		return d.clients.attach(ctx, pluginID)
	}
	client, err := d.clients.live(pluginID)
	if err != nil {
		return nil, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The target plugin %q is not running.", pluginID),
			Cause:  err,
		}
	}
	return client, nil
}

// Cancel asks the running job of operationID to stop. It never starts a unit:
// a plugin that is already gone has nothing to cancel.
func (d *pluginDispatcher) Cancel(ctx context.Context, req operations.PluginCancelRequest) error {
	client, err := d.clients.live(req.PluginID)
	if err != nil {
		return problem.From(err)
	}
	if err := client.Cancel(ctx, req.OperationID); err != nil {
		return problem.From(err)
	}
	return nil
}

// requestContext builds the ABI call context of one host-to-plugin call.
func requestContext(nodeID, instanceID, requestID, operationID, traceID, locale string, act actor.Actor) *platformv1.RequestContext {
	out := &platformv1.RequestContext{
		RequestId:   requestID,
		OperationId: operationID,
		TraceId:     traceID,
		NodeId:      nodeID,
		InstanceId:  instanceID,
		Locale:      locale,
	}
	if act.ID != "" {
		out.Actor = actorProto(act)
	}
	return out
}

// actorProto renders an actor as the ABI Actor message.
func actorProto(a actor.Actor) *platformv1.Actor {
	kind := platformv1.ActorKind_ACTOR_KIND_UNSPECIFIED
	switch a.Kind {
	case actor.Human:
		kind = platformv1.ActorKind_ACTOR_KIND_HUMAN
	case actor.AIAgent:
		kind = platformv1.ActorKind_ACTOR_KIND_AI_AGENT
	case actor.Service:
		kind = platformv1.ActorKind_ACTOR_KIND_SERVICE
	case actor.System:
		kind = platformv1.ActorKind_ACTOR_KIND_SYSTEM
	}
	return &platformv1.Actor{Kind: kind, Id: a.ID, OnBehalfOf: a.OnBehalfOf}
}

// attemptProto maps the host attempt number; the ABI counts from 1.
func attemptProto(attempt int) uint32 {
	if attempt <= 0 {
		return 0
	}
	return uint32(attempt)
}

// preconditionsProto maps plugin-side preconditions to the ABI message.
func preconditionsProto(in []operations.Precondition) []*platformv1.Precondition {
	if len(in) == 0 {
		return nil
	}
	out := make([]*platformv1.Precondition, 0, len(in))
	for _, p := range in {
		out = append(out, &platformv1.Precondition{Subject: p.Subject, Revision: p.Revision})
	}
	return out
}

// changesFromProto maps plugin-owned resource changes.
func changesFromProto(in []*platformv1.ResourceChange) []operations.ResourceChange {
	if len(in) == 0 {
		return nil
	}
	out := make([]operations.ResourceChange, 0, len(in))
	for _, c := range in {
		if c == nil {
			continue
		}
		out = append(out, operations.ResourceChange{
			Subject:         c.GetSubject(),
			Revision:        c.GetRevision(),
			ChangedPointers: append([]string(nil), c.GetChangedPointers()...),
			Deleted:         c.GetDeleted(),
		})
	}
	return out
}

// previewFromProto maps a plugin plan response. Subjects stay relative: the
// operations package prefixes them with the instance namespace and validates
// them, so a plugin cannot address another plugin's resources.
func previewFromProto(resp *platformv1.PlanOperationResponse, pluginID string) operations.Preview {
	var preview operations.Preview
	if resp == nil {
		return preview
	}
	for _, c := range resp.GetChanges() {
		if c == nil {
			continue
		}
		preview.Changes = append(preview.Changes, operations.PlannedChange{
			Kind:        plannedKind(c.GetKind()),
			Subject:     c.GetSubject(),
			Pointer:     c.GetPointer(),
			Before:      json.RawMessage(c.GetBeforeJson()),
			After:       json.RawMessage(c.GetAfterJson()),
			Reversible:  c.GetReversible(),
			Source:      string(operations.PluginSource),
			PluginID:    pluginID,
			Description: c.GetDescription(),
		})
	}
	for _, v := range resp.GetViolations() {
		if v == nil {
			continue
		}
		preview.Violations = append(preview.Violations, violationFromProto(v))
	}
	for _, v := range resp.GetWarnings() {
		if v == nil {
			continue
		}
		preview.Warnings = append(preview.Warnings, violationFromProto(v))
	}
	for _, p := range resp.GetPreconditions() {
		if p == nil {
			continue
		}
		preview.Preconditions = append(preview.Preconditions, operations.Precondition{
			Subject:  p.GetSubject(),
			Revision: p.GetRevision(),
		})
	}
	return preview
}

// violationFromProto maps one field violation.
func violationFromProto(v *platformv1.FieldViolation) problem.Violation {
	return problem.Violation{Pointer: v.GetPointer(), Code: v.GetCode(), Message: v.GetMessage()}
}

// plannedKind maps the ABI change kind to the host vocabulary. An unspecified
// kind stays empty so the operations package rejects the plan as a plugin bug
// instead of guessing what the plugin meant.
func plannedKind(kind platformv1.PlannedChange_Kind) string {
	switch kind {
	case platformv1.PlannedChange_KIND_CREATE:
		return "create"
	case platformv1.PlannedChange_KIND_UPDATE:
		return "update"
	case platformv1.PlannedChange_KIND_DELETE:
		return "delete"
	}
	return ""
}

// jobProgressFromProto maps one stream message. A percent of 0 means "unknown"
// in the ABI, so it becomes a nil host percent.
func jobProgressFromProto(p *platformv1.JobProgress) operations.JobProgress {
	var out operations.JobProgress
	if p == nil {
		return out
	}
	if percent := p.GetPercent(); percent > 0 {
		v := int(percent)
		out.Percent = &v
	}
	out.Step = p.GetStep()
	out.StepIndex = int(p.GetStepIndex())
	out.StepCount = int(p.GetStepCount())
	out.Message = p.GetMessage()
	out.Result = p.GetResultJson()
	out.Completed = p.GetCompleted()
	out.Changes = changesFromProto(p.GetChanges())
	if e := p.GetError(); e != nil {
		out.Error = pluginErrorFromProto(e)
	}
	return out
}

// pluginErrorFromProto maps a plugin-reported terminal error.
func pluginErrorFromProto(e *platformv1.ErrorDetail) error {
	violations := make([]problem.Violation, 0, len(e.GetViolations()))
	for _, v := range e.GetViolations() {
		if v == nil {
			continue
		}
		violations = append(violations, violationFromProto(v))
	}
	return problem.FromPlugin(e.GetCode(), e.GetMessage(), e.GetRetryable(), violations)
}

// --- plugin package layout -------------------------------------------------

// ---------------------------------------------------------------------------
// PluginDirs：以 updater 的 ACTIVE 版本解析插件目录。
// 更新后旧版本目录保留用于回滚，目录扫描无法判断该用哪个；ACTIVE 记录才是唯一事实。
// runtime 先于 updater 构造，故延迟绑定；未绑定（serve-agent）时退回目录扫描。
// ---------------------------------------------------------------------------

// PluginDirs resolves plugin package directories from the updater's ACTIVE
// version once SetActive bound it, and by scanning the directory before.
type PluginDirs struct {
	Root   string
	active atomic.Pointer[func(pluginID string) (string, bool)]
}

// SetActive binds the ACTIVE version lookup. It may be called once the
// updater exists; resolutions in flight keep the lookup they loaded.
func (d *PluginDirs) SetActive(f func(pluginID string) (string, bool)) { d.active.Store(&f) }

// Resolve returns the package directory of pluginID's ACTIVE version. A
// plugin without one (rejected, uninstalled) is NOT_FOUND, so the dispatcher
// does not start it.
func (d *PluginDirs) Resolve(pluginID string) (string, error) {
	if err := sandbox.ValidateID(pluginID); err != nil {
		return "", problem.New(problem.ValidationFailed, "%q is not a valid plugin id.", pluginID)
	}
	f := d.active.Load()
	if f == nil {
		return PluginDirResolver(d.Root)(pluginID)
	}
	v, ok := (*f)(pluginID)
	if !ok {
		return "", problem.New(problem.NotFound, "Plugin %q has no active version.", pluginID)
	}
	dir := install.VersionDir(filepath.Clean(d.Root), pluginID, v)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return "", problem.New(problem.PluginUnavailable, "The active version %s of plugin %q is missing.", v, pluginID)
	}
	return dir, nil
}

// PluginDirResolver returns a supervisor plugin directory resolver below
// pluginsDir. The privileged installer (P3) will own the final layout; until it
// is wired the agent accepts the layout the unit template documents:
//
//	<pluginsDir>/<id>/<version>/   immutable package directory
//	<pluginsDir>/<id>/current      symlink or directory, preferred when present
//
// A plugin with exactly one installed version resolves to it; zero versions is
// NOT_FOUND and several versions without a "current" pointer is a STATE_CONFLICT
// rather than a guess.
func PluginDirResolver(pluginsDir string) func(pluginID string) (string, error) {
	return func(pluginID string) (string, error) {
		if err := sandbox.ValidateID(pluginID); err != nil {
			return "", problem.New(problem.ValidationFailed, "%q is not a valid plugin id.", pluginID)
		}
		root := filepath.Join(pluginsDir, pluginID)
		current := filepath.Join(root, "current")
		if info, err := os.Stat(current); err == nil && info.IsDir() {
			return current, nil
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", problem.New(problem.NotFound, "The package of plugin %q is not installed.", pluginID)
			}
			return "", problem.New(problem.Unavailable, "The package directory of plugin %q is not readable.", pluginID)
		}
		var versions []string
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != "current" {
				versions = append(versions, entry.Name())
			}
		}
		switch len(versions) {
		case 0:
			return "", problem.New(problem.NotFound, "The package of plugin %q is not installed.", pluginID)
		case 1:
			return filepath.Join(root, versions[0]), nil
		default:
			return "", problem.New(problem.StateConflict,
				"Plugin %q has several installed versions and no current pointer.", pluginID)
		}
	}
}
