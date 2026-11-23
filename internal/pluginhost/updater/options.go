// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Defaults of Options.
const (
	defaultStopGrace     = 10 * time.Second
	defaultTimeout       = 2 * time.Minute
	defaultMemoryReserve = 64 << 20
	defaultKeepConfigs   = 20
	defaultKeepConfigAge = 30 * 24 * time.Hour
	defaultMemoryMaxMB   = 48
	maxConfigBytes       = 1 << 20
	maxPluginIDLen       = 128
	maxVersionLen        = 128
	sagaIDPrefix         = "sag"
	eventsSchemaVersion  = "1"
)

// Options configure New.
type Options struct {
	// DB is the host database; required.
	DB *storage.DB
	// Runtime starts, stops and routes plugin instances; required.
	Runtime Runtime
	// Installer stages packages and installs units; required.
	Installer Installer
	// Memory is the preflight memory source; required. A host without cgroups
	// can return an error from Available: the updater then conservatively uses
	// the restart strategy instead of failing every update.
	Memory MemorySource
	// Clock is the time source; the zero value is clock.System.
	Clock clock.Clock
	// Logger receives diagnostics; the zero value discards them.
	Logger *slog.Logger
	// StopGrace is the drain window passed to Runtime.Stop (default 10s).
	StopGrace time.Duration
	// Timeout bounds one install, update, rollback or configuration apply
	// when the request does not set its own (default 2m).
	Timeout time.Duration
	// MemoryReserveBytes is kept free in addition to the candidate's
	// MemoryMax during the preflight (default 64 MiB).
	MemoryReserveBytes uint64
	// KeepConfigs is how many recent configuration revisions are retained on
	// top of KeepConfigAge (default 20).
	KeepConfigs int
	// KeepConfigAge retains every configuration revision younger than this
	// (default 30 days).
	KeepConfigAge time.Duration
	// RestartOnly declares a runtime that can run only one version of a plugin
	// at a time. The production systemd unit is per plugin rather than per
	// version, so an overlap step would have no second unit to start. When set,
	// the memory preflight still refuses to start the candidate when the node
	// cannot hold it, but the chosen strategy is always StrategyRestart. The
	// guarantee covers update and rollback alike, including a rollback the
	// caller did not annotate with a strategy.
	RestartOnly bool
	// TrustStore, when non-nil, is consulted during Rollback so versions signed
	// by a revoked/removed publisher key cannot be re-activated.
	TrustStore manifest.TrustStore
}

func (o Options) withDefaults() Options {
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.StopGrace <= 0 {
		o.StopGrace = defaultStopGrace
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MemoryReserveBytes == 0 {
		o.MemoryReserveBytes = defaultMemoryReserve
	}
	if o.KeepConfigs <= 0 {
		o.KeepConfigs = defaultKeepConfigs
	}
	if o.KeepConfigAge <= 0 {
		o.KeepConfigAge = defaultKeepConfigAge
	}
	return o
}

// Updater owns the plugin version, configuration and saga state of one node.
// One Updater is shared by all plugins: it serializes work per plugin with
// per-plugin mutexes and never takes a global plugin lock.
type Updater struct {
	db      *storage.DB
	rt      Runtime
	install Installer
	mem     MemorySource
	trust   manifest.TrustStore
	clock   clock.Clock
	log     *slog.Logger
	opts    Options

	locks keyedLocks

	// handles maps plugin id -> version -> runtime handle. It is only touched
	// while holding that plugin's lock (except for the map guard itself).
	handleMu sync.Mutex
	handles  map[string]map[string]Handle

	// active is the committed active version per plugin. The database is the
	// source of truth; this cache is reloaded by New and Recover and updated
	// by commit.
	activeMu sync.RWMutex
	active   map[string]Version

	configMu sync.RWMutex
	configs  map[string]ConfigRevision

	routes  atomic.Pointer[RouteTable]
	routeMu sync.Mutex
}

// New opens the updater over an already migrated database and loads the
// committed active versions and configurations into memory. It performs no
// runtime call: call Recover at host startup to reattach and rebuild routes.
func New(o Options) (*Updater, error) {
	switch {
	case o.DB == nil:
		return nil, errors.New("updater: Options.DB is required")
	case o.Runtime == nil:
		return nil, errors.New("updater: Options.Runtime is required")
	case o.Installer == nil:
		return nil, errors.New("updater: Options.Installer is required")
	case o.Memory == nil:
		return nil, errors.New("updater: Options.Memory is required")
	}
	o = o.withDefaults()
	u := &Updater{
		db:      o.DB,
		rt:      o.Runtime,
		install: o.Installer,
		mem:     o.Memory,
		trust:   o.TrustStore,
		clock:   o.Clock,
		log:     o.Logger,
		opts:    o,
		locks:   keyedLocks{m: make(map[string]*sync.Mutex)},
		handles: make(map[string]map[string]Handle),
		active:  make(map[string]Version),
		configs: make(map[string]ConfigRevision),
	}
	u.routes.Store(NewRouteTable(nil))
	if err := u.loadState(context.Background()); err != nil {
		return nil, err
	}
	return u, nil
}

// loadState reloads the committed active versions and configurations and the
// route table derived from them. Unfinished sagas are not touched; Recover
// resolves them before this state is trusted operationally.
func (u *Updater) loadState(ctx context.Context) error {
	versions, err := u.listVersions(ctx, "")
	if err != nil {
		return err
	}
	active := make(map[string]Version)
	for _, v := range versions {
		if v.Active {
			active[v.PluginID] = v
			if v.Manifest != nil && schemaMinor(v.Manifest) < minInstallSchemaMinor {
				u.log.WarnContext(ctx, "active plugin uses an old manifest schema; its next update must be schema 1.2 or later",
					"plugin", v.PluginID, "version", v.Version, "schema_version", v.Manifest.SchemaVersion)
			}
		}
	}
	configs, err := u.listActiveConfigs(ctx)
	if err != nil {
		return err
	}
	u.activeMu.Lock()
	u.active = active
	u.activeMu.Unlock()
	u.configMu.Lock()
	u.configs = configs
	u.configMu.Unlock()
	u.setRoutesFromActive(active)
	return nil
}

// Active returns the committed active version of pluginID. It reflects the
// database state after the last committed saga; during an update it still
// returns the old version until the commit step.
func (u *Updater) Active(pluginID string) (Version, bool) {
	u.activeMu.RLock()
	defer u.activeMu.RUnlock()
	v, ok := u.active[pluginID]
	return v, ok
}

// ActiveConfig returns the applied configuration revision of pluginID.
func (u *Updater) ActiveConfig(pluginID string) (ConfigRevision, bool) {
	u.configMu.RLock()
	defer u.configMu.RUnlock()
	c, ok := u.configs[pluginID]
	return c, ok
}

// SyncActiveConfig updates the in-memory active configuration snapshot after an
// out-of-band cross-plugin PutPluginConfig commit so subsequent hostConfigSource
// reads, prerequisite consumer checks, and core.apply calls never observe a stale
// or incomplete revision.
func (u *Updater) SyncActiveConfig(pluginID string, rev int64, raw []byte) {
	now := time.Now().UTC()
	if u.clock != nil {
		now = u.clock.Now().UTC()
	}
	u.configMu.Lock()
	u.configs[pluginID] = ConfigRevision{
		PluginID:  pluginID,
		Revision:  rev,
		Config:    append([]byte(nil), raw...),
		Active:    true,
		CreatedAt: now,
		AppliedAt: now,
	}
	u.configMu.Unlock()
}

// Routes returns the currently published route table. The pointer and the
// table are immutable; concurrent readers always observe one complete
// snapshot.
func (u *Updater) Routes() *RouteTable { return u.routes.Load() }

// Versions returns every recorded version of pluginID, newest first.
func (u *Updater) Versions(pluginID string) ([]Version, error) {
	if err := checkPluginID(pluginID); err != nil {
		return nil, err
	}
	return u.listVersions(context.Background(), pluginID)
}

// AllVersions returns every recorded version of every plugin, ordered by
// plugin id and installed_at descending. It is a read-only query used by the
// host's plugin list; it changes no state and publishes no route.
func (u *Updater) AllVersions() ([]Version, error) {
	return u.listVersions(context.Background(), "")
}

// setRoutesFromActive builds a fresh table from the active versions without
// publishing it to the runtime. New uses it for the initial snapshot.
func (u *Updater) setRoutesFromActive(active map[string]Version) {
	routes := make([]Route, 0, len(active))
	for id, v := range active {
		routes = append(routes, Route{PluginID: id, Version: v.Version})
	}
	t := NewRouteTable(routes)
	if cur := u.routes.Load(); cur != nil {
		t.revision = cur.revision + 1
	}
	u.routes.Store(t)
}

// swapRoute publishes a snapshot in which pluginID routes to version and
// hands it to the runtime. A panic in Runtime.SwapRoutes leaves the updater's
// pointer untouched, so recovery republishes the same content.
func (u *Updater) swapRoute(pluginID, version string) {
	u.routeMu.Lock()
	defer u.routeMu.Unlock()
	cur := u.routes.Load()
	next := cur.clone()
	next.routes[pluginID] = Route{PluginID: pluginID, Version: version}
	next.revision = cur.Revision() + 1
	u.rt.SwapRoutes(next)
	u.routes.Store(next)
}

// publishActiveRoutes republishes the route table derived from the committed
// active versions and hands it to the runtime. Recover calls it
// unconditionally so a restarted host gets the table even when the content did
// not change.
func (u *Updater) publishActiveRoutes() {
	u.activeMu.RLock()
	routes := make([]Route, 0, len(u.active))
	for id, v := range u.active {
		routes = append(routes, Route{PluginID: id, Version: v.Version})
	}
	u.activeMu.RUnlock()

	u.routeMu.Lock()
	defer u.routeMu.Unlock()
	cur := u.routes.Load()
	next := NewRouteTable(routes)
	next.revision = cur.Revision() + 1
	u.rt.SwapRoutes(next)
	u.routes.Store(next)
}

// abortTimeout bounds the rollback and terminal record of a failed saga.
const abortTimeout = 30 * time.Second

// withTimeout bounds an operation, falling back to Options.Timeout. The
// operation is detached from the caller's cancellation: a saga stopped half way
// leaves the plugin in a state only recovery can resolve, so the deadline is
// the only thing allowed to end it.
func (u *Updater) withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = u.opts.Timeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

// handle returns the cached handle of one version.
func (u *Updater) handle(pluginID, version string) Handle {
	u.handleMu.Lock()
	defer u.handleMu.Unlock()
	if byVersion := u.handles[pluginID]; byVersion != nil {
		return byVersion[version]
	}
	return nil
}

func (u *Updater) setHandle(pluginID, version string, h Handle) {
	u.handleMu.Lock()
	defer u.handleMu.Unlock()
	byVersion := u.handles[pluginID]
	if byVersion == nil {
		byVersion = make(map[string]Handle)
		u.handles[pluginID] = byVersion
	}
	byVersion[version] = h
}

func (u *Updater) dropHandle(pluginID, version string) {
	u.handleMu.Lock()
	defer u.handleMu.Unlock()
	if byVersion := u.handles[pluginID]; byVersion != nil {
		delete(byVersion, version)
	}
}

// ensureHandle returns a handle for spec, attaching to a running instance
// first and starting a new one only when canStart is true. attachOnly
// failures are reported as (nil, false, nil) for cleanup paths and as an
// error for paths that need the instance.
func (u *Updater) ensureHandle(ctx context.Context, spec InstanceSpec, canStart bool) (Handle, bool, error) {
	if h := u.handle(spec.PluginID, spec.Version); h != nil {
		return h, true, nil
	}
	h, err := u.rt.Attach(ctx, spec)
	if err == nil && h == nil {
		err = errors.New("updater: Runtime.Attach returned a nil handle")
	}
	if err == nil {
		u.setHandle(spec.PluginID, spec.Version, h)
		return h, true, nil
	}
	u.log.DebugContext(ctx, "attach failed", "plugin", spec.PluginID, "version", spec.Version, "err", err)
	if !canStart {
		return nil, false, nil
	}
	h, err = u.rt.Start(ctx, spec)
	if err != nil {
		return nil, false, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The plugin %s version %s could not be started.", spec.PluginID, spec.Version),
			Cause:  err,
		}
	}
	if h == nil {
		return nil, false, &problem.Error{
			Code:   problem.PluginUnavailable,
			Detail: fmt.Sprintf("The plugin %s version %s started without an instance.", spec.PluginID, spec.Version),
		}
	}
	u.setHandle(spec.PluginID, spec.Version, h)
	return h, true, nil
}

// specFor builds the runtime spec of a version.
func (u *Updater) specFor(pluginID string, v Version) InstanceSpec {
	spec := InstanceSpec{
		PluginID: pluginID,
		Version:  v.Version,
		Digest:   v.Digest,
		Manifest: v.Manifest,
	}
	if cfg, ok := u.ActiveConfig(pluginID); ok {
		spec.ConfigRevision = cfg.Revision
		spec.Config = append(json.RawMessage(nil), cfg.Config...)
	}
	return spec
}

// checkPluginID validates the manifest id grammar and the length bound. The
// sandbox is stricter about the length because the id becomes a group name;
// that check stays with the installer.
func checkPluginID(id string) error {
	if id == "" {
		return problem.New(problem.ValidationFailed, "plugin_id is required.")
	}
	if len(id) > maxPluginIDLen || !pluginIDPattern.MatchString(id) {
		return problem.Validation(problem.Violation{
			Pointer: "/plugin_id",
			Code:    "INVALID_PLUGIN_ID",
			Message: "The plugin id does not match the manifest id grammar.",
		})
	}
	return nil
}

var pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`)

func checkVersion(v string) error {
	if v != "" && len(v) <= maxVersionLen && versionPattern.MatchString(v) {
		return nil
	}
	return problem.New(problem.ValidationFailed, "The plugin version is not a valid version string.")
}

var versionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.+-]+)?$`)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// normalizeStaged fills the defaults of a Staged value and validates it.
func normalizeStaged(s Staged) (Staged, error) {
	if s.Manifest == nil {
		return s, errors.New("updater: staged package has no manifest")
	}
	if s.PluginID == "" {
		s.PluginID = s.Manifest.ID
	}
	if s.Version == "" {
		s.Version = s.Manifest.Version
	}
	if s.PluginID != s.Manifest.ID || s.Version != s.Manifest.Version {
		return s, errors.New("updater: staged identity does not match its manifest")
	}
	if len(s.ManifestJSON) == 0 {
		raw, err := json.Marshal(s.Manifest)
		if err != nil {
			return s, err
		}
		s.ManifestJSON = raw
	}
	if !json.Valid(s.ManifestJSON) {
		return s, errors.New("updater: staged manifest bytes are not valid JSON")
	}
	if s.Digest == "" {
		s.Digest = digestOf(s.ManifestJSON)
	}
	if !digestPattern.MatchString(s.Digest) {
		return s, fmt.Errorf("updater: staged digest %q is not sha256:<hex>", s.Digest)
	}
	if err := checkPluginID(s.PluginID); err != nil {
		return s, err
	}
	if err := checkVersion(s.Version); err != nil {
		return s, err
	}
	return s, nil
}

// keyedLocks is a set of per-key mutexes. Entries are small and never
// released: the number of plugins on a node is bounded.
type keyedLocks struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

// lock locks key and returns the unlock function.
func (k *keyedLocks) lock(key string) func() {
	k.mu.Lock()
	mu := k.m[key]
	if mu == nil {
		mu = new(sync.Mutex)
		k.m[key] = mu
	}
	k.mu.Unlock()
	mu.Lock()
	return mu.Unlock
}
