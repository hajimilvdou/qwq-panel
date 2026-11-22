// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// pkgSpec describes one fake package the installer can stage.
type pkgSpec struct {
	ID          string
	Version     string
	Caps        []manifest.Capability
	MemoryMB    int64
	OverlapSafe bool
	HotApply    bool
	NoManifest  bool
	Publisher   string
	// SchemaVersion overrides the manifest schema_version (default 1.2).
	SchemaVersion string
	// UnpackedBytes is what Inspect reports as the verified content size.
	UnpackedBytes int64
}

func defaultPkg(id, version string) pkgSpec {
	return pkgSpec{ID: id, Version: version, MemoryMB: 48, OverlapSafe: true, HotApply: true}
}

// fakeInstaller implements Installer for the tests.
type fakeInstaller struct {
	mu        sync.Mutex
	packages  map[string]pkgSpec
	stageErr  error
	installNx map[string]error
	removeErr error

	// inspectVerdict, when set, is returned by Inspect instead of deriving a
	// verdict from the package table; inspectErr fails the call.
	inspectVerdict *InspectionVerdict
	inspectErr     error

	stageCalls   int
	inspectCalls int
	installCalls []string
	removed      []string
	discarded    int
}

func newFakeInstaller() *fakeInstaller {
	return &fakeInstaller{packages: make(map[string]pkgSpec), installNx: make(map[string]error)}
}

func (f *fakeInstaller) add(path string, spec pkgSpec) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.packages[path] = spec
}

func (f *fakeInstaller) Stage(_ context.Context, pkgPath string) (Staged, error) {
	f.mu.Lock()
	f.stageCalls++
	err := f.stageErr
	spec, ok := f.packages[pkgPath]
	f.mu.Unlock()
	if err != nil {
		return Staged{}, err
	}
	if !ok {
		return Staged{}, fmt.Errorf("fake installer: unknown package %q", pkgPath)
	}
	if spec.NoManifest {
		return Staged{PluginID: spec.ID, Version: spec.Version}, nil
	}
	return f.buildStaged(spec)
}

// Inspect answers the pre-install inspection from the same package table as
// Stage.
func (f *fakeInstaller) Inspect(_ context.Context, pkgPath string) (InspectionVerdict, error) {
	f.mu.Lock()
	f.inspectCalls++
	err := f.inspectErr
	verdict := f.inspectVerdict
	spec, ok := f.packages[pkgPath]
	f.mu.Unlock()
	if err != nil {
		return InspectionVerdict{}, err
	}
	if verdict != nil {
		return *verdict, nil
	}
	if !ok {
		return InspectionVerdict{}, fmt.Errorf("fake installer: unknown package %q", pkgPath)
	}
	if spec.NoManifest {
		// A package whose manifest cannot be parsed: nothing to describe.
		return InspectionVerdict{Staged: &Staged{PluginID: spec.ID, Version: spec.Version}}, nil
	}
	staged, serr := f.buildStaged(spec)
	if serr != nil {
		return InspectionVerdict{}, serr
	}
	return InspectionVerdict{
		Staged:        &staged,
		Manifest:      staged.Manifest,
		Valid:         true,
		Trusted:       true,
		KeyID:         "ed25519:" + strings.Repeat("a", 64),
		UnpackedBytes: spec.UnpackedBytes,
	}, nil
}

// buildStaged builds the verified package of one spec, mirroring Stage's
// happy path.
func (f *fakeInstaller) buildStaged(spec pkgSpec) (Staged, error) {
	schema := spec.SchemaVersion
	if schema == "" {
		schema = "1.2"
	}
	m := &manifest.Manifest{
		SchemaVersion: schema,
		ID:            spec.ID,
		Version:       spec.Version,
		Name:          "Fake " + spec.ID,
		Summary:       "fake",
		Publisher:     manifest.Publisher{ID: spec.Publisher},
		Lifecycle: manifest.Lifecycle{
			Startup:        "eager",
			Background:     true,
			UpdateStrategy: "auto",
			OverlapSafe:    boolPtr(spec.OverlapSafe),
		},
		Config:       manifest.Config{HotApply: spec.HotApply},
		Resources:    manifest.Resources{MemoryMaxMB: spec.MemoryMB, CPUQuotaPercent: 100, PIDsMax: 32, FDsMax: 256},
		Capabilities: append([]manifest.Capability(nil), spec.Caps...),
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Staged{}, err
	}
	return Staged{
		PluginID:     spec.ID,
		Version:      spec.Version,
		Digest:       digestOf(raw),
		Manifest:     m,
		ManifestJSON: raw,
		Discard: func() error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.discarded++
			return nil
		},
	}, nil
}

func (f *fakeInstaller) InstallUnit(_ context.Context, staged Staged) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installCalls = append(f.installCalls, staged.PluginID+"@"+staged.Version)
	if err := f.installNx[staged.PluginID+"@"+staged.Version]; err != nil {
		return err
	}
	return nil
}

func (f *fakeInstaller) ReinstallUnit(_ context.Context, pluginID, version string, _ *manifest.Manifest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installCalls = append(f.installCalls, "reinstall|"+pluginID+"@"+version)
	return nil
}

func (f *fakeInstaller) RemoveUnit(_ context.Context, pluginID, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, pluginID+"@"+version)
	return f.removeErr
}

func (f *fakeInstaller) PurgeData(context.Context, string) error { return nil }

func (f *fakeInstaller) counts() (stage, discard int, installs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stageCalls, f.discarded, append([]string(nil), f.installCalls...)
}

func (f *fakeInstaller) removedCopy() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.removed...)
}

// fakeInstance is one running plugin process.
type fakeInstance struct {
	key           string
	pluginID      string
	version       string
	active        bool
	stopped       bool
	released      bool
	appliedConfig int64
	configs       map[int64]json.RawMessage
}

// fakeRuntime implements Runtime for the tests. Failures and panics are keyed
// by "Operation|plugin@version" so a test can break exactly one saga step.
type fakeRuntime struct {
	mu sync.Mutex
	// singleUnit models production's one systemd unit per plugin: at most one
	// process per plugin, and Attach returns whatever version runs (the
	// weakest Runtime the saga must stay correct against).
	singleUnit bool

	live     map[string]*fakeInstance
	routes   *RouteTable
	calls    []string
	fail     map[string]error
	panicOn  map[string]bool
	activate map[string]int
	deact    map[string]int
	readies  map[string]int
	stops    map[string]int
	releases map[string]int
	started  map[string]int
	attached map[string]int
	nextID   int
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		live:     make(map[string]*fakeInstance),
		fail:     make(map[string]error),
		panicOn:  make(map[string]bool),
		activate: make(map[string]int),
		deact:    make(map[string]int),
		readies:  make(map[string]int),
		stops:    make(map[string]int),
		releases: make(map[string]int),
		started:  make(map[string]int),
		attached: make(map[string]int),
	}
}

func key(pluginID, version string) string { return pluginID + "@" + version }

// liveKey is the process slot of a version: per version, or per plugin in
// singleUnit mode. It must run with r.mu held.
func (r *fakeRuntime) liveKey(pluginID, version string) string {
	if r.singleUnit {
		return pluginID
	}
	return key(pluginID, version)
}

// liveFor returns the running instance of exactly pluginID@version. It must
// run with r.mu held.
func (r *fakeRuntime) liveFor(pluginID, version string) *fakeInstance {
	inst := r.live[r.liveKey(pluginID, version)]
	if inst == nil || inst.version != version {
		return nil
	}
	return inst
}

func opKey(op, pluginID, version string) string { return op + "|" + key(pluginID, version) }

func (r *fakeRuntime) setFail(op, pluginID, version string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail[opKey(op, pluginID, version)] = err
}

// check applies the configured failure for op. It must run with r.mu held.
func (r *fakeRuntime) check(op, pluginID, version string) error {
	if r.panicOn[op] {
		panic(fmt.Sprintf("fake runtime: panic at %s", op))
	}
	return r.fail[opKey(op, pluginID, version)]
}

func (r *fakeRuntime) Start(_ context.Context, spec InstanceSpec) (Handle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Start|"+key(spec.PluginID, spec.Version))
	if err := r.check("Start", spec.PluginID, spec.Version); err != nil {
		return nil, err
	}
	k := key(spec.PluginID, spec.Version)
	slot := r.liveKey(spec.PluginID, spec.Version)
	if inst := r.live[slot]; inst != nil && !inst.stopped {
		return nil, fmt.Errorf("fake runtime: %s is already running", inst.key)
	}
	r.nextID++
	inst := &fakeInstance{key: k, pluginID: spec.PluginID, version: spec.Version, configs: make(map[int64]json.RawMessage)}
	r.live[slot] = inst
	r.started[k]++
	return inst, nil
}

func (r *fakeRuntime) Attach(_ context.Context, spec InstanceSpec) (Handle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Attach|"+key(spec.PluginID, spec.Version))
	if err := r.check("Attach", spec.PluginID, spec.Version); err != nil {
		return nil, err
	}
	inst := r.liveFor(spec.PluginID, spec.Version)
	if inst == nil || inst.stopped || inst.released {
		return nil, fmt.Errorf("fake runtime: %s is not running", spec.PluginID)
	}
	r.attached[inst.key]++
	return inst, nil
}

func (r *fakeRuntime) Ready(_ context.Context, h Handle) error {
	inst := h.(*fakeInstance)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Ready|"+inst.key)
	if err := r.check("Ready", inst.pluginID, inst.version); err != nil {
		return err
	}
	if inst.stopped {
		return fmt.Errorf("fake runtime: %s stopped", inst.key)
	}
	r.readies[inst.key]++
	return nil
}

func (r *fakeRuntime) Activate(_ context.Context, h Handle) error {
	inst := h.(*fakeInstance)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Activate|"+inst.key)
	if err := r.check("Activate", inst.pluginID, inst.version); err != nil {
		return err
	}
	if inst.stopped {
		return fmt.Errorf("fake runtime: %s stopped", inst.key)
	}
	if inst.active {
		return nil // idempotent: activating twice is a no-op
	}
	inst.active = true
	r.activate[inst.key]++
	return nil
}

func (r *fakeRuntime) Deactivate(_ context.Context, h Handle) error {
	inst := h.(*fakeInstance)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Deactivate|"+inst.key)
	if err := r.check("Deactivate", inst.pluginID, inst.version); err != nil {
		return err
	}
	if inst.active {
		inst.active = false
		r.deact[inst.key]++
	}
	return nil
}

func (r *fakeRuntime) Stop(_ context.Context, h Handle, _ time.Duration) error {
	inst := h.(*fakeInstance)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Stop|"+inst.key)
	if err := r.check("Stop", inst.pluginID, inst.version); err != nil {
		return err
	}
	if inst.stopped {
		return nil
	}
	inst.stopped = true
	inst.active = false
	r.stops[inst.key]++
	return nil
}

func (r *fakeRuntime) Release(_ context.Context, h Handle) error {
	inst := h.(*fakeInstance)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Release|"+inst.key)
	if err := r.check("Release", inst.pluginID, inst.version); err != nil {
		return err
	}
	inst.released = true
	inst.stopped = true
	inst.active = false
	if r.live[r.liveKey(inst.pluginID, inst.version)] == inst {
		delete(r.live, r.liveKey(inst.pluginID, inst.version))
	}
	r.releases[inst.key]++
	return nil
}

func (r *fakeRuntime) Health(_ context.Context, h Handle) error {
	inst := h.(*fakeInstance)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Health|"+inst.key)
	if err := r.check("Health", inst.pluginID, inst.version); err != nil {
		return err
	}
	if inst.stopped {
		return fmt.Errorf("fake runtime: %s stopped", inst.key)
	}
	return nil
}

func (r *fakeRuntime) ValidateConfig(_ context.Context, h Handle, revision int64, cfg json.RawMessage) error {
	inst := h.(*fakeInstance)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("ValidateConfig|%s|%d", inst.key, revision))
	if err := r.check("ValidateConfig", inst.pluginID, inst.version); err != nil {
		return err
	}
	inst.configs[revision] = append(json.RawMessage(nil), cfg...)
	return nil
}

func (r *fakeRuntime) ApplyConfig(_ context.Context, h Handle, revision int64, cfg json.RawMessage) error {
	inst := h.(*fakeInstance)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("ApplyConfig|%s|%d", inst.key, revision))
	if err := r.check("ApplyConfig", inst.pluginID, inst.version); err != nil {
		return err
	}
	inst.configs[revision] = append(json.RawMessage(nil), cfg...)
	inst.appliedConfig = revision
	return nil
}

func (r *fakeRuntime) SwapRoutes(routes *RouteTable) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("SwapRoutes|%d", routes.Revision()))
	if r.panicOn["SwapRoutes"] {
		panic("fake runtime: panic at SwapRoutes")
	}
	r.routes = routes
}

func (r *fakeRuntime) callList() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *fakeRuntime) count(op string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if len(c) > len(op) && c[:len(op)] == op {
			n++
		}
	}
	return n
}

func (r *fakeRuntime) activations(pluginID, version string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.activate[key(pluginID, version)]
}

func (r *fakeRuntime) deactivations(pluginID, version string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deact[key(pluginID, version)]
}

func (r *fakeRuntime) instanceFor(pluginID, version string) *fakeInstance {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.liveFor(pluginID, version)
}

func (r *fakeRuntime) appliedConfig(pluginID, version string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if inst := r.liveFor(pluginID, version); inst != nil {
		return inst.appliedConfig
	}
	return 0
}

// fakeMemory implements MemorySource.
type fakeMemory struct {
	mu       sync.Mutex
	avail    uint64
	cur      map[string]uint64
	availErr error
	curErr   error
}

func newFakeMemory() *fakeMemory {
	return &fakeMemory{avail: 4 << 30, cur: make(map[string]uint64)}
}

func (m *fakeMemory) Available() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.avail, m.availErr
}

func (m *fakeMemory) Current(pluginID string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur[pluginID], m.curErr
}

func (m *fakeMemory) set(avail uint64, pluginID string, current uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.avail = avail
	if pluginID != "" {
		m.cur[pluginID] = current
	}
}

func boolPtr(b bool) *bool { return &b }

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// env is a fully wired updater over a real SQLite database in t.TempDir().
type env struct {
	t    *testing.T
	db   *storage.DB
	rt   *fakeRuntime
	ins  *fakeInstaller
	mem  *fakeMemory
	clk  *clock.Fake
	u    *Updater
	opts Options
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWithStorage(t, nil)
}

// newEnvWithStorage 复用原真实数据库夹具，只开放测试所需的存储观测配置。
func newEnvWithStorage(t *testing.T, configure func(*storage.Options)) *env {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	dbOptions := storage.Options{
		Path:   filepath.Join(t.TempDir(), "qwq.db"),
		Clock:  clk,
		Logger: discardLogger(),
	}
	if configure != nil {
		configure(&dbOptions)
	}
	db, err := storage.Open(context.Background(), dbOptions)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := &env{
		t:   t,
		db:  db,
		rt:  newFakeRuntime(),
		ins: newFakeInstaller(),
		mem: newFakeMemory(),
		clk: clk,
		opts: Options{
			DB:        db,
			Runtime:   nil,
			Installer: nil,
			Memory:    nil,
			Clock:     clk,
			Logger:    discardLogger(),
		},
	}
	e.opts.Runtime, e.opts.Installer, e.opts.Memory = e.rt, e.ins, e.mem
	e.u = e.newUpdater()
	return e
}

func (e *env) newUpdater() *Updater {
	e.t.Helper()
	u, err := New(e.opts)
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	return u
}

// reopen simulates a host restart: the same database and runtime, but a new
// in-memory Updater without handles.
func (e *env) reopen() *Updater {
	e.t.Helper()
	e.u = e.newUpdater()
	return e.u
}

func (e *env) advance(d time.Duration) { e.clk.Advance(d) }

func (e *env) ctx() context.Context { return context.Background() }

// installPackage adds a package to the fake installer and installs it.
func (e *env) installPackage(path string, spec pkgSpec, accepted ...string) *Version {
	e.t.Helper()
	e.ins.add(path, spec)
	v, err := e.u.Install(e.ctx(), InstallRequest{PackagePath: path, AcceptedCapabilities: accepted})
	if err != nil {
		e.t.Fatalf("Install(%s): %v", path, err)
	}
	e.advance(time.Second)
	return v
}

// mustInstallV1 adds and installs the default v1 package of id.
func (e *env) mustInstallV1(id string, accepted ...string) *Version {
	e.t.Helper()
	spec := defaultPkg(id, "1.0.0")
	return e.installPackage("pkg/"+id+"-1.0.0.pkg", spec, accepted...)
}

// dbVersion reads one version row directly.
func (e *env) dbVersion(pluginID, version string) Version {
	e.t.Helper()
	v, err := e.u.loadVersion(e.ctx(), pluginID, version)
	if err != nil {
		e.t.Fatalf("load version %s/%s: %v", pluginID, version, err)
	}
	return v
}

func (e *env) activeConfigRevision(pluginID string) int64 {
	e.t.Helper()
	c, ok := e.u.ActiveConfig(pluginID)
	if !ok {
		return 0
	}
	return c.Revision
}

func requireProblem(t *testing.T, err error, code problem.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", code)
	}
	if !problem.HasCode(err, code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

// findCall returns the index of the first call containing substr.
func findCall(t *testing.T, calls []string, substr string) int {
	t.Helper()
	for i, c := range calls {
		if strings.Contains(c, substr) {
			return i
		}
	}
	t.Fatalf("call %q not found in %v", substr, calls)
	return -1
}

// lastCall returns the index of the last call containing substr.
func lastCall(t *testing.T, calls []string, substr string) int {
	t.Helper()
	for i := len(calls) - 1; i >= 0; i-- {
		if strings.Contains(calls[i], substr) {
			return i
		}
	}
	t.Fatalf("call %q not found in %v", substr, calls)
	return -1
}

// sagasFor returns the sagas of a plugin, oldest first.
func (e *env) sagasFor(pluginID string) []saga {
	e.t.Helper()
	var out []saga
	err := e.db.View(e.ctx(), func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(e.ctx(), `SELECT saga_id, plugin_id, from_version, to_version, mode, strategy,
			state, step, error, created_at, updated_at FROM plugin_update_sagas
			WHERE plugin_id = ? ORDER BY created_at, saga_id`, pluginID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			s, err := scanSaga(rows)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		e.t.Fatalf("list sagas: %v", err)
	}
	return out
}

func (e *env) runningSagaCount() int {
	e.t.Helper()
	var n int
	err := e.db.View(e.ctx(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(e.ctx(), `SELECT COUNT(*) FROM plugin_update_sagas WHERE state = 'RUNNING'`).Scan(&n)
	})
	if err != nil {
		e.t.Fatalf("count running sagas: %v", err)
	}
	return n
}

func (e *env) activeRowCount(pluginID string) int {
	e.t.Helper()
	var n int
	err := e.db.View(e.ctx(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(e.ctx(),
			`SELECT COUNT(*) FROM plugin_versions WHERE plugin_id = ? AND active = 1`, pluginID).Scan(&n)
	})
	if err != nil {
		e.t.Fatalf("count active rows: %v", err)
	}
	return n
}

// requireActive asserts that the committed active version and the published
// route agree on version, and that exactly one row is active.
func (e *env) requireActive(pluginID, version string) {
	e.t.Helper()
	v, ok := e.u.Active(pluginID)
	if !ok || v.Version != version || !v.Active {
		e.t.Fatalf("Active(%s) = %+v, %v; want %s", pluginID, v, ok, version)
	}
	route, ok := e.u.Routes().Lookup(pluginID)
	if !ok || route.Version != version {
		e.t.Fatalf("Routes(%s) = %+v, %v; want %s", pluginID, route, ok, version)
	}
	if n := e.activeRowCount(pluginID); n != 1 {
		e.t.Fatalf("active rows of %s = %d, want 1", pluginID, n)
	}
}

var errBoom = errors.New("boom")
