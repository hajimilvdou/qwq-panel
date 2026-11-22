// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/sdk/abi"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

const (
	updaterTestID      = "test.plugin"
	updaterTestVersion = "1.2.3"
)

// shortUpdaterTempDir returns a short temporary path: unix sockets are limited
// to 108 bytes on Linux and t.TempDir embeds the test name.
func shortUpdaterTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "qwqupd-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// --- fake systemd -----------------------------------------------------------

// sagaSystemctl is a sandbox.Systemctl whose Start installs a live-looking main
// process (the test process itself remains alive throughout attach/release).
type sagaSystemctl struct {
	mu         sync.Mutex
	status     sandbox.UnitStatus
	startPID   int
	startTime  time.Time
	startErr   error
	stopErr    error
	killErr    error
	showErr    error
	startCalls int
	stopCalls  int
	killCalls  int
	showCalls  int
}

func newSagaSystemctl() *sagaSystemctl {
	return &sagaSystemctl{
		startPID:  os.Getpid(),
		startTime: time.Unix(1700000000, 0).UTC(),
	}
}

func (f *sagaSystemctl) Start(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls++
	if f.startErr != nil {
		return f.startErr
	}
	if f.status.MainPID == 0 {
		f.status.MainPID = f.startPID
		f.status.StartTime = f.startTime
		f.status.ActiveState = "active"
		f.status.SubState = "running"
	}
	return nil
}

func (f *sagaSystemctl) Stop(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
	if f.stopErr != nil {
		return f.stopErr
	}
	f.clearProcess()
	return nil
}

func (f *sagaSystemctl) Kill(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killCalls++
	if f.killErr != nil {
		return f.killErr
	}
	f.clearProcess()
	return nil
}

func (f *sagaSystemctl) Show(context.Context, string) (sandbox.UnitStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.showCalls++
	if f.showErr != nil {
		return sandbox.UnitStatus{}, f.showErr
	}
	return f.status, nil
}

func (f *sagaSystemctl) counts() (starts, stops, kills int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls, f.stopCalls, f.killCalls
}

// clearProcess 在持锁时清理进程状态；systemd 的已加载单元定义仍存在。
func (f *sagaSystemctl) clearProcess() {
	f.status = sandbox.UnitStatus{ExecStart: f.status.ExecStart}
}

func (f *sagaSystemctl) setRunning(mainPID int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = sandbox.UnitStatus{
		ExecStart:    f.status.ExecStart,
		MainPID:      mainPID,
		StartTime:    f.startTime,
		ActiveState:  "active",
		SubState:     "running",
		ControlGroup: "/system.slice/qwq-plugin@test.plugin.service",
	}
}

// --- in-process plugin service ----------------------------------------------

// sagaPlugin is a scripted PluginService on a real unix socket.
type sagaPlugin struct {
	platformv1.UnimplementedPluginServiceServer

	mu         sync.Mutex
	calls      map[string]int
	requests   map[string]any
	order      []string
	errs       map[string]error
	health     *platformv1.CheckHealthResponse
	validate   *platformv1.ValidateConfigResponse
	apply      *platformv1.ApplyConfigResponse
	descriptor *platformv1.PluginDescriptor
	state      platformv1.LifecycleState
	// hangs names the RPCs that never answer until their context ends.
	hangs map[string]bool
}

func newSagaPlugin() *sagaPlugin {
	return &sagaPlugin{calls: make(map[string]int), requests: make(map[string]any), errs: make(map[string]error)}
}

func (p *sagaPlugin) record(name string, req any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[name]++
	p.requests[name] = req
	p.order = append(p.order, name)
	return p.errs[name]
}

// orderSnapshot returns the RPC names in call order.
func (p *sagaPlugin) orderSnapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.order...)
}

func (p *sagaPlugin) callCount(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[name]
}

func (p *sagaPlugin) request(name string) any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests[name]
}

func (p *sagaPlugin) setErr(name string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		delete(p.errs, name)
		return
	}
	p.errs[name] = err
}

func (p *sagaPlugin) setHealth(h *platformv1.CheckHealthResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.health = h
}

func (p *sagaPlugin) setValidate(v *platformv1.ValidateConfigResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.validate = v
}

func (p *sagaPlugin) setApply(a *platformv1.ApplyConfigResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.apply = a
}

func (p *sagaPlugin) setDescriptor(d *platformv1.PluginDescriptor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.descriptor = d
}

func (p *sagaPlugin) GetDescriptor(ctx context.Context, req *platformv1.GetDescriptorRequest) (*platformv1.GetDescriptorResponse, error) {
	if err := p.record("GetDescriptor", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.descriptor == nil {
		return nil, status.Error(codes.Unimplemented, "no descriptor")
	}
	return &platformv1.GetDescriptorResponse{Descriptor_: p.descriptor}, nil
}

func (p *sagaPlugin) Initialize(ctx context.Context, req *platformv1.InitializeRequest) (*platformv1.InitializeResponse, error) {
	if err := p.record("Initialize", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if req.GetInstanceHandle() == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_handle is required")
	}
	if p.state != platformv1.LifecycleState_LIFECYCLE_STATE_UNSPECIFIED {
		return nil, status.Error(codes.FailedPrecondition, "the instance is already initialized")
	}
	p.state = platformv1.LifecycleState_LIFECYCLE_STATE_INITIALIZED
	return &platformv1.InitializeResponse{StateSchemaVersion: "1"}, nil
}

func (p *sagaPlugin) Start(ctx context.Context, req *platformv1.StartRequest) (*platformv1.StartResponse, error) {
	if err := p.record("Start", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != platformv1.LifecycleState_LIFECYCLE_STATE_INITIALIZED {
		return nil, status.Errorf(codes.FailedPrecondition, "the instance is %s", p.state)
	}
	p.state = platformv1.LifecycleState_LIFECYCLE_STATE_READY
	return &platformv1.StartResponse{}, nil
}

func (p *sagaPlugin) ReleaseInstance(ctx context.Context, req *platformv1.ReleaseInstanceRequest) (*platformv1.ReleaseInstanceResponse, error) {
	if err := p.record("ReleaseInstance", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// The instance is gone from the plugin; a later Initialize may recreate it.
	p.state = platformv1.LifecycleState_LIFECYCLE_STATE_UNSPECIFIED
	return &platformv1.ReleaseInstanceResponse{}, nil
}

// setLifecycle forces the fake instance state.
func (p *sagaPlugin) setLifecycle(st platformv1.LifecycleState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = st
}

func (p *sagaPlugin) CheckHealth(ctx context.Context, req *platformv1.CheckHealthRequest) (*platformv1.CheckHealthResponse, error) {
	if err := p.record("CheckHealth", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.health != nil {
		return p.health, nil
	}
	if p.state == platformv1.LifecycleState_LIFECYCLE_STATE_UNSPECIFIED {
		return nil, status.Error(codes.NotFound, "the instance is not initialized")
	}
	statusValue := platformv1.CheckHealthResponse_STATUS_NOT_SERVING
	if p.state == platformv1.LifecycleState_LIFECYCLE_STATE_READY ||
		p.state == platformv1.LifecycleState_LIFECYCLE_STATE_ACTIVE {
		statusValue = platformv1.CheckHealthResponse_STATUS_SERVING
	}
	return &platformv1.CheckHealthResponse{Status: statusValue, LifecycleState: p.state}, nil
}

func (p *sagaPlugin) Activate(ctx context.Context, req *platformv1.ActivateRequest) (*platformv1.ActivateResponse, error) {
	if err := p.record("Activate", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	hang := p.hangs["Activate"]
	p.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return &platformv1.ActivateResponse{}, nil
}

func (p *sagaPlugin) Deactivate(ctx context.Context, req *platformv1.DeactivateRequest) (*platformv1.DeactivateResponse, error) {
	if err := p.record("Deactivate", req); err != nil {
		return nil, err
	}
	return &platformv1.DeactivateResponse{}, nil
}

func (p *sagaPlugin) Stop(ctx context.Context, req *platformv1.StopRequest) (*platformv1.StopResponse, error) {
	if err := p.record("Stop", req); err != nil {
		return nil, err
	}
	return &platformv1.StopResponse{Drained: true}, nil
}

func (p *sagaPlugin) ValidateConfig(ctx context.Context, req *platformv1.ValidateConfigRequest) (*platformv1.ValidateConfigResponse, error) {
	if err := p.record("ValidateConfig", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.validate == nil {
		return &platformv1.ValidateConfigResponse{}, nil
	}
	return p.validate, nil
}

func (p *sagaPlugin) ApplyConfig(ctx context.Context, req *platformv1.ApplyConfigRequest) (*platformv1.ApplyConfigResponse, error) {
	if err := p.record("ApplyConfig", req); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.apply != nil {
		return p.apply, nil
	}
	return &platformv1.ApplyConfigResponse{AppliedRevision: req.GetProposedRevision()}, nil
}

// --- runtime fixture --------------------------------------------------------

type runtimeFixture struct {
	rt         *UpdaterRuntime
	systemctl  *sagaSystemctl
	plugin     *sagaPlugin
	server     *grpc.Server
	runDir     string
	pluginsDir string
	socket     string
	pluginID   string
	version    string
}

func newRuntimeFixture(t *testing.T) *runtimeFixture {
	t.Helper()
	base := shortUpdaterTempDir(t)
	runDir := filepath.Join(base, "run")
	pluginsDir := filepath.Join(base, "plugins")
	pluginID, version := updaterTestID, updaterTestVersion
	if err := os.MkdirAll(install.VersionDir(pluginsDir, pluginID, version), 0o755); err != nil {
		t.Fatalf("mkdir version dir: %v", err)
	}
	socket := supervisor.SocketPath(runDir, pluginID)
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen %s: %v", socket, err)
	}
	fake := newSagaPlugin()
	srv := grpc.NewServer()
	platformv1.RegisterPluginServiceServer(srv, fake)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	systemctl := newSagaSystemctl()
	// 真实签名包有入口，systemd 提供已加载路径；正向 fixture 也保留这项事实。
	systemctl.status.ExecStart = filepath.Join(install.VersionDir(pluginsDir, pluginID, version), "bin/plugin")
	rt := &UpdaterRuntime{
		Systemctl:      systemctl,
		PluginsRoot:    pluginsDir,
		RunDir:         runDir,
		Clock:          clock.NewFake(time.Unix(1700000000, 0).UTC()),
		Logger:         slog.New(slog.DiscardHandler),
		NodeID:         "test-node",
		ConnectTimeout: 200 * time.Millisecond,
	}
	return &runtimeFixture{
		rt: rt, systemctl: systemctl, plugin: fake, server: srv,
		runDir: runDir, pluginsDir: pluginsDir, socket: socket,
		pluginID: pluginID, version: version,
	}
}

// spec returns a valid instance spec for the fixture's plugin.
func (f *runtimeFixture) spec() updater.InstanceSpec {
	return updater.InstanceSpec{
		PluginID: f.pluginID,
		Version:  f.version,
		Digest:   "sha256:" + strings.Repeat("a", 64),
		Manifest: &manifest.Manifest{ID: f.pluginID, Version: f.version, Entrypoint: "bin/plugin"},
	}
}

// --- package fixture --------------------------------------------------------

const updaterTestManifest = `{
  "schema_version": "1.2",
  "id": "test.plugin",
  "version": "1.2.3",
  "name": "Test Plugin",
  "summary": "Updater runtime fixture.",
  "publisher": {"id": "test", "key_id": "%s"},
  "abi": {"major": 1, "minimum_minor": 0},
  "engine_constraint": ">=1.0.0",
  "target": "linux/amd64",
  "entrypoint": "bin/plugin",
  "files": {},
  "provenance": {"sbom": "attestations/sbom.spdx.json"},
  "placement": "node",
  "lifecycle": {"startup": "eager", "background": false, "update_strategy": "restart"},
  "operations": [],
  "capabilities": [],
  "dependencies": [],
  "state": {"schema_version": "1", "minimum_rollback_version": "1.0.0", "backup_paths": []},
  "config": {"schema": "schemas/config.schema.json", "hot_apply": false},
  "resources": {"memory_max_mb": 32, "cpu_quota_percent": 50, "pids_max": 16, "fds_max": 64, "disk_max_mb": 64}
}
`

var updaterTestFiles = map[string]string{
	"bin/plugin":                  "#!/bin/sh\necho test plugin\n",
	"schemas/config.schema.json":  `{"type":"object"}`,
	"attestations/sbom.spdx.json": `{"spdxVersion":"SPDX-2.3"}`,
}

type updaterPackage struct {
	path string
	pub  ed25519.PublicKey
}

func newUpdaterPackage(t *testing.T) *updaterPackage {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	src := t.TempDir()
	manifestJSON := []byte(strings.Replace(updaterTestManifest, "%s", manifest.KeyID(pub), 1))
	tree := map[string]string{"manifest.json": string(manifestJSON)}
	for name, content := range updaterTestFiles {
		tree[name] = content
	}
	for name, content := range tree {
		path := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := fs.FileMode(0o644)
		if name == "bin/plugin" {
			mode = 0o755
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if _, err := pkgfile.Pack(src, &buf, pkgfile.PackOptions{SigningKey: priv}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	path := filepath.Join(src, "package.ppkg")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return &updaterPackage{path: path, pub: pub}
}

// trustDir writes the package key into a temporary trust root.
func (p *updaterPackage) trustDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pemBytes, err := pkgfile.MarshalPublicKeyPEM(p.pub)
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "publisher.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// --- installer fixture ------------------------------------------------------

// sagaRunner is a sandbox.Runner that records the privileged commands instead
// of running them.
type sagaRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *sagaRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return "", nil
}

type installerFixture struct {
	installer   *PluginInstaller
	systemctl   *sagaSystemctl
	pkg         *updaterPackage
	pluginsRoot string
	stagingRoot string
	unitDir     string
	tmpfilesDir string
	runtimeBase string
	runner      *sagaRunner
}

func newInstallerFixture(t *testing.T) *installerFixture {
	t.Helper()
	base := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if d.IsDir() {
				_ = os.Chmod(p, 0o700)
			}
			return nil
		})
	})
	pluginsRoot := filepath.Join(base, "plugins")
	stagingRoot := filepath.Join(base, "staging")
	unitDir := filepath.Join(base, "units")
	tmpfilesDir := filepath.Join(base, "tmpfiles")
	runtimeBase := filepath.Join(base, "run")
	credDir := filepath.Join(base, "creds")
	if err := os.MkdirAll(credDir, 0o700); err != nil {
		t.Fatalf("credential dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runtimeBase, "qwq", "host"), 0o711); err != nil {
		t.Fatalf("runtime dir: %v", err)
	}
	pkg := newUpdaterPackage(t)
	systemctl := newSagaSystemctl()
	runner := &sagaRunner{}
	return &installerFixture{
		installer: &PluginInstaller{
			PluginsRoot: pluginsRoot,
			StagingRoot: stagingRoot,
			TrustDir:    pkg.trustDir(t),
			HostBinary:  sandbox.DefaultHostBinary,
			Sandbox: sandbox.Installer{
				UnitDir:     unitDir,
				TmpfilesDir: tmpfilesDir,
				RuntimeBase: runtimeBase,
				CredDir:     credDir,
				AgentUser:   sandbox.DefaultAgentUser,
				Runner:      runner,
				Trust:       sandbox.TrustPolicy{UID: os.Getuid(), StopAt: base},
				LookupIDs:   func(string, string) (int, int, error) { return os.Getuid(), os.Getgid(), nil },
			},
			Systemctl: systemctl,
			Logger:    slog.New(slog.DiscardHandler),
		},
		systemctl:   systemctl,
		pkg:         pkg,
		pluginsRoot: pluginsRoot,
		stagingRoot: stagingRoot,
		unitDir:     unitDir,
		tmpfilesDir: tmpfilesDir,
		runtimeBase: runtimeBase,
		runner:      runner,
	}
}

func TestPluginInstallerStageInstallRemove(t *testing.T) {
	f := newInstallerFixture(t)
	ctx := t.Context()

	staged, err := f.installer.Stage(ctx, f.pkg.path)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if staged.PluginID != updaterTestID || staged.Version != updaterTestVersion {
		t.Fatalf("staged identity = %s/%s", staged.PluginID, staged.Version)
	}
	if !strings.HasPrefix(staged.Digest, "sha256:") || len(staged.Digest) != len("sha256:")+64 {
		t.Fatalf("staged digest = %q", staged.Digest)
	}
	if !json.Valid(staged.ManifestJSON) || len(staged.ManifestJSON) == 0 {
		t.Fatalf("staged manifest bytes are not valid JSON: %q", staged.ManifestJSON)
	}
	if _, ok := staged.Handle.(*install.Staged); !ok {
		t.Fatalf("staged handle = %T, want *install.Staged", staged.Handle)
	}

	if err := f.installer.InstallUnit(ctx, staged); err != nil {
		t.Fatalf("InstallUnit: %v", err)
	}
	versionDir := install.VersionDir(f.pluginsRoot, updaterTestID, updaterTestVersion)
	info, err := os.Stat(filepath.Join(versionDir, "bin", "plugin"))
	if err != nil {
		t.Fatalf("published entrypoint: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o111 == 0 {
		t.Fatalf("published entrypoint mode = %04o, want executable", perm)
	}
	servicePath := filepath.Join(f.unitDir, supervisor.UnitName(updaterTestID))
	body, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	if want := "ExecStart=" + filepath.Join(versionDir, "bin", "plugin"); !strings.Contains(string(body), want) {
		t.Fatalf("unit has no %q:\n%s", want, body)
	}
	entryDigest := staged.Manifest.Files["bin/plugin"]
	if entryDigest == "" {
		t.Fatal("manifest carries no entrypoint digest")
	}
	if !strings.Contains(string(body), "-digest "+entryDigest) {
		t.Fatalf("unit has no entrypoint digest %s:\n%s", entryDigest, body)
	}
	dropin, err := os.ReadFile(filepath.Join(f.unitDir, supervisor.UnitName(updaterTestID)+".d", "10-resources.conf"))
	if err != nil {
		t.Fatalf("read drop-in: %v", err)
	}
	if !strings.Contains(string(dropin), "MemoryMax=32M") {
		t.Fatalf("drop-in does not apply the manifest limit:\n%s", dropin)
	}
	if calls := len(f.runner.calls); calls == 0 {
		t.Fatal("the sandbox installer ran no privileged command")
	}

	// The same Staged value can be installed again (recovery retries).
	if err := f.installer.InstallUnit(ctx, staged); err != nil {
		t.Fatalf("second InstallUnit with the same staged package: %v", err)
	}
	// A fresh staging of the same version is discarded, not republished.
	stagedAgain, err := f.installer.Stage(ctx, f.pkg.path)
	if err != nil {
		t.Fatalf("second Stage: %v", err)
	}
	if err := f.installer.InstallUnit(ctx, stagedAgain); err != nil {
		t.Fatalf("InstallUnit with an already published version: %v", err)
	}
	entries, err := os.ReadDir(f.stagingRoot)
	if err != nil {
		t.Fatalf("read staging root: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), install.StagingPrefix) {
			t.Fatalf("staging directory %q was left behind", entry.Name())
		}
	}

	// A retained version keeps the per-plugin unit alive: starting or rolling
	// back to it needs the unit and the runtime directories.
	retained := install.VersionDir(f.pluginsRoot, updaterTestID, "9.9.9")
	if err := os.MkdirAll(retained, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.installer.RemoveUnit(ctx, updaterTestID, updaterTestVersion); err != nil {
		t.Fatalf("RemoveUnit with a retained version: %v", err)
	}
	if _, err := os.Stat(versionDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("version directory still exists: %v", err)
	}
	if _, err := os.Stat(servicePath); err != nil {
		t.Fatalf("the unit was removed while another version is installed: %v", err)
	}
	if err := os.RemoveAll(retained); err != nil {
		t.Fatal(err)
	}
	// Removing the last version removes the unit and its host channel too.
	hosts := &recordingHostChannels{systemctl: f.systemctl}
	f.installer.HostChannels = hosts
	if err := f.installer.RemoveUnit(ctx, updaterTestID, updaterTestVersion); err != nil {
		t.Fatalf("RemoveUnit of the last version: %v", err)
	}
	if len(hosts.released) != 1 || hosts.released[0] != updaterTestID {
		t.Fatalf("released host channels = %v, want [%s]", hosts.released, updaterTestID)
	}
	if _, err := os.Stat(servicePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unit file still exists: %v", err)
	}
	// Removing an already removed version succeeds.
	if err := f.installer.RemoveUnit(ctx, updaterTestID, updaterTestVersion); err != nil {
		t.Fatalf("second RemoveUnit: %v", err)
	}
}

func TestPluginInstallerRequiresTrustedKey(t *testing.T) {
	f := newInstallerFixture(t)
	ctx := t.Context()
	f.installer.TrustDir = t.TempDir()

	_, err := f.installer.Stage(ctx, f.pkg.path)
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Stage without a trusted key = %v, want UNAVAILABLE", err)
	}
	if _, statErr := os.Stat(f.stagingRoot); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("a refused package created the staging root: %v", statErr)
	}
}

func TestPluginInstallerRejectsBadInput(t *testing.T) {
	f := newInstallerFixture(t)
	ctx := t.Context()

	if _, err := f.installer.Stage(ctx, ""); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Stage(empty) = %v, want VALIDATION_FAILED", err)
	}
	m := &manifest.Manifest{ID: updaterTestID, Version: updaterTestVersion}
	if err := f.installer.InstallUnit(ctx, updater.Staged{Manifest: m}); !problem.HasCode(err, problem.Internal) {
		t.Fatalf("InstallUnit with a foreign handle = %v, want INTERNAL", err)
	}
	if err := f.installer.RemoveUnit(ctx, updaterTestID, "../escape"); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("RemoveUnit with a traversal version = %v, want VALIDATION_FAILED", err)
	}
	if err := f.installer.RemoveUnit(ctx, "../../escape", updaterTestVersion); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("RemoveUnit with a traversal id = %v, want VALIDATION_FAILED", err)
	}
}

func TestPluginInstallerRefusesToRemoveRunningUnit(t *testing.T) {
	f := newInstallerFixture(t)
	f.systemctl.setRunning(os.Getpid())

	err := f.installer.RemoveUnit(t.Context(), updaterTestID, updaterTestVersion)
	if !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("RemoveUnit of a running plugin = %v, want PRECONDITION_FAILED", err)
	}
}

// --- runtime tests ----------------------------------------------------------

func TestUpdaterRuntimeLifecycle(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	spec := f.spec()

	handle, err := f.rt.Start(ctx, spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if starts, _, _ := f.systemctl.counts(); starts != 1 {
		t.Fatalf("systemctl start calls = %d, want 1", starts)
	}
	if got := f.plugin.callCount("CheckHealth"); got != 0 {
		t.Fatalf("Start called %d RPCs before Ready", got)
	}
	h, ok := handle.(*pluginHandle)
	if !ok {
		t.Fatalf("handle = %T, want *pluginHandle", handle)
	}
	if h.unit != "qwq-plugin@"+updaterTestID+".service" || h.mainPID != os.Getpid() {
		t.Fatalf("handle identity = %+v", h)
	}
	if len(h.generation) != 16 || h.owner != supervisor.Owner(updaterTestID, h.generation) {
		t.Fatalf("handle generation/owner = %q/%q", h.generation, h.owner)
	}

	if err := f.rt.Ready(ctx, handle); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if got := f.plugin.callCount("CheckHealth"); got != 1 {
		t.Fatalf("CheckHealth calls = %d, want 1", got)
	}

	f.plugin.setHealth(&platformv1.CheckHealthResponse{Status: platformv1.CheckHealthResponse_STATUS_NOT_SERVING, Message: "warming up"})
	if err := f.rt.Ready(ctx, handle); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Ready with NOT_SERVING = %v, want PLUGIN_UNAVAILABLE", err)
	}
	f.plugin.setHealth(&platformv1.CheckHealthResponse{Status: platformv1.CheckHealthResponse_STATUS_SERVING})

	if err := f.rt.Activate(ctx, handle); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if got := f.plugin.callCount("Activate"); got != 1 {
		t.Fatalf("Activate calls = %d, want 1", got)
	}
	if err := f.rt.Health(ctx, handle); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if err := f.rt.Deactivate(ctx, handle); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	f.plugin.setValidate(&platformv1.ValidateConfigResponse{
		Violations: []*platformv1.FieldViolation{{Pointer: "/port", Code: "OUT_OF_RANGE", Message: "bad"}},
	})
	err = f.rt.ValidateConfig(ctx, handle, 4, json.RawMessage(`{"port":1}`))
	if !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("ValidateConfig with violations = %v, want VALIDATION_FAILED", err)
	}
	var pe *problem.Error
	if !errors.As(err, &pe) || len(pe.Violations) != 1 || pe.Violations[0].Pointer != "/port" {
		t.Fatalf("ValidateConfig violations = %+v", pe)
	}
	validateReq := f.plugin.request("ValidateConfig").(*platformv1.ValidateConfigRequest)
	if validateReq.GetProposedRevision() != "4" || validateReq.GetCurrentRevision() != "0" {
		t.Fatalf("ValidateConfig revisions = %q/%q, want 4/0",
			validateReq.GetProposedRevision(), validateReq.GetCurrentRevision())
	}

	f.plugin.setValidate(nil)
	if err := f.rt.ValidateConfig(ctx, handle, 4, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	if err := f.rt.ApplyConfig(ctx, handle, 4, json.RawMessage(`{"port":1}`)); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	// The handle now reports revision 4 as the current one.
	if err := f.rt.ValidateConfig(ctx, handle, 5, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ValidateConfig after apply: %v", err)
	}
	validateReq = f.plugin.request("ValidateConfig").(*platformv1.ValidateConfigRequest)
	if validateReq.GetCurrentRevision() != "4" {
		t.Fatalf("current revision after apply = %q, want 4", validateReq.GetCurrentRevision())
	}

	f.plugin.setApply(&platformv1.ApplyConfigResponse{AppliedRevision: "3"})
	if err := f.rt.ApplyConfig(ctx, handle, 5, json.RawMessage(`{}`)); !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("ApplyConfig with a stale revision = %v, want PLUGIN_ERROR", err)
	}

	f.plugin.setErr("Activate", status.Error(codes.Unimplemented, "no activate"))
	if err := f.rt.Activate(ctx, handle); !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("unimplemented Activate = %v, want PLUGIN_ERROR", err)
	}
	f.plugin.setErr("Activate", nil)
}

// bootstrapDirect initializes and starts the fake instance without the
// runtime, to model a process that survived a host restart.
func (p *sagaPlugin) bootstrapDirect(t *testing.T, handle string) {
	t.Helper()
	rc := &platformv1.RequestContext{InstanceId: DefaultInstanceID}
	if _, err := p.Initialize(t.Context(), &platformv1.InitializeRequest{Context: rc, InstanceHandle: handle}); err != nil {
		t.Fatalf("direct Initialize: %v", err)
	}
	if _, err := p.Start(t.Context(), &platformv1.StartRequest{Context: rc}); err != nil {
		t.Fatalf("direct Start: %v", err)
	}
}

func TestUpdaterRuntimeInitializesThenStarts(t *testing.T) {
	f := newRuntimeFixture(t)
	handle, err := f.rt.Start(t.Context(), f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	order := f.plugin.orderSnapshot()
	want := []string{"GetDescriptor", "Initialize", "Start"}
	if len(order) != len(want) {
		t.Fatalf("RPC order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("RPC order = %v, want %v", order, want)
		}
	}
	initReq := f.plugin.request("Initialize").(*platformv1.InitializeRequest)
	if initReq.GetInstanceHandle() == "" || !strings.HasPrefix(initReq.GetInstanceHandle(), "inst-") {
		t.Errorf("instance_handle = %q, want the derived generation handle", initReq.GetInstanceHandle())
	}
	if initReq.GetContext().GetInstanceId() != DefaultInstanceID {
		t.Errorf("instance_id = %q, want %q", initReq.GetContext().GetInstanceId(), DefaultInstanceID)
	}
	if string(initReq.GetConfigJson()) != "{}" || initReq.GetConfigRevision() != "0" {
		t.Errorf("config = %s revision %q, want {} and 0", initReq.GetConfigJson(), initReq.GetConfigRevision())
	}
	if initReq.GetHostAbiMinor() != uint32(abi.Minor) {
		t.Errorf("host_abi_minor = %d, want %d", initReq.GetHostAbiMinor(), abi.Minor)
	}
	if got := f.plugin.callCount("CheckHealth"); got != 0 {
		t.Errorf("Start called CheckHealth %d times, want 0 (Ready owns it)", got)
	}
	if h, ok := handle.(*pluginHandle); !ok || h.instanceHandle != initReq.GetInstanceHandle() {
		t.Errorf("handle instance_handle = %q, want %q", h.instanceHandle, initReq.GetInstanceHandle())
	}
	if err := f.rt.Ready(t.Context(), handle); err != nil {
		t.Fatalf("Ready: %v", err)
	}
}

func TestUpdaterRuntimePassesConfigAtInitialize(t *testing.T) {
	f := newRuntimeFixture(t)
	spec := f.spec()
	spec.Config = json.RawMessage(`{"listen":"127.0.0.1:8080"}`)
	spec.ConfigRevision = 7
	spec.InstanceHandle = "inst-explicit"
	handle, err := f.rt.Start(t.Context(), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	initReq := f.plugin.request("Initialize").(*platformv1.InitializeRequest)
	if string(initReq.GetConfigJson()) != string(spec.Config) {
		t.Errorf("config = %s, want %s", initReq.GetConfigJson(), spec.Config)
	}
	if initReq.GetConfigRevision() != "7" {
		t.Errorf("config_revision = %q, want 7", initReq.GetConfigRevision())
	}
	if initReq.GetInstanceHandle() != "inst-explicit" {
		t.Errorf("instance_handle = %q, want the spec value", initReq.GetInstanceHandle())
	}
	if err := f.rt.ValidateConfig(t.Context(), handle, 8, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	validateReq := f.plugin.request("ValidateConfig").(*platformv1.ValidateConfigRequest)
	if validateReq.GetCurrentRevision() != "7" {
		t.Errorf("current revision = %q, want the initialized revision 7", validateReq.GetCurrentRevision())
	}
}

func TestUpdaterRuntimeBootstrapFailureStopsUnit(t *testing.T) {
	t.Run("initialize", func(t *testing.T) {
		f := newRuntimeFixture(t)
		f.plugin.setErr("Initialize", status.Error(codes.FailedPrecondition, "the plugin rejected the configuration"))
		_, err := f.rt.Start(t.Context(), f.spec())
		if !problem.HasCode(err, problem.PluginUnavailable) {
			t.Fatalf("Start = %v, want PLUGIN_UNAVAILABLE", err)
		}
		if got := f.plugin.callCount("Start"); got != 0 {
			t.Errorf("Start RPC calls = %d, want 0 after a failed Initialize", got)
		}
		if _, stops, _ := f.systemctl.counts(); stops != 1 {
			t.Errorf("systemctl stops = %d, want the failed unit stopped", stops)
		}
		if f.rt.liveFor(updaterTestID) != nil {
			t.Error("a failed bootstrap left a live handle")
		}
	})
	t.Run("start", func(t *testing.T) {
		f := newRuntimeFixture(t)
		f.plugin.setErr("Start", status.Error(codes.Internal, "the plugin failed to start"))
		_, err := f.rt.Start(t.Context(), f.spec())
		if !problem.HasCode(err, problem.PluginUnavailable) {
			t.Fatalf("Start = %v, want PLUGIN_UNAVAILABLE", err)
		}
		if got := f.plugin.callCount("Initialize"); got != 1 {
			t.Errorf("Initialize calls = %d, want 1", got)
		}
		if _, stops, _ := f.systemctl.counts(); stops != 1 {
			t.Errorf("systemctl stops = %d, want the failed unit stopped", stops)
		}
	})
}

func TestUpdaterRuntimeAttachRespectsExistingLifecycle(t *testing.T) {
	t.Run("ready is not reinitialized", func(t *testing.T) {
		f := newRuntimeFixture(t)
		f.plugin.bootstrapDirect(t, "inst-before-restart")
		f.systemctl.setRunning(os.Getpid())
		before := len(f.plugin.orderSnapshot())

		handle, err := f.rt.Attach(t.Context(), f.spec())
		if err != nil {
			t.Fatalf("Attach: %v", err)
		}
		order := f.plugin.orderSnapshot()
		// The version check (GetDescriptor) precedes the lifecycle probe.
		if len(order) != before+2 || order[before] != "GetDescriptor" || order[before+1] != "CheckHealth" {
			t.Fatalf("RPCs after Attach = %v, want GetDescriptor then one CheckHealth", order[before:])
		}
		if got := f.plugin.callCount("Initialize"); got != 1 {
			t.Errorf("Initialize calls = %d, want only the pre-restart call", got)
		}
		if err := f.rt.Ready(t.Context(), handle); err != nil {
			t.Fatalf("Ready: %v", err)
		}
	})
	t.Run("initialized is started", func(t *testing.T) {
		f := newRuntimeFixture(t)
		rc := &platformv1.RequestContext{InstanceId: DefaultInstanceID}
		if _, err := f.plugin.Initialize(t.Context(), &platformv1.InitializeRequest{Context: rc, InstanceHandle: "inst-half"}); err != nil {
			t.Fatalf("direct Initialize: %v", err)
		}
		f.systemctl.setRunning(os.Getpid())
		handle, err := f.rt.Attach(t.Context(), f.spec())
		if err != nil {
			t.Fatalf("Attach: %v", err)
		}
		if got := f.plugin.callCount("Initialize"); got != 1 {
			t.Errorf("Initialize calls = %d, want 1", got)
		}
		if got := f.plugin.callCount("Start"); got != 1 {
			t.Errorf("Start calls = %d, want the instance started", got)
		}
		if err := f.rt.Ready(t.Context(), handle); err != nil {
			t.Fatalf("Ready: %v", err)
		}
	})
	t.Run("uninitialized is initialized", func(t *testing.T) {
		f := newRuntimeFixture(t)
		f.systemctl.setRunning(os.Getpid())
		handle, err := f.rt.Attach(t.Context(), f.spec())
		if err != nil {
			t.Fatalf("Attach: %v", err)
		}
		if got := f.plugin.callCount("Initialize"); got != 1 {
			t.Errorf("Initialize calls = %d, want 1", got)
		}
		if err := f.rt.Ready(t.Context(), handle); err != nil {
			t.Fatalf("Ready: %v", err)
		}
	})
	t.Run("stopped is not attachable", func(t *testing.T) {
		f := newRuntimeFixture(t)
		f.plugin.setLifecycle(platformv1.LifecycleState_LIFECYCLE_STATE_STOPPED)
		f.systemctl.setRunning(os.Getpid())
		_, err := f.rt.Attach(t.Context(), f.spec())
		if !problem.HasCode(err, problem.PluginUnavailable) {
			t.Fatalf("Attach of a stopped instance = %v, want PLUGIN_UNAVAILABLE", err)
		}
		if _, stops, _ := f.systemctl.counts(); stops != 1 {
			t.Errorf("systemctl stops = %d, want the unusable unit stopped", stops)
		}
	})
}

func TestUpdaterRuntimeStopReleasesInstance(t *testing.T) {
	f := newRuntimeFixture(t)
	handle, err := f.rt.Start(t.Context(), f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := f.rt.Stop(t.Context(), handle, 200*time.Millisecond); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	order := f.plugin.orderSnapshot()
	if len(order) < 2 || order[len(order)-2] != "Stop" || order[len(order)-1] != "ReleaseInstance" {
		t.Fatalf("RPCs at Stop = %v, want Stop then ReleaseInstance", order)
	}
	if got := f.plugin.callCount("ReleaseInstance"); got != 1 {
		t.Errorf("ReleaseInstance calls = %d, want 1", got)
	}
}

func TestUpdaterRuntimeStopSkipsReleaseAfterFailedDrain(t *testing.T) {
	f := newRuntimeFixture(t)
	handle, err := f.rt.Start(t.Context(), f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.plugin.setErr("Stop", errors.New("plugin is wedged"))
	if err := f.rt.Stop(t.Context(), handle, time.Second); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := f.plugin.callCount("ReleaseInstance"); got != 0 {
		t.Errorf("ReleaseInstance calls = %d, want 0 after a failed drain", got)
	}
	if _, stops, _ := f.systemctl.counts(); stops != 2 {
		t.Errorf("systemctl stops = %d, want the service and socket stopped", stops)
	}
}

func TestUpdaterRuntimeStartPrecondition(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	handle, err := f.rt.Start(ctx, f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := f.rt.Start(ctx, f.spec()); !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("second Start = %v, want PRECONDITION_FAILED", err)
	}

	// The registry check is independent of systemd: a live handle blocks Start
	// even when systemd lost track of the process.
	f.systemctl.setRunning(0)
	if _, err := f.rt.Start(ctx, f.spec()); !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("Start with a live handle = %v, want PRECONDITION_FAILED", err)
	}
	if starts, _, _ := f.systemctl.counts(); starts != 1 {
		t.Fatalf("a refused Start still ran systemctl start (%d calls)", starts)
	}
	if _, ok := handle.(*pluginHandle); !ok {
		t.Fatal("handle type changed")
	}
}

func TestUpdaterRuntimeAttach(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	f.systemctl.setRunning(os.Getpid())

	handle, err := f.rt.Attach(ctx, f.spec())
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if starts, stops, kills := f.systemctl.counts(); starts != 0 || stops != 0 || kills != 0 {
		t.Fatalf("Attach touched the unit: start=%d stop=%d kill=%d", starts, stops, kills)
	}
	again, err := f.rt.Attach(ctx, f.spec())
	if err != nil {
		t.Fatalf("second Attach: %v", err)
	}
	if again != handle {
		t.Fatal("Attach created a second connection for a live instance")
	}

	notRunning := newRuntimeFixture(t)
	if _, err := notRunning.rt.Attach(ctx, notRunning.spec()); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Attach without a process = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if starts, _, _ := notRunning.systemctl.counts(); starts != 0 {
		t.Fatalf("a failed Attach started the unit")
	}
}

func TestUpdaterRuntimeStopDrainsThenStops(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	handle, err := f.rt.Start(ctx, f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := f.rt.Stop(ctx, handle, 500*time.Millisecond); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if starts, stops, kills := f.systemctl.counts(); starts != 1 || stops != 2 || kills != 0 {
		t.Fatalf("systemctl calls after Stop = start %d stop %d kill %d", starts, stops, kills)
	}
	stopReq := f.plugin.request("Stop").(*platformv1.StopRequest)
	if !stopReq.GetDrain() || stopReq.GetGracePeriodMs() != 500 {
		t.Fatalf("drain request = %+v, want drain with 500ms", stopReq)
	}
	// Stop is idempotent and does not touch the unit twice.
	if err := f.rt.Stop(ctx, handle, 500*time.Millisecond); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if _, stops, _ := f.systemctl.counts(); stops != 2 {
		t.Fatalf("second Stop called systemctl stop again (%d calls)", stops)
	}
	if err := f.rt.Health(ctx, handle); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Health after Stop = %v, want PLUGIN_UNAVAILABLE", err)
	}

	if err := f.rt.Deactivate(ctx, handle); err != nil {
		t.Fatalf("Deactivate after Stop = %v, want nil", err)
	}
	if err := f.rt.Release(ctx, handle); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := f.rt.Release(ctx, handle); err != nil {
		t.Fatalf("second Release: %v", err)
	}
	if f.rt.lookup(updaterTestID, updaterTestVersion) != nil {
		t.Fatal("Release left the handle registered")
	}
	if err := f.rt.Activate(ctx, handle); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Activate after Release = %v, want PLUGIN_UNAVAILABLE", err)
	}

	// A stopped and released instance can be started again.
	if _, err := f.rt.Start(ctx, f.spec()); err != nil {
		t.Fatalf("Start after Release: %v", err)
	}
}

func TestUpdaterRuntimeStopForceKills(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	handle, err := f.rt.Start(ctx, f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.systemctl.stopErr = errors.New("stop timed out")
	if err := f.rt.Stop(ctx, handle, 100*time.Millisecond); err != nil {
		t.Fatalf("Stop with a failed systemctl stop = %v, want nil after the force kill", err)
	}
	if _, stops, kills := f.systemctl.counts(); stops != 2 || kills != 2 {
		t.Fatalf("force stop calls = stop %d kill %d, want 2/2", stops, kills)
	}

	// A failed graceful stop leaves the handle stopped: a retry must try again.
	g := newRuntimeFixture(t)
	g.systemctl.stopErr = errors.New("stop failed")
	g.systemctl.killErr = errors.New("kill failed")
	other, err := g.rt.Start(ctx, g.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := g.rt.Stop(ctx, other, 0); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Stop with a failed force kill = %v, want PLUGIN_UNAVAILABLE", err)
	}
	g.systemctl.stopErr, g.systemctl.killErr = nil, nil
	if err := g.rt.Stop(ctx, other, 0); err != nil {
		t.Fatalf("Stop retry: %v", err)
	}
}

func TestUpdaterRuntimeDrainFailureStillStops(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	handle, err := f.rt.Start(ctx, f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.plugin.setErr("Stop", errors.New("plugin is wedged"))
	if err := f.rt.Stop(ctx, handle, time.Second); err != nil {
		t.Fatalf("Stop with a failed drain = %v, want nil", err)
	}
	if _, stops, _ := f.systemctl.counts(); stops != 2 {
		t.Fatalf("systemctl stop calls = %d, want 2", stops)
	}
}

func TestUpdaterRuntimeHealthTransportFailure(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	handle, err := f.rt.Start(ctx, f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.plugin.setErr("CheckHealth", status.Error(codes.Unavailable, "no answer"))
	if err := f.rt.Ready(ctx, handle); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Ready with a transport failure = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if err := f.rt.Health(ctx, handle); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Health with a transport failure = %v, want PLUGIN_UNAVAILABLE", err)
	}
}

// TestUpdaterRuntimeRejectsOversizedPluginResponse pins the receive limit of
// the updater's own plugin connection, which attach opens apart from the
// supervisor: an oversized health response fails instead of being buffered,
// and a 4 MiB payload, the ABI's largest, still fits together with its framing.
func TestUpdaterRuntimeRejectsOversizedPluginResponse(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	handle, err := f.rt.Start(ctx, f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	cases := []struct {
		name string
		size int
		want codes.Code
	}{
		{"4 MiB details", 4 << 20, codes.OK},
		{"5 MiB details", 5 << 20, codes.ResourceExhausted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.plugin.setHealth(&platformv1.CheckHealthResponse{
				Status:      platformv1.CheckHealthResponse_STATUS_SERVING,
				DetailsJson: []byte(`"` + strings.Repeat("a", tc.size-2) + `"`),
			})
			if err := f.rt.Health(ctx, handle); status.Code(err) != tc.want {
				t.Fatalf("Health with %d bytes of details = %v, want %v", tc.size, err, tc.want)
			}
		})
	}
}

func TestUpdaterRuntimeRejectsBadSpecs(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()

	bad := []struct {
		name string
		spec updater.InstanceSpec
	}{
		{"bad id", updater.InstanceSpec{PluginID: "../x", Version: updaterTestVersion, Manifest: &manifest.Manifest{}}},
		{"bad version", updater.InstanceSpec{PluginID: updaterTestID, Version: "../x", Manifest: &manifest.Manifest{}}},
		{"no manifest", updater.InstanceSpec{PluginID: updaterTestID, Version: updaterTestVersion}},
	}
	for _, c := range bad {
		if _, err := f.rt.Start(ctx, c.spec); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("Start(%s) = %v, want VALIDATION_FAILED", c.name, err)
		}
		if _, err := f.rt.Attach(ctx, c.spec); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("Attach(%s) = %v, want VALIDATION_FAILED", c.name, err)
		}
	}

	// A version directory that does not exist is rejected before systemd runs.
	missing := newRuntimeFixture(t)
	if err := os.RemoveAll(filepath.Join(missing.pluginsDir, updaterTestID)); err != nil {
		t.Fatal(err)
	}
	if _, err := missing.rt.Start(ctx, missing.spec()); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Start without installed files = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if starts, _, _ := missing.systemctl.counts(); starts != 0 {
		t.Fatal("a missing package still started the unit")
	}

	// No systemd client.
	bare := newRuntimeFixture(t)
	bare.rt.Systemctl = nil
	if _, err := bare.rt.Start(ctx, bare.spec()); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Start without systemctl = %v, want UNAVAILABLE", err)
	}

	// systemd failures are PLUGIN_UNAVAILABLE.
	broken := newRuntimeFixture(t)
	broken.systemctl.showErr = errors.New("dbus down")
	if _, err := broken.rt.Start(ctx, broken.spec()); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Start with a systemd failure = %v, want PLUGIN_UNAVAILABLE", err)
	}

	noPID := newRuntimeFixture(t)
	noPID.systemctl.startPID = 0
	if _, err := noPID.rt.Start(ctx, noPID.spec()); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Start without a main process = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if _, stops, _ := noPID.systemctl.counts(); stops != 1 {
		t.Fatalf("a unit started without a process was not stopped (%d stop calls)", stops)
	}

	// A unit that starts but whose socket cannot be attached is stopped again,
	// so the saga rollback can start the old version.
	unreachable := newRuntimeFixture(t)
	unreachable.server.Stop()
	if _, err := unreachable.rt.Start(ctx, unreachable.spec()); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Start with an unreachable socket = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if _, stops, _ := unreachable.systemctl.counts(); stops != 1 {
		t.Fatalf("a unit whose attach failed was not stopped (%d stop calls)", stops)
	}
}

func TestUpdaterRuntimeRejectsStaleUnitVersion(t *testing.T) {
	f := newRuntimeFixture(t)
	ctx := t.Context()
	f.plugin.setDescriptor(&platformv1.PluginDescriptor{
		PluginId:      updaterTestID,
		PluginVersion: "0.9.0",
	})
	_, err := f.rt.Start(ctx, f.spec())
	if !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Start of a stale unit = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if _, stops, _ := f.systemctl.counts(); stops != 1 {
		t.Fatalf("a stale unit was not stopped (%d stop calls)", stops)
	}

	// A matching descriptor (or an unimplemented one) is accepted.
	matched := newRuntimeFixture(t)
	matched.plugin.setDescriptor(&platformv1.PluginDescriptor{
		PluginId:      updaterTestID,
		PluginVersion: matched.version,
	})
	if _, err := matched.rt.Start(ctx, matched.spec()); err != nil {
		t.Fatalf("Start with a matching descriptor: %v", err)
	}
}

func TestUpdaterRuntimeRoutes(t *testing.T) {
	f := newRuntimeFixture(t)
	if f.rt.Routes() != nil {
		t.Fatal("a new runtime published routes")
	}
	table := updater.NewRouteTable([]updater.Route{{PluginID: updaterTestID, Version: updaterTestVersion}})
	f.rt.SwapRoutes(table)
	if f.rt.Routes() != table {
		t.Fatal("SwapRoutes did not store the snapshot")
	}
	f.rt.SwapRoutes(nil)
	if routes := f.rt.Routes(); routes == nil || routes.Len() != 0 {
		t.Fatalf("SwapRoutes(nil) = %+v, want an empty table", routes)
	}
}

func TestHostMemory(t *testing.T) {
	base := t.TempDir()
	proc := filepath.Join(base, "proc")
	cgroup := filepath.Join(base, "cgroup")
	unitDir := filepath.Join(cgroup, "system.slice", supervisor.UnitName(updaterTestID))
	for _, dir := range []string{proc, unitDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(proc, "meminfo"),
		[]byte("MemTotal:  1000 kB\nMemAvailable:  512 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "memory.current"), []byte("1048576\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	memory := &HostMemory{ProcRoot: proc, CgroupRoot: cgroup}
	available, err := memory.Available()
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	if available != 512*1024 {
		t.Fatalf("Available = %d, want %d", available, 512*1024)
	}
	current, err := memory.Current(updaterTestID)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if current != 1048576 {
		t.Fatalf("Current = %d, want 1048576", current)
	}
	if _, err := memory.Current("other.plugin"); err == nil {
		t.Fatal("Current of a missing cgroup succeeded")
	}
}

func TestControllerUpdaterAccessorAndUpdatePlugin(t *testing.T) {
	c := &Controller{}
	if c.Updater() != nil {
		t.Fatal("a new controller reports an updater")
	}
	_, err := c.UpdatePlugin(t.Context(), updater.UpdateRequest{PluginID: updaterTestID, PackagePath: "/pkg"})
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("UpdatePlugin without an updater = %v, want UNAVAILABLE", err)
	}

	up := newControllerTestUpdater(t)
	c.SetUpdater(up)
	if c.Updater() != up {
		t.Fatal("SetUpdater did not install the updater")
	}
	// The request reaches the updater: a plugin without an active version is a
	// state conflict, not the UNAVAILABLE above.
	_, err = c.UpdatePlugin(t.Context(), updater.UpdateRequest{PluginID: updaterTestID, PackagePath: "/pkg"})
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("UpdatePlugin = %v, want STATE_CONFLICT", err)
	}
	c.SetUpdater(nil)
	if c.Updater() != nil {
		t.Fatal("SetUpdater(nil) left the updater installed")
	}
}

// newControllerTestUpdater is a real updater over the fake systemctl.
func newControllerTestUpdater(t *testing.T) *updater.Updater {
	t.Helper()
	up, err := updater.New(updater.Options{
		DB:        testDB(t),
		Runtime:   &UpdaterRuntime{Systemctl: newSagaSystemctl(), Logger: slog.New(slog.DiscardHandler)},
		Installer: &PluginInstaller{PluginsRoot: t.TempDir(), TrustDir: t.TempDir()},
		Memory:    &stubMemory{},
		Clock:     clock.NewFake(time.Unix(1700000000, 0).UTC()),
		Logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("updater.New: %v", err)
	}
	return up
}

// TestUpdatePluginSurvivesCallerCancel: a caller that is already gone reaches
// the same decision as a live one instead of failing on its context.
func TestUpdatePluginSurvivesCallerCancel(t *testing.T) {
	c := &Controller{}
	c.SetUpdater(newControllerTestUpdater(t))
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := c.UpdatePlugin(canceled, updater.UpdateRequest{PluginID: updaterTestID, PackagePath: "/pkg"})
	if !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("UpdatePlugin with a canceled caller = %v, want STATE_CONFLICT", err)
	}
}

// stubMemory satisfies updater.MemorySource without touching the node.
type stubMemory struct{}

func (stubMemory) Available() (uint64, error)     { return 1 << 30, nil }
func (stubMemory) Current(string) (uint64, error) { return 32 << 20, nil }

// TestLifecycleRPCHasDefaultDeadline hangs the plugin's Activate and calls it
// with a context that has no deadline: the runtime's default RPC timeout must
// end the call instead of blocking the host forever.
func TestLifecycleRPCHasDefaultDeadline(t *testing.T) {
	f := newRuntimeFixture(t)
	f.rt.RPCTimeout = 100 * time.Millisecond
	ctx := t.Context()
	handle, err := f.rt.Start(ctx, f.spec())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.plugin.mu.Lock()
	f.plugin.hangs = map[string]bool{"Activate": true}
	f.plugin.mu.Unlock()

	begin := time.Now()
	err = f.rt.Activate(context.Background(), handle)
	if err == nil {
		t.Fatal("Activate on a hung plugin succeeded")
	}
	if took := time.Since(begin); took > 5*time.Second {
		t.Fatalf("Activate returned after %s, want the 100ms default deadline", took)
	}
	if ctx.Err() != nil {
		t.Fatal("test context ended early")
	}
}

func TestUpdaterRuntimeAttachRejectsVersionMismatch(t *testing.T) {
	ctx := t.Context()
	// The plugin reports another version through its descriptor.
	f := newRuntimeFixture(t)
	f.systemctl.setRunning(os.Getpid())
	f.plugin.setDescriptor(&platformv1.PluginDescriptor{PluginId: updaterTestID, PluginVersion: "0.9.0"})
	if _, err := f.rt.Attach(ctx, f.spec()); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Attach(descriptor mismatch) = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if starts, stops, kills := f.systemctl.counts(); starts+stops+kills != 0 {
		t.Fatalf("a mismatching Attach touched the unit: start=%d stop=%d kill=%d", starts, stops, kills)
	}
	if n := f.plugin.callCount("Initialize"); n != 0 {
		t.Fatalf("a mismatching Attach bootstrapped the process (%d Initialize)", n)
	}

	// Without a descriptor the loaded ExecStart path identifies the version.
	g := newRuntimeFixture(t)
	g.systemctl.setRunning(os.Getpid())
	g.systemctl.mu.Lock()
	g.systemctl.status.ExecStart = filepath.Join(install.VersionDir(g.pluginsDir, g.pluginID, "0.9.0"), "bin/plugin")
	g.systemctl.mu.Unlock()
	spec := g.spec()
	spec.Manifest.Entrypoint = "bin/plugin"
	if _, err := g.rt.Attach(ctx, spec); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Attach(ExecStart mismatch) = %v, want PLUGIN_UNAVAILABLE", err)
	}
	g.systemctl.mu.Lock()
	g.systemctl.status.ExecStart = filepath.Join(install.VersionDir(g.pluginsDir, g.pluginID, g.version), "bin/plugin")
	g.systemctl.mu.Unlock()
	if _, err := g.rt.Attach(ctx, spec); err != nil {
		t.Fatalf("Attach(matching ExecStart) = %v", err)
	}
}

func TestPluginInstallerAppliesTrustPolicy(t *testing.T) {
	f := newInstallerFixture(t)
	pems, err := filepath.Glob(filepath.Join(f.installer.TrustDir, "*.pem"))
	if err != nil || len(pems) == 0 {
		t.Fatalf("trust dir has no key: %v", err)
	}
	policy := strings.TrimSuffix(pems[0], ".pem") + ".policy.json"
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(policy, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"plugin_ids":["somebody.else"]}`)
	if _, err := f.installer.Stage(t.Context(), f.pkg.path); err == nil || !strings.Contains(err.Error(), manifest.CodePluginNamespaceMismatch) {
		t.Fatalf("Stage outside the policy = %v", err)
	}
	write(`{"plugin_idz":[]}`)
	if _, err := f.installer.Stage(t.Context(), f.pkg.path); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Stage with a malformed policy = %v, want UNAVAILABLE", err)
	}
	write(`{"plugin_ids":["` + updaterTestID + `"]}`)
	staged, err := f.installer.Stage(t.Context(), f.pkg.path)
	if err != nil {
		t.Fatalf("Stage inside the policy: %v", err)
	}
	_ = staged.DiscardStaged()
}

func TestPluginInstallerPreflightRefusesStage(t *testing.T) {
	f := newInstallerFixture(t)
	f.installer.Preflight = func(context.Context) error {
		return problem.New(problem.PreconditionFailed, "sandbox-cgroup: cgroup v2 not mounted")
	}
	if _, err := f.installer.Stage(t.Context(), f.pkg.path); !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("Stage with a failing preflight = %v, want PRECONDITION_FAILED", err)
	}
	if entries, _ := os.ReadDir(f.installer.StagingRoot); len(entries) != 0 {
		t.Fatalf("a refused package was staged: %v", entries)
	}
}

// TestUnitSpecForNetworkProxy pins X1: only the exact (network.proxy, direct)
// capability in the verified manifest sets the internal policy bool. Prefix or
// scope lookalikes and unrelated capabilities must not relax the sandbox.
func TestUnitSpecForNetworkProxy(t *testing.T) {
	const versionDir = "/var/lib/qwq-plugins/core.xray/0.1.0"
	specFor := func(caps ...manifest.Capability) sandbox.UnitSpec {
		m := &manifest.Manifest{
			ID:           "core.xray",
			Version:      "0.1.0",
			Entrypoint:   "bin/plugin",
			Files:        map[string]string{"bin/plugin": "sha256:" + strings.Repeat("a", 64)},
			Capabilities: caps,
		}
		spec, err := unitSpecFor(m, versionDir, "")
		if err != nil {
			t.Fatalf("unitSpecFor: %v", err)
		}
		return spec
	}
	cases := []struct {
		name string
		caps []manifest.Capability
		want bool
	}{
		{"no capabilities", nil, false},
		{"exact match", []manifest.Capability{{Name: "network.proxy", Scope: "direct"}}, true},
		{"wrong scope", []manifest.Capability{{Name: "network.proxy", Scope: "other"}}, false},
		{"name prefix lookalike", []manifest.Capability{{Name: "network.proxyx", Scope: "direct"}}, false},
		{"name suffix lookalike", []manifest.Capability{{Name: "network.proxy.extra", Scope: "direct"}}, false},
		{"unrelated capabilities", []manifest.Capability{{Name: "network.egress", Scope: "direct"}, {Name: "state.kv.read", Scope: "self"}}, false},
		{"exact among others", []manifest.Capability{{Name: "state.kv.read", Scope: "self"}, {Name: "network.proxy", Scope: "direct"}}, true},
		{"empty scope", []manifest.Capability{{Name: "network.proxy", Scope: ""}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := specFor(tc.caps...).NetworkProxyDirect; got != tc.want {
				t.Fatalf("NetworkProxyDirect = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestUnitSpecForDataDir pins X2: the host derives a stable per-instance data
// directory only for a manifest that declares backup paths, and only when a
// data root is configured. The path carries no version or generation.
func TestUnitSpecForDataDir(t *testing.T) {
	const versionDir = "/var/lib/qwq-plugins/core.xray/0.1.0"
	const dataRoot = sandbox.DefaultPluginDataRoot
	m := &manifest.Manifest{
		ID:         "core.xray",
		Version:    "0.1.0",
		Entrypoint: "bin/plugin",
		Files:      map[string]string{"bin/plugin": "sha256:" + strings.Repeat("a", 64)},
		State:      manifest.State{BackupPaths: []string{"runtime"}},
	}
	spec, err := unitSpecFor(m, versionDir, dataRoot)
	if err != nil {
		t.Fatalf("unitSpecFor: %v", err)
	}
	if spec.DataDir != "/var/lib/qwq-plugin-data/core.xray/default" {
		t.Fatalf("DataDir = %q, want the stable per-instance path", spec.DataDir)
	}
	if strings.Contains(spec.DataDir, "0.1.0") {
		t.Fatalf("DataDir must not contain the version: %q", spec.DataDir)
	}
	// No backup paths → no data dir (noop keeps the original behaviour).
	m.State.BackupPaths = nil
	if spec, err = unitSpecFor(m, versionDir, dataRoot); err != nil || spec.DataDir != "" {
		t.Fatalf("no backup paths: DataDir = %q, err = %v, want empty", spec.DataDir, err)
	}
	// Backup paths but no data root configured → no data dir.
	m.State.BackupPaths = []string{"runtime"}
	if spec, err = unitSpecFor(m, versionDir, ""); err != nil || spec.DataDir != "" {
		t.Fatalf("no data root: DataDir = %q, err = %v, want empty", spec.DataDir, err)
	}
}

// TestUpdaterRuntimeDataDirAtInitialize 验证启动与恢复均下发 systemd 的真实私有目录。
// 无状态目录的插件仍收到空路径；单元自身继续使用稳定的逻辑 StateDirectory。
func TestUpdaterRuntimeDataDirAtInitialize(t *testing.T) {
	const dataRoot = sandbox.DefaultPluginDataRoot
	wantDir := sandbox.DefaultPrivatePluginDataRoot + "/" + updaterTestID + "/default"

	f := newRuntimeFixture(t)
	f.rt.DataRoot = dataRoot
	spec := f.spec()
	spec.Manifest.State = manifest.State{BackupPaths: []string{"runtime"}}
	if _, err := f.rt.Start(t.Context(), spec); err != nil {
		t.Fatalf("Start: %v", err)
	}
	initReq := f.plugin.request("Initialize").(*platformv1.InitializeRequest)
	if initReq.GetDataDir() != wantDir {
		t.Fatalf("Initialize data_dir = %q, want %q", initReq.GetDataDir(), wantDir)
	}

	// A plugin without backup paths (noop) keeps an empty data dir.
	g := newRuntimeFixture(t)
	g.rt.DataRoot = dataRoot
	if _, err := g.rt.Start(t.Context(), g.spec()); err != nil {
		t.Fatalf("Start(noop): %v", err)
	}
	if req := g.plugin.request("Initialize").(*platformv1.InitializeRequest); req.GetDataDir() != "" {
		t.Fatalf("noop Initialize data_dir = %q, want empty", req.GetDataDir())
	}

	// Attach (host-restart recovery) derives the same directory.
	h := newRuntimeFixture(t)
	h.rt.DataRoot = dataRoot
	h.systemctl.setRunning(os.Getpid())
	attachSpec := h.spec()
	attachSpec.Manifest.State = manifest.State{BackupPaths: []string{"runtime"}}
	if _, err := h.rt.Attach(t.Context(), attachSpec); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if req := h.plugin.request("Initialize").(*platformv1.InitializeRequest); req.GetDataDir() != wantDir {
		t.Fatalf("Attach Initialize data_dir = %q, want %q", req.GetDataDir(), wantDir)
	}
}
