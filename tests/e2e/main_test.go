// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

// Package e2e is the real-systemd end-to-end test of the installed product.
//
// It runs as root on a disposable Linux host and drives the production code
// path, not fakes: the host is installed by the release tarball's install.sh
// (sysusers, tmpfiles, every unit including qwq-controller.service running as
// qwq), the panel is driven over its HTTPS API, the privileged helper is
// socket activated by systemd, plugin packages are signed and installed into
// immutable version directories, and the plugin talks to the controller's
// host channel. Nothing below /run/qwq or /var/lib is created by the test.
//
// Every test refuses to start on a host that already has qwq state and ends
// with `uninstall.sh --purge`, verifying that nothing is left behind.
//
// Usage (see tests/e2e/REPORT.md; build the fixtures with tests/e2e/build.sh):
//
//	QWQ_E2E_RELEASE_TAR=<release/qwq-e2e-linux-<arch>.tar.gz> \
//	QWQ_E2E_PKG_V1=<noop 0.1.1> QWQ_E2E_PKG_V2=<noop 0.1.2> QWQ_E2E_PKG_BAD=<noop 0.1.3> \
//	QWQ_E2E_TRUST_PUB=<publisher public key PEM> \
//	./e2e.test -test.v -test.run 'TestPluginEndToEnd|TestControllerEndToEnd'
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/sandbox"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Paths and identities of the installed product. They are the production
// constants, not test-specific ones, because the point of the test is to
// exercise them.
const (
	pluginID  = "noop"
	versionV1 = "0.1.1"
	versionV2 = "0.1.2"
	qwqUser   = "qwq"
	pluginGrp = "qwq-p-noop"

	pluginsRoot = "/var/lib/qwq-plugins"
	stagingRoot = "/var/lib/qwq/staging"
	credsDir    = "/var/lib/qwq-privileged/creds"
	trustDir    = "/etc/qwq/trust"
	runtimeBase = "/run/qwq"
	hostBin     = "/opt/qwq/current/bin/qwq"
	qwqCLI      = "/usr/local/bin/qwq"

	unitDir      = "/etc/systemd/system"
	tmpfilesDir  = "/etc/tmpfiles.d"
	helperSocket = "/run/qwq/privileged.sock"

	controllerU   = "qwq-controller.service"
	helperService = "qwq-privileged.service"
	helperSocketU = "qwq-privileged.socket"
	pluginService = "qwq-plugin@noop.service"
	pluginSocketU = "qwq-plugin@noop.socket"
)

// pluginCaps are the capabilities the noop manifest declares; a fresh install
// must have them approved.
var pluginCaps = []string{"state.kv.read", "state.kv.write"}

// prepareHost installs the product from the release tarball, trusts the test
// publisher and returns once the controller answers. Cleanup purges it again.
func prepareHost(t *testing.T) string {
	t.Helper()
	requireEnv(t, "QWQ_E2E_RELEASE_TAR", "QWQ_E2E_TRUST_PUB")
	scripts := prepareInstall(t)
	runScript(t, scripts, "install.sh", "", "--offline", os.Getenv("QWQ_E2E_RELEASE_TAR"))

	writeFile(t, filepath.Join(trustDir, "e2e-publisher.pem"), readFile(t, os.Getenv("QWQ_E2E_TRUST_PUB")), 0o644)
	// The updater reads the trust directory at startup.
	run(t, "systemctl", "restart", controllerU)
	waitPanelReady(t)
	requireProductLayout(t)
	return scripts
}

// requireProductLayout checks what install.sh, tmpfiles and the units created:
// the fixture made none of it.
func requireProductLayout(t *testing.T) {
	t.Helper()
	requireModeOwner(t, "/var/lib/qwq", 0o700, qwqUser)
	requireModeOwner(t, stagingRoot, 0o700, qwqUser)
	requireModeOwner(t, pluginsRoot, 0o755, "root")
	requireModeOwner(t, credsDir, 0o700, "root")
	requireModeOwner(t, runtimeBase, 0o711, "root")
	requireModeOwner(t, filepath.Join(runtimeBase, "host"), 0o750, qwqUser)
	requireMode(t, helperSocket, 0o660)
	requireSocketGroup(t, helperSocket, qwqUser)
	if state := showUnit(t, helperService); state.ActiveState == "active" || state.MainPID != 0 {
		t.Fatalf("the socket-activated helper is already running: %+v", state)
	}
	pid := showUnit(t, controllerU).MainPID
	if pid == 0 {
		t.Fatal("qwq-controller is not running")
	}
	if uid := processUID(t, pid); uid != lookupUID(t, qwqUser) {
		t.Fatalf("qwq-controller runs as uid %d, want %s", uid, qwqUser)
	}
}

// requireCleanHost refuses to run on a host that already has qwq state. The
// test removes everything it creates; failing here is better than deleting a
// real installation.
func requireCleanHost(t *testing.T) {
	t.Helper()
	for _, path := range []string{helperSocket, "/var/lib/qwq", runtimeBase, "/opt/qwq", qwqCLI, "/etc/qwq",
		pluginsRoot, "/var/lib/qwq-privileged", "/var/lib/qwq-capability", "/var/lib/qwq-plugin-data", "/var/lib/private/qwq-plugin-data", filepath.Join(unitDir, helperSocketU)} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("the host is not clean: %s exists; use a disposable machine", path)
		}
	}
	for _, lookup := range [][]string{{"getent", "passwd", qwqUser}, {"getent", "group", qwqUser}, {"getent", "group", pluginGrp}} {
		if err := exec.Command(lookup[0], lookup[1:]...).Run(); err == nil {
			t.Fatalf("the host is not clean: %s exists", strings.Join(lookup, " "))
		}
	}
	if units := qwqUnitFiles(t); strings.TrimSpace(units) != "" {
		t.Fatalf("the host has qwq units installed:\n%s", units)
	}
	requireNoQwqProcesses(t)
}

// requirePurged proves `uninstall.sh --purge` left nothing behind.
func requirePurged(t *testing.T) {
	t.Helper()
	for _, path := range []string{helperSocket, runtimeBase, "/var/lib/qwq", "/etc/qwq", "/opt/qwq", qwqCLI,
		pluginsRoot, "/var/lib/qwq-privileged", "/var/lib/qwq-capability", "/var/lib/qwq-plugin-data", "/var/lib/private/qwq-plugin-data", filepath.Join(tmpfilesDir, "qwq-plugin-"+pluginID+".conf"),
		"/usr/lib/tmpfiles.d/qwq.conf", "/usr/lib/sysusers.d/qwq.conf"} {
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("purge left behind: %s (err %v)", path, err)
		}
	}
	if units := qwqUnitFiles(t); strings.TrimSpace(units) != "" {
		t.Errorf("qwq unit files remain after purge:\n%s", units)
	}
	requireNoQwqProcesses(t)
	for _, lookup := range [][]string{{"getent", "passwd", qwqUser}, {"getent", "group", qwqUser}, {"getent", "group", pluginGrp}} {
		if err := exec.Command(lookup[0], lookup[1:]...).Run(); err == nil {
			t.Errorf("%s still exists after purge", strings.Join(lookup, " "))
		}
	}
}

// requireNoQwqProcesses 同时检查已加载的实例，防止单位文件删除掩盖活进程。
func requireNoQwqProcesses(t *testing.T) {
	t.Helper()
	units := run(t, "systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager")
	for _, line := range strings.Split(units, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasPrefix(fields[0], "qwq-") || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		state := showUnit(t, fields[0])
		if state.MainPID != 0 || state.ActiveState == "active" || state.ActiveState == "activating" {
			t.Fatalf("qwq process remains: %s %+v", fields[0], state)
		}
	}
}

// qwqUnitFiles returns the installed qwq-* unit files, one per line. It reads
// the full list and filters in Go because `systemctl list-unit-files 'qwq-*'`
// exits non-zero when the glob matches nothing.
func qwqUnitFiles(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("systemctl", "list-unit-files", "--no-legend", "--no-pager").CombinedOutput()
	if err != nil {
		t.Fatalf("systemctl list-unit-files: %v\n%s", err, out)
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "qwq-") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// --- plugin assertions ------------------------------------------------------

// requireRunningPlugin asserts the unit is active with a main process and that
// the process advertises the expected version over the real gRPC socket.
func requireRunningPlugin(t *testing.T, ctx context.Context, wantVersion string) int {
	t.Helper()
	return requireRunningPluginFor(t, ctx, pluginID, wantVersion)
}

func requireRunningPluginFor(t *testing.T, ctx context.Context, id, wantVersion string) int {
	t.Helper()
	unit := "qwq-plugin@" + id + ".service"
	socket := supervisorSocketPathFor(id)
	state := showUnit(t, unit)
	if state.MainPID == 0 || state.ActiveState != "active" {
		t.Fatalf("unit state = %+v, want active with a main process", state)
	}
	conn, err := waitForPluginSocket(ctx, socket)
	if err != nil {
		t.Fatalf("dial %s: %v", socket, err)
	}
	defer func() { _ = conn.Close() }()
	desc, err := platformv1.NewPluginServiceClient(conn).GetDescriptor(ctx, &platformv1.GetDescriptorRequest{})
	if err != nil {
		t.Fatalf("GetDescriptor: %v", err)
	}
	if got := desc.GetDescriptor_().GetPluginId(); got != id {
		t.Fatalf("descriptor plugin id = %q, want %q", got, id)
	}
	if got := desc.GetDescriptor_().GetPluginVersion(); got != wantVersion {
		t.Fatalf("descriptor version = %q, want %q", got, wantVersion)
	}
	t.Logf("unit %s active: MainPID %d, descriptor %s %s", unit, state.MainPID, id, wantVersion)
	return state.MainPID
}

// requirePluginHealth asserts the instance answers SERVING over CheckHealth.
func requirePluginHealth(t *testing.T, wantVersion string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := waitForPluginSocket(ctx, supervisorSocketPath())
	if err != nil {
		t.Fatalf("dial %s: %v", supervisorSocketPath(), err)
	}
	defer func() { _ = conn.Close() }()
	client := platformv1.NewPluginServiceClient(conn)
	deadline := time.Now().Add(10 * time.Second)
	var last *platformv1.CheckHealthResponse
	for time.Now().Before(deadline) {
		resp, err := client.CheckHealth(ctx, &platformv1.CheckHealthRequest{
			Context: &platformv1.RequestContext{NodeId: "local", InstanceId: controller.DefaultInstanceID},
		})
		if err != nil {
			t.Fatalf("CheckHealth: %v", err)
		}
		last = resp
		if resp.GetStatus() == platformv1.CheckHealthResponse_STATUS_SERVING {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("CheckHealth never became SERVING: %+v (want version %s)", last, wantVersion)
}

// requireVersionTree checks the published layout: every directory 0555, every
// regular file 0444, the entrypoint executable, root owned.
func requireVersionTree(t *testing.T, version string) {
	t.Helper()
	requireVersionTreeFor(t, pluginID, version)
}

func requireVersionTreeFor(t *testing.T, id, version string) {
	t.Helper()
	root := install.VersionDir(pluginsRoot, id, version)
	requireModeOwner(t, root, install.DirMode, "root")
	requireMode(t, filepath.Join(root, "bin"), install.DirMode)
	requireMode(t, filepath.Join(root, "bin", "plugin"), install.ExecMode)
	requireMode(t, filepath.Join(root, "schemas", "config.schema.json"), install.FileMode)
}

// requireVerifyEntrypoint runs the ExecStartPre command by hand with the
// digest recorded in the installed manifest, so the test proves the installed
// host binary accepts the published entrypoint.
func requireVerifyEntrypoint(t *testing.T, version string) {
	t.Helper()
	requireVerifyEntrypointFor(t, pluginID, version)
}

func requireVerifyEntrypointFor(t *testing.T, id, version string) {
	t.Helper()
	dir := install.VersionDir(pluginsRoot, id, version)
	var m struct {
		Entrypoint string            `json:"entrypoint"`
		Files      map[string]string `json:"files"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, "manifest.json")), &m); err != nil {
		t.Fatalf("parse the installed manifest: %v", err)
	}
	digest, ok := m.Files[m.Entrypoint]
	if !ok {
		t.Fatalf("the manifest of %s does not record the entrypoint digest", version)
	}
	out := run(t, hostBin, "privileged", "verify-entrypoint", "-dir", dir, "-entrypoint", m.Entrypoint, "-digest", digest)
	if !strings.Contains(out, `"ok": true`) {
		t.Fatalf("verify-entrypoint output = %q", out)
	}
}

// requireCredential checks the persistent systemd credential source.
func requireCredential(t *testing.T) {
	t.Helper()
	path := filepath.Join(credsDir, pluginID+".token")
	requireModeOwner(t, path, 0o600, "root")
	token := readFile(t, path)
	if len(token) != 43 || strings.ContainsAny(string(token), " \t\n") {
		t.Fatalf("credential = %d bytes, want a 43-byte base64url token", len(token))
	}
}

// requirePluginSocket checks the systemd-owned listener.
func requirePluginSocket(t *testing.T) {
	t.Helper()
	path := supervisorSocketPath()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the plugin socket: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s is %s, want a 0600 socket", path, fi.Mode())
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); !ok || sys.Uid != lookupUID(t, qwqUser) {
		t.Fatalf("plugin socket owner = %+v, want %s", fi.Sys(), qwqUser)
	}
	if _, err := os.Stat(filepath.Join(runtimeBase, "link")); err != nil {
		t.Fatalf("the bind target %s/link is missing: %v", runtimeBase, err)
	}
}

// requireHostChannel checks the product created the plugin's host channel:
// the helper made the directory (2750 qwq:qwq-p-<id>), the controller serves
// host.sock in it.
func requireHostChannel(t *testing.T) {
	t.Helper()
	dir := filepath.Join(runtimeBase, "host", pluginID)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat the host channel dir: %v", err)
	}
	if fi.Mode()&os.ModeSetgid == 0 || fi.Mode().Perm() != 0o750 {
		t.Fatalf("%s mode = %s, want 2750", dir, fi.Mode())
	}
	if got := run(t, "stat", "-c", "%U:%G", dir); got != qwqUser+":"+pluginGrp {
		t.Fatalf("%s owner = %s, want %s:%s", dir, got, qwqUser, pluginGrp)
	}
	sock, err := os.Stat(filepath.Join(dir, "host.sock"))
	if err != nil || sock.Mode()&os.ModeSocket == 0 {
		t.Fatalf("host.sock is not served: %v", err)
	}
}

// requireRuntimeSockets checks the sockets a controller restart must not
// remove (no RuntimeDirectory= on qwq-controller.service).
func requireRuntimeSockets(t *testing.T) {
	t.Helper()
	for _, p := range []string{helperSocket, supervisorSocketPath(), filepath.Join(runtimeBase, "host", pluginID, "host.sock")} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode()&os.ModeSocket == 0 {
			t.Fatalf("socket %s missing after the controller restart: %v", p, err)
		}
	}
}

// requirePluginRemoved proves an uninstall removed the plugin's units, files
// and private group through the helper.
func requirePluginRemoved(t *testing.T) {
	t.Helper()
	requirePluginRemovedFor(t, pluginID)
}

func requirePluginRemovedFor(t *testing.T, id string) {
	t.Helper()
	service, socket, group := "qwq-plugin@"+id+".service", "qwq-plugin@"+id+".socket", "qwq-p-"+id
	for _, path := range []string{
		filepath.Join(unitDir, service), filepath.Join(unitDir, socket), filepath.Join(unitDir, service+".d"),
		filepath.Join(unitDir, "sockets.target.wants", socket), filepath.Join(tmpfilesDir, "qwq-plugin-"+id+".conf"),
		filepath.Join(pluginsRoot, id), filepath.Join(credsDir, id+".token"), filepath.Join(runtimeBase, "plugin", id),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("left behind after uninstall: %s (err %v)", path, err)
		}
	}
	// A root-side groupdel fallback would hide a helper sandbox regression
	// (its seccomp filter must let shadow call fchown), so a surviving group
	// fails the test.
	if err := exec.Command("getent", "group", group).Run(); err == nil {
		t.Errorf("the plugin group %s remains after the uninstall", group)
	}
}

// --- generic helpers --------------------------------------------------------

func supervisorSocketPath() string {
	return supervisorSocketPathFor(pluginID)
}

func supervisorSocketPathFor(id string) string {
	return filepath.Join(runtimeBase, "plugin", id, "plugin.sock")
}

// waitForPluginSocket dials until the gRPC server answers a health check.
func waitForPluginSocket(ctx context.Context, socket string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		callCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, last = grpc_health_v1.NewHealthClient(conn).Check(callCtx, &grpc_health_v1.HealthCheckRequest{})
		cancel()
		if last == nil {
			return conn, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = conn.Close()
	return nil, fmt.Errorf("no health answer: %w", last)
}

// showUnit returns the systemd state of any unit.
func showUnit(t *testing.T, unit string) sandbox.UnitStatus {
	t.Helper()
	out := run(t, "systemctl", "show", "-p", "MainPID", "-p", "ActiveState", "-p", "SubState", unit)
	state := sandbox.UnitStatus{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "MainPID":
			state.MainPID, _ = strconv.Atoi(value)
		case "ActiveState":
			state.ActiveState = value
		case "SubState":
			state.SubState = value
		}
	}
	return state
}

func requireEnv(t *testing.T, names ...string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("the end-to-end tests must run as root")
	}
	for _, name := range names {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required", name)
		}
	}
}

func requireMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if fi.Mode().Perm() != want.Perm() {
		t.Fatalf("%s mode = %#o, want %#o", path, fi.Mode().Perm(), want.Perm())
	}
}

func requireModeOwner(t *testing.T, path string, mode fs.FileMode, user string) {
	t.Helper()
	requireMode(t, path, mode)
	if got := run(t, "stat", "-c", "%U", path); got != user {
		t.Fatalf("%s owner = %s, want %s", path, got, user)
	}
}

func requireSocketGroup(t *testing.T, path, group string) {
	t.Helper()
	if got := run(t, "stat", "-c", "%G", path); got != group {
		t.Fatalf("%s group = %s, want %s", path, got, group)
	}
}

func lookupUID(t *testing.T, user string) uint32 {
	t.Helper()
	uid, err := strconv.ParseUint(run(t, "id", "-u", user), 10, 32)
	if err != nil {
		t.Fatalf("parse the uid of %s: %v", user, err)
	}
	return uint32(uid)
}

// processUID reads the real uid of pid from /proc.
func processUID(t *testing.T, pid int) uint32 {
	t.Helper()
	for _, line := range strings.Split(string(readFile(t, fmt.Sprintf("/proc/%d/status", pid))), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				if uid, err := strconv.ParseUint(f[0], 10, 32); err == nil {
					return uint32(uid)
				}
			}
		}
	}
	t.Fatalf("no Uid line for pid %d", pid)
	return 0
}

// run runs a command and fails the test with its combined output on error.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// writeFile writes data atomically with the exact mode.
func writeFile(t *testing.T, path string, data []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create the parent of %s: %v", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		t.Fatalf("write %s: %v", tmp, err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		t.Fatalf("chmod %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("publish %s: %v", path, err)
	}
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
