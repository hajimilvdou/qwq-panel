// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeInfo is a FileInfo with an owner, for the layout checks.
type fakeInfo struct {
	mode     fs.FileMode
	uid, gid uint32
}

func (f fakeInfo) Name() string       { return "" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid, Gid: f.gid} }

const qwqUID = 990

// installedEnv is a healthy installed host; tests break one thing at a time.
func installedEnv(stats map[string]fakeInfo, files fakeFS, cmds map[string]string) Env {
	env := fake(files, cmds)
	env.Stat = func(p string) (os.FileInfo, error) {
		if fi, ok := stats[p]; ok {
			return fi, nil
		}
		return nil, fs.ErrNotExist
	}
	env.LookupUser = func(name string) (uint32, uint32, error) {
		switch name {
		case "root":
			return 0, 0, nil
		case "qwq":
			return qwqUID, qwqUID, nil
		}
		return 0, 0, errors.New("unknown user")
	}
	env.Glob = func(string) ([]string, error) { return []string{"/etc/qwq/trust/publisher.pem"}, nil }
	return env
}

func healthyStats() map[string]fakeInfo {
	stats := map[string]fakeInfo{
		"/run/qwq/privileged.sock": {mode: fs.ModeSocket | 0o660, gid: qwqUID},
	}
	for _, e := range Layout("/var/lib/qwq", "/run/qwq") {
		uid := uint32(0)
		if e.Owner == "qwq" {
			uid = qwqUID
		}
		stats[e.Path] = fakeInfo{mode: fs.ModeDir | e.Mode, uid: uid, gid: uid}
	}
	return stats
}

var healthyFiles = fakeFS{
	"/etc/qwq/qwq.json":                `{"http":{"listen":"127.0.0.1:8443"}}`,
	"/proc/sys/fs/protected_hardlinks": "1\n",
	"/proc/net/tcp": "  sl  local_address rem_address   st\n" +
		"   0: 00000000:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n", // :8888 BaoTa
	"/proc/net/tcp6": "  sl  local_address rem_address   st\n",
}

func installChecks(env Env) map[string]Result {
	return byID(InstallChecks(context.Background(), env, InstallOptions{ConfigPath: "/etc/qwq/qwq.json"}))
}

func TestDoctorHealthyInstall(t *testing.T) {
	rs := InstallChecks(context.Background(), installedEnv(healthyStats(), healthyFiles, nil), InstallOptions{ConfigPath: "/etc/qwq/qwq.json"})
	for _, r := range rs {
		if r.Status == Fail || r.Status == Warn {
			t.Errorf("%s = %+v", r.ID, r)
		}
	}
	if p := byID(rs)["port"]; !strings.Contains(p.Detail, "8888 (BaoTa panel)") {
		t.Errorf("port detail does not name the BaoTa listener: %+v", p)
	}
}

func TestDoctorDetectsWrongDirMode(t *testing.T) {
	stats := healthyStats()
	stats["/var/lib/qwq"] = fakeInfo{mode: fs.ModeDir | 0o755, uid: qwqUID, gid: qwqUID}
	stats["/run/qwq"] = fakeInfo{mode: fs.ModeDir | 0o711, uid: qwqUID, gid: qwqUID} // qwq-owned ancestry
	m := installChecks(installedEnv(stats, healthyFiles, nil))

	r := m["dir /var/lib/qwq"]
	if r.Status != Fail || !strings.Contains(r.Fix, "chmod 0700 /var/lib/qwq") {
		t.Fatalf("data dir 0755 = %+v", r)
	}
	if r := m["dir /run/qwq"]; r.Status != Fail || !strings.Contains(r.Fix, "chown root:root /run/qwq") {
		t.Fatalf("qwq-owned /run/qwq = %+v", r)
	}
	delete(stats, "/var/lib/qwq-plugins")
	if r := installChecks(installedEnv(stats, healthyFiles, nil))["dir /var/lib/qwq-plugins"]; r.Status != Fail || !strings.Contains(r.Fix, "systemd-tmpfiles") {
		t.Fatalf("missing plugins root = %+v", r)
	}
}

func TestDoctorDetectsPortInUse(t *testing.T) {
	files := with(healthyFiles, fakeFS{
		"/proc/net/tcp6": "  sl  local_address rem_address   st\n" +
			"   0: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 0A 0 0 0 0 0 1\n", // :8443
	})
	r := installChecks(installedEnv(healthyStats(), files, nil))["port"]
	if r.Status != Fail || !strings.Contains(r.Fix, "sport = :8443") {
		t.Fatalf("port taken by another process = %+v", r)
	}
	// Held by our own running controller: expected.
	r = installChecks(installedEnv(healthyStats(), files, map[string]string{"systemctl": "active"}))["port"]
	if r.Status != OK {
		t.Fatalf("port held by qwq-controller = %+v", r)
	}
	// Non-listening sockets on the port do not count.
	files["/proc/net/tcp6"] = "  sl  local_address rem_address   st\n" +
		"   0: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 01 0 0 0 0 0 1\n"
	if r := installChecks(installedEnv(healthyStats(), files, nil))["port"]; r.Status != OK {
		t.Fatalf("established connection counted as listener: %+v", r)
	}
}

// Next to another panel the web server owns 80/443 (DEP-06): doctor must name
// the way out instead of only telling the operator to stop nginx.
func TestDoctorCoexistenceHints(t *testing.T) {
	const acme = `"tls":{"mode":"acme","domains":["panel.example.com"]}`
	nginx := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n" // :443

	// ACME on the port nginx holds: the port check points at proxy mode.
	files := with(healthyFiles, fakeFS{"/etc/qwq/qwq.json": `{"http":{"listen":"0.0.0.0:443",` + acme + `}}`, "/proc/net/tcp": nginx})
	m := installChecks(installedEnv(healthyStats(), files, nil))
	if r := m["port"]; r.Status != Fail || !strings.Contains(r.Fix, `"proxy"`) || !strings.Contains(r.Fix, "coexistence-baota.md") {
		t.Errorf("443 held by a web server = %+v", r)
	}

	// ACME moved to a free port: the configuration itself is the failure, and
	// no listener is described because the file did not load.
	files = with(healthyFiles, fakeFS{"/etc/qwq/qwq.json": `{"http":{"listen":"0.0.0.0:8443",` + acme + `}}`})
	m = installChecks(installedEnv(healthyStats(), files, nil))
	if r := m["config"]; r.Status != Fail || !strings.Contains(r.Detail, "requires port 443") {
		t.Errorf("acme off port 443 = %+v", r)
	}
	if r, ok := m["listen"]; ok {
		t.Errorf("listen reported for a configuration that did not load: %+v", r)
	}
}

// "Installed but unreachable": a listener on all interfaces still needs the
// firewall opened, which neither the installer nor the panel does.
func TestDoctorListenReachability(t *testing.T) {
	if r := installChecks(installedEnv(healthyStats(), healthyFiles, nil))["listen"]; r.Status != OK || !strings.Contains(r.Detail, "loopback") {
		t.Errorf("loopback listener = %+v", r)
	}
	for listen, port := range map[string]string{"0.0.0.0:8443": "8443", "[::]:9443": "9443", "203.0.113.5:8443": "8443"} {
		files := with(healthyFiles, fakeFS{"/etc/qwq/qwq.json": `{"http":{"listen":"` + listen + `"}}`})
		r := installChecks(installedEnv(healthyStats(), files, nil))["listen"]
		if r.Status != Info {
			t.Errorf("%s = %+v", listen, r)
		}
		for _, want := range []string{"ufw allow " + port + "/tcp", "firewall-cmd --permanent --add-port=" + port + "/tcp", "BaoTa"} {
			if !strings.Contains(r.Fix, want) {
				t.Errorf("%s: fix lacks %q: %s", listen, want, r.Fix)
			}
		}
	}
}

// Rocky 9 runs SELinux enforcing with the plugin tree unlabelled: systemd may
// refuse to execute plugin binaries (203/EXEC). The check stays a warning —
// the platform is not verified yet — but must name the symptom and the
// diagnosis (PRIV-06).
func TestDoctorSELinuxEnforcing(t *testing.T) {
	files := with(healthyFiles, fakeFS{"/sys/fs/selinux/enforce": "1\n"})
	r := installChecks(installedEnv(healthyStats(), files, nil))["selinux"]
	if r.Status != Warn || !strings.Contains(r.Detail, "203/EXEC") || !strings.Contains(r.Detail, "bin_t") {
		t.Errorf("enforcing = %+v", r)
	}
	if !strings.Contains(r.Fix, "ausearch") || !strings.Contains(r.Fix, "not verified") {
		t.Errorf("enforcing fix = %q", r.Fix)
	}
	files = with(healthyFiles, fakeFS{"/sys/fs/selinux/enforce": "0\n"})
	if r := installChecks(installedEnv(healthyStats(), files, nil))["selinux"]; r.Status != OK || r.Detail != "permissive" {
		t.Errorf("permissive = %+v", r)
	}
}

func TestDoctorDetectsHelperAndTrust(t *testing.T) {
	stats := healthyStats()
	stats["/run/qwq/privileged.sock"] = fakeInfo{mode: fs.ModeSocket | 0o666, gid: qwqUID}
	env := installedEnv(stats, healthyFiles, nil)
	env.Glob = func(string) ([]string, error) { return nil, nil }
	m := installChecks(env)
	if m["helper"].Status != Fail {
		t.Errorf("0666 helper socket = %+v", m["helper"])
	}
	if m["trust"].Status != Warn {
		t.Errorf("empty trust dir = %+v", m["trust"])
	}
	files := with(healthyFiles, fakeFS{"/proc/sys/fs/protected_hardlinks": "0\n", "/etc/qwq/qwq.json": `{"bogus":1}`})
	m = installChecks(installedEnv(healthyStats(), files, nil))
	if m["protected-hardlinks"].Status != Fail || m["config"].Status != Fail {
		t.Errorf("hardlinks/config = %+v / %+v", m["protected-hardlinks"], m["config"])
	}
}

func TestDoctorExitCodes(t *testing.T) {
	for _, c := range []struct {
		rs   []Result
		want int
	}{
		{nil, 0},
		{[]Result{{Status: OK}, {Status: Info}}, 0},
		{[]Result{{Status: OK}, {Status: Warn}}, 1},
		{[]Result{{Status: Warn}, {Status: Fail}, {Status: OK}}, 3},
	} {
		if got := ExitCode(c.rs); got != c.want {
			t.Errorf("ExitCode(%+v) = %d, want %d", c.rs, got, c.want)
		}
	}
}
