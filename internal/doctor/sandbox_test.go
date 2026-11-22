// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// cmdResult is one fake command invocation.
type cmdResult struct {
	out string
	err error
}

// sandboxEnv is a fake Env that dispatches Run on "name arg1 arg2 ...". It is
// deliberately separate from the fake in doctor_test.go, which ignores
// arguments and is enough for the older checks.
type sandboxEnv struct {
	files  map[string]string
	cmds   map[string]cmdResult
	exists map[string]bool
}

func (f sandboxEnv) env() Env {
	return Env{
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := f.files[p]; ok {
				return []byte(s), nil
			}
			return nil, fs.ErrNotExist
		},
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			key := name
			if len(args) > 0 {
				key += " " + strings.Join(args, " ")
			}
			if r, ok := f.cmds[key]; ok {
				return r.out, r.err
			}
			if r, ok := f.cmds[name]; ok {
				return r.out, r.err
			}
			return "", errors.New("executable file not found")
		},
		Statfs: func(string) (uint64, uint64, error) { return 8 << 30, 24 << 30, nil },
		Stat: func(p string) (os.FileInfo, error) {
			if f.exists[p] {
				return nil, nil
			}
			if _, ok := f.files[p]; ok {
				return nil, nil
			}
			return nil, fs.ErrNotExist
		},
	}
}

// targetHost is the P2-T1 test VPS after a full install: Ubuntu 24.04,
// systemd 255, cgroup v2, KVM, polkit, units installed.
func targetHost() sandboxEnv {
	return sandboxEnv{
		files: map[string]string{
			"/sys/fs/cgroup/cgroup.controllers":          "cpuset cpu io memory hugetlb pids rdma misc\n",
			"/proc/self/status":                          "Name:\tqwq\nSeccomp:\t0\nSeccomp_filters:\t0\n",
			"/proc/sys/kernel/seccomp/actions_avail":     "kill_process kill_thread trap errno user_notify notify log allow\n",
			"/proc/sys/kernel/unprivileged_userns_clone": "1\n",
		},
		cmds: map[string]cmdResult{
			"systemctl --version": {out: "systemd 255 (255.4-1ubuntu8.18)\n+PAM +AUDIT"},
			"systemctl show -p ActiveState -p LoadState -p UnitFileState polkit.service": {
				out: "ActiveState=active\nLoadState=loaded\nUnitFileState=static\n",
			},
			"pkaction --version": {out: "pkaction version 124"},
			"systemd-analyze security qwq-plugin@.service": {
				out: "  NAME   DESCRIPTION   EXPOSURE\n✓ PrivateNetwork= ... 0.2\n" +
					"→ Overall exposure level for qwq-plugin@.service: 0.6 SAFE :-}\n",
			},
			"systemd-detect-virt": {out: "kvm"},
		},
		exists: map[string]bool{
			"/run/qwq": true,
			"/etc/polkit-1/rules.d/60-qwq-plugin.rules": true,
			"/etc/systemd/system/qwq-plugin@.service":   true,
			"/etc/systemd/system/qwq-plugin@.socket":    true,
		},
	}
}

func sandboxIDs() []string {
	return []string{
		"sandbox-systemd", "sandbox-cgroup", "sandbox-userns", "sandbox-seccomp",
		"sandbox-virt", "sandbox-exposure", "sandbox-polkit", "sandbox-runtime", "sandbox-units",
	}
}

func TestSandboxChecksTargetHost(t *testing.T) {
	rs := SandboxChecks(targetHost().env(), SandboxOptions{})
	if len(rs) != len(sandboxIDs()) {
		t.Fatalf("SandboxChecks returned %d results, want %d", len(rs), len(sandboxIDs()))
	}
	m := byID(rs)
	if len(m) != len(rs) {
		t.Errorf("SandboxChecks returned duplicate ids: %+v", rs)
	}
	for _, id := range sandboxIDs() {
		r, ok := m[id]
		if !ok {
			t.Errorf("missing check %s", id)
			continue
		}
		if r.Status != OK {
			t.Errorf("%s = %+v", id, r)
		}
	}
	if !strings.Contains(m["sandbox-exposure"].Detail, "0.6") {
		t.Errorf("exposure detail = %q", m["sandbox-exposure"].Detail)
	}
	if Worst(rs) != OK {
		t.Errorf("Worst = %s", Worst(rs))
	}
}

func TestSandboxChecksMissingSystemd(t *testing.T) {
	f := sandboxEnv{files: map[string]string{}, cmds: map[string]cmdResult{}, exists: map[string]bool{}}
	rs := SandboxChecks(f.env(), SandboxOptions{})
	m := byID(rs)
	if m["sandbox-systemd"].Status != Fail {
		t.Errorf("systemd = %+v", m["sandbox-systemd"])
	}
	if m["sandbox-cgroup"].Status != Fail {
		t.Errorf("cgroup = %+v", m["sandbox-cgroup"])
	}
	if m["sandbox-polkit"].Status != Fail {
		t.Errorf("polkit = %+v", m["sandbox-polkit"])
	}
	if m["sandbox-exposure"].Status != Info {
		t.Errorf("exposure without a unit = %+v", m["sandbox-exposure"])
	}
	if m["sandbox-units"].Status != Warn || !strings.Contains(m["sandbox-units"].Fix, "daemon-reload") {
		t.Errorf("units = %+v", m["sandbox-units"])
	}
	if Worst(rs) != Fail {
		t.Errorf("Worst = %s", Worst(rs))
	}
}

func TestSandboxChecksCgroupV1(t *testing.T) {
	f := targetHost()
	delete(f.files, "/sys/fs/cgroup/cgroup.controllers")
	m := byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-cgroup"].Status != Fail || !strings.Contains(m["sandbox-cgroup"].Detail, "v1") {
		t.Errorf("cgroup = %+v", m["sandbox-cgroup"])
	}
}

func TestSandboxChecksMissingControllers(t *testing.T) {
	f := targetHost()
	f.files["/sys/fs/cgroup/cgroup.controllers"] = "cpuset cpu memory\n"
	m := byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-cgroup"].Status != Warn || !strings.Contains(m["sandbox-cgroup"].Detail, "pids, io") {
		t.Errorf("cgroup = %+v", m["sandbox-cgroup"])
	}
}

func TestSandboxChecksPolkitInactive(t *testing.T) {
	f := targetHost()
	f.cmds["systemctl show -p ActiveState -p LoadState -p UnitFileState polkit.service"] = cmdResult{
		out: "ActiveState=inactive\nLoadState=loaded\nUnitFileState=enabled\n",
	}
	m := byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-polkit"].Status != Info || !strings.Contains(m["sandbox-polkit"].Detail, "D-Bus") {
		t.Errorf("inactive polkit = %+v", m["sandbox-polkit"])
	}

	// daemon 缺失会让原安装门禁拒绝插件，不能只给警告。
	f = targetHost()
	f.cmds["systemctl show -p ActiveState -p LoadState -p UnitFileState polkit.service"] = cmdResult{
		out: "ActiveState=inactive\nLoadState=not-found\nUnitFileState=\n",
	}
	m = byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-polkit"].Status != Fail {
		t.Errorf("missing polkit = %+v", m["sandbox-polkit"])
	}

	// 查询失败时无法确认运行条件，保留明确的失败而不是推测可用。
	f = targetHost()
	f.cmds["systemctl show -p ActiveState -p LoadState -p UnitFileState polkit.service"] = cmdResult{err: errors.New("exit status 1")}
	f.exists["/usr/lib/polkit-1/polkitd"] = true
	m = byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-polkit"].Status != Fail {
		t.Errorf("unqueryable polkit = %+v", m["sandbox-polkit"])
	}
}

// Ubuntu 22.04 ships polkit 0.105, which reads only .pkla files: the
// qwq-plugin.rules JavaScript file is ignored and every plugin start, stop or
// kill from the unprivileged controller is denied. The check must refuse the
// host instead of letting a plugin be installed that can never run (PRIV-06).
func TestSandboxChecksPolkitVersion(t *testing.T) {
	f := targetHost()
	f.cmds["pkaction --version"] = cmdResult{out: "pkaction version 0.105"}
	r := byID(SandboxChecks(f.env(), SandboxOptions{}))["sandbox-polkit"]
	if r.Status != Fail || !strings.Contains(r.Detail, "0.105") || !strings.Contains(r.Detail, "JavaScript") {
		t.Errorf("polkit 0.105 = %+v", r)
	}
	if !strings.Contains(r.Fix, "0.106") || !strings.Contains(r.Fix, "qwq-compat-polkit") {
		t.Errorf("polkit 0.105 fix = %q", r.Fix)
	}

	// Installing and activating qwq-compat-polkit resolves polkit 0.105 and
	// missing-polkit hosts cleanly without weakening native hosts.
	f = targetHost()
	f.cmds["pkaction --version"] = cmdResult{out: "pkaction version 0.105"}
	f.exists[CompatPolkitMarkerPath] = true
	f.cmds["systemctl show -p ActiveState -p LoadState "+CompatUnitctlSocketUnit] = cmdResult{
		out: "ActiveState=active\nLoadState=loaded\n",
	}
	if r := byID(SandboxChecks(f.env(), SandboxOptions{}))["sandbox-polkit"]; r.Status != OK || !strings.Contains(r.Detail, "compat patch active") {
		t.Errorf("polkit 0.105 with compat patch = %+v", r)
	}

	// Missing polkit (e.g. Debian 11) with active compat patch also passes.
	f = targetHost()
	delete(f.cmds, "pkaction --version")
	f.cmds["systemctl show -p ActiveState -p LoadState -p UnitFileState polkit.service"] = cmdResult{
		out: "ActiveState=inactive\nLoadState=not-found\nUnitFileState=\n",
	}
	f.exists[CompatPolkitMarkerPath] = true
	f.cmds["systemctl show -p ActiveState -p LoadState "+CompatUnitctlSocketUnit] = cmdResult{
		out: "ActiveState=active\nLoadState=loaded\n",
	}
	if r := byID(SandboxChecks(f.env(), SandboxOptions{}))["sandbox-polkit"]; r.Status != OK || !strings.Contains(r.Detail, "compat patch active") {
		t.Errorf("missing polkit with compat patch = %+v", r)
	}

	// Marker present without active socket must still fail.
	f.cmds["systemctl show -p ActiveState -p LoadState "+CompatUnitctlSocketUnit] = cmdResult{
		out: "ActiveState=inactive\nLoadState=loaded\n",
	}
	if r := byID(SandboxChecks(f.env(), SandboxOptions{}))["sandbox-polkit"]; r.Status != Fail {
		t.Errorf("inactive compat socket = %+v, want Fail", r)
	}

	// 0.106 introduced JavaScript rules; the meson era (121+) keeps them.
	for _, version := range []string{"pkaction version 0.106", "pkaction version 122"} {
		f := targetHost()
		f.cmds["pkaction --version"] = cmdResult{out: version}
		if r := byID(SandboxChecks(f.env(), SandboxOptions{}))["sandbox-polkit"]; r.Status != OK {
			t.Errorf("%s = %+v", version, r)
		}
	}

	// Without pkaction the version cannot be probed; the check keeps its old
	// meaning instead of guessing.
	f = targetHost()
	delete(f.cmds, "pkaction --version")
	if r := byID(SandboxChecks(f.env(), SandboxOptions{}))["sandbox-polkit"]; r.Status != OK || !strings.Contains(r.Detail, "active") {
		t.Errorf("unprobeable version = %+v", r)
	}

	// An unparseable version is reported rather than assumed supported.
	f = targetHost()
	f.cmds["pkaction --version"] = cmdResult{out: "pkaction version unknown"}
	if r := byID(SandboxChecks(f.env(), SandboxOptions{}))["sandbox-polkit"]; r.Status != Fail {
		t.Errorf("unparseable version = %+v", r)
	}

	// Both shapes of a host without polkit (Debian 12 minimal) name the package.
	const show = "systemctl show -p ActiveState -p LoadState -p UnitFileState polkit.service"
	for name, reply := range map[string]cmdResult{
		"unit not found":  {out: "ActiveState=inactive\nLoadState=not-found\nUnitFileState=\n"},
		"query fails":     {err: errors.New("exit status 1")},
		"empty LoadState": {out: "ActiveState=\n"},
	} {
		f := targetHost()
		delete(f.cmds, "pkaction --version")
		f.cmds[show] = reply
		if r := byID(SandboxChecks(f.env(), SandboxOptions{}))["sandbox-polkit"]; r.Status != Fail || !strings.Contains(r.Fix, "apt install polkitd") {
			t.Errorf("%s = %+v", name, r)
		}
	}
}

func TestSandboxChecksUsernsAndSeccomp(t *testing.T) {
	f := targetHost()
	f.files["/proc/sys/kernel/unprivileged_userns_clone"] = "0\n"
	m := byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-userns"].Status != Info || m["sandbox-userns"].Fix == "" {
		t.Errorf("userns disabled = %+v", m["sandbox-userns"])
	}

	f = targetHost()
	delete(f.files, "/proc/sys/kernel/unprivileged_userns_clone")
	m = byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-userns"].Status != Info || !strings.Contains(m["sandbox-userns"].Detail, "no unprivileged_userns_clone") {
		t.Errorf("userns absent = %+v", m["sandbox-userns"])
	}

	f = targetHost()
	f.files["/proc/self/status"] = "Name:\tqwq\n"
	m = byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-seccomp"].Status != Fail {
		t.Errorf("seccomp without the field = %+v", m["sandbox-seccomp"])
	}

	f = targetHost()
	f.files["/proc/sys/kernel/seccomp/actions_avail"] = "kill_process kill_thread trap user_notify notify log allow\n"
	m = byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-seccomp"].Status != Warn || !strings.Contains(m["sandbox-seccomp"].Fix, "SystemCallErrorNumber") {
		t.Errorf("seccomp without errno = %+v", m["sandbox-seccomp"])
	}
}

func TestSandboxChecksRuntimeAndUnits(t *testing.T) {
	f := targetHost()
	delete(f.exists, "/run/qwq")
	m := byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-runtime"].Status != Warn || !strings.Contains(m["sandbox-runtime"].Fix, "tmpfiles") {
		t.Errorf("runtime dir = %+v", m["sandbox-runtime"])
	}

	f = targetHost()
	delete(f.exists, "/etc/systemd/system/qwq-plugin@.socket")
	m = byID(SandboxChecks(f.env(), SandboxOptions{}))
	if m["sandbox-units"].Status != Warn || !strings.Contains(m["sandbox-units"].Detail, "qwq-plugin@.socket") {
		t.Errorf("units = %+v", m["sandbox-units"])
	}
}

func TestSandboxChecksExposureOverLimit(t *testing.T) {
	f := targetHost()
	f.cmds["systemd-analyze security qwq-plugin@.service"] = cmdResult{
		out: "→ Overall exposure level for qwq-plugin@.service: 1.4 UNSAFE :-(\n",
	}
	m := byID(SandboxChecks(f.env(), SandboxOptions{MaxExposure: 1.0}))
	if m["sandbox-exposure"].Status != Fail || !strings.Contains(m["sandbox-exposure"].Detail, "1.4") {
		t.Errorf("exposure = %+v", m["sandbox-exposure"])
	}
	if Worst(SandboxChecks(f.env(), SandboxOptions{MaxExposure: 1.0})) != Fail {
		t.Error("隔离预算超限必须让原安装门禁拒绝插件")
	}

	// A custom unit and threshold are honoured.
	f.cmds["systemd-analyze security qwq-plugin@alpha.service"] = cmdResult{
		out: "→ Overall exposure level for qwq-plugin@alpha.service: 0.4 OK\n",
	}
	m = byID(SandboxChecks(f.env(), SandboxOptions{Unit: "qwq-plugin@alpha.service", MaxExposure: 0.5}))
	if m["sandbox-exposure"].Status != OK {
		t.Errorf("custom exposure = %+v", m["sandbox-exposure"])
	}
}

func TestParseExposure(t *testing.T) {
	for _, c := range []struct {
		name string
		out  string
		want float64
	}{
		{"systemd 255", "→ Overall exposure level for qwq-plugin@alpha.service: 0.6 SAFE :-}", 0.6},
		{"systemd 245", "Overall exposure level for qwq-plugin@alpha.service: 1.2 UNSAFE", 1.2},
		{"no unit name", "Overall exposure level: 9.6", 9.6},
		{"integer", "Overall exposure level: 0", 0},
	} {
		got, err := ParseExposure(c.out)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: ParseExposure = %v, want %v", c.name, got, c.want)
		}
	}
	for _, c := range []struct{ name, out string }{
		{"empty", ""},
		{"no line", "NAME DESCRIPTION EXPOSURE\n"},
		{"not a number", "Overall exposure level: abc"},
		{"out of range", "Overall exposure level: 12.0"},
	} {
		if _, err := ParseExposure(c.out); err == nil {
			t.Errorf("%s: ParseExposure accepted the output", c.name)
		}
	}
}

func TestSandboxScore(t *testing.T) {
	env := targetHost().env()
	score, ok, err := SandboxScore(env, SandboxOptions{}, 1.0)
	if err != nil || !ok || score != 0.6 {
		t.Fatalf("SandboxScore = %v, %v, %v", score, ok, err)
	}
	// A zero limit falls back to DefaultMaxExposure.
	score, ok, err = SandboxScore(env, SandboxOptions{}, 0)
	if err != nil || !ok || score != 0.6 {
		t.Fatalf("default limit: %v, %v, %v", score, ok, err)
	}
	// Above the limit fails the gate.
	over := targetHost()
	over.cmds["systemd-analyze security qwq-plugin@.service"] = cmdResult{
		out: "→ Overall exposure level for qwq-plugin@.service: 1.4 UNSAFE\n",
	}
	if score, ok, err = SandboxScore(over.env(), SandboxOptions{}, 1.0); err != nil || ok || score != 1.4 {
		t.Errorf("over the limit = %v, %v, %v", score, ok, err)
	}
	// A missing systemd-analyze is an error, not a passing score.
	broken := targetHost()
	delete(broken.cmds, "systemd-analyze security qwq-plugin@.service")
	if _, ok, err = SandboxScore(broken.env(), SandboxOptions{}, 1.0); err == nil || ok {
		t.Errorf("missing systemd-analyze = %v, %v", ok, err)
	}
}
