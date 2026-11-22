// SPDX-License-Identifier: AGPL-3.0-only

// Package doctor implements `qwq doctor`: read-only checks of the host
// environment that the sandbox and the 1C1G budget depend on (ARCH §10.2,
// §13; review O1). It never changes the system. The installer runs the same
// checks and refuses third-party plugins when isolation prerequisites are
// missing.
package doctor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Status of a check.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Info Status = "info"
)

// Result of one check. Fix says what the operator can do; checks never act.
type Result struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Env abstracts the system for tests.
type Env struct {
	ReadFile func(string) ([]byte, error)
	Run      func(ctx context.Context, name string, args ...string) (string, error)
	Statfs   func(path string) (free, total uint64, err error)
	Stat     func(string) (os.FileInfo, error)
	// LookupUser returns a user's uid and primary gid. Nil skips owner checks.
	LookupUser func(name string) (uid, gid uint32, err error)
	// Glob is filepath.Glob. Nil skips checks that list directories.
	Glob func(pattern string) ([]string, error)
}

// System returns the real environment.
func System() Env {
	return Env{
		ReadFile: os.ReadFile,
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, name, args...).Output()
			return strings.TrimSpace(string(out)), err
		},
		Statfs: func(path string) (uint64, uint64, error) {
			var s syscall.Statfs_t
			if err := syscall.Statfs(path, &s); err != nil {
				return 0, 0, err
			}
			return s.Bavail * uint64(s.Bsize), s.Blocks * uint64(s.Bsize), nil
		},
		Stat:       os.Stat,
		LookupUser: lookupUser,
		Glob:       filepath.Glob,
	}
}

func lookupUser(name string) (uint32, uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	return uint32(uid), uint32(gid), nil
}

// Options select paths to check.
type Options struct {
	DataDir string
}

// Minimums from ADR-0005 Q4 and ADR-0003.
const (
	minSystemd        = 249 // target platform
	minSystemdSandbox = 247 // LoadCredential, ProtectProc
	minKernelPIDFD    = "6.5"
	minDiskFreeBytes  = 1 << 30
	minMemTotalBytes  = 900 << 20 // a "1 GiB" VPS reports ~960 MiB
)

// Run executes every check in a fixed order.
func Run(ctx context.Context, env Env, opts Options) []Result {
	var rs []Result
	add := func(r Result) { rs = append(rs, r) }
	add(checkOS(env))
	add(checkKernel(env))
	add(checkSystemd(ctx, env))
	add(checkCgroup(env))
	add(checkVirt(ctx, env))
	add(checkSeccomp(env))
	add(checkNamespaces(env))
	add(checkMemory(env))
	add(checkTimeSync(ctx, env))
	if opts.DataDir != "" {
		add(checkDisk(env, opts.DataDir))
	}
	add(checkCoexistence(env))
	return rs
}

// Worst returns the most severe status in rs.
func Worst(rs []Result) Status {
	w := OK
	for _, r := range rs {
		switch {
		case r.Status == Fail:
			return Fail
		case r.Status == Warn:
			w = Warn
		}
	}
	return w
}

// checkOS reports the distribution and its verification / compatibility status.
// Native verified: Debian 12/13, Ubuntu 24.04/26.04.
// Verified with qwq-compat-polkit patch: Ubuntu 22.04, Debian 11.
func checkOS(env Env) Result {
	b, err := env.ReadFile("/etc/os-release")
	if err != nil {
		return Result{ID: "os", Status: Warn, Detail: "cannot read /etc/os-release"}
	}
	kv := parseKV(b)
	id, ver := kv["ID"], kv["VERSION_ID"]
	name := kv["PRETTY_NAME"]
	major, _ := strconv.Atoi(strings.SplitN(ver, ".", 2)[0])

	_, compatErr := env.Stat(CompatPolkitMarkerPath)
	hasCompat := compatErr == nil

	// Native verified platforms.
	if (id == "ubuntu" && (ver == "24.04" || ver == "26.04")) ||
		(id == "debian" && (major == 12 || major == 13)) {
		return Result{ID: "os", Status: OK, Detail: name}
	}
	// Legacy-polkit platforms supported through the optional qwq-compat-polkit patch.
	if id == "ubuntu" && ver == "22.04" {
		if hasCompat {
			return Result{ID: "os", Status: OK, Detail: name + " (compat patch active)"}
		}
		return Result{ID: "os", Status: OK, Detail: name + " (requires qwq-compat-polkit patch; install.sh applies it automatically)"}
	}
	if id == "debian" && major == 11 {
		if hasCompat {
			return Result{ID: "os", Status: OK, Detail: name + " (compat patch active)"}
		}
		return Result{ID: "os", Status: Warn, Detail: name + " is supported via qwq-compat-polkit patch",
			Fix: "install.sh automatically applies qwq-compat-polkit on Debian 11; native support starts at Debian 12+ / Ubuntu 24.04+"}
	}
	supported := (id == "debian" && major >= 12) || (id == "ubuntu" && major >= 22) ||
		((id == "rocky" || id == "almalinux") && major >= 9)
	if !supported {
		return Result{ID: "os", Status: Warn, Detail: name + " is not a supported distribution",
			Fix: "native: Debian 12+, Ubuntu 24.04+, Rocky/Alma 9+; compat patch: Ubuntu 22.04, Debian 11"}
	}
	return Result{ID: "os", Status: OK,
		Detail: name + " (not verified yet; see the support table in README)"}
}

func checkKernel(env Env) Result {
	b, err := env.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return Result{ID: "kernel", Status: Warn, Detail: "cannot read kernel version"}
	}
	rel := strings.TrimSpace(string(b))
	if versionAtLeast(rel, minKernelPIDFD) {
		return Result{ID: "kernel", Status: OK, Detail: rel + " (SO_PEERPIDFD available)"}
	}
	return Result{ID: "kernel", Status: Info, Detail: rel + " (no SO_PEERPIDFD; peer checks fall back to SO_PEERCRED + cgroup)"}
}

var systemdVersion = regexp.MustCompile(`^systemd (\d+)`)

func checkSystemd(ctx context.Context, env Env) Result {
	out, err := env.Run(ctx, "systemctl", "--version")
	m := systemdVersion.FindStringSubmatch(out)
	if err != nil || m == nil {
		return Result{ID: "systemd", Status: Fail, Detail: "systemd not found",
			Fix: "the plugin runtime requires systemd (ADR-0003)"}
	}
	v, _ := strconv.Atoi(m[1])
	switch {
	case v >= minSystemd:
		return Result{ID: "systemd", Status: OK, Detail: fmt.Sprintf("systemd %d", v)}
	case v >= minSystemdSandbox:
		return Result{ID: "systemd", Status: Warn, Detail: fmt.Sprintf("systemd %d is below the target %d", v, minSystemd),
			Fix: "full sandbox works; upgrade the distribution for support"}
	default:
		return Result{ID: "systemd", Status: Fail, Detail: fmt.Sprintf("systemd %d lacks LoadCredential/ProtectProc (needs %d)", v, minSystemdSandbox),
			Fix: "third-party plugins are refused; built-in plugins run with a reduced sandbox"}
	}
}

func checkCgroup(env Env) Result {
	b, err := env.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return Result{ID: "cgroup", Status: Fail, Detail: "cgroup v2 unified hierarchy not mounted (v1 or hybrid)",
			Fix: "boot with systemd.unified_cgroup_hierarchy=1; resource limits for plugins need cgroup v2"}
	}
	have := map[string]bool{}
	for _, c := range strings.Fields(string(b)) {
		have[c] = true
	}
	var missing []string
	for _, c := range []string{"cpu", "memory", "pids", "io"} {
		if !have[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return Result{ID: "cgroup", Status: Warn, Detail: "cgroup v2 without controllers: " + strings.Join(missing, ", ")}
	}
	return Result{ID: "cgroup", Status: OK, Detail: "cgroup v2 with cpu, memory, pids, io"}
}

func checkVirt(ctx context.Context, env Env) Result {
	out, _ := env.Run(ctx, "systemd-detect-virt")
	switch out {
	case "", "none":
		return Result{ID: "virtualization", Status: Info, Detail: "bare metal or unknown"}
	case "openvz", "lxc", "lxc-libvirt", "docker", "podman", "wsl":
		return Result{ID: "virtualization", Status: Warn, Detail: out + ": container virtualization may block namespaces, seccomp or cgroup delegation",
			Fix: "a KVM/Xen VPS is recommended; third-party plugins may be refused"}
	default:
		return Result{ID: "virtualization", Status: OK, Detail: out}
	}
}

func checkSeccomp(env Env) Result {
	b, err := env.ReadFile("/proc/self/status")
	if err != nil {
		return Result{ID: "seccomp", Status: Warn, Detail: "cannot read /proc/self/status"}
	}
	if _, ok := parseColon(b)["Seccomp"]; !ok {
		return Result{ID: "seccomp", Status: Fail, Detail: "kernel without seccomp", Fix: "SystemCallFilter= will not work"}
	}
	return Result{ID: "seccomp", Status: OK, Detail: "available"}
}

func checkNamespaces(env Env) Result {
	var missing []string
	for _, ns := range []string{"mnt", "net", "pid", "user", "ipc", "uts"} {
		if _, err := env.Stat("/proc/self/ns/" + ns); err != nil {
			missing = append(missing, ns)
		}
	}
	if len(missing) > 0 {
		return Result{ID: "namespaces", Status: Fail, Detail: "missing: " + strings.Join(missing, ", "),
			Fix: "PrivateNetwork=, PrivateTmp= and ProtectSystem= need these namespaces"}
	}
	return Result{ID: "namespaces", Status: OK, Detail: "mnt, net, pid, user, ipc, uts"}
}

func checkMemory(env Env) Result {
	b, err := env.ReadFile("/proc/meminfo")
	if err != nil {
		return Result{ID: "memory", Status: Warn, Detail: "cannot read /proc/meminfo"}
	}
	m := parseColon(b)
	total, avail, swap := kib(m["MemTotal"]), kib(m["MemAvailable"]), kib(m["SwapTotal"])
	detail := fmt.Sprintf("total %d MiB, available %d MiB, swap %d MiB", total>>20, avail>>20, swap>>20)
	switch {
	case total < minMemTotalBytes:
		return Result{ID: "memory", Status: Warn, Detail: detail + "; below the 1 GiB minimum"}
	case total < 2<<30 && swap == 0:
		return Result{ID: "memory", Status: Warn, Detail: detail + "; no swap on a small host",
			Fix: "consider zram or a small swap file; qwq does not change it for you"}
	}
	return Result{ID: "memory", Status: OK, Detail: detail}
}

func checkTimeSync(ctx context.Context, env Env) Result {
	out, err := env.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	switch {
	case err != nil:
		return Result{ID: "time", Status: Warn, Detail: "cannot query timedatectl"}
	case out == "yes":
		return Result{ID: "time", Status: OK, Detail: "clock synchronized"}
	default:
		return Result{ID: "time", Status: Warn, Detail: "clock not synchronized",
			Fix: "enable systemd-timesyncd or chrony; TOTP and certificates depend on correct time"}
	}
}

func checkDisk(env Env, dir string) Result {
	free, total, err := env.Statfs(dir)
	if err != nil {
		// The data dir may not exist before installation; check its parent.
		free, total, err = env.Statfs("/")
	}
	if err != nil {
		return Result{ID: "disk", Status: Warn, Detail: "cannot stat " + dir}
	}
	detail := fmt.Sprintf("%s: %d MiB free of %d MiB", dir, free>>20, total>>20)
	if free < minDiskFreeBytes {
		return Result{ID: "disk", Status: Warn, Detail: detail, Fix: "keep at least 1 GiB free for packages, backups and the WAL"}
	}
	return Result{ID: "disk", Status: OK, Detail: detail}
}

// checkCoexistence reports other panels and security tools that manage the
// same things the basic protection plugin would (ADR-0009 rule 8).
func checkCoexistence(env Env) Result {
	var found []string
	probe := map[string]string{
		"/www/server/panel": "BaoTa", "/opt/1panel": "1Panel", "/etc/ufw/ufw.conf": "ufw",
		"/etc/firewalld/firewalld.conf": "firewalld", "/etc/fail2ban/jail.conf": "fail2ban",
	}
	for _, p := range []string{"/www/server/panel", "/opt/1panel", "/etc/ufw/ufw.conf", "/etc/firewalld/firewalld.conf", "/etc/fail2ban/jail.conf"} {
		if _, err := env.Stat(p); err == nil {
			found = append(found, probe[p])
		}
	}
	if len(found) == 0 {
		return Result{ID: "coexistence", Status: OK, Detail: "no other panel or firewall manager found"}
	}
	return Result{ID: "coexistence", Status: Info, Detail: "found: " + strings.Join(found, ", "),
		Fix: "basic protection shows their state read-only until you choose to let qwq manage it (ADR-0009)"}
}

func parseKV(b []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

func parseColon(b []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// kib parses "123456 kB" into bytes.
func kib(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(s), " kB"), 10, 64)
	return n << 10
}

// versionAtLeast compares the leading "major.minor" of a kernel release.
func versionAtLeast(rel, min string) bool {
	parse := func(s string) (int, int, error) {
		parts := strings.SplitN(s, ".", 3)
		if len(parts) < 2 {
			return 0, 0, errors.New("bad version")
		}
		a, err1 := strconv.Atoi(parts[0])
		b, err2 := strconv.Atoi(strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
		return a, b, errors.Join(err1, err2)
	}
	a1, b1, err1 := parse(rel)
	a2, b2, err2 := parse(min)
	if err1 != nil || err2 != nil {
		return false
	}
	return a1 > a2 || (a1 == a2 && b1 >= b2)
}
