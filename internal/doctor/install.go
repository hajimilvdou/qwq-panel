// SPDX-License-Identifier: AGPL-3.0-only

package doctor

// =============================================================================
//  安装后检查（DEP-05）：配置、端口、目录布局、helper、数据库、证书、信任根、
//  内核加固开关与 SELinux。与 Run 一样只读；每个非 ok 结果都给出修复命令。
// =============================================================================

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/config"
)

// ExitCode maps results to the `qwq doctor` exit status: 0 all ok, 1 warnings,
// 3 failures. 2 is reserved for usage errors (install.sh relies on this).
func ExitCode(rs []Result) int {
	switch Worst(rs) {
	case Fail:
		return 3
	case Warn:
		return 1
	}
	return 0
}

// InstallOptions configure InstallChecks. Function fields are optional; a nil
// one skips its check with an info result.
type InstallOptions struct {
	ConfigPath string
	// HelperSocket is the root helper listener. Default /run/qwq/privileged.sock.
	HelperSocket string
	// TrustDir holds the publisher keys. Default /etc/qwq/trust.
	TrustDir string
	// PingHelper connects to the helper and asks for its version.
	PingHelper func(ctx context.Context) error
	// CheckDB runs quick_check and reads the schema version of the database
	// in dataDir. It must not create or migrate anything.
	CheckDB func(ctx context.Context, dataDir string) Result
}

// LayoutEntry is one row of the target directory layout (PRIV batch, ADR-0012).
type LayoutEntry struct {
	Path  string
	Owner string
	Mode  fs.FileMode
}

// Layout returns the directories tmpfiles creates, below dataDir and runDir.
func Layout(dataDir, runDir string) []LayoutEntry {
	return []LayoutEntry{
		{dataDir, "qwq", 0o700},
		{filepath.Join(dataDir, "staging"), "qwq", 0o700},
		{"/var/lib/qwq-plugins", "root", 0o755},
		{"/var/lib/qwq-privileged/creds", "root", 0o700},
		{runDir, "root", 0o711},
		{filepath.Join(runDir, "plugin"), "root", 0o711},
		{filepath.Join(runDir, "link"), "root", 0o711},
		{filepath.Join(runDir, "host"), "qwq", 0o750},
	}
}

// InstallChecks inspects an installed host. The configuration is loaded first;
// when it cannot be loaded the defaults are used for the remaining checks.
func InstallChecks(ctx context.Context, env Env, opts InstallOptions) []Result {
	if opts.HelperSocket == "" {
		opts.HelperSocket = "/run/qwq/privileged.sock"
	}
	if opts.TrustDir == "" {
		opts.TrustDir = "/etc/qwq/trust"
	}
	var rs []Result
	add := func(r Result) { rs = append(rs, r) }

	cfg, r := checkConfig(env, opts.ConfigPath)
	add(r)
	add(CheckPorts(ctx, env, cfg.HTTP.Listen))
	if r.Status == OK {
		// The defaults stand in for a file that did not load; describing their
		// listener would be a guess.
		add(checkListen(cfg.HTTP))
	}
	for _, e := range Layout(cfg.DataDir, cfg.RunDir) {
		add(checkDir(env, e))
	}
	add(checkHelper(ctx, env, opts))
	if opts.CheckDB != nil {
		add(opts.CheckDB(ctx, cfg.DataDir))
	} else {
		add(Result{ID: "database", Status: Info, Detail: "not checked"})
	}
	if cfg.HTTP.TLS.Mode == config.TLSSelfSigned {
		add(checkCertificate(env, filepath.Join(cfg.DataDir, "tls", "self_signed.crt"), time.Now()))
	}
	add(checkTrust(env, opts.TrustDir))
	add(checkHardlinks(env))
	add(checkSELinux(env))
	return rs
}

func checkConfig(env Env, path string) (config.Config, Result) {
	if path == "" {
		path = config.DefaultPath
	}
	b, err := env.ReadFile(path)
	if err != nil {
		return config.Default(), Result{ID: "config", Status: Fail, Detail: path + ": " + errText(err),
			Fix: "install /opt/qwq/current/share/config/qwq.json.example as " + path + " (root:qwq 0640); qwq-controller does not start without it"}
	}
	cfg, err := config.Parse(b)
	if err != nil {
		return config.Default(), Result{ID: "config", Status: Fail, Detail: path + ": " + err.Error(),
			Fix: "fix the file; the variants are documented in /opt/qwq/current/share/config/qwq.json.example.md"}
	}
	return cfg, Result{ID: "config", Status: OK, Detail: path + ": listen " + cfg.HTTP.Listen + ", tls " + cfg.HTTP.TLS.Mode}
}

// wellKnownPorts are listeners worth naming when present: they are what the
// panel would collide with on a typical VPS.
var wellKnownPorts = map[int]string{80: "http", 443: "https", 888: "BaoTa phpMyAdmin", 8888: "BaoTa panel"}

// CheckPorts reports whether the panel's listen port is taken. A port held by
// a running qwq-controller is expected (upgrade, post-install check).
func CheckPorts(ctx context.Context, env Env, listen string) Result {
	_, p, err := net.SplitHostPort(listen)
	port, perr := strconv.Atoi(p)
	if err != nil || perr != nil {
		return Result{ID: "port", Status: Warn, Detail: "cannot parse listen address " + strconv.Quote(listen)}
	}
	ports, err := listeningPorts(env)
	if err != nil {
		return Result{ID: "port", Status: Warn, Detail: "cannot read /proc/net/tcp: " + err.Error()}
	}
	var others []string
	for _, wk := range sortedKeys(wellKnownPorts) {
		if ports[wk] {
			others = append(others, fmt.Sprintf("%d (%s)", wk, wellKnownPorts[wk]))
		}
	}
	suffix := ""
	if len(others) > 0 {
		suffix = "; other listeners: " + strings.Join(others, ", ")
	}
	if !ports[port] {
		return Result{ID: "port", Status: OK, Detail: fmt.Sprintf("listen port %d is free%s", port, suffix)}
	}
	if out, _ := env.Run(ctx, "systemctl", "is-active", "qwq-controller.service"); out == "active" {
		return Result{ID: "port", Status: OK, Detail: fmt.Sprintf("listen port %d is served by qwq-controller%s", port, suffix)}
	}
	fix := fmt.Sprintf("find it with `ss -ltnp 'sport = :%d'` and stop it, or change http.listen in /etc/qwq/qwq.json", port)
	if port == 80 || port == config.ACMEPort {
		// On a shared host these belong to the web server of another panel;
		// stopping it takes the operator's sites down.
		fix = fmt.Sprintf("port %d normally belongs to a web server (BaoTa, nginx): keep it running and put qwq behind it with http.tls.mode %q, "+
			"or move http.listen to a free port with mode %q; see %s", port, config.TLSProxy, config.TLSSelfSigned, config.CoexistenceDoc)
	}
	return Result{ID: "port", Status: Fail, Detail: fmt.Sprintf("listen port %d is already in use by another process%s", port, suffix), Fix: fix}
}

// checkListen says what a listener outside loopback still needs before a
// browser reaches it.
func checkListen(h config.HTTP) Result {
	if h.Loopback() {
		return Result{ID: "listen", Status: OK, Detail: h.Listen + " is loopback only; reach it through an SSH tunnel or a reverse proxy on this host"}
	}
	_, port, _ := net.SplitHostPort(h.Listen)
	return Result{ID: "listen", Status: Info,
		Detail: h.Listen + " listens on all/external interfaces; ensure TCP " + port + " is allowed in the host firewall and cloud security group",
		Fix: fmt.Sprintf("if unreachable externally, allow TCP %s in the host firewall (`ufw allow %s/tcp`, "+
			"`firewall-cmd --permanent --add-port=%s/tcp && firewall-cmd --reload`, or nftables/iptables) and in your cloud provider security group",
			port, port, port)}
}

// listeningPorts parses /proc/net/tcp{,6} for sockets in state LISTEN (0A).
func listeningPorts(env Env) (map[int]bool, error) {
	ports := map[int]bool{}
	var firstErr error
	read := 0
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := env.ReadFile(f)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		read++
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			_, hexPort, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			if n, err := strconv.ParseUint(hexPort, 16, 16); err == nil {
				ports[int(n)] = true
			}
		}
	}
	if read == 0 {
		return nil, firstErr
	}
	return ports, nil
}

func checkDir(env Env, e LayoutEntry) Result {
	id := "dir " + e.Path
	tmpfilesFix := "systemd-tmpfiles --create /usr/lib/tmpfiles.d/qwq.conf"
	fi, err := env.Stat(e.Path)
	if err != nil {
		return Result{ID: id, Status: Fail, Detail: e.Path + ": " + errText(err), Fix: tmpfilesFix}
	}
	want := fmt.Sprintf("%s %#o", e.Owner, e.Mode.Perm())
	fix := fmt.Sprintf("chown %s:%s %s && chmod %#o %s", e.Owner, e.Owner, e.Path, e.Mode.Perm(), e.Path)
	if !fi.IsDir() {
		return Result{ID: id, Status: Fail, Detail: e.Path + " is not a directory", Fix: tmpfilesFix}
	}
	uid, ok := fileUID(fi)
	if !ok || env.LookupUser == nil {
		if fi.Mode().Perm() != e.Mode.Perm() {
			return Result{ID: id, Status: Fail, Detail: fmt.Sprintf("mode %#o, want %#o", fi.Mode().Perm(), e.Mode.Perm()), Fix: fix}
		}
		return Result{ID: id, Status: OK, Detail: fmt.Sprintf("%#o (owner not checked)", fi.Mode().Perm())}
	}
	wantUID, _, err := env.LookupUser(e.Owner)
	if err != nil {
		return Result{ID: id, Status: Fail, Detail: "user " + e.Owner + " does not exist",
			Fix: "systemd-sysusers /usr/lib/sysusers.d/qwq.conf"}
	}
	if uid != wantUID || fi.Mode().Perm() != e.Mode.Perm() {
		return Result{ID: id, Status: Fail,
			Detail: fmt.Sprintf("uid %d mode %#o, want %s", uid, fi.Mode().Perm(), want), Fix: fix}
	}
	return Result{ID: id, Status: OK, Detail: want}
}

func checkHelper(ctx context.Context, env Env, opts InstallOptions) Result {
	fix := "systemctl enable --now qwq-privileged.socket"
	fi, err := env.Stat(opts.HelperSocket)
	if err != nil {
		return Result{ID: "helper", Status: Fail, Detail: opts.HelperSocket + ": " + errText(err), Fix: fix}
	}
	if fi.Mode()&fs.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		return Result{ID: "helper", Status: Fail, Detail: fmt.Sprintf("%s is %s, want a 0660 socket", opts.HelperSocket, fi.Mode()),
			Fix: "systemctl restart qwq-privileged.socket (SocketMode=0660 in the unit)"}
	}
	if gid, ok := fileGID(fi); ok && env.LookupUser != nil {
		if _, want, err := env.LookupUser("qwq"); err == nil && gid != want {
			return Result{ID: "helper", Status: Fail, Detail: fmt.Sprintf("%s group gid %d, want qwq (%d)", opts.HelperSocket, gid, want),
				Fix: "systemctl restart qwq-privileged.socket (SocketGroup=qwq in the unit)"}
		}
	}
	if opts.PingHelper == nil {
		return Result{ID: "helper", Status: OK, Detail: opts.HelperSocket + " root:qwq 0660 (not pinged)"}
	}
	if err := opts.PingHelper(ctx); err != nil {
		return Result{ID: "helper", Status: Fail, Detail: "ping: " + err.Error(),
			Fix: "journalctl -u qwq-privileged.service -n 50; systemctl restart qwq-privileged.socket"}
	}
	return Result{ID: "helper", Status: OK, Detail: opts.HelperSocket + " answers ping"}
}

// certWarnBefore is how early an expiring certificate is reported.
const certWarnBefore = 14 * 24 * time.Hour

func checkCertificate(env Env, path string, now time.Time) Result {
	b, err := env.ReadFile(path)
	if err != nil {
		return Result{ID: "certificate", Status: Info, Detail: path + ": " + errText(err) + " (created on the controller's first start)"}
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return Result{ID: "certificate", Status: Fail, Detail: path + " holds no PEM certificate",
			Fix: "move the file away and restart qwq-controller; it generates a new self-signed certificate"}
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Result{ID: "certificate", Status: Fail, Detail: path + ": " + err.Error(),
			Fix: "move the file away and restart qwq-controller"}
	}
	left := c.NotAfter.Sub(now)
	detail := "self-signed, expires " + c.NotAfter.UTC().Format(time.DateOnly)
	switch {
	case left <= 0:
		return Result{ID: "certificate", Status: Fail, Detail: detail + " (expired)", Fix: "systemctl restart qwq-controller renews it"}
	case left < certWarnBefore:
		return Result{ID: "certificate", Status: Warn, Detail: fmt.Sprintf("%s (%d days left)", detail, int(left.Hours()/24)),
			Fix: "systemctl restart qwq-controller renews it"}
	}
	return Result{ID: "certificate", Status: OK, Detail: detail}
}

func checkTrust(env Env, dir string) Result {
	if env.Glob == nil {
		return Result{ID: "trust", Status: Info, Detail: "not checked"}
	}
	keys, err := env.Glob(filepath.Join(dir, "*.pem"))
	if err != nil || len(keys) == 0 {
		return Result{ID: "trust", Status: Warn, Detail: dir + " has no publisher key; plugin installs and updates are disabled",
			Fix: "copy the publisher public key (PEM) into " + dir + " and restart qwq-controller"}
	}
	return Result{ID: "trust", Status: OK, Detail: fmt.Sprintf("%d publisher key(s)", len(keys))}
}

func checkHardlinks(env Env) Result {
	b, err := env.ReadFile("/proc/sys/fs/protected_hardlinks")
	if err != nil {
		return Result{ID: "protected-hardlinks", Status: Warn, Detail: "cannot read fs.protected_hardlinks"}
	}
	if strings.TrimSpace(string(b)) != "1" {
		return Result{ID: "protected-hardlinks", Status: Fail, Detail: "fs.protected_hardlinks is off",
			Fix: "echo fs.protected_hardlinks=1 > /etc/sysctl.d/90-qwq.conf && sysctl --system"}
	}
	return Result{ID: "protected-hardlinks", Status: OK, Detail: "fs.protected_hardlinks=1"}
}

func checkSELinux(env Env) Result {
	b, err := env.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return Result{ID: "selinux", Status: OK, Detail: "not enabled"}
	}
	if strings.TrimSpace(string(b)) == "1" {
		return Result{ID: "selinux", Status: Warn,
			Detail: "enforcing; qwq ships no SELinux policy and labels nothing bin_t, so systemd may refuse to execute the binaries under /opt/qwq and /var/lib/qwq-plugins (203/EXEC)",
			Fix: "if qwq-controller or a plugin unit fails to start, inspect `ausearch -m avc -ts recent` and `journalctl -u qwq-controller -u 'qwq-plugin@*'`; " +
				"this platform is not verified yet (see the support table in README)"}
	}
	return Result{ID: "selinux", Status: OK, Detail: "permissive"}
}

func fileUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

func fileGID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Gid, true
}

func errText(err error) string {
	if pe, ok := err.(*fs.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}

func sortedKeys(m map[int]string) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
