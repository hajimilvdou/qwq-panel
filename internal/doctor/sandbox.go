// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// DefaultMaxExposure is the `systemd-analyze security` threshold from ADR-0003
// decision 7 and P2-T1 (the template measured 0.6 SAFE; CI fails above 1.0).
const DefaultMaxExposure = 1.0

// SandboxOptions select the paths and the exposure threshold the sandbox
// checks use.
type SandboxOptions struct {
	// UnitDir is where the plugin units are installed. Default
	// /etc/systemd/system.
	UnitDir string
	// RuntimeDir is the plugin runtime directory. Default /run/qwq.
	RuntimeDir string
	// Unit is the unit `systemd-analyze security` scores. Default
	// qwq-plugin@.service.
	Unit string
	// MaxExposure is the largest acceptable exposure level. Zero means
	// DefaultMaxExposure.
	MaxExposure float64
}

func (o SandboxOptions) withDefaults() SandboxOptions {
	if o.UnitDir == "" {
		o.UnitDir = "/etc/systemd/system"
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = "/run/qwq"
	}
	if o.Unit == "" {
		o.Unit = "qwq-plugin@.service"
	}
	if o.MaxExposure <= 0 {
		o.MaxExposure = DefaultMaxExposure
	}
	return o
}

// SandboxChecks probes everything the plugin sandbox depends on: systemd
// version, cgroup v2, seccomp, user namespaces, virtualization, the
// `systemd-analyze security` score, polkit, the runtime directory and the
// installed units. It never changes the system and never starts a plugin.
//
// It is separate from Run so the existing `qwq doctor` output keeps its order
// and meaning; callers that gate plugin installation use this list (and
// SandboxScore) instead.
func SandboxChecks(env Env, opts SandboxOptions) []Result {
	ctx := context.Background()
	o := opts.withDefaults()
	var rs []Result
	add := func(r Result) { rs = append(rs, r) }
	add(sandboxSystemd(ctx, env))
	add(sandboxCgroup(env))
	add(sandboxUserNS(env))
	add(sandboxSeccomp(env))
	virt := checkVirt(ctx, env)
	virt.ID = "sandbox-virt"
	add(virt)
	add(sandboxExposure(ctx, env, o))
	add(sandboxPolkit(ctx, env))
	add(sandboxRuntimeDir(env, o))
	add(sandboxUnits(env, o))
	return rs
}

func sandboxSystemd(ctx context.Context, env Env) Result {
	out, err := env.Run(ctx, "systemctl", "--version")
	m := systemdVersion.FindStringSubmatch(out)
	if err != nil || m == nil {
		return Result{ID: "sandbox-systemd", Status: Fail, Detail: "systemd not found",
			Fix: "the plugin runtime requires systemd (ADR-0003); third-party plugins are refused"}
	}
	v, _ := strconv.Atoi(m[1])
	switch {
	case v >= minSystemd:
		return Result{ID: "sandbox-systemd", Status: OK, Detail: fmt.Sprintf("systemd %d", v)}
	case v >= minSystemdSandbox:
		return Result{ID: "sandbox-systemd", Status: Warn, Detail: fmt.Sprintf("systemd %d is below the target %d", v, minSystemd),
			Fix: "the S2 sandbox works; upgrade the distribution for support"}
	default:
		return Result{ID: "sandbox-systemd", Status: Fail,
			Detail: fmt.Sprintf("systemd %d lacks LoadCredential/ProtectProc (needs %d)", v, minSystemdSandbox),
			Fix:    "third-party plugins are refused; built-in plugins run with a reduced sandbox"}
	}
}

func sandboxCgroup(env Env) Result {
	b, err := env.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return Result{ID: "sandbox-cgroup", Status: Fail, Detail: "cgroup v2 unified hierarchy not mounted (v1 or hybrid)",
			Fix: "boot with systemd.unified_cgroup_hierarchy=1; MemoryMax/TasksMax/CPUQuota for plugins need cgroup v2"}
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
		return Result{ID: "sandbox-cgroup", Status: Warn, Detail: "cgroup v2 without controllers: " + strings.Join(missing, ", "),
			Fix: "the kernel does not provide these controllers; the matching unit limits are ignored"}
	}
	return Result{ID: "sandbox-cgroup", Status: OK, Detail: "cgroup v2 with cpu, memory, pids, io"}
}

func sandboxUserNS(env Env) Result {
	b, err := env.ReadFile("/proc/sys/kernel/unprivileged_userns_clone")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Result{ID: "sandbox-userns", Status: Info, Detail: "no unprivileged_userns_clone knob; the kernel default applies"}
		}
		return Result{ID: "sandbox-userns", Status: Info, Detail: "cannot read /proc/sys/kernel/unprivileged_userns_clone",
			Fix: "check that /proc is mounted; the user namespace state cannot be verified"}
	}
	switch strings.TrimSpace(string(b)) {
	case "1":
		return Result{ID: "sandbox-userns", Status: OK, Detail: "unprivileged user namespaces enabled"}
	case "0":
		return Result{ID: "sandbox-userns", Status: Info, Detail: "unprivileged user namespaces disabled",
			Fix: "the S2 template does not use PrivateUsers, but a capability relaxation that needs user namespaces will fail"}
	default:
		return Result{ID: "sandbox-userns", Status: Warn, Detail: "unexpected unprivileged_userns_clone value " + strconv.Quote(strings.TrimSpace(string(b))),
			Fix: "expected 0 or 1; check the kernel documentation for this host"}
	}
}

func sandboxSeccomp(env Env) Result {
	b, err := env.ReadFile("/proc/self/status")
	if err != nil {
		return Result{ID: "sandbox-seccomp", Status: Warn, Detail: "cannot read /proc/self/status",
			Fix: "check that /proc is mounted; the sandbox cannot be verified"}
	}
	mode, ok := parseColon(b)["Seccomp"]
	if !ok {
		return Result{ID: "sandbox-seccomp", Status: Fail, Detail: "kernel without seccomp",
			Fix: "SystemCallFilter= and SystemCallErrorNumber= will not work; plugins are refused"}
	}
	actions := ""
	if ab, aerr := env.ReadFile("/proc/sys/kernel/seccomp/actions_avail"); aerr == nil {
		actions = strings.Join(strings.Fields(string(ab)), " ")
	}
	detail := "mode " + mode
	if actions != "" {
		detail += "; actions: " + actions
	}
	if actions != "" && !strings.Contains(actions, "errno") {
		return Result{ID: "sandbox-seccomp", Status: Warn, Detail: detail,
			Fix: "SECCOMP_RET_ERRNO is unavailable, so SystemCallErrorNumber=EPERM cannot work"}
	}
	return Result{ID: "sandbox-seccomp", Status: OK, Detail: detail}
}

// exposurePattern matches both the systemd 245 and the systemd 255 wording:
//
//	Overall exposure level for qwq-plugin@alpha.service: 0.6 SAFE :-}
//	Overall exposure level: 1.2
var exposurePattern = regexp.MustCompile(`Overall exposure level[^:\n]*:\s*([0-9]+(?:\.[0-9]+)?)`)

// ParseExposure extracts the score from `systemd-analyze security` output. The
// scale runs from 0 (best) to 10 (worst).
func ParseExposure(out string) (float64, error) {
	m := exposurePattern.FindStringSubmatch(out)
	if m == nil {
		return 0, errors.New(`no "Overall exposure level" line in systemd-analyze security output`)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse exposure level %q: %w", m[1], err)
	}
	if v < 0 || v > 10 {
		return 0, fmt.Errorf("exposure level %.2f is outside 0..10", v)
	}
	return v, nil
}

// SandboxScore runs `systemd-analyze security` for the configured unit and
// applies the exposure threshold, which is what CI and the installer gate on
// (ADR-0003 decision 7). limit <= 0 means opts.MaxExposure or
// DefaultMaxExposure. A missing unit or a missing systemd-analyze is an error,
// not a score of zero.
func SandboxScore(env Env, opts SandboxOptions, limit float64) (score float64, ok bool, err error) {
	o := opts.withDefaults()
	if limit <= 0 {
		limit = o.MaxExposure
	}
	score, err = exposureScore(context.Background(), env, o.Unit)
	if err != nil {
		return 0, false, err
	}
	return score, score <= limit, nil
}

func exposureScore(ctx context.Context, env Env, unit string) (float64, error) {
	out, err := env.Run(ctx, "systemd-analyze", "security", unit)
	if err != nil {
		return 0, fmt.Errorf("systemd-analyze security %s: %w", unit, err)
	}
	return ParseExposure(out)
}

func sandboxExposure(ctx context.Context, env Env, o SandboxOptions) Result {
	score, err := exposureScore(ctx, env, o.Unit)
	if err != nil {
		if _, serr := env.Stat(filepath.Join(o.UnitDir, o.Unit)); serr != nil {
			return Result{ID: "sandbox-exposure", Status: Info,
				Detail: o.Unit + " is not installed, cannot score the sandbox",
				Fix:    "install deployments/systemd/qwq-plugin@.service and run systemctl daemon-reload, then re-run"}
		}
		return Result{ID: "sandbox-exposure", Status: Warn, Detail: "cannot score " + o.Unit + ": " + err.Error(),
			Fix: "install systemd-analyze and make sure the unit loads"}
	}
	detail := fmt.Sprintf("%.1f (limit %.1f)", score, o.MaxExposure)
	if score > o.MaxExposure {
		return Result{ID: "sandbox-exposure", Status: Fail, Detail: detail,
			Fix: "the S2 sandbox regressed; compare the unit with deployments/systemd/qwq-plugin@.service"}
	}
	return Result{ID: "sandbox-exposure", Status: OK, Detail: detail}
}

// SandboxPolkitID is the id of the polkit check. It is exported because the
// check describes the unprivileged controller only: a caller that gates on the
// sandbox results as root must be able to tell it apart.
const SandboxPolkitID = "sandbox-polkit"

// PluginPolkitRulePath 是发布包必须安装的最小插件单元授权规则。
const PluginPolkitRulePath = "/etc/polkit-1/rules.d/60-qwq-plugin.rules"

// CompatPolkitMarkerPath 与 CompatUnitctlSocketUnit 标识旧版 polkit 兼容补丁
// （qwq-compat-polkit，面向 Ubuntu 22.04 / Debian 11 等缺少 polkit >= 0.106 的系统）。
// 原生支持 polkit JS 规则的系统（Debian 12+ / Ubuntu 24.04+）绝不安装此补丁。
const (
	CompatPolkitMarkerPath  = "/etc/qwq/compat/polkit-compat.json"
	CompatUnitctlSocketUnit = "qwq-compat-unitctl.socket"
)

// polkitMissingFix is shared by both shapes of a host without polkit: the unit
// query failing outright and LoadState=not-found.
const polkitMissingFix = "install polkit (`apt install polkitd`) or let `install.sh` apply the qwq-compat-polkit compatibility patch; " +
	"without it the unprivileged agent cannot start, stop or kill plugin units (ADR-0003 decision 1)"

// compatPolkitActive reports whether the optional qwq-compat-polkit patch is
// installed safely and its socket unit is active.
func compatPolkitActive(ctx context.Context, env Env) bool {
	info, err := env.Stat(CompatPolkitMarkerPath)
	if err != nil {
		return false
	}
	if info != nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0) {
		return false
	}
	out, err := env.Run(ctx, "systemctl", "show", "-p", "ActiveState", "-p", "LoadState", CompatUnitctlSocketUnit)
	if err != nil {
		return false
	}
	kv := parseShow(out)
	return kv["LoadState"] == "loaded" && kv["ActiveState"] == "active"
}

// sandboxPolkit reports whether the unprivileged controller can manage plugin
// units through native polkit (>= 0.106) or, on legacy-polkit hosts, through
// the optional qwq-compat-polkit patch. Ubuntu 22.04 and Debian 11 ship
// polkit 0.105 (or no polkitd), which ignores JavaScript rules; without the
// compat patch every plugin start, stop or kill is denied (PRIV-06).
func sandboxPolkit(ctx context.Context, env Env) Result {
	compatOK := func() Result {
		return Result{
			ID:     SandboxPolkitID,
			Status: OK,
			Detail: "polkit compat patch active (qwq-compat-unitctl.socket; scoped to qwq-plugin@*)",
		}
	}
	out, err := env.Run(ctx, "systemctl", "show", "-p", "ActiveState", "-p", "LoadState", "-p", "UnitFileState", "polkit.service")
	kv := parseShow(out)
	if err != nil || kv["LoadState"] == "" {
		if compatPolkitActive(ctx, env) {
			return compatOK()
		}
		if _, serr := env.Stat("/usr/lib/polkit-1/polkitd"); serr == nil {
			return Result{ID: SandboxPolkitID, Status: Fail, Detail: "polkit is installed but systemctl could not query it",
				Fix: "check `systemctl status polkit.service`; the agent cannot start or stop plugin units without it"}
		}
		return Result{ID: SandboxPolkitID, Status: Fail, Detail: "polkit not found", Fix: polkitMissingFix}
	}
	if r, ok := polkitVersionCheck(ctx, env); ok {
		if compatPolkitActive(ctx, env) {
			return compatOK()
		}
		return r
	}
	// ========================================================================
	// daemon 存在不代表插件授权已部署；原安装门禁必须看到缺失或坏规则的 Fail。
	// ========================================================================
	if kv["LoadState"] == "loaded" {
		info, err := env.Stat(PluginPolkitRulePath)
		if err != nil {
			if os.Geteuid() != 0 && errors.Is(err, os.ErrPermission) {
				// On Debian 12 / Rocky 9, /etc/polkit-1/rules.d is 0750 root:polkitd;
				// EACCES for the unprivileged qwq user is expected isolation, not a missing rule.
			} else {
				if compatPolkitActive(ctx, env) {
					return compatOK()
				}
				return Result{ID: SandboxPolkitID, Status: Fail, Detail: "the plugin unit authorization rule is missing or unsafe",
					Fix: "reinstall " + PluginPolkitRulePath + " from deployments/polkit/qwq-plugin.rules as root:root 0644"}
			}
		} else if info != nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0) {
			if compatPolkitActive(ctx, env) {
				return compatOK()
			}
			return Result{ID: SandboxPolkitID, Status: Fail, Detail: "the plugin unit authorization rule is missing or unsafe",
				Fix: "reinstall " + PluginPolkitRulePath + " from deployments/polkit/qwq-plugin.rules as root:root 0644"}
		}
	}
	switch kv["ActiveState"] {
	case "active":
		return Result{ID: SandboxPolkitID, Status: OK, Detail: "polkit active"}
	}
	if kv["LoadState"] == "loaded" {
		return Result{ID: SandboxPolkitID, Status: Info,
			Detail: "polkit is " + kv["ActiveState"] + "; it is D-Bus activated on first use",
			Fix:    "nothing to do unless the agent's systemctl calls fail; then start polkit.service"}
	}
	if compatPolkitActive(ctx, env) {
		return compatOK()
	}
	return Result{ID: SandboxPolkitID, Status: Fail,
		Detail: "polkit.service is not loaded (" + kv["LoadState"] + ")", Fix: polkitMissingFix}
}

// polkitVersionPattern matches `pkaction --version`: "pkaction version 0.105"
// in the pre-1.0 series, "pkaction version 122" in the meson era.
var polkitVersionPattern = regexp.MustCompile(`version\s+(\d+)(?:\.(\d+))?`)

// polkitVersionCheck probes the installed polkit version. ok is false when the
// version cannot be probed or is known to read the JavaScript rules, so the
// caller keeps its own answer instead of guessing.
func polkitVersionCheck(ctx context.Context, env Env) (Result, bool) {
	out, err := env.Run(ctx, "pkaction", "--version")
	if err != nil {
		return Result{}, false
	}
	m := polkitVersionPattern.FindStringSubmatch(out)
	if m == nil {
		return Result{ID: SandboxPolkitID, Status: Fail,
			Detail: "polkit version not understood: " + strconv.Quote(strings.TrimSpace(out)),
			Fix:    `expected "pkaction version <major>[.<minor>]"; if plugin units fail with authentication errors, the rules file may be ignored`}, true
	}
	major, _ := strconv.Atoi(m[1])
	minor := 0
	if m[2] != "" {
		minor, _ = strconv.Atoi(m[2])
	}
	if major > 0 || minor >= 106 {
		return Result{}, false
	}
	return Result{ID: SandboxPolkitID, Status: Fail,
		Detail: fmt.Sprintf("polkit %d.%d reads no JavaScript rules (Ubuntu 22.04 / Debian 11): /etc/polkit-1/rules.d/60-qwq-plugin.rules is ignored and plugin units cannot be started, stopped or killed", major, minor),
		Fix:    "let `install.sh` automatically install the qwq-compat-polkit compatibility patch, or use a platform with polkit >= 0.106 (Debian 12+, Ubuntu 24.04+)"}, true
}

func sandboxRuntimeDir(env Env, o SandboxOptions) Result {
	fi, err := env.Stat(o.RuntimeDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Result{ID: "sandbox-runtime", Status: Warn, Detail: o.RuntimeDir + " does not exist",
				Fix: "install deployments/tmpfiles/qwq.conf and run systemd-tmpfiles --create; the plugin socket directory lives there"}
		}
		return Result{ID: "sandbox-runtime", Status: Warn, Detail: "cannot stat " + o.RuntimeDir,
			Fix: "check that /run is mounted and readable"}
	}
	if fi != nil && !fi.IsDir() {
		return Result{ID: "sandbox-runtime", Status: Warn, Detail: o.RuntimeDir + " is not a directory",
			Fix: "remove the file and let systemd-tmpfiles create the directory"}
	}
	return Result{ID: "sandbox-runtime", Status: OK, Detail: o.RuntimeDir + " exists"}
}

func sandboxUnits(env Env, o SandboxOptions) Result {
	var missing []string
	for _, name := range []string{"qwq-plugin@.service", "qwq-plugin@.socket"} {
		if _, err := env.Stat(filepath.Join(o.UnitDir, name)); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Result{ID: "sandbox-units", Status: Warn, Detail: "missing: " + strings.Join(missing, ", "),
			Fix: "install deployments/systemd/qwq-plugin@.service and qwq-plugin@.socket into " + o.UnitDir + ", then systemctl daemon-reload"}
	}
	return Result{ID: "sandbox-units", Status: OK, Detail: "qwq-plugin@.service and qwq-plugin@.socket installed"}
}

// parseShow parses `systemctl show -p ...` output into a map.
func parseShow(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if ok {
			m[k] = v
		}
	}
	return m
}
