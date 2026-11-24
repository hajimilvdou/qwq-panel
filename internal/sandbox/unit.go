// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bytes"
	_ "embed"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// The packaged templates. TestTemplateMatchesDeployments asserts that these
// embedded copies are byte-identical to deployments/systemd/*, so the file the
// host package installs and the file the renderer rewrites cannot drift.
//
//go:embed templates/qwq-plugin@.service
var serviceTemplate string

//go:embed templates/qwq-plugin@.socket
var socketTemplate string

const (
	// ServiceTemplateName is the packaged service template and the name
	// systemd loads it under.
	ServiceTemplateName = "qwq-plugin@.service"
	// SocketTemplateName is the packaged socket template.
	SocketTemplateName = "qwq-plugin@.socket"

	// DropinName is the resource drop-in below
	// qwq-plugin@<id>.service.d/. It is rendered from the manifest limits on
	// every install and replaces the defaults in the template.
	DropinName = "10-resources.conf"

	// TmpfilesPrefix and TmpfilesSuffix build the per-plugin tmpfiles.d
	// snippet name: /etc/tmpfiles.d/qwq-plugin-<id>.conf.
	TmpfilesPrefix = "qwq-plugin-"
	TmpfilesSuffix = ".conf"

	// DefaultRuntimeBase is systemd's %t for system units. The units are
	// rendered with it expanded, so a different value is only meaningful in
	// tests; production always uses /run.
	DefaultRuntimeBase = "/run"

	// DefaultAgentUser is the unprivileged user that runs the agent and owns
	// the plugin socket (SocketUser=). deployments/tmpfiles/qwq.conf creates
	// /run/qwq for it. ADR-0003 section 5 writes this user as qwq-agent; the
	// helper takes -agent-user so the unit, the socket owner and
	// deployments/polkit/qwq-plugin.rules can be kept in step.
	DefaultAgentUser = "qwq"

	// DefaultCredDir holds the plugin tokens (root 0700, files 0600). It is
	// persistent storage, not /run: LoadCredential= fails the unit when its
	// source is missing, and the token is only written at install time
	// (PRIV-05, ADR-0013).
	DefaultCredDir = "/var/lib/qwq-privileged/creds"

	// DefaultPluginDataRoot 是可由动态 UID 遍历的专用数据根。宿主数据库仍位于
	// qwq 私有的 0700 目录；helper 只接受本插件在该根下的 default 目录。
	DefaultPluginDataRoot = "/var/lib/qwq-plugin-data"

	// DefaultHostBinary is the installed host binary. The digest check in
	// ExecStartPre calls `qwq privileged verify-entrypoint`, which is only
	// wired up by cmd/qwq.
	DefaultHostBinary = "/opt/qwq/current/bin/qwq"

	// MaxIDLen is the longest plugin id the sandbox accepts.
	//
	// The manifest schema allows 128 characters, but the id is also the
	// systemd instance name and the suffix of the per-plugin group name
	// (qwq-p-<id>). groupadd and the shadow tools cap group names at 32
	// characters, so ids are limited to 26 here and rejected with a clear
	// error instead of failing later in groupadd.
	MaxIDLen = 26

	// runtimeDirName is the qwq directory below the runtime base.
	runtimeDirName = "qwq"

	// maxValueLen bounds every string that is written into a unit file.
	maxValueLen = 512
)

// Directory and file names below the runtime base.
const (
	pluginDirName = "plugin"
	hostDirName   = "host"
	linkDirName   = "link"
	socketName    = "plugin.sock"
	hostSockName  = "host.sock"
)

// idPattern is the manifest plugin_id grammar. Ids such as security.scan are
// valid; the length cap is applied separately by ValidateID.
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`)

// entrypointPattern is the manifest entrypoint grammar: exactly one "bin/"
// component and no nested directories.
var entrypointPattern = regexp.MustCompile(`^bin/[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

// digestPattern is the manifest file digest form.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// leftoverSpecifierPattern matches a systemd specifier that survived
// rendering. A lone percent (CPUQuota=100%) is not a specifier.
var leftoverSpecifierPattern = regexp.MustCompile(`%[A-Za-z%]`)

// userPattern is a conservative Linux user name.
var userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// groupPattern is a conservative Linux group name.
var groupPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// ValidateID checks a plugin id against the manifest grammar and the sandbox
// length limit (MaxIDLen).
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("sandbox: plugin id is empty")
	}
	if len(id) > MaxIDLen {
		return fmt.Errorf("sandbox: plugin id %q is %d characters, the sandbox limit is %d because the id becomes the group name qwq-p-<id>", id, len(id), MaxIDLen)
	}
	if !idPattern.MatchString(id) {
		return fmt.Errorf("sandbox: plugin id %q does not match %s", id, idPattern)
	}
	return nil
}

// UnitNames returns the concrete service and socket unit names for id.
func UnitNames(id string) (service, socket string, err error) {
	if err := ValidateID(id); err != nil {
		return "", "", err
	}
	return "qwq-plugin@" + id + ".service", "qwq-plugin@" + id + ".socket", nil
}

// GroupName returns the per-plugin private group, qwq-p-<id>.
func GroupName(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	return "qwq-p-" + id, nil
}

// TmpfilesName returns the per-plugin tmpfiles.d snippet name.
func TmpfilesName(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	return TmpfilesPrefix + id + TmpfilesSuffix, nil
}

// Paths is the runtime layout of one plugin. Every path below is derived from
// the runtime base and the validated id, so the helper, the agent and the
// units agree on one spelling.
type Paths struct {
	// Runtime is <base>/qwq.
	Runtime string
	// PluginRoot is <runtime>/plugin (root 0711).
	PluginRoot string
	// PluginDir is <runtime>/plugin/<id> (root 0711).
	PluginDir string
	// Socket is the listener systemd creates:
	// <runtime>/plugin/<id>/plugin.sock.
	Socket string
	// HostDir is <runtime>/host/<id>, owned by the agent and the plugin
	// group (2750).
	HostDir string
	// HostSocket is <runtime>/host/<id>/host.sock (0660).
	HostSocket string
	// Link is <runtime>/link, the bind target inside the plugin's mount
	// namespace (root 0711).
	Link string
	// CredDir is DefaultCredDir (root 0700); it is not below the runtime
	// base.
	CredDir string
	// Token is <CredDir>/<id>.token (root 0600).
	Token string
}

// PathsFor derives the layout for id below runtimeBase.
func PathsFor(runtimeBase, id string) (Paths, error) {
	base, err := checkDirPath("runtime base", runtimeBase)
	if err != nil {
		return Paths{}, err
	}
	if err := ValidateID(id); err != nil {
		return Paths{}, err
	}
	runtime := filepath.Join(base, runtimeDirName)
	pluginDir := filepath.Join(runtime, pluginDirName, id)
	hostDir := filepath.Join(runtime, hostDirName, id)
	credDir := DefaultCredDir
	return Paths{
		Runtime:    runtime,
		PluginRoot: filepath.Join(runtime, pluginDirName),
		PluginDir:  pluginDir,
		Socket:     filepath.Join(pluginDir, socketName),
		HostDir:    hostDir,
		HostSocket: filepath.Join(hostDir, hostSockName),
		Link:       filepath.Join(runtime, linkDirName),
		CredDir:    credDir,
		Token:      filepath.Join(credDir, id+".token"),
	}, nil
}

// Limits are the per-plugin resource limits rendered into the drop-in. They
// come from manifest.resources and are bounded by the manifest schema.
type Limits struct {
	MemoryMaxMB     int64 `json:"memory_max_mb"`
	CPUQuotaPercent int64 `json:"cpu_quota_percent"`
	PIDsMax         int64 `json:"pids_max"`
	FDsMax          int64 `json:"fds_max"`
}

// Limits bounds, taken from api/manifest/v1/manifest.schema.json.
const (
	MinMemoryMaxMB     = 16
	MaxMemoryMaxMB     = 65536
	MinCPUQuotaPercent = 1
	MaxCPUQuotaPercent = 100000
	MinPIDsMax         = 1
	MaxPIDsMax         = 4096
	MinFDsMax          = 16
	MaxFDsMax          = 65536
)

// DefaultLimits are the spike-verified defaults (P2-T1 section 9): 48 MiB of
// memory, one core, 32 tasks and 256 file descriptors.
func DefaultLimits() Limits {
	return Limits{MemoryMaxMB: 48, CPUQuotaPercent: 100, PIDsMax: 32, FDsMax: 256}
}

// withDefaults replaces zero fields with DefaultLimits so that omitting the
// limits in a spec yields the template defaults rather than an invalid zero.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MemoryMaxMB == 0 {
		l.MemoryMaxMB = d.MemoryMaxMB
	}
	if l.CPUQuotaPercent == 0 {
		l.CPUQuotaPercent = d.CPUQuotaPercent
	}
	if l.PIDsMax == 0 {
		l.PIDsMax = d.PIDsMax
	}
	if l.FDsMax == 0 {
		l.FDsMax = d.FDsMax
	}
	return l
}

// Validate checks the manifest bounds.
func (l Limits) Validate() error {
	switch {
	case l.MemoryMaxMB < MinMemoryMaxMB || l.MemoryMaxMB > MaxMemoryMaxMB:
		return fmt.Errorf("sandbox: memory_max_mb %d is outside %d..%d", l.MemoryMaxMB, MinMemoryMaxMB, MaxMemoryMaxMB)
	case l.CPUQuotaPercent < MinCPUQuotaPercent || l.CPUQuotaPercent > MaxCPUQuotaPercent:
		return fmt.Errorf("sandbox: cpu_quota_percent %d is outside %d..%d", l.CPUQuotaPercent, MinCPUQuotaPercent, MaxCPUQuotaPercent)
	case l.PIDsMax < MinPIDsMax || l.PIDsMax > MaxPIDsMax:
		return fmt.Errorf("sandbox: pids_max %d is outside %d..%d", l.PIDsMax, MinPIDsMax, MaxPIDsMax)
	case l.FDsMax < MinFDsMax || l.FDsMax > MaxFDsMax:
		return fmt.Errorf("sandbox: fds_max %d is outside %d..%d", l.FDsMax, MinFDsMax, MaxFDsMax)
	}
	return nil
}

// MemoryHighMB is memory.high: 0.9 x MemoryMax (ARCH section 13 asks for
// throttling before the OOM killer).
func (l Limits) MemoryHighMB() int64 {
	if v := l.MemoryMaxMB * 9 / 10; v > 0 {
		return v
	}
	return 1
}

// GOMEMLIMITMiB is the Go runtime soft limit: 0.85 x MemoryMax. The Go runtime
// does not read cgroup limits, so the unit has to tell it.
func (l Limits) GOMEMLIMITMiB() int64 {
	if v := l.MemoryMaxMB * 85 / 100; v > 0 {
		return v
	}
	return 1
}

// UnitSpec is one plugin's rendered systemd configuration. The agent builds it
// from the manifest it already verified (sdk/manifest, internal/pluginhost/
// install) and hands it to the privileged helper.
type UnitSpec struct {
	// ID is the manifest plugin id.
	ID string `json:"id"`
	// VersionDir is the absolute path of the installed, immutable version
	// directory: <plugins_root>/<id>/<version>.
	VersionDir string `json:"version_dir"`
	// Entrypoint is the manifest entrypoint, a clean relative path under
	// bin/.
	Entrypoint string `json:"entrypoint"`
	// Digest is the manifest digest of the entrypoint, "sha256:<hex>".
	Digest string `json:"digest"`
	// Executable is the absolute path of the entrypoint. It may be left
	// empty; when set it must equal <VersionDir>/<Entrypoint>.
	Executable string `json:"executable,omitempty"`
	// RuntimeBase is systemd's %t. Empty means DefaultRuntimeBase.
	RuntimeBase string `json:"runtime_base,omitempty"`
	// AgentUser owns the plugin socket. Empty means DefaultAgentUser.
	AgentUser string `json:"agent_user,omitempty"`
	// Limits are the manifest resources. Nil means DefaultLimits.
	Limits *Limits `json:"limits,omitempty"`
	// NetworkProxyDirect is the host-computed policy for the exact capability
	// (network.proxy, direct): it relaxes PrivateNetwork and the address-family
	// allowlist so a proxy data plane can use the host network namespace. The
	// host sets it from the verified manifest (controller.unitSpecFor); a plugin
	// cannot request a systemd directive. Zero keeps the default deny.
	NetworkProxyDirect bool `json:"network_proxy_direct,omitempty"`
	// Relaxations carries host-derived minimal sandbox relaxations (host network
	// for network.egress / network.listen / network.proxy:direct, and
	// CAP_NET_BIND_SERVICE for ingress/proxy low ports). Zero keeps default deny.
	Relaxations SandboxRelaxations `json:"relaxations,omitzero"`
	// DataDir is the host-derived absolute per-instance data directory, e.g.
	// /var/lib/qwq-plugin-data/<id>/default. Empty means the plugin needs no
	// persistent directory (noop) and the unit keeps its original behaviour.
	// When set it must be a clean path below /var/lib; the renderer turns it
	// into a controlled StateDirectory= that systemd assigns to the dynamic UID.
	// The host computes it; a plugin cannot choose a system path.
	DataDir string `json:"data_dir,omitempty"`
	// Startup and Background mirror manifest.lifecycle so on-demand foreground
	// plugins receive QWQ_PLUGIN_IDLE_TTL=180s in their resource drop-in for
	// scale-to-zero hibernation.
	Startup    string `json:"startup,omitempty"`
	Background bool   `json:"background,omitempty"`
	// PublicStream is derived by the host when the verified manifest declares
	// public.route capabilities. It grants a plugin-writable systemd
	// RuntimeDirectory=qwq-plugin-stream-<id> and QWQ_PUBLIC_STREAM_SOCKET so
	// streaming plugins (e.g. ai.relay) can serve zero-buffered SSE over UDS
	// while SO_PEERCRED restricts peers to the host agent UID.
	PublicStream bool `json:"public_stream,omitempty"`
}

// prepared is a validated UnitSpec with defaults applied and derived values
// filled in. It is the only input the renderer sees.
type prepared struct {
	id                 string
	runtimeBase        string
	agentUser          string
	versionDir         string
	entrypoint         string
	digest             string
	executable         string
	limits             Limits
	paths              Paths
	group              string
	service            string
	socket             string
	networkProxyDirect bool
	relaxations        SandboxRelaxations
	stateDirectory     string
	startup            string
	background         bool
	publicStream       bool
}

func (s UnitSpec) prepare() (prepared, error) {
	var p prepared
	if err := ValidateID(s.ID); err != nil {
		return p, err
	}
	p.id = s.ID

	base := s.RuntimeBase
	if base == "" {
		base = DefaultRuntimeBase
	}
	if _, err := checkDirPath("runtime base", base); err != nil {
		return p, err
	}
	p.runtimeBase = base

	user := s.AgentUser
	if user == "" {
		user = DefaultAgentUser
	}
	if !userPattern.MatchString(user) {
		return p, fmt.Errorf("sandbox: agent user %q is not a valid user name", user)
	}
	p.agentUser = user

	versionDir, err := checkDirPath("version dir", s.VersionDir)
	if err != nil {
		return p, err
	}
	p.versionDir = versionDir

	if !entrypointPattern.MatchString(s.Entrypoint) {
		return p, fmt.Errorf("sandbox: entrypoint %q must match %s", s.Entrypoint, entrypointPattern)
	}
	p.entrypoint = s.Entrypoint

	if !digestPattern.MatchString(s.Digest) {
		return p, fmt.Errorf("sandbox: digest %q must be \"sha256:\" plus 64 lower-case hex digits", s.Digest)
	}
	p.digest = s.Digest

	want := filepath.Join(versionDir, s.Entrypoint)
	executable := s.Executable
	if executable == "" {
		executable = want
	}
	if executable != want {
		return p, fmt.Errorf("sandbox: executable %q does not match version dir + entrypoint (%q)", executable, want)
	}
	if _, err := checkDirPath("executable", executable); err != nil {
		return p, err
	}
	p.executable = executable

	p.limits = DefaultLimits()
	if s.Limits != nil {
		p.limits = *s.Limits
	}
	p.limits = p.limits.withDefaults()
	if err := p.limits.Validate(); err != nil {
		return p, err
	}

	paths, err := PathsFor(base, s.ID)
	if err != nil {
		return p, err
	}
	p.paths = paths

	group, err := GroupName(s.ID)
	if err != nil {
		return p, err
	}
	p.group = group

	service, socket, err := UnitNames(s.ID)
	if err != nil {
		return p, err
	}
	p.service, p.socket = service, socket
	p.networkProxyDirect = s.NetworkProxyDirect
	p.relaxations = s.Relaxations
	if s.NetworkProxyDirect {
		p.relaxations.HostNetwork = true
	}
	if s.DataDir != "" {
		dir, err := checkDirPath("data dir", s.DataDir)
		if err != nil {
			return p, err
		}
		if dir != filepath.Join(DefaultPluginDataRoot, s.ID, "default") {
			return p, fmt.Errorf("sandbox: data dir must be the current plugin's dedicated state directory")
		}
		// StateDirectory= is relative to /var/lib; only a clean path below it
		// can be rendered. The host derives the exact path, so anything outside
		// this root (or a traversal) is a programming error, not plugin input.
		const stateRoot = "/var/lib/"
		if !strings.HasPrefix(dir, stateRoot) {
			return p, fmt.Errorf("sandbox: data dir %q must be below /var/lib", dir)
		}
		rel := strings.TrimPrefix(dir, stateRoot)
		if rel == "" || filepath.Clean(rel) != rel {
			return p, fmt.Errorf("sandbox: data dir %q has an unsafe state directory", dir)
		}
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			if part == "" || part == "." || part == ".." {
				return p, fmt.Errorf("sandbox: data dir %q has an unsafe state directory", dir)
			}
		}
		p.stateDirectory = rel
	}
	p.startup = strings.TrimSpace(s.Startup)
	p.background = s.Background
	p.publicStream = s.PublicStream
	return p, nil
}

// RenderUnit renders the concrete systemd files for one plugin. The returned
// map is keyed by destination path relative to the systemd unit directory:
//
//	qwq-plugin@<id>.service
//	qwq-plugin@<id>.socket
//	qwq-plugin@<id>.service.d/10-resources.conf
//
// The resource drop-in is always present so that `systemctl cat` shows the
// effective limits and a missing manifest value cannot silently keep a stale
// one. RenderUnit is pure: it never touches the filesystem.
func RenderUnit(spec UnitSpec) (map[string][]byte, error) {
	p, err := spec.prepare()
	if err != nil {
		return nil, err
	}
	service, err := renderService(p)
	if err != nil {
		return nil, err
	}
	socket, err := renderSocket(p)
	if err != nil {
		return nil, err
	}
	dropin, err := RenderResources(p.limits)
	if err != nil {
		return nil, err
	}
	if p.startup == "on_demand" && !p.background {
		dropin = append(dropin, []byte("Environment=QWQ_PLUGIN_IDLE_TTL=180s\n")...)
	}
	files := map[string][]byte{
		p.service:                      service,
		p.socket:                       socket,
		p.service + ".d/" + DropinName: dropin,
	}
	for name := range files {
		if path.IsAbs(name) || path.Clean(name) != name {
			return nil, fmt.Errorf("sandbox: rendered file name %q is not a clean relative path", name)
		}
		if name == ".." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("sandbox: rendered file name %q escapes the unit directory", name)
		}
	}
	return files, nil
}

// RenderResources renders the resource drop-in for limits. It is exported so
// tooling can show the effective values without rendering the units, and so
// the CI golden test can pin the 0.9 / 0.85 derivation.
func RenderResources(limits Limits) ([]byte, error) {
	l := limits.withDefaults()
	if err := l.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("# SPDX-License-Identifier: AGPL-3.0-only\n")
	b.WriteString("#\n")
	b.WriteString("# qwq resource limits, rendered by `qwq privileged install` from the verified\n")
	b.WriteString("# manifest. Do not edit: the next install replaces this file. MemoryHigh is\n")
	b.WriteString("# 0.9 x MemoryMax and GOMEMLIMIT is 0.85 x MemoryMax (ARCH section 13).\n")
	b.WriteString("\n[Service]\n")
	fmt.Fprintf(&b, "MemoryMax=%dM\n", l.MemoryMaxMB)
	fmt.Fprintf(&b, "MemoryHigh=%dM\n", l.MemoryHighMB())
	fmt.Fprintf(&b, "CPUQuota=%d%%\n", l.CPUQuotaPercent)
	fmt.Fprintf(&b, "TasksMax=%d\n", l.PIDsMax)
	fmt.Fprintf(&b, "LimitNOFILE=%d\n", l.FDsMax)
	fmt.Fprintf(&b, "Environment=GOMEMLIMIT=%dMiB\n", l.GOMEMLIMITMiB())
	return b.Bytes(), nil
}

// RenderTmpfiles renders the per-plugin tmpfiles.d snippet that recreates the
// runtime directories after a reboot. /run is a tmpfs, and the socket unit
// cannot create the directory it listens on, so these entries are what make
// `systemctl start qwq-plugin@<id>.socket` work on a freshly booted host.
//
// RuntimeDirectory= would create them too, but it applies its mode and
// ownership to every path component, including the shared root-owned /run/qwq
// (ADR-0012).
func RenderTmpfiles(spec UnitSpec) ([]byte, error) {
	p, err := spec.prepare()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("# SPDX-License-Identifier: AGPL-3.0-only\n")
	b.WriteString("#\n")
	b.WriteString("# qwq plugin " + p.id + " runtime directories, rendered by\n")
	b.WriteString("# `qwq privileged install`. Removed on uninstall. systemd-tmpfiles runs\n")
	b.WriteString("# before sockets.target, so the listener directory exists after a reboot.\n")
	b.WriteString("#\n")
	b.WriteString("# type path mode user group age\n")
	fmt.Fprintf(&b, "d %s 0711 root root -\n", p.paths.PluginRoot)
	fmt.Fprintf(&b, "d %s 0711 root root -\n", p.paths.PluginDir)
	fmt.Fprintf(&b, "d %s 0711 root root -\n", p.paths.Link)
	// The host channel directory: agent-writable, plugin-group traversable,
	// setgid so host.sock inherits the plugin group (PRIV-04).
	fmt.Fprintf(&b, "d %s 2750 %s %s -\n", p.paths.HostDir, p.agentUser, p.group)
	return b.Bytes(), nil
}

// renderService expands the service template for p. The template keeps the
// sandbox and the resource defaults; the two command lines and the specifiers
// are the only parts that differ per plugin.
func renderService(p prepared) ([]byte, error) {
	out, err := expandTemplate(ServiceTemplateName, serviceTemplate, p)
	if err != nil {
		return nil, err
	}
	startPre := fmt.Sprintf("%s privileged verify-entrypoint -dir %s -entrypoint %s -digest %s",
		DefaultHostBinary, p.versionDir, p.entrypoint, p.digest)
	if out, err = replaceLine(out, "ExecStartPre=+", "ExecStartPre=+"+startPre); err != nil {
		return nil, err
	}
	if out, err = replaceLine(out, "ExecStart=", "ExecStart="+p.executable); err != nil {
		return nil, err
	}
	if p.relaxations.HostNetwork || p.relaxations.BindPrivilegedPorts {
		if out, err = ApplySandboxRelaxations(out, p.relaxations); err != nil {
			return nil, err
		}
	}
	var extraDirectives []string
	if p.stateDirectory != "" {
		// systemd creates the directory below /var/lib and assigns it to the
		// unit's dynamic UID; ProtectSystem=strict keeps everything else read
		// only. The relative path was validated in prepare; no plugin text
		// reaches this directive.
		extraDirectives = append(extraDirectives,
			"StateDirectory="+p.stateDirectory,
			"StateDirectoryMode=0700",
		)
	}
	if p.publicStream {
		dirName := "qwq-plugin-stream-" + p.id
		sockPath := path.Join(filepath.ToSlash(p.runtimeBase), dirName, "public-stream.sock")
		extraDirectives = append(extraDirectives,
			"RuntimeDirectory="+dirName,
			"RuntimeDirectoryMode=0755",
			"Environment=QWQ_PUBLIC_STREAM_SOCKET="+sockPath,
		)
	}
	if len(extraDirectives) > 0 {
		repl := "ProtectSystem=strict\n" + strings.Join(extraDirectives, "\n")
		if out, err = replaceLine(out, "ProtectSystem=strict", repl); err != nil {
			return nil, err
		}
	}
	return []byte(out), nil
}

// renderSocket expands the socket template for p. The listener path and the
// unit it triggers follow from the id; the socket owner is the agent user.
func renderSocket(p prepared) ([]byte, error) {
	out, err := expandTemplate(SocketTemplateName, socketTemplate, p)
	if err != nil {
		return nil, err
	}
	const want = "SocketUser=" + DefaultAgentUser
	if !strings.Contains(out, want) {
		return nil, fmt.Errorf("sandbox: template %s has no %q line", SocketTemplateName, want)
	}
	if p.agentUser != DefaultAgentUser {
		out = strings.ReplaceAll(out, want, "SocketUser="+p.agentUser)
	}
	return []byte(out), nil
}

// expandTemplate substitutes the systemd specifiers the templates use and
// refuses to emit anything that still contains one: a leftover specifier would
// be expanded by systemd to a value the script never validated.
//
// A literal percent that is not a specifier (CPUQuota=100%) is left alone.
func expandTemplate(name, text string, p prepared) (string, error) {
	if text == "" {
		return "", fmt.Errorf("sandbox: template %s is empty", name)
	}
	out := strings.NewReplacer("%i", p.id, "%t", p.runtimeBase).Replace(text)
	if loc := leftoverSpecifierPattern.FindString(out); loc != "" {
		return "", fmt.Errorf("sandbox: template %s still contains the specifier %q", name, loc)
	}
	return out, nil
}

// replaceLine replaces the single line of text that starts with prefix. Zero
// or several matches mean the template changed under the renderer, which is a
// programming error, not input from a plugin.
func replaceLine(text, prefix, replacement string) (string, error) {
	lines := strings.Split(text, "\n")
	found := 0
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[i] = replacement
			found++
		}
	}
	if found != 1 {
		return "", fmt.Errorf("sandbox: template line %q matched %d times, want 1", prefix, found)
	}
	return strings.Join(lines, "\n"), nil
}

// checkText rejects values that could break out of a unit file line or smuggle
// a second directive. The renderer never quotes, so anything that systemd
// treats as syntax is refused instead of escaped.
func checkText(field, s string) error {
	if s == "" {
		return fmt.Errorf("sandbox: %s is empty", field)
	}
	if len(s) > maxValueLen {
		return fmt.Errorf("sandbox: %s is %d bytes, the limit is %d", field, len(s), maxValueLen)
	}
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("sandbox: %s contains a control character", field)
		case unicode.IsSpace(r):
			return fmt.Errorf("sandbox: %s contains whitespace", field)
		case r == '%':
			return fmt.Errorf("sandbox: %s contains a systemd specifier character (%%): %q", field, s)
		case r == '\\' || r == '"' || r == '\'':
			return fmt.Errorf("sandbox: %s contains a quote or backslash: %q", field, s)
		}
	}
	return nil
}

// checkDirPath validates an absolute, clean, single-line path.
func checkDirPath(field, p string) (string, error) {
	if err := checkText(field, p); err != nil {
		return "", err
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("sandbox: %s %q is not absolute", field, p)
	}
	if filepath.Clean(p) != p {
		return "", fmt.Errorf("sandbox: %s %q is not a clean path", field, p)
	}
	if p == string(filepath.Separator) {
		return "", fmt.Errorf("sandbox: %s must not be the root directory", field)
	}
	return p, nil
}
