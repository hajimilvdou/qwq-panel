// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata golden files")

// alphaSpec is the reference spec used by the golden files. The limits mirror
// api/manifest/v1/examples/security.scan.manifest.json (32 MiB, 20% CPU, 16
// tasks, 128 file descriptors) so the golden files show a realistic drop-in.
func alphaSpec() UnitSpec {
	return UnitSpec{
		ID:         "alpha",
		VersionDir: "/var/lib/qwq-plugins/alpha/1.2.3",
		Entrypoint: "bin/plugin",
		Digest:     "sha256:" + strings.Repeat("a", 64),
		Limits:     &Limits{MemoryMaxMB: 32, CPUQuotaPercent: 20, PIDsMax: 16, FDsMax: 128},
	}
}

// TestTemplateMatchesDeployments fails when the embedded templates and the
// files the host package installs drift. Deployments are the contract; the
// embedded copy only exists because go:embed cannot reach outside the package.
func TestTemplateMatchesDeployments(t *testing.T) {
	for name, embedded := range map[string]string{
		ServiceTemplateName: serviceTemplate,
		SocketTemplateName:  socketTemplate,
	} {
		path := filepath.Join("..", "..", "deployments", "systemd", name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(b) != embedded {
			t.Fatalf("%s differs from deployments/systemd/%s; copy the deployment file into internal/sandbox/templates", name, name)
		}
	}
}

// TestServiceTemplateDirectives pins the sandbox: a directive may only disappear
// together with this test, so a regression is visible in review.
func TestServiceTemplateDirectives(t *testing.T) {
	required := []string{
		// Unit wiring and lifecycle.
		"Requires=qwq-plugin@%i.socket",
		"After=qwq-plugin@%i.socket",
		"Type=exec",
		"DynamicUser=yes",
		"SupplementaryGroups=qwq-p-%i",
		"Restart=on-failure",
		"KillMode=control-group",
		// Credential and host channel.
		"LoadCredential=qwq-token:/var/lib/qwq-privileged/creds/%i.token",
		"BindPaths=%t/qwq/host/%i:%t/qwq/link",
		"ExecStartPre=+/opt/qwq/current/bin/qwq privileged verify-entrypoint",
		// Resource defaults (overridden by the drop-in).
		"MemoryMax=48M",
		"MemoryHigh=43M",
		"CPUQuota=100%",
		"TasksMax=32",
		"LimitNOFILE=256",
		"OOMScoreAdjust=500",
		"Environment=GOMEMLIMIT=40MiB",
		// The S2 sandbox template.
		"PrivateNetwork=yes",
		"RestrictAddressFamilies=AF_UNIX",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"DevicePolicy=closed",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectKernelLogs=yes",
		"ProtectControlGroups=yes",
		"ProtectClock=yes",
		"ProtectHostname=yes",
		"ProtectProc=invisible",
		"ProcSubset=pid",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"LockPersonality=yes",
		"MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native",
		"SystemCallFilter=@system-service",
		"SystemCallFilter=~@privileged @resources",
		"SystemCallErrorNumber=EPERM",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"KeyringMode=private",
		"UMask=0077",
	}
	for _, want := range required {
		if !strings.Contains(serviceTemplate, want+"\n") {
			t.Errorf("service template is missing %q", want)
		}
	}
}

func TestSocketTemplateDirectives(t *testing.T) {
	required := []string{
		"ListenStream=%t/qwq/plugin/%i/plugin.sock",
		"SocketUser=qwq",
		"SocketMode=0600",
		"Service=qwq-plugin@%i.service",
		"RemoveOnStop=yes",
	}
	for _, want := range required {
		if !strings.Contains(socketTemplate, want+"\n") {
			t.Errorf("socket template is missing %q", want)
		}
	}
}

// TestTemplatesStyle enforces the two unit-file rules that are easy to break in
// review: comments must be on their own line, and no line may carry trailing
// whitespace or a stray CR.
func TestTemplatesStyle(t *testing.T) {
	for name, text := range map[string]string{
		ServiceTemplateName: serviceTemplate,
		SocketTemplateName:  socketTemplate,
	} {
		if !strings.HasSuffix(text, "\n") || strings.HasSuffix(text, "\n\n") {
			t.Errorf("%s must end with exactly one newline", name)
		}
		for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			if strings.ContainsRune(line, '\r') {
				t.Errorf("%s:%d has a CR", name, i+1)
			}
			if strings.TrimRight(line, " \t") != line {
				t.Errorf("%s:%d has trailing whitespace", name, i+1)
			}
			if strings.Contains(line, " #") || strings.Contains(line, " ;") {
				t.Errorf("%s:%d has an inline comment; systemd unit comments must be on their own line", name, i+1)
			}
		}
	}
}

func TestRenderUnitGolden(t *testing.T) {
	files, err := RenderUnit(alphaSpec())
	if err != nil {
		t.Fatalf("RenderUnit: %v", err)
	}
	cases := map[string]string{
		"qwq-plugin@alpha.service":                     "testdata/alpha.service",
		"qwq-plugin@alpha.socket":                      "testdata/alpha.socket",
		"qwq-plugin@alpha.service.d/10-resources.conf": "testdata/alpha.resources.conf",
	}
	if len(files) != len(cases) {
		t.Fatalf("RenderUnit returned %d files, want %d", len(files), len(cases))
	}
	for name, golden := range cases {
		got, ok := files[name]
		if !ok {
			t.Fatalf("RenderUnit did not return %s", name)
		}
		if *updateGolden {
			if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
				t.Fatalf("create %s: %v", filepath.Dir(golden), err)
			}
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatalf("update %s: %v", golden, err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("read %s: %v (run `go test -run TestRenderUnitGolden -update`)", golden, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s does not match %s:\n--- got ---\n%s\n--- want ---\n%s", name, golden, got, want)
		}
	}
}

// TestRenderUnitExpansion checks the parts of the rendered unit the golden
// files only show indirectly: specifiers are gone, the digest check carries
// the manifest values, and the socket owner follows the agent user.
func TestRenderUnitExpansion(t *testing.T) {
	spec := alphaSpec()
	spec.AgentUser = "qwq-agent"
	spec.RuntimeBase = "/run"
	files, err := RenderUnit(spec)
	if err != nil {
		t.Fatalf("RenderUnit: %v", err)
	}
	service := string(files["qwq-plugin@alpha.service"])
	for _, want := range []string{
		"Description=qwq plugin alpha\n",
		"Requires=qwq-plugin@alpha.socket\n",
		"SupplementaryGroups=qwq-p-alpha\n",
		"LoadCredential=qwq-token:/var/lib/qwq-privileged/creds/alpha.token\n",
		"BindPaths=/run/qwq/host/alpha:/run/qwq/link\n",
		"Environment=QWQ_PLUGIN_ID=alpha\n",
		"Environment=QWQ_PLUGIN_SOCKET=/run/qwq/plugin/alpha/plugin.sock\n",
		"Environment=QWQ_HOST_SOCKET=/run/qwq/link/host.sock\n",
		"ExecStartPre=+/opt/qwq/current/bin/qwq privileged verify-entrypoint -dir /var/lib/qwq-plugins/alpha/1.2.3 -entrypoint bin/plugin -digest sha256:" + strings.Repeat("a", 64) + "\n",
		"ExecStart=/var/lib/qwq-plugins/alpha/1.2.3/bin/plugin\n",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("service unit is missing %q", want)
		}
	}
	if leftoverSpecifierPattern.MatchString(service) {
		t.Errorf("service unit still contains a specifier:\n%s", service)
	}
	if !strings.Contains(service, "CPUQuota=100%\n") {
		t.Errorf("service unit lost its literal percent:\n%s", service)
	}
	if strings.Contains(service, "@EXEC") || strings.Contains(service, "/opt/qwq/current/libexec/qwq-plugin\n") {
		t.Errorf("service unit was not fully rendered:\n%s", service)
	}
	socket := string(files["qwq-plugin@alpha.socket"])
	if !strings.Contains(socket, "SocketUser=qwq-agent\n") {
		t.Errorf("socket unit did not use the agent user:\n%s", socket)
	}
	if !strings.Contains(socket, "ListenStream=/run/qwq/plugin/alpha/plugin.sock\n") {
		t.Errorf("socket unit did not expand the listener path:\n%s", socket)
	}
	if !strings.Contains(socket, "Service=qwq-plugin@alpha.service\n") {
		t.Errorf("socket unit did not expand Service=:\n%s", socket)
	}
}

// TestRenderUnitNetworkProxyDirect pins the X1 relaxation: only the exact host
// policy flips the two network lines, and every other sandbox directive stays
// byte-identical to the default render. The default golden (alphaSpec) must not
// move; a plugin cannot ask for this — the host sets the internal bool.
func TestRenderUnitNetworkProxyDirect(t *testing.T) {
	base, err := RenderUnit(alphaSpec())
	if err != nil {
		t.Fatalf("RenderUnit(default): %v", err)
	}
	baseService := string(base["qwq-plugin@alpha.service"])
	if !strings.Contains(baseService, "PrivateNetwork=yes\n") ||
		!strings.Contains(baseService, "RestrictAddressFamilies=AF_UNIX\n") {
		t.Fatalf("default render lost its network isolation:\n%s", baseService)
	}

	spec := alphaSpec()
	spec.NetworkProxyDirect = true
	files, err := RenderUnit(spec)
	if err != nil {
		t.Fatalf("RenderUnit(network): %v", err)
	}
	service := string(files["qwq-plugin@alpha.service"])
	for _, want := range []string{
		"PrivateNetwork=no\n",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("network render is missing %q:\n%s", want, service)
		}
	}
	if strings.Contains(service, "PrivateNetwork=yes\n") {
		t.Errorf("network render kept PrivateNetwork=yes:\n%s", service)
	}
	// Everything except the two network lines must be unchanged: dynamic UID,
	// empty capability sets, KillMode and the rest of the sandbox.
	normalized := strings.Replace(service, "PrivateNetwork=no\n", "PrivateNetwork=yes\n", 1)
	normalized = strings.Replace(normalized, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n", "RestrictAddressFamilies=AF_UNIX\n", 1)
	if normalized != baseService {
		t.Errorf("network relaxation changed more than the two network lines:\n--- got ---\n%s\n--- want ---\n%s", normalized, baseService)
	}
	for _, unchanged := range []string{
		"DynamicUser=yes\n", "CapabilityBoundingSet=\n", "AmbientCapabilities=\n",
		"KillMode=control-group\n", "NoNewPrivileges=yes\n", "ProtectSystem=strict\n",
	} {
		if !strings.Contains(service, unchanged) {
			t.Errorf("network render dropped %q:\n%s", unchanged, service)
		}
	}
	// The socket and resource drop-in are unaffected by the network policy.
	if string(files["qwq-plugin@alpha.socket"]) != string(base["qwq-plugin@alpha.socket"]) {
		t.Errorf("network policy changed the socket unit")
	}
}

// TestRenderUnitDataDir pins X2: a host-derived DataDir below /var/lib adds a
// controlled StateDirectory= (assigned to the dynamic UID by systemd) and
// StateDirectoryMode=0700, and nothing else. The default render (no DataDir)
// must stay byte-identical, and unsafe paths are refused.
func TestRenderUnitDataDir(t *testing.T) {
	base, err := RenderUnit(alphaSpec())
	if err != nil {
		t.Fatalf("RenderUnit(default): %v", err)
	}
	baseService := string(base["qwq-plugin@alpha.service"])
	if strings.Contains(baseService, "StateDirectory=") {
		t.Fatalf("default render must not provision a state directory:\n%s", baseService)
	}

	spec := alphaSpec()
	spec.DataDir = "/var/lib/qwq-plugin-data/alpha/default"
	files, err := RenderUnit(spec)
	if err != nil {
		t.Fatalf("RenderUnit(data dir): %v", err)
	}
	service := string(files["qwq-plugin@alpha.service"])
	for _, want := range []string{
		"StateDirectory=qwq-plugin-data/alpha/default\n",
		"StateDirectoryMode=0700\n",
		"ProtectSystem=strict\n",
		"DynamicUser=yes\n",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("data dir render is missing %q:\n%s", want, service)
		}
	}
	// Only the two StateDirectory lines are added; everything else is unchanged.
	normalized := strings.Replace(service, "StateDirectory=qwq-plugin-data/alpha/default\n", "", 1)
	normalized = strings.Replace(normalized, "StateDirectoryMode=0700\n", "", 1)
	if normalized != baseService {
		t.Errorf("data dir changed more than the StateDirectory lines:\n--- got ---\n%s\n--- want ---\n%s", normalized, baseService)
	}

	for _, bad := range []string{
		"/var/lib/qwq",
		"/var/lib/qwq/plugin-data/alpha/default",
		"/var/lib/qwq-plugin-data/beta/default",
		"/var/lib/qwq-plugin-data/alpha/other",
		"/var/lib/unrelated/alpha/default",
		"relative/path",
		"/etc/qwq/plugin-data/alpha/default",
		"/var/lib",
		"/var/lib/../etc/alpha",
		"/var/lib//alpha",
	} {
		s := alphaSpec()
		s.DataDir = bad
		if _, err := RenderUnit(s); err == nil {
			t.Errorf("RenderUnit accepted unsafe data dir %q", bad)
		}
	}
}

func TestRenderResourcesDefaults(t *testing.T) {
	got, err := RenderResources(Limits{})
	if err != nil {
		t.Fatalf("RenderResources: %v", err)
	}
	for _, want := range []string{
		"MemoryMax=48M\n", "MemoryHigh=43M\n", "CPUQuota=100%\n",
		"TasksMax=32\n", "LimitNOFILE=256\n", "Environment=GOMEMLIMIT=40MiB\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("default drop-in is missing %q:\n%s", want, got)
		}
	}
}

func TestLimitsDerivation(t *testing.T) {
	for _, c := range []struct {
		memMB    int64
		highMB   int64
		goMemMiB int64
	}{
		{16, 14, 13},
		{32, 28, 27},
		{48, 43, 40},
		{65536, 58982, 55705},
	} {
		l := Limits{MemoryMaxMB: c.memMB, CPUQuotaPercent: 100, PIDsMax: 32, FDsMax: 256}
		if got := l.MemoryHighMB(); got != c.highMB {
			t.Errorf("MemoryMax %d: MemoryHigh = %d, want %d", c.memMB, got, c.highMB)
		}
		if got := l.GOMEMLIMITMiB(); got != c.goMemMiB {
			t.Errorf("MemoryMax %d: GOMEMLIMIT = %d, want %d", c.memMB, got, c.goMemMiB)
		}
	}
}

func TestLimitsValidate(t *testing.T) {
	valid := Limits{MemoryMaxMB: 48, CPUQuotaPercent: 100, PIDsMax: 32, FDsMax: 256}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid limits rejected: %v", err)
	}
	for _, c := range []struct {
		name string
		l    Limits
	}{
		{"memory too small", Limits{MemoryMaxMB: 15, CPUQuotaPercent: 1, PIDsMax: 1, FDsMax: 16}},
		{"memory too large", Limits{MemoryMaxMB: 65537, CPUQuotaPercent: 1, PIDsMax: 1, FDsMax: 16}},
		{"cpu too small", Limits{MemoryMaxMB: 16, CPUQuotaPercent: -1, PIDsMax: 1, FDsMax: 16}},
		{"cpu too large", Limits{MemoryMaxMB: 16, CPUQuotaPercent: 100001, PIDsMax: 1, FDsMax: 16}},
		{"pids too small", Limits{MemoryMaxMB: 16, CPUQuotaPercent: 1, PIDsMax: -1, FDsMax: 16}},
		{"pids too large", Limits{MemoryMaxMB: 16, CPUQuotaPercent: 1, PIDsMax: 4097, FDsMax: 16}},
		{"fds too small", Limits{MemoryMaxMB: 16, CPUQuotaPercent: 1, PIDsMax: 1, FDsMax: 15}},
		{"fds too large", Limits{MemoryMaxMB: 16, CPUQuotaPercent: 1, PIDsMax: 1, FDsMax: 65537}},
	} {
		if err := c.l.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", c.name, c.l)
		}
	}
	if _, err := RenderResources(Limits{MemoryMaxMB: 70000, CPUQuotaPercent: 1, PIDsMax: 1, FDsMax: 16}); err == nil {
		t.Error("RenderResources accepted an out-of-range memory limit")
	}
}

func TestValidateID(t *testing.T) {
	for _, id := range []string{"alpha", "security.scan", "proxy.xray", "a", "a-b", "a.b-c"} {
		if err := ValidateID(id); err != nil {
			t.Errorf("ValidateID(%q) = %v", id, err)
		}
	}
	long := strings.Repeat("a", MaxIDLen+1)
	for _, c := range []struct{ name, id string }{
		{"empty", ""},
		{"uppercase", "Alpha"},
		{"leading digit", "1alpha"},
		{"leading dot", ".alpha"},
		{"trailing dot", "alpha."},
		{"double dot", "a..b"},
		{"trailing dash", "alpha-"},
		{"slash", "a/b"},
		{"underscore", "a_b"},
		{"newline", "alpha\nbeta"},
		{"too long", long},
	} {
		if err := ValidateID(c.id); err == nil {
			t.Errorf("%s: ValidateID(%q) = nil", c.name, c.id)
		}
	}
}

func TestPathsFor(t *testing.T) {
	p, err := PathsFor("/run", "security.scan")
	if err != nil {
		t.Fatalf("PathsFor: %v", err)
	}
	for got, want := range map[string]string{
		p.Runtime:    "/run/qwq",
		p.PluginRoot: "/run/qwq/plugin",
		p.PluginDir:  "/run/qwq/plugin/security.scan",
		p.Socket:     "/run/qwq/plugin/security.scan/plugin.sock",
		p.HostDir:    "/run/qwq/host/security.scan",
		p.HostSocket: "/run/qwq/host/security.scan/host.sock",
		p.Link:       "/run/qwq/link",
		p.CredDir:    "/var/lib/qwq-privileged/creds",
		p.Token:      "/var/lib/qwq-privileged/creds/security.scan.token",
	} {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
	if _, err := PathsFor("run", "alpha"); err == nil {
		t.Error("PathsFor accepted a relative runtime base")
	}
	if _, err := PathsFor("/run", "Alpha"); err == nil {
		t.Error("PathsFor accepted an invalid id")
	}
}

func TestUnitAndGroupNames(t *testing.T) {
	service, socket, err := UnitNames("security.scan")
	if err != nil {
		t.Fatalf("UnitNames: %v", err)
	}
	if service != "qwq-plugin@security.scan.service" || socket != "qwq-plugin@security.scan.socket" {
		t.Errorf("UnitNames = %q, %q", service, socket)
	}
	group, err := GroupName("security.scan")
	if err != nil || group != "qwq-p-security.scan" {
		t.Errorf("GroupName = %q, %v", group, err)
	}
	if len(group) > 32 {
		t.Errorf("group name %q exceeds the 32-character limit", group)
	}
	name, err := TmpfilesName("security.scan")
	if err != nil || name != "qwq-plugin-security.scan.conf" {
		t.Errorf("TmpfilesName = %q, %v", name, err)
	}
	if _, _, err := UnitNames("bad/id"); err == nil {
		t.Error("UnitNames accepted an invalid id")
	}
}

// TestRenderUnitRejects covers the injection surface: every value that ends up
// in a unit file must be refused when it could change the file's structure or
// smuggle a directive.
func TestRenderUnitRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*UnitSpec)
	}{
		{"id newline", func(s *UnitSpec) { s.ID = "alpha\nExecStart=/bin/sh" }},
		{"id percent", func(s *UnitSpec) { s.ID = "alpha%i" }},
		{"id space", func(s *UnitSpec) { s.ID = "alpha beta" }},
		{"version dir relative", func(s *UnitSpec) { s.VersionDir = "var/lib/qwq/plugins/alpha/1" }},
		{"version dir unclean", func(s *UnitSpec) { s.VersionDir = "/var/lib/qwq-plugins/alpha/../alpha/1" }},
		{"version dir newline", func(s *UnitSpec) { s.VersionDir = "/var/lib/qwq-plugins/alpha/1\nExecStart=/bin/sh" }},
		{"version dir root", func(s *UnitSpec) { s.VersionDir = "/" }},
		{"version dir percent", func(s *UnitSpec) { s.VersionDir = "/var/lib/qwq-plugins/%i/1" }},
		{"executable mismatch", func(s *UnitSpec) { s.Executable = "/usr/bin/true" }},
		{"executable quote", func(s *UnitSpec) {
			s.Executable = "/var/lib/qwq-plugins/alpha/1.2.3/bin/plugin\"/x"
		}},
		{"entrypoint traversal", func(s *UnitSpec) { s.Entrypoint = "../bin/plugin" }},
		{"entrypoint nested", func(s *UnitSpec) { s.Entrypoint = "bin/sub/plugin" }},
		{"entrypoint absolute", func(s *UnitSpec) { s.Entrypoint = "/bin/plugin" }},
		{"entrypoint newline", func(s *UnitSpec) { s.Entrypoint = "bin/plugin\nExecStart=/bin/sh" }},
		{"entrypoint outside bin", func(s *UnitSpec) { s.Entrypoint = "plugin" }},
		{"digest uppercase", func(s *UnitSpec) { s.Digest = "sha256:" + strings.Repeat("A", 64) }},
		{"digest short", func(s *UnitSpec) { s.Digest = "sha256:abc" }},
		{"digest no prefix", func(s *UnitSpec) { s.Digest = strings.Repeat("a", 64) }},
		{"digest newline", func(s *UnitSpec) { s.Digest = "sha256:" + strings.Repeat("a", 64) + "\n" }},
		{"runtime base relative", func(s *UnitSpec) { s.RuntimeBase = "run" }},
		{"runtime base unclean", func(s *UnitSpec) { s.RuntimeBase = "/run/../run" }},
		{"runtime base newline", func(s *UnitSpec) { s.RuntimeBase = "/run\nExecStart=/bin/sh" }},
		{"runtime base root", func(s *UnitSpec) { s.RuntimeBase = "/" }},
		{"agent user uppercase", func(s *UnitSpec) { s.AgentUser = "Qwq" }},
		{"agent user newline", func(s *UnitSpec) { s.AgentUser = "qwq\nUser=root" }},
		{"agent user space", func(s *UnitSpec) { s.AgentUser = "qwq root" }},
		{"limits memory", func(s *UnitSpec) {
			s.Limits = &Limits{MemoryMaxMB: 8, CPUQuotaPercent: 10, PIDsMax: 4, FDsMax: 16}
		}},
		{"limits cpu", func(s *UnitSpec) {
			s.Limits = &Limits{MemoryMaxMB: 32, CPUQuotaPercent: 200000, PIDsMax: 4, FDsMax: 16}
		}},
		{"limits pids", func(s *UnitSpec) {
			s.Limits = &Limits{MemoryMaxMB: 32, CPUQuotaPercent: 10, PIDsMax: 4097, FDsMax: 16}
		}},
		{"limits pids negative", func(s *UnitSpec) {
			s.Limits = &Limits{MemoryMaxMB: 32, CPUQuotaPercent: 10, PIDsMax: -1, FDsMax: 16}
		}},
		{"limits fds", func(s *UnitSpec) {
			s.Limits = &Limits{MemoryMaxMB: 32, CPUQuotaPercent: 10, PIDsMax: 4, FDsMax: 15}
		}},
	}
	for _, c := range cases {
		spec := alphaSpec()
		c.mutate(&spec)
		if _, err := RenderUnit(spec); err == nil {
			t.Errorf("%s: RenderUnit accepted %+v", c.name, spec)
		}
	}
}

// TestRenderUnitAcceptsExplicitExecutable pins the convenience: the caller may
// pass Executable explicitly, as long as it is the verified path.
func TestRenderUnitAcceptsExplicitExecutable(t *testing.T) {
	spec := alphaSpec()
	spec.Executable = spec.VersionDir + "/" + spec.Entrypoint
	if _, err := RenderUnit(spec); err != nil {
		t.Fatalf("RenderUnit: %v", err)
	}
}

// TestSystemdAnalyzeVerify runs the packaged templates and a fully rendered
// instance through `systemd-analyze verify`. Missing executables are the only
// expected errors: the packaged template carries placeholder paths, and a
// rendered unit points at a version directory that does not exist on a build
// machine. systemd before 247 also reports LoadCredential, ProtectProc and
// ProcSubset as unknown keys; those directives are why doctor refuses
// third-party plugins below 247.
func TestSystemdAnalyzeVerify(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze not installed")
	}
	allowed := []*regexp.Regexp{
		regexp.MustCompile(`is not executable: No such file or directory`),
		regexp.MustCompile(`Unknown key name '(LoadCredential|ProtectProc|ProcSubset)' in section 'Service', ignoring\.`),
		regexp.MustCompile(`(?i)credential.*(not found|no such file|failed to load)`),
	}
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	verify := func(t *testing.T, path string) {
		t.Helper()
		cmd := exec.Command("systemd-analyze", "verify", path)
		cmd.Env = append(os.Environ(), "SYSTEMD_COLORS=0", "LC_ALL=C")
		out, err := cmd.CombinedOutput()
		text := ansi.ReplaceAllString(string(out), "")
		t.Logf("systemd-analyze verify %s: err=%v\n%s", path, err, text)
		if strings.Contains(text, "Failed to parse") || strings.Contains(text, "Invalid") {
			t.Errorf("systemd-analyze verify %s reported a syntax error:\n%s", path, text)
		}
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			ok := false
			for _, re := range allowed {
				if re.MatchString(line) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("systemd-analyze verify %s: unexpected diagnostic: %s", path, line)
			}
		}
	}
	for _, name := range []string{ServiceTemplateName, SocketTemplateName} {
		verify(t, filepath.Join("..", "..", "deployments", "systemd", name))
	}
	// The concrete unit is what systemd actually starts: it must parse too.
	files, err := RenderUnit(alphaSpec())
	if err != nil {
		t.Fatalf("RenderUnit: %v", err)
	}
	dir := t.TempDir()
	for name, data := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	verify(t, filepath.Join(dir, "qwq-plugin@alpha.service"))
	verify(t, filepath.Join(dir, "qwq-plugin@alpha.socket"))
}
