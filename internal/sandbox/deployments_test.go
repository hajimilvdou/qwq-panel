// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readDeployment 读取仓库 deployments/ 下的文件。
func readDeployment(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "deployments"}, parts...)...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestCapabilityDeploymentBoundaries(t *testing.T) {
	service := readDeployment(t, "systemd", "qwq-capability.service")
	for key, want := range map[string]string{"Restart": "no", "RuntimeMaxSec": "120", "MemoryMax": "48M", "TasksMax": "24", "ProtectSystem": "strict", "ProtectHome": "yes", "NoNewPrivileges": "yes", "PrivateNetwork": "no"} {
		values := unitDirectives(service, key)
		if len(values) != 1 || values[0] != want {
			t.Errorf("能力 helper %s 未保持约束", key)
		}
	}
	socket := readDeployment(t, "systemd", "qwq-capability.socket")
	for key, want := range map[string]string{"ListenStream": DefaultCapabilitySocket, "SocketMode": "0660", "SocketGroup": "qwq", "RemoveOnStop": "yes"} {
		values := unitDirectives(socket, key)
		if len(values) != 1 || values[0] != want {
			t.Errorf("能力 socket %s 未保持访问边界", key)
		}
	}
	if strings.Contains(service, "ReadWritePaths=/home") || strings.Contains(service, "ReadWritePaths=/root") {
		t.Fatal("能力 helper 放开了完整家目录")
	}
}

// unitDirectives 返回 unit 文件中 key= 的全部取值（忽略注释）。
func unitDirectives(unit, key string) []string {
	var values []string
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			values = append(values, v)
		}
	}
	return values
}

// tmpfilesMode 返回 tmpfiles 配置里 path 那一行的权限。
func tmpfilesMode(conf, path string) string {
	for _, line := range strings.Split(conf, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "d" && f[1] == path {
			return f[2]
		}
	}
	return ""
}

// TestControllerUnitLeavesRuntimeTreeToTmpfiles: RuntimeDirectory= 会在每次
// 停止时 rm -rf /run/qwq 并把它改回 qwq 所有（PRIV-03），controller unit 必须
// 把运行时树完全交给 tmpfiles。
func TestControllerUnitLeavesRuntimeTreeToTmpfiles(t *testing.T) {
	unit := readDeployment(t, "systemd", "qwq-controller.service")
	conf := readDeployment(t, "tmpfiles", "qwq.conf")
	if mode := tmpfilesMode(conf, "/var/lib/qwq-plugin-data"); mode != "0711" {
		t.Errorf("专用插件数据根权限=%q，期望 root 可遍历的 0711", mode)
	}
	for _, key := range []string{"RuntimeDirectory", "RuntimeDirectoryMode", "LogsDirectory", "LogsDirectoryMode"} {
		if v := unitDirectives(unit, key); len(v) != 0 {
			t.Errorf("qwq-controller.service sets %s=%v", key, v)
		}
	}
	modes := unitDirectives(unit, "StateDirectoryMode")
	if len(modes) != 1 || modes[0] != tmpfilesMode(conf, "/var/lib/qwq") {
		t.Errorf("StateDirectoryMode=%v, tmpfiles /var/lib/qwq mode %q", modes, tmpfilesMode(conf, "/var/lib/qwq"))
	}
	if rw := unitDirectives(unit, "ReadWritePaths"); len(rw) != 1 || rw[0] != "/run/qwq/host" {
		t.Errorf("ReadWritePaths=%v, want /run/qwq/host", rw)
	}
	if got := tmpfilesMode(conf, "/run/qwq"); got != "0711" {
		t.Errorf("tmpfiles /run/qwq mode %q, want 0711", got)
	}
	if after := strings.Join(unitDirectives(unit, "After"), " "); !strings.Contains(after, "systemd-tmpfiles-setup.service") {
		t.Errorf("After=%q does not order after systemd-tmpfiles-setup.service", after)
	}
}

func TestPrivilegedDeploymentBoundaries(t *testing.T) {
	service := readDeployment(t, "systemd", "qwq-privileged.service")
	for key, want := range map[string]string{
		"ProtectSystem":   "strict",
		"PrivateNetwork":  "yes",
		"NoNewPrivileges": "yes",
		"ProtectHome":     "yes",
	} {
		values := unitDirectives(service, key)
		if len(values) != 1 || values[0] != want {
			t.Errorf("特权 helper %s=%v，期望 %q", key, values, want)
		}
	}

	rwValues := unitDirectives(service, "ReadWritePaths")
	if len(rwValues) != 1 {
		t.Fatalf("特权 helper ReadWritePaths 条数=%d，期望 1", len(rwValues))
	}
	rwSet := make(map[string]bool)
	for _, entry := range strings.Fields(rwValues[0]) {
		rwSet[entry] = true
		clean := strings.TrimPrefix(entry, "-")
		if clean == "/" || clean == "/var/lib" || clean == "/home" || clean == "/root" ||
			strings.HasPrefix(clean, "/home/") || strings.HasPrefix(clean, "/root/") {
			t.Errorf("特权 helper ReadWritePaths 过度开放：%q", entry)
		}
	}
	for _, want := range []string{"-/var/lib/qwq-plugin-data", "-/var/lib/private/qwq-plugin-data"} {
		if !rwSet[want] {
			t.Errorf("特权 helper ReadWritePaths 缺少受限数据根 %q", want)
		}
	}

	capValues := unitDirectives(service, "CapabilityBoundingSet")
	if len(capValues) != 1 {
		t.Fatalf("特权 helper CapabilityBoundingSet 条数=%d，期望 1", len(capValues))
	}
	allowedCaps := map[string]bool{
		"CAP_CHOWN":        true,
		"CAP_DAC_OVERRIDE": true,
		"CAP_SETGID":       true,
		"CAP_SETUID":       true,
	}
	caps := strings.Fields(capValues[0])
	if len(caps) != len(allowedCaps) {
		t.Fatalf("特权 helper CapabilityBoundingSet=%v，期望精确受限集合", caps)
	}
	seenCaps := make(map[string]bool, len(caps))
	for _, capName := range caps {
		if !allowedCaps[capName] || seenCaps[capName] {
			t.Errorf("特权 helper CapabilityBoundingSet 包含非预期或重复能力：%q", capName)
		}
		seenCaps[capName] = true
	}
}

func TestCompatUnitctlDeploymentBoundaries(t *testing.T) {
	service := readDeployment(t, "compat", "polkit", "qwq-compat-unitctl.service")
	for key, want := range map[string]string{
		"Restart":               "no",
		"RuntimeMaxSec":         "60",
		"MemoryMax":             "32M",
		"TasksMax":              "16",
		"ProtectSystem":         "strict",
		"PrivateNetwork":        "yes",
		"NoNewPrivileges":       "yes",
		"ProtectHome":           "yes",
		"CapabilityBoundingSet": "",
	} {
		values := unitDirectives(service, key)
		if len(values) != 1 || values[0] != want {
			t.Errorf("compat unitctl %s=%v，期望 %q", key, values, want)
		}
	}
	if len(unitDirectives(service, "ReadWritePaths")) != 0 {
		t.Fatal("compat unitctl 不应声明任何 ReadWritePaths")
	}
	if bp := unitDirectives(service, "BindPaths"); len(bp) != 1 || bp[0] != "-/run/credentials:/run/qwq/compat-creds" {
		t.Fatalf("compat unitctl BindPaths=%v，期望仅限 -/run/credentials:/run/qwq/compat-creds", bp)
	}
	socket := readDeployment(t, "compat", "polkit", "qwq-compat-unitctl.socket")
	for key, want := range map[string]string{
		"ListenStream": DefaultCompatUnitctlSocket,
		"SocketMode":   "0660",
		"SocketGroup":  "qwq",
		"RemoveOnStop": "yes",
	} {
		values := unitDirectives(socket, key)
		if len(values) != 1 || values[0] != want {
			t.Errorf("compat unitctl socket %s=%v，期望 %q", key, values, want)
		}
	}
}
