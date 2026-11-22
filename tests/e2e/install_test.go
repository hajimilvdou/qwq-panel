// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

// =============================================================================
//  install.sh / uninstall.sh 的真机测试（DEP-02）
// -----------------------------------------------------------------------------
//  QWQ_E2E_RELEASE_TAR=<build.sh 产出的 release/qwq-e2e-linux-<arch>.tar.gz> \
//  ./e2e.test -test.v -test.run 'TestInstallScriptIdempotent|TestUninstallKeepsData'
//
//  与 TestPluginEndToEnd 一样只在一次性主机上运行：主机已有 qwq 状态即拒绝。
//  每个测试结束都以 uninstall.sh --purge 复原主机（prepareInstall 是所有
//  e2e 测试共用的安装夹具）。
// =============================================================================

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// installedFiles 是安装脚本写出的文件；二次安装后它们的内容、权限与
// mtime 都不得变化。
var installedFiles = []string{
	"/usr/lib/sysusers.d/qwq.conf",
	"/usr/lib/tmpfiles.d/qwq.conf",
	"/etc/systemd/system/qwq-controller.service",
	"/etc/systemd/system/qwq-backup.service",
	"/etc/systemd/system/qwq-backup.timer",
	"/etc/systemd/system/qwq-privileged.service",
	"/etc/systemd/system/qwq-privileged.socket",
	"/etc/systemd/system/qwq-capability.service",
	"/etc/systemd/system/qwq-capability.socket",
	"/etc/systemd/system/qwq-plugin@.service",
	"/etc/systemd/system/qwq-plugin@.socket",
	"/etc/qwq/qwq.json",
	"/opt/qwq/current",
	"/usr/local/bin/qwq",
}

func TestInstallScriptIdempotent(t *testing.T) {
	scripts := prepareInstall(t)

	runScript(t, scripts, "install.sh", "", "--offline", os.Getenv("QWQ_E2E_RELEASE_TAR"))
	first := snapshotInstall(t)
	pid := showUnit(t, "qwq-controller.service").MainPID
	if pid == 0 {
		t.Fatal("qwq-controller is not running after install")
	}
	requireDoctorHealthy(t)
	requireModeOwner(t, "/var/lib/qwq", 0o700, "qwq")
	requireModeOwner(t, "/run/qwq", 0o711, "root")
	requireModeOwner(t, "/etc/qwq/qwq.json", 0o640, "root")

	runScript(t, scripts, "install.sh", "", "--offline", os.Getenv("QWQ_E2E_RELEASE_TAR"))
	if second := snapshotInstall(t); second != first {
		t.Fatalf("the second install changed the host:\n--- first\n%s\n--- second\n%s", first, second)
	}
	if again := showUnit(t, "qwq-controller.service").MainPID; again != pid {
		t.Fatalf("the second install restarted the controller (MainPID %d → %d)", pid, again)
	}
	requireDoctorHealthy(t)
}

func TestUninstallKeepsData(t *testing.T) {
	scripts := prepareInstall(t)
	runScript(t, scripts, "install.sh", "", "--offline", os.Getenv("QWQ_E2E_RELEASE_TAR"))

	runScript(t, scripts, "uninstall.sh", "")
	if units := qwqUnitFiles(t); strings.TrimSpace(units) != "" {
		t.Fatalf("unit files remain after uninstall:\n%s", units)
	}
	for _, path := range []string{"/opt/qwq", "/usr/local/bin/qwq", "/run/qwq", "/var/lib/qwq-plugins", "/var/lib/qwq-privileged"} {
		if fileExists(path) {
			t.Errorf("left behind after uninstall: %s", path)
		}
	}
	for _, path := range []string{"/var/lib/qwq/qwq.db", "/var/lib/qwq/keys/master.key", "/etc/qwq/qwq.json"} {
		if !fileExists(path) {
			t.Errorf("uninstall without --purge removed %s", path)
		}
	}

	// 确认词不符：什么都不删。
	if out, err := scriptCmd(scripts, "uninstall.sh", "wrong\n", "--purge").CombinedOutput(); err == nil {
		t.Fatalf("--purge accepted a wrong confirmation word:\n%s", out)
	}
	if !fileExists("/var/lib/qwq/qwq.db") {
		t.Fatal("a refused --purge still removed the data")
	}
}

// prepareInstall 检查主机干净、解出发布包里的脚本，并注册 --purge 复原。
func prepareInstall(t *testing.T) string {
	t.Helper()
	requireEnv(t, "QWQ_E2E_RELEASE_TAR")
	requireCleanHost(t)
	dir := t.TempDir()
	run(t, "tar", "-C", dir, "-xzf", os.Getenv("QWQ_E2E_RELEASE_TAR"), "./install.sh", "./uninstall.sh")
	t.Cleanup(func() {
		out, err := scriptCmd(dir, "uninstall.sh", "purge-qwq\n", "--purge").CombinedOutput()
		if err != nil {
			t.Errorf("uninstall --purge: %v\n%s", err, out)
		}
		requirePurged(t)
	})
	return dir
}

func scriptCmd(dir, name, stdin string, args ...string) *exec.Cmd {
	cmd := exec.Command("bash", append([]string{filepath.Join(dir, name)}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd
}

func runScript(t *testing.T, dir, name, stdin string, args ...string) {
	t.Helper()
	out, err := scriptCmd(dir, name, stdin, args...).CombinedOutput()
	// 安装器为操作者打印初始化令牌，验收日志只保留脱敏链接。
	transcript := setupLinkRe.ReplaceAllString(string(out), "/setup#token=[REDACTED]")
	t.Logf("%s %s:\n%s", name, strings.Join(args, " "), transcript)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// snapshotInstall 记录安装产物的类型、权限、属主、mtime 与链接目标。
func snapshotInstall(t *testing.T) string {
	t.Helper()
	var lines []string
	for _, path := range installedFiles {
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("installed file missing: %s: %v", path, err)
		}
		line := fmt.Sprintf("%s %s %d", path, fi.Mode(), fi.ModTime().UnixNano())
		if target, err := os.Readlink(path); err == nil {
			line += " -> " + target
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// requireDoctorHealthy 断言 qwq doctor 的退出码 ≤1（没有失败项）。
func requireDoctorHealthy(t *testing.T) {
	t.Helper()
	out, err := exec.Command("/usr/local/bin/qwq", "doctor").CombinedOutput()
	if code := exitCode(err); code > 1 {
		t.Fatalf("qwq doctor exit = %d:\n%s", code, out)
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}
