// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 不可运行或不满足隔离预算的宿主，必须让原插件安装门禁看到 Fail。
// ============================================================================

func TestSandboxAdmissionRejectsMissingPolkitRule(t *testing.T) {
	f := targetHost()
	rule := "/etc/polkit-1/rules.d/60-qwq-plugin.rules"
	delete(f.exists, rule)
	delete(f.files, rule)
	result := sandboxPolkit(context.Background(), f.env())
	if result.Status != Fail || !strings.Contains(result.Fix, "60-qwq-plugin.rules") {
		t.Fatalf("missing deployment rule=%+v; want Fail with the exact rule path", result)
	}
}

func TestSandboxAdmissionRejectsMissingPolkitDaemon(t *testing.T) {
	f := targetHost()
	f.cmds["systemctl show -p ActiveState -p LoadState -p UnitFileState polkit.service"] = cmdResult{out: "LoadState=not-found\nActiveState=inactive\nUnitFileState=\n"}
	result := sandboxPolkit(context.Background(), f.env())
	if result.Status != Fail {
		t.Fatalf("missing polkit daemon=%+v; want Fail", result)
	}
}

func TestSandboxAdmissionRejectsExposureOverBudget(t *testing.T) {
	f := targetHost()
	f.cmds["systemd-analyze security qwq-plugin@.service"] = cmdResult{out: "Overall exposure level: 1.4 UNSAFE\n"}
	result := sandboxExposure(context.Background(), f.env(), SandboxOptions{Unit: "qwq-plugin@.service", UnitDir: "/etc/systemd/system", MaxExposure: 1})
	if result.Status != Fail {
		t.Fatalf("exposure over budget=%+v; want Fail", result)
	}
}

func TestSandboxAdmissionRequiresRegularReadOnlyRule(t *testing.T) {
	f := targetHost()
	env := f.env()
	stat := env.Stat
	rule := filepath.Join(t.TempDir(), "60-qwq-plugin.rules")
	if err := os.WriteFile(rule, []byte("TEST-ONLY: rule file mode fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	env.Stat = func(path string) (os.FileInfo, error) {
		if path == PluginPolkitRulePath {
			return os.Stat(rule)
		}
		return stat(path)
	}
	if result := sandboxPolkit(t.Context(), env); result.Status != OK {
		t.Fatalf("regular rule=%+v", result)
	}
	if err := os.Chmod(rule, 0o666); err != nil {
		t.Fatal(err)
	}
	if result := sandboxPolkit(t.Context(), env); result.Status != Fail {
		t.Fatalf("writable rule=%+v", result)
	}
	env.Stat = func(path string) (os.FileInfo, error) {
		if path == PluginPolkitRulePath {
			return os.Stat(filepath.Dir(rule))
		}
		return stat(path)
	}
	if result := sandboxPolkit(t.Context(), env); result.Status != Fail {
		t.Fatalf("directory as rule=%+v", result)
	}
}

func TestSandboxPolkitAllowsUnprivilegedPermissionDeniedOnRuleDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test checks non-root unprivileged EACCES behavior")
	}
	f := targetHost()
	env := f.env()
	stat := env.Stat
	env.Stat = func(path string) (os.FileInfo, error) {
		if path == PluginPolkitRulePath {
			return nil, os.ErrPermission
		}
		return stat(path)
	}
	if result := sandboxPolkit(t.Context(), env); result.Status != OK {
		t.Fatalf("unprivileged EACCES on polkit rule=%+v; want OK", result)
	}
}
