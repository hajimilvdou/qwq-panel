// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// TestXrayPluginLifecycle 只走正式签名包、公共 HTTPS API 和实际 systemd 单元。
func TestXrayPluginLifecycle(t *testing.T) {
	requireXrayEnabled(t)
	requireEnv(t, "QWQ_E2E_PASSWORD", "QWQ_E2E_XRAY_PKG_V1", "QWQ_E2E_XRAY_PKG_V2", "QWQ_E2E_XRAY_PKG_BAD")
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	prepared := false
	// 先登记最终核验，让既有安装夹具的 purge cleanup 先执行。
	t.Cleanup(func() {
		if !prepared {
			return
		}
		for _, root := range []string{sandbox.DefaultPluginDataRoot, "/var/lib/private/qwq-plugin-data"} {
			if _, err := os.Lstat(filepath.Join(root, xrayID)); !os.IsNotExist(err) {
				t.Error("最终 purge 遗留本轮消费者私有数据树")
			}
		}
	})
	prepareHost(t)
	prepared = true
	p := xrayPanel(t)
	mfa := enrollXrayMFA(p)
	markXrayResourcePhase(t, "startup")
	p.install(os.Getenv("QWQ_E2E_XRAY_PKG_V1"))
	driver := requireRunningPluginFor(t, ctx, xrayID, "0.1.1")
	status := readXrayStatus(p)
	if status.State != "UNCONFIGURED" || status.ProcessState != "STOPPED" || status.Available {
		t.Fatal("全新安装虚报核心已运行")
	}
	requireVersionTreeFor(t, xrayID, "0.1.1")
	requireVerifyEntrypointFor(t, xrayID, "0.1.1")
	requireModeOwner(t, filepath.Join(install.VersionDir(pluginsRoot, xrayID, "0.1.1"), "bin", "xray"), 0o555, "root")
	unit, socket := "qwq-plugin@"+xrayID+".service", "qwq-plugin@"+xrayID+".socket"
	properties := run(t, "systemctl", "show", unit, "-p", "PrivateNetwork", "-p", "NoNewPrivileges", "-p", "MemoryMax", "-p", "TasksMax", "-p", "LimitNOFILE")
	for _, expected := range []string{"PrivateNetwork=no", "NoNewPrivileges=yes", "MemoryMax=268435456", "TasksMax=64", "LimitNOFILE=4096"} {
		if !strings.Contains(properties, expected) {
			t.Fatal("Xray 单元未遵循已批准的网络与资源策略")
		}
	}
	fixture := newXrayFixture(t)
	revision := saveXrayDesired(p, fixture, "")
	status = readXrayStatus(p)
	if status.State != "PENDING_APPLY" || status.Desired != revision || status.Running != "" || status.Available {
		t.Fatal("保存 desired 提前改变了运行配置")
	}
	fixture.releasePort(t)
	markXrayResourcePhase(t, "apply")
	applyXrayPlan(p, revision, "", mfa)
	status = requireHealthyXray(p, revision, "")
	core := xrayChild(t, driver)
	markXrayResourcePhase(t, "idle")
	requireXrayPrivateTree(t, driver)
	observed := p.invoke("core.observe", map[string]any{"kind": "inbound", "ids": []string{"e2e-inbound"}})
	if observed["source"] != "xray" || observed["reset_epoch"] != status.Epoch {
		t.Fatal("Observe 不是当前真实核心的统计")
	}
	beforeReveals := xrayRevealCount(p)
	if beforeReveals < 2 {
		t.Fatal("受控 Apply 没有记录所需秘密揭示审计")
	}

	// 同时停 controller 防止夹具的后台协调器再次拉起已停单元。
	run(t, "systemctl", "stop", controllerU, socket, unit)
	if state := showUnit(t, unit); state.MainPID != 0 || state.ActiveState == "active" {
		t.Fatal("停止单元没有回收故障域")
	}
	requirePIDsGone(t, driver, core)
	run(t, "systemctl", "start", socket, controllerU)
	waitPanelReady(t)
	driver = requireRunningPluginFor(t, ctx, xrayID, "0.1.1")
	restored := requireHealthyXray(p, revision, status.Digest)
	if restored.Epoch == status.Epoch {
		t.Fatal("systemd 重启没有产生新的统计代次")
	}
	core = xrayChild(t, driver)
	if xrayRevealCount(p) != beforeReveals {
		t.Fatal("恢复已提交 generation 再次揭示了秘密")
	}

	oldDriver, oldCore := driver, core
	markXrayResourcePhase(t, "update")
	p.update(os.Getenv("QWQ_E2E_XRAY_PKG_V2"))
	driver = requireRunningPluginFor(t, ctx, xrayID, "0.1.2")
	requireHealthyXray(p, revision, status.Digest)
	xrayChild(t, driver)
	requirePIDsGone(t, oldDriver, oldCore)
	if xrayRevealCount(p) != beforeReveals {
		t.Fatal("插件版本更新依赖新的秘密揭示")
	}

	markXrayResourcePhase(t, "update_recovery")
	p.updateFails(os.Getenv("QWQ_E2E_XRAY_PKG_BAD"))
	driver = requireRunningPluginFor(t, ctx, xrayID, "0.1.2")
	requireHealthyXray(p, revision, status.Digest)
	core = xrayChild(t, driver)
	if xrayRevealCount(p) != beforeReveals {
		t.Fatal("失败更新恢复依赖新的秘密揭示")
	}

	oldDriver, oldCore = driver, core
	markXrayResourcePhase(t, "rollback")
	p.rollback()
	driver = requireRunningPluginFor(t, ctx, xrayID, "0.1.1")
	restored = requireHealthyXray(p, revision, status.Digest)
	if restored.Desired != revision {
		t.Fatal("版本回滚改变了期望配置")
	}
	core = xrayChild(t, driver)
	requirePIDsGone(t, oldDriver, oldCore)
	requireXrayPrivateTree(t, driver)
	if xrayRevealCount(p) != beforeReveals {
		t.Fatal("插件版本回滚依赖新的秘密揭示")
	}
	markXrayResourcePhase(t, "uninstall")
	p.uninstall()
	requirePluginRemovedFor(t, xrayID)
	requirePIDsGone(t, driver, core)
	// 默认插件卸载按 ARCH 保留用户状态；本轮专属 DataDir 由宿主 purge 夹具删除。
	t.Log("真实签名包、双进程 cgroup/UID、私有文件、免 reveal 恢复、更新/失败恢复/回滚及公共卸载进程清理通过；最终私有数据 purge 由夹具核验")
}
