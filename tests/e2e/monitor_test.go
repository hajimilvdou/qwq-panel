// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const monitorID = "monitor.basic"

// TestMonitorEndToEnd 经真实安装、签名校验、systemd 沙箱与 HTTPS API 验证监控。
// SSH、防火墙与账户不在本测试的变更范围；prepareHost 负责失败时也卸载恢复。
func TestMonitorEndToEnd(t *testing.T) {
	requireEnv(t, "QWQ_E2E_MONITOR_PKG")
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	prepareHost(t)
	p := setupPanel(t)
	p.plugin, p.caps = monitorID, acceptedCaps("metrics.read")
	p.install(os.Getenv("QWQ_E2E_MONITOR_PKG"))
	pid := requireRunningPluginFor(t, ctx, monitorID, "0.1.0")
	requireVersionTreeFor(t, monitorID, "0.1.0")
	requireVerifyEntrypointFor(t, monitorID, "0.1.0")
	requireModeOwner(t, filepath.Join(credsDir, monitorID+".token"), 0o600, "root")
	if processUID(t, pid) == 0 || processUID(t, pid) == lookupUID(t, qwqUser) {
		t.Fatal("monitor does not run as its own dynamic UID")
	}
	unit := "qwq-plugin@" + monitorID + ".service"
	properties := run(t, "systemctl", "show", unit, "-p", "PrivateNetwork", "-p", "NoNewPrivileges", "-p", "MemoryMax", "-p", "TasksMax", "-p", "LimitNOFILE", "-p", "ControlGroup")
	if !strings.Contains(properties, "PrivateNetwork=yes") || !strings.Contains(properties, "NoNewPrivileges=yes") || !strings.Contains(properties, "MemoryMax=25165824") || !strings.Contains(properties, "TasksMax=8") || !strings.Contains(properties, "LimitNOFILE=64") {
		t.Fatalf("monitor sandbox differs from the manifest: %s", properties)
	}
	if own, host := run(t, "readlink", fmt.Sprintf("/proc/%d/ns/net", pid)), run(t, "readlink", "/proc/1/ns/net"); own == host {
		t.Fatal("monitor unexpectedly shares the host network namespace")
	}
	deadline := time.Now().Add(20 * time.Second)
	var snapshot map[string]any
	for time.Now().Before(deadline) {
		snapshot = p.invoke("monitor.snapshot", map[string]any{})
		if snapshot["status"] == "ready" && len(array(snapshot["points"])) >= 2 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	current, ok := snapshot["current"].(map[string]any)
	if !ok || snapshot["status"] != "ready" || current["cpu_pct"] == nil || current["mem_pct"] == nil || current["disk_pct"] == nil {
		t.Fatalf("no valid host sample: %v", snapshot)
	}
	if stamp, ok := current["t"].(float64); !ok || time.Since(time.UnixMilli(int64(stamp))) > 5*time.Second {
		t.Fatal("host sample is stale")
	}
	for _, metric := range []string{"cpu", "mem", "disk"} {
		result := p.invoke("monitor.stat."+metric, map[string]any{})
		value, ok := result["percent"].(float64)
		if !ok || value < 0 || value > 100 || len(array(result["spark"])) == 0 {
			t.Fatalf("invalid %s stat widget: %v", metric, result)
		}
	}
	for _, metric := range []string{"net", "load"} {
		result := p.invoke("monitor.series."+metric, map[string]any{})
		if len(array(result["series"])) != 2 {
			t.Fatalf("invalid %s series widget", metric)
		}
	}
	history := p.invoke("monitor.history", map[string]any{"range": "5m"})
	if len(array(history["points"])) < 2 || history["reset_epoch"] != snapshot["reset_epoch"] {
		t.Fatal("history did not come from the active sampler")
	}
	p.decode(p.request(http.MethodGet, "/plugin-ui/monitor.basic/0.1.0/ui/index.html", nil, "", false), http.StatusOK, nil)
	measureMonitorResources(t, ctx, unit, pid)
	awaitMonitorBrowser(t, ctx)

	// 停用必须真正停止采样进程；启用产生新的内存历史代次。
	oldEpoch := snapshot["reset_epoch"]
	setMonitorEnabled(p, false)
	if state := showUnit(t, unit); state.MainPID != 0 || state.ActiveState == "active" {
		t.Fatalf("disabled monitor still running: %+v", state)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
		t.Fatal("disabled monitor left its old process")
	}
	setMonitorEnabled(p, true)
	newPID := requireRunningPluginFor(t, ctx, monitorID, "0.1.0")
	if newPID == pid {
		t.Fatal("enable reused the stopped monitor process")
	}
	snapshot = p.invoke("monitor.snapshot", map[string]any{})
	if snapshot["reset_epoch"] == oldEpoch {
		t.Fatal("enable did not start a new history epoch")
	}
	p.uninstall()
	requirePluginRemovedFor(t, monitorID)
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", newPID)); !os.IsNotExist(err) {
		t.Fatal("uninstall left the monitor process")
	}
	t.Log("真实宿主指标、七个读取、五个小组件、沙箱、停用/启用与卸载回收通过")
}

// TestMonitorHostUninstall 直接卸载宿主，覆盖仍活跃的后台模板实例及其整个 cgroup。
func TestMonitorHostUninstall(t *testing.T) {
	requireEnv(t, "QWQ_E2E_MONITOR_PKG")
	scripts := prepareHost(t)
	p := setupPanel(t)
	p.plugin, p.caps = monitorID, acceptedCaps("metrics.read")
	p.install(os.Getenv("QWQ_E2E_MONITOR_PKG"))
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pid := requireRunningPluginFor(t, ctx, monitorID, "0.1.0")
	runScript(t, scripts, "uninstall.sh", "")
	requireNoQwqProcesses(t)
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
		t.Fatal("host uninstall left the background monitor process")
	}
	if files := qwqUnitFiles(t); files != "" {
		t.Fatal("host uninstall left qwq unit files")
	}
	for _, retained := range []string{"/var/lib/qwq/qwq.db", "/var/lib/qwq/keys/master.key", "/etc/qwq/qwq.json"} {
		if !fileExists(retained) {
			t.Fatal("host uninstall removed retained data")
		}
	}
	t.Log("宿主卸载已停止后台监控，后续 purge 由夹具清理并验证")
}

func array(value any) []any {
	values, _ := value.([]any)
	return values
}

func setMonitorEnabled(p *panel, enabled bool) {
	p.t.Helper()
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	var operation operationResult
	p.postJSON("/api/v1/plugins/"+monitorID+"/"+verb, nil, http.StatusAccepted, &operation)
	p.approveFixtureJob(&operation)
	p.waitOperation(&operation)
}

func measureMonitorResources(t *testing.T, ctx context.Context, unit string, pid int) {
	t.Helper()
	var peakRSS, peakFD, peakTasks uint64
	start := time.Now()
	initialCPU := unitNumber(t, unit, "CPUUsageNSec")
	for sample := 0; sample < 12; sample++ {
		status := readFile(t, fmt.Sprintf("/proc/%d/status", pid))
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "VmRSS:" {
				value, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				peakRSS = max(peakRSS, value*1024)
			}
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			t.Fatal(err)
		}
		peakFD, peakTasks = max(peakFD, uint64(len(fds))), max(peakTasks, unitNumber(t, unit, "TasksCurrent"))
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	cpu := float64(unitNumber(t, unit, "CPUUsageNSec")-initialCPU) / float64(time.Since(start)) * 100
	peakMemory := unitNumber(t, unit, "MemoryPeak")
	t.Logf("monitor 24s: RSS_peak=%d bytes cgroup_peak=%d bytes FD_peak=%d Tasks_peak=%d CPU_avg=%.3f%%", peakRSS, peakMemory, peakFD, peakTasks, cpu)
	if peakRSS == 0 || peakMemory > 24<<20 || peakRSS > 24<<20 || peakFD > 64 || peakTasks > 8 || cpu > 8 {
		t.Fatal("monitor exceeded its approved resource envelope")
	}
}

func unitNumber(t *testing.T, unit, property string) uint64 {
	t.Helper()
	raw := run(t, "systemctl", "show", unit, "-p", property, "--value")
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		t.Fatalf("missing systemd metric %s", property)
	}
	return value
}

// awaitMonitorBrowser 只交换非敏感完成标记；凭据由测试环境安全传入浏览器。
func awaitMonitorBrowser(t *testing.T, ctx context.Context) {
	t.Helper()
	prefix := os.Getenv("QWQ_E2E_BROWSER_SYNC")
	if prefix == "" {
		t.Log("未启用真实浏览器协作；本次结果只含安装/API/沙箱")
		return
	}
	if !filepath.IsAbs(prefix) || !strings.Contains(prefix, "/monitor-e2e/") {
		t.Fatal("invalid browser synchronization path")
	}
	ready, done := prefix+".ready", prefix+".done"
	defer os.Remove(ready)
	defer os.Remove(done)
	if err := os.WriteFile(ready, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(3 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatal("browser did not complete within three minutes")
		case <-tick.C:
			data, err := os.ReadFile(done)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || strings.TrimSpace(string(data)) != "ok" {
				t.Fatal("real browser acceptance failed")
			}
			return
		}
	}
}
