// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// pauseXrayProcess 固定到已经由测试确认的 PID 句柄，恢复与释放始终执行。
func pauseXrayProcess(t *testing.T, pid int) func() {
	t.Helper()
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.Release(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("暂停句柄释放失败: %v", err)
		}
	})
	if err := process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if err := process.Signal(syscall.SIGCONT); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("专属测试进程恢复失败: %v", err)
			}
		})
	}
	t.Cleanup(restore)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(string(readFile(t, fmt.Sprintf("/proc/%d/status", pid))), "\n") {
			if strings.HasPrefix(line, "State:") && (strings.Contains(line, "T") || strings.Contains(line, "t (tracing")) {
				return restore
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("专属测试进程没有实际暂停")
	return restore
}

func waitXrayOperation(p *panel, operation *operationResult, status string, timeout time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		p.decode(p.request(http.MethodGet, "/api/v1/operations/"+operation.OperationID, nil, "", false), http.StatusOK, operation)
		if operation.Status == status {
			return
		}
		switch operation.Status {
		case "SUCCEEDED", "FAILED", "CANCELED", "REJECTED", "EXPIRED":
			p.t.Fatalf("operation 实际结束 %s，期望 %s", operation.Status, status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.t.Fatalf("operation 没有在预算内达到 %s", status)
}

func pendingXrayApplyPlan(p *panel, scenario *xrayTrafficScenario) string {
	p.t.Helper()
	candidate := *scenario.fixture
	candidate.shortID = "00" + candidate.shortID[2:]
	if candidate.shortID == scenario.fixture.shortID {
		candidate.shortID = "01" + candidate.shortID[2:]
	}
	revision := saveXrayDesired(p, &candidate, scenario.status.Desired)
	return createXrayApplyPlan(p, revision, scenario.status.Running)
}

// TestXrayCancelTraffic 在真实宿主 RUNNING/驱动分发阻塞阶段取消，旧数据面保持可用。
func TestXrayCancelTraffic(t *testing.T) {
	scenario := newXrayTrafficScenario(t)
	p := scenario.panel
	client := newXrayTestClient(t, scenario.fixture, scenario.fixture.uuid, scenario.fixture.publicKey)
	plan := pendingXrayApplyPlan(p, scenario)
	restore := pauseXrayProcess(t, scenario.driver)
	defer restore()
	if !client.transfers(scenario.url, scenario.payload) {
		t.Fatal("暂停驱动时旧核心没有独立保持转发")
	}
	operation := executeXrayApplyPlan(p, plan, scenario.mfa)
	waitXrayOperation(p, operation, "RUNNING", 10*time.Second)
	request, err := json.Marshal(map[string]string{"reason": "isolated-xray-e2e-cancel"})
	if err != nil {
		t.Fatal(err)
	}
	response := p.request(http.MethodPost, "/api/v1/operations/"+operation.OperationID+"/cancel", bytes.NewReader(request), "application/json", true)
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		p.t.Fatal("真实 RUNNING operation 取消请求被拒绝")
	}
	p.decode(response, response.StatusCode, operation)
	restore()
	waitXrayOperation(p, operation, "CANCELED", 15*time.Second)
	after := requireHealthyPendingXray(p, scenario.status)
	if after.Epoch != scenario.status.Epoch || xrayChild(t, scenario.driver) != scenario.core || !client.transfers(scenario.url, scenario.payload) {
		t.Fatal("取消分发破坏了原配置或真实转发")
	}
	p.uninstall()
	requirePluginRemovedFor(t, xrayID)
	requirePIDsGone(t, scenario.driver, scenario.core)
}

// TestXrayDeadlineTraffic 等待声明的 120 秒 job deadline，不借请求断连取消长期任务。
func TestXrayDeadlineTraffic(t *testing.T) {
	scenario := newXrayTrafficScenario(t)
	p := scenario.panel
	client := newXrayTestClient(t, scenario.fixture, scenario.fixture.uuid, scenario.fixture.publicKey)
	plan := pendingXrayApplyPlan(p, scenario)
	restore := pauseXrayProcess(t, scenario.driver)
	defer restore()
	operation := executeXrayApplyPlan(p, plan, scenario.mfa)
	waitXrayOperation(p, operation, "RUNNING", 10*time.Second)
	// 宿主默认最多三次幂等尝试；每次 120 秒，预算覆盖完整重试。
	waitXrayOperation(p, operation, "FAILED", 7*time.Minute)
	data, err := json.Marshal(operation.Error)
	if err != nil {
		t.Fatal(err)
	}
	var failure struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(data, &failure) != nil || failure.Code != "TIMEOUT" {
		t.Fatal("真实 job 没有因既定 deadline 超时结束")
	}
	restore()
	after := requireHealthyPendingXray(p, scenario.status)
	if after.Epoch != scenario.status.Epoch || !client.transfers(scenario.url, scenario.payload) {
		t.Fatal("job deadline 破坏了原运行期核心")
	}
	p.uninstall()
	requirePluginRemovedFor(t, xrayID)
	requirePIDsGone(t, scenario.driver, scenario.core)
}

// TestXrayAPIOutageTraffic 真实 API 暂时不可用时不能补零或虚报代理健康。
func TestXrayAPIOutageTraffic(t *testing.T) {
	scenario := newXrayTrafficScenario(t)
	p := scenario.panel
	client := newXrayTestClient(t, scenario.fixture, scenario.fixture.uuid, scenario.fixture.publicKey)
	restore := pauseXrayProcess(t, scenario.core)
	defer restore()
	body, err := json.Marshal(map[string]any{"payload": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	response := p.request(http.MethodPost, "/api/v1/nodes/local/plugins/"+xrayID+"/instances/default/operations/core.observe", bytes.NewReader(body), "application/json", false)
	var failure struct {
		Code       string `json:"code"`
		PluginCode string `json:"plugin_code"`
	}
	if response.StatusCode < 400 {
		_ = response.Body.Close()
		t.Fatal("暂停真实 API 后 Observe 仍虚报成功")
	}
	p.decode(response, response.StatusCode, &failure)
	if failure.Code != "CORE_API_UNAVAILABLE" && failure.PluginCode != "CORE_API_UNAVAILABLE" {
		t.Fatal("真实 API 故障没有保留明确的不可用原因")
	}
	status := readXrayStatus(p)
	if status.Available || status.APIState != "UNAVAILABLE" || status.ProcessState != "RUNNING" {
		t.Fatal("API 故障被误报为可用或进程消失")
	}
	restore()
	status = requireHealthyXray(p, scenario.status.Running, scenario.status.Digest)
	if status.Epoch != scenario.status.Epoch || !client.transfers(scenario.url, scenario.payload) {
		t.Fatal("API 恢复不能继续相同运行代的真实转发")
	}
	p.uninstall()
	requirePluginRemovedFor(t, xrayID)
	requirePIDsGone(t, scenario.driver, scenario.core)
}
