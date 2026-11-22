// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"net/http"
	"syscall"
	"testing"
	"time"
)

// TestXrayRecoveryTraffic 同版本重放、核心/驱动强杀和宿主重启后再次真实转发。
func TestXrayRecoveryTraffic(t *testing.T) {
	scenario := newXrayTrafficScenario(t)
	p, fixture := scenario.panel, scenario.fixture
	client := newXrayTestClient(t, fixture, fixture.uuid, fixture.publicKey)
	if !client.transfers(scenario.url, scenario.payload) {
		t.Fatal("恢复测试初始代理链路失败")
	}
	applyXrayPlan(p, scenario.status.Running, scenario.status.Running, scenario.mfa)
	replayed := requireHealthyXray(p, scenario.status.Running, scenario.status.Digest)
	if replayed.Epoch != scenario.status.Epoch || xrayChild(t, scenario.driver) != scenario.core {
		t.Fatal("同 revision 重放重复切换了进程")
	}
	for _, fault := range []string{"core-sigkill", "driver-sigkill", "controller-restart"} {
		t.Run(fault, func(t *testing.T) {
			previousTest := p.t
			p.t = t
			defer func() { p.t = previousTest }()
			before := requireHealthyXray(p, scenario.status.Running, scenario.status.Digest)
			driver := requireRunningPluginFor(t, scenario.context, xrayID, "0.1.1")
			core := xrayChild(t, driver)
			oldCounters := xrayCounters(p)
			switch fault {
			case "core-sigkill":
				if err := syscall.Kill(core, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
			case "driver-sigkill":
				if err := syscall.Kill(driver, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
			case "controller-restart":
				run(t, "systemctl", "restart", controllerU)
				waitPanelReady(t)
			}
			// 先等实际单元恢复，再检查代理健康；瞬间失败不能写成恢复成功。
			deadline := time.Now().Add(45 * time.Second)
			for time.Now().Before(deadline) {
				state := showUnit(t, "qwq-plugin@"+xrayID+".service")
				if state.MainPID != 0 && state.ActiveState == "active" && (fault == "controller-restart" || state.MainPID != driver) {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			scenario.driver = requireRunningPluginFor(t, scenario.context, xrayID, "0.1.1")
			after := requireHealthyXray(p, before.Running, before.Digest)
			scenario.core = xrayChild(t, scenario.driver)
			if fault != "controller-restart" {
				if after.Epoch == before.Epoch {
					t.Fatal("真实强杀恢复没有建立新 epoch")
				}
				requirePIDsGone(t, driver, core)
				newCounters := xrayCounters(p)
				for key, value := range newCounters {
					previous := oldCounters[key]
					if value.Epoch == previous.Epoch {
						t.Fatal("新代次统计仍使用旧 epoch")
					}
					if value.Present && counterBytes(t, value.Downlink) > counterBytes(t, previous.Downlink) {
						t.Fatal("重启前累计流量被拼接到新代次")
					}
				}
			}
			if !client.transfers(scenario.url, scenario.payload) {
				t.Fatal("故障恢复后不能再次完成真实转发")
			}
			scenario.status = after
		})
	}
	p.uninstall()
	requirePluginRemovedFor(t, xrayID)
	requirePIDsGone(t, scenario.driver, scenario.core)
}

// TestXrayCandidateFailureTraffic 期望未应用、坏认证与端口占用均保留健康旧配置。
func TestXrayCandidateFailureTraffic(t *testing.T) {
	scenario := newXrayTrafficScenario(t)
	p := scenario.panel
	client := newXrayTestClient(t, scenario.fixture, scenario.fixture.uuid, scenario.fixture.publicKey)
	candidate := *scenario.fixture
	candidate.uuid = "invalid-ephemeral-uuid"
	revision := saveXrayDesired(p, &candidate, scenario.status.Desired)
	pending := readXrayStatus(p)
	if pending.State != "PENDING_APPLY" || pending.Running != scenario.status.Running || pending.Digest != scenario.status.Digest || !client.transfers(scenario.url, scenario.payload) {
		t.Fatal("未 Apply 的 desired 改变了旧代理链路")
	}
	failed := startXrayPlan(p, revision, scenario.status.Running, scenario.mfa)
	waitXrayFailure(p, failed)
	requireHealthyPendingXray(p, scenario.status)
	if !client.transfers(scenario.url, scenario.payload) {
		t.Fatal("无效认证候选破坏了旧代理")
	}
	candidate = *scenario.fixture
	occupied := newXrayFixture(t)
	candidate.port = occupied.port
	// 保留专属临时监听，让原生预检通过后真实候选启动失败。
	revision = saveXrayDesired(p, &candidate, revision)
	failed = startXrayPlan(p, revision, scenario.status.Running, scenario.mfa)
	waitXrayFailure(p, failed)
	requireHealthyPendingXray(p, scenario.status)
	if !client.transfers(scenario.url, scenario.payload) {
		t.Fatal("端口占用候选没有恢复旧代理")
	}
	scenario.driver = requireRunningPluginFor(t, scenario.context, xrayID, "0.1.1")
	scenario.core = xrayChild(t, scenario.driver)
	p.uninstall()
	requirePluginRemovedFor(t, xrayID)
	requirePIDsGone(t, scenario.driver, scenario.core)
}

func waitXrayFailure(p *panel, operation *operationResult) {
	p.t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		p.decode(p.request(http.MethodGet, "/api/v1/operations/"+operation.OperationID, nil, "", false), http.StatusOK, operation)
		if operation.Status == "FAILED" {
			if operation.Error == nil {
				p.t.Fatal("失败 operation 缺少明确错误")
			}
			return
		}
		if operation.Status == "SUCCEEDED" || operation.Status == "CANCELED" || operation.Status == "REJECTED" {
			p.t.Fatal("候选没有按预期失败")
		}
		time.Sleep(200 * time.Millisecond)
	}
	p.t.Fatal("候选失败/补偿没有在有界时间内完成")
}

func requireHealthyPendingXray(p *panel, previous xrayStatus) xrayStatus {
	p.t.Helper()
	status := readXrayStatus(p)
	if status.State != "PENDING_APPLY" || !status.Available || status.ProcessState != "RUNNING" || status.APIState != "READY" || status.Running != previous.Running || status.Digest != previous.Digest {
		p.t.Fatal("候选失败后旧运行配置没有真实保持健康")
	}
	return status
}
