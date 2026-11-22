// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type xrayTrafficScenario struct {
	panel   *panel
	context context.Context
	fixture *xrayFixture
	mfa     *xrayMFA
	status  xrayStatus
	driver  int
	core    int
	url     string
	payload []byte
}

func newXrayTrafficScenario(t *testing.T) *xrayTrafficScenario {
	t.Helper()
	requireXrayEnabled(t)
	requireEnv(t, "QWQ_E2E_PASSWORD", "QWQ_E2E_XRAY_PKG_V1")
	url, payload := newXrayHTTPPayload(t)
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	t.Cleanup(cancel)
	prepareHost(t)
	p := xrayPanel(t)
	mfa := enrollXrayMFA(p)
	markXrayResourcePhase(t, "startup")
	p.install(os.Getenv("QWQ_E2E_XRAY_PKG_V1"))
	driver := requireRunningPluginFor(t, ctx, xrayID, "0.1.1")
	fixture := newXrayFixture(t)
	revision := saveXrayDesired(p, fixture, "")
	fixture.releasePort(t)
	markXrayResourcePhase(t, "apply")
	applyXrayPlan(p, revision, "", mfa)
	status := requireHealthyXray(p, revision, "")
	return &xrayTrafficScenario{panel: p, context: ctx, fixture: fixture, mfa: mfa, status: status, driver: driver, core: xrayChild(t, driver), url: url, payload: payload}
}

// TestXrayRealTraffic 验证已知响应、真实双向统计和两种认证失败。
func TestXrayRealTraffic(t *testing.T) {
	scenario := newXrayTrafficScenario(t)
	p, fixture := scenario.panel, scenario.fixture
	client := newXrayTestClient(t, fixture, fixture.uuid, fixture.publicKey)
	markXrayResourcePhase(t, "traffic", client.command.Process.Pid)
	before := xrayCounters(p)
	for request := 0; request < 3; request++ {
		if !client.transfers(scenario.url, scenario.payload) {
			t.Fatal("真实客户端没有转发完整的固定公开响应")
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	grown := false
	var after map[string]xrayCounter
	for time.Now().Before(deadline) {
		after = xrayCounters(p)
		grown = true
		for _, key := range []string{"inbound/e2e-inbound", "user/e2e-user"} {
			current, exists := after[key]
			previous := before[key]
			currentDown, previousDown := counterBytes(t, current.Downlink), counterBytes(t, previous.Downlink)
			if !exists || !current.Present || current.Epoch != scenario.status.Epoch || counterBytes(t, current.Uplink) <= counterBytes(t, previous.Uplink) || currentDown < previousDown || currentDown-previousDown < uint64(3*len(scenario.payload)) {
				grown = false
			}
		}
		if grown {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !grown {
		for _, key := range []string{"inbound/e2e-inbound", "user/e2e-user"} {
			previous, current := before[key], after[key]
			t.Logf("统计对照 %s：before up=%d down=%d；after up=%d down=%d present=%t；期望down增长至少%d bytes",
				key, counterBytes(t, previous.Uplink), counterBytes(t, previous.Downlink), counterBytes(t, current.Uplink), counterBytes(t, current.Downlink), current.Present, 3*len(scenario.payload))
		}
		t.Fatal("入站与用户统计没有反映真实双向流量")
	}
	wrongUUID := "0" + fixture.uuid[1:]
	if wrongUUID == fixture.uuid {
		wrongUUID = "1" + fixture.uuid[1:]
	}
	badUser := newXrayTestClient(t, fixture, wrongUUID, fixture.publicKey)
	markXrayResourcePhase(t, "traffic", client.command.Process.Pid, badUser.command.Process.Pid)
	if badUser.transfers(scenario.url, scenario.payload) {
		t.Fatal("错误 UUID 完成了真实代理转发")
	}
	wrongKey := "A" + fixture.publicKey[1:]
	if wrongKey == fixture.publicKey {
		wrongKey = "B" + fixture.publicKey[1:]
	}
	badKey := newXrayTestClient(t, fixture, fixture.uuid, wrongKey)
	markXrayResourcePhase(t, "traffic", client.command.Process.Pid, badUser.command.Process.Pid, badKey.command.Process.Pid)
	if badKey.transfers(scenario.url, scenario.payload) {
		t.Fatal("错误 REALITY 密钥完成了真实代理转发")
	}
	requireHealthyXray(p, scenario.status.Running, scenario.status.Digest)
	logXrayProcessUsage(t, "driver", scenario.driver)
	logXrayProcessUsage(t, "server", scenario.core)
	logXrayProcessUsage(t, "client-test-only", client.command.Process.Pid)
	markXrayResourcePhase(t, "uninstall", client.command.Process.Pid, badUser.command.Process.Pid, badKey.command.Process.Pid)
	p.uninstall()
	requirePluginRemovedFor(t, xrayID)
	requirePIDsGone(t, scenario.driver, scenario.core)
	t.Logf("真实 VLESS/Vision/REALITY/RAW 已知响应转发三次，各 %d bytes；入站/用户统计增长，错误 UUID/密钥拒绝", len(scenario.payload))
}

// logXrayProcessUsage 是实际 /proc 快照；不会把单点值写成峰值或完整资源验收。
func logXrayProcessUsage(t *testing.T, role string, pid int) {
	t.Helper()
	var rss, threads uint64
	for _, line := range strings.Split(string(readFile(t, fmt.Sprintf("/proc/%d/status", pid))), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "VmRSS:" || fields[0] == "Threads:" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			if fields[0] == "VmRSS:" {
				rss = value * 1024
			} else {
				threads = value
			}
		}
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	if rss == 0 || threads == 0 {
		t.Fatal("真实资源快照缺少 RSS 或线程数")
	}
	t.Logf("%s snapshot: RSS=%d bytes FD=%d threads=%d；完整 CPU/阶段峰值仍需单独采样", role, rss, len(fds), threads)
}
