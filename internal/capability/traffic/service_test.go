// SPDX-License-Identifier: AGPL-3.0-only

package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

type fakeTrafficRunner struct {
	cmds      []string
	failQdisc bool
	noIFB     bool
}

func (f *fakeTrafficRunner) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, line)
	if name == "ip" && len(args) >= 4 && args[1] == "route" {
		return []byte("default via 192.0.2.1 dev eth0 proto static\n"), nil
	}
	if name == "tc" && f.failQdisc {
		return []byte("RTNETLINK answers: Operation not supported"), errors.New("exit 2")
	}
	if (name == "ip" && len(args) >= 4 && args[3] == "ifb0") || name == "modprobe" {
		if f.noIFB {
			return []byte("no ifb"), errors.New("exit 1")
		}
		return nil, nil
	}
	_ = stdin
	return nil, nil
}

func TestTrafficApplyProtectsDefaultClass999AndIsolatesTable(t *testing.T) {
	runner := &fakeTrafficRunner{noIFB: true}
	svc := NewServiceWithRunner(runner)

	// 1. 状态探测
	stResp, err := svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "traffic.status", ID: "proxy.advanced"})
	if err != nil || !stResp.OK {
		t.Fatalf("status failed: err=%v resp=%+v", err, stResp)
	}
	var st StatusPayload
	if err := json.Unmarshal(stResp.ResultJSON, &st); err != nil {
		t.Fatal(err)
	}
	if !st.Supported || st.UplinkIFBSupported || st.EgressInterface != "eth0" {
		t.Fatalf("unexpected status: %+v", st)
	}

	// 2. 应用两条每用户限速规则（无 ifb 时应优雅降级 degraded_uplink=true）
	in, _ := json.Marshal(ApplyInput{
		ExpectedRevision: st.Revision,
		Classes: []ClassSpec{
			{TrafficMark: 0x5101, DownLimitKbps: 50000, UpLimitKbps: 20000},
			{TrafficMark: 0x5102, DownLimitKbps: 100000, UpLimitKbps: 0},
		},
	})
	apResp, err := svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "traffic.apply", ID: "proxy.advanced", ParamsJSON: in})
	if err != nil || !apResp.OK {
		t.Fatalf("apply failed: err=%v resp=%+v", err, apResp)
	}
	var ap ApplyPayload
	if err := json.Unmarshal(apResp.ResultJSON, &ap); err != nil {
		t.Fatal(err)
	}
	if !ap.DegradedUplink || ap.Revision == st.Revision {
		t.Fatalf("unexpected apply result: %+v", ap)
	}

	joined := strings.Join(runner.cmds, "\n")
	if !strings.Contains(joined, "htb default 999") || !strings.Contains(joined, "classid 1:999 htb rate 10000mbit ceil 10000mbit prio 0") {
		t.Fatalf("default protection class 1:999 missing in cmds:\n%s", joined)
	}
	if !strings.Contains(joined, "classid 1:101 htb rate 50000kbit") || !strings.Contains(joined, "handle 20737 fw flowid 1:101") {
		t.Fatalf("user class 1:101 missing in cmds:\n%s", joined)
	}
	if strings.Contains(joined, "table inet qwq ") {
		t.Fatalf("must never touch firewall table inet qwq:\n%s", joined)
	}

	// 3. 非法 mark 必须拒绝
	badIn, _ := json.Marshal(ApplyInput{Classes: []ClassSpec{{TrafficMark: 0x1000, DownLimitKbps: 1000}}})
	badResp, _ := svc.Run(t.Context(), sandbox.CapabilityRequest{Op: "traffic.apply", ID: "proxy.advanced", ParamsJSON: badIn})
	if badResp.OK || badResp.Code != "VALIDATION_FAILED" {
		t.Fatalf("expected VALIDATION_FAILED for out-of-range mark, got %+v", badResp)
	}

	// 4. 容器不支持 qdisc 时诚实降级
	containerSvc := NewServiceWithRunner(&fakeTrafficRunner{failQdisc: true})
	cResp, _ := containerSvc.Run(t.Context(), sandbox.CapabilityRequest{Op: "traffic.status", ID: "proxy.advanced"})
	var cSt StatusPayload
	_ = json.Unmarshal(cResp.ResultJSON, &cSt)
	if cSt.Supported || cSt.DegradedReason != "KERNEL_QDISC_UNAVAILABLE" {
		t.Fatalf("expected graceful container degradation, got %+v", cSt)
	}
}
