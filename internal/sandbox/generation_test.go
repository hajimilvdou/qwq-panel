// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"errors"
	"strings"
	"testing"
)

// ======================== 缺属性不能获得默认授权，旧版本能力必须明确 ========================

func generationProfileText(pid string) string {
	return "MainPID=" + pid + "\nControlGroup=/system.slice/qwq-plugin@alpha.service\nType=exec\nDynamicUser=yes\n" +
		"KillMode=control-group\nRemainAfterExit=no\nSendSIGKILL=yes\nInvocationID=0123456789abcdef0123456789abcdef\nExitType=main\n"
}

func TestGenerationLoadedProfileRejectsMissingAndUnsafeProperties(t *testing.T) {
	original := generationProfileText("42")
	if _, err := ParseGenerationProfile("alpha", 255, original); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(original), "\n") {
		t.Run("missing-"+strings.SplitN(line, "=", 2)[0], func(t *testing.T) {
			if _, err := ParseGenerationProfile("alpha", 255, strings.Replace(original, line+"\n", "", 1)); !errors.Is(err, ErrGenerationProfile) {
				t.Fatalf("缺失 loaded 属性未拒绝：%v", err)
			}
		})
	}
	for _, change := range []struct{ before, after string }{
		{"MainPID=42", "MainPID=1"}, {"Type=exec", "Type=forking"},
		{"DynamicUser=yes", "DynamicUser=no"}, {"KillMode=control-group", "KillMode=process"},
		{"RemainAfterExit=no", "RemainAfterExit=yes"}, {"SendSIGKILL=yes", "SendSIGKILL=no"},
		{"ExitType=main", "ExitType=cgroup"}, {"InvocationID=0123456789abcdef0123456789abcdef", "InvocationID="},
		{"ControlGroup=/system.slice/qwq-plugin@alpha.service", "ControlGroup=/system.slice/qwq-plugin@beta.service"},
		{"DynamicUser=yes", "DynamicUser=true"},
	} {
		if _, err := ParseGenerationProfile("alpha", 255, strings.Replace(original, change.before, change.after, 1)); !errors.Is(err, ErrGenerationProfile) {
			t.Fatalf("弱 loaded 属性未拒绝：%v", err)
		}
	}
	if _, err := ParseGenerationProfile("alpha", 255, original+"KillMode=control-group\n"); !errors.Is(err, ErrGenerationProfile) {
		t.Fatal("重复属性未拒绝")
	}
	if err := (LoadedGenerationProfile{}).Validate("alpha"); !errors.Is(err, ErrGenerationProfile) {
		t.Fatal("未解析零值获得停止授权")
	}
}

func TestGenerationExitTypeUsesVerifiedSystemdVersion(t *testing.T) {
	without := strings.Replace(generationProfileText("42"), "ExitType=main\n", "", 1)
	for _, version := range []uint32{247, 249} {
		if _, err := ParseGenerationProfile("alpha", version, without); err != nil {
			t.Fatalf("旧版本 main 语义未复用：%v", err)
		}
	}
	for _, version := range []uint32{0, 246, 250, 255} {
		if _, err := ParseGenerationProfile("alpha", version, without); !errors.Is(err, ErrGenerationProfile) {
			t.Fatalf("版本 %d 缺属性未拒绝：%v", version, err)
		}
	}
}

func TestGenerationCompletionRequiresOriginalGroupEmpty(t *testing.T) {
	if !errors.Is((StopObservation{OriginalExited: true, OriginalCgroupEmpty: true}).ValidateCompleted("alpha", ProcessProof{}), ErrGenerationUnconfirmed) {
		t.Fatal("零身份得到完成证明")
	}
	proof := ProcessProof{Version: 1, Unit: "qwq-plugin@alpha.service", PID: 42, KernelStartTicks: 123, UID: 1234,
		BootID: "0123456789abcdef0123456789abcdef", InvocationID: "fedcba9876543210fedcba9876543210",
		Cgroup: "/system.slice/qwq-plugin@alpha.service", CgroupDevice: 1, CgroupInode: 2}
	if err := proof.Validate("alpha"); err != nil {
		t.Fatal(err)
	}
	for _, observation := range []StopObservation{{Proof: proof, OriginalExited: true}, {Proof: proof, OriginalCgroupEmpty: true}} {
		if !errors.Is(observation.ValidateCompleted("alpha", proof), ErrGenerationUnconfirmed) {
			t.Fatal("原主退出或新代次不能替代全旧组退出")
		}
	}
	if err := (StopObservation{Proof: proof, OriginalExited: true, OriginalCgroupEmpty: true}).ValidateCompleted("alpha", proof); err != nil {
		t.Fatal(err)
	}
	changed := proof
	changed.CgroupInode++
	if !errors.Is((StopObservation{Proof: changed, OriginalExited: true, OriginalCgroupEmpty: true}).ValidateCompleted("alpha", proof), ErrGenerationUnconfirmed) {
		t.Fatal("替换控制组获得原完成证明")
	}
}
