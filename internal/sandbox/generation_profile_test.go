// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// ======================== manager getter 回归：实际版本、完整元组、单预算和只读 argv ========================

func TestGenerationProfileGetterReadsStableManagerAndLoadedTuple(t *testing.T) {
	managerCalls, profileCalls := 0, 0
	runner := &fakeRunner{reply: func(name string, args []string) (string, error) {
		if name != "systemctl" || len(args) < 3 || args[0] != "show" || args[1] != "--no-pager" || slices.Contains(args, "--version") {
			t.Fatalf("getter执行了非只读/客户端version argv：%s %v", name, args)
		}
		if slices.Equal(args, []string{"show", "--no-pager", "--property=Version"}) {
			managerCalls++
			return "Version=255.4-1ubuntu8.18", nil
		}
		profileCalls++
		if !slices.Equal(args, []string{"show", "--no-pager", "--property=MainPID", "--property=ControlGroup", "--property=Type",
			"--property=DynamicUser", "--property=KillMode", "--property=RemainAfterExit", "--property=SendSIGKILL",
			"--property=InvocationID", "--property=ExitType", "qwq-plugin@alpha.service"}) {
			t.Fatalf("getter未使用固定派生unit/属性：%v", args)
		}
		return generationProfileText("42"), nil
	}}
	profile, err := NewExecSystemctl(runner).ReadGenerationProfile(generationTestContext(t), "alpha")
	if err != nil || profile.Validate("alpha") != nil || profile.SystemdVersion != 255 || managerCalls != 2 || profileCalls != 2 {
		t.Fatalf("实际manager/两份loaded元组不完整：%+v manager=%d profile=%d %v", profile, managerCalls, profileCalls, err)
	}
}

func TestGenerationProfileGetterOldVersionDoesNotRequestExitType(t *testing.T) {
	runner := &fakeRunner{reply: func(_ string, args []string) (string, error) {
		if slices.Contains(args, "--property=Version") {
			return "Version=249.11-0ubuntu3", nil
		}
		if slices.Contains(args, "--property=ExitType") {
			t.Fatal("旧manager被查询不存在的ExitType")
		}
		return strings.ReplaceAll(generationProfileText("42"), "ExitType=main\n", ""), nil
	}}
	profile, err := NewExecSystemctl(runner).ReadGenerationProfile(generationTestContext(t), "alpha")
	if err != nil || profile.SystemdVersion != 249 || profile.ExitType != "main" {
		t.Fatalf("已核旧版本能力未严格复用：%+v %v", profile, err)
	}
}

func TestGenerationProfileGetterRejectsChangingAndUnknownFacts(t *testing.T) {
	for _, change := range []string{"manager-major", "manager-package", "pid", "invocation", "cgroup", "unknown", "missing", "inactive", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			managerCalls, profileCalls := 0, 0
			runner := &fakeRunner{reply: func(_ string, args []string) (string, error) {
				if slices.Contains(args, "--property=Version") {
					managerCalls++
					if managerCalls == 2 && change == "manager-major" {
						return "Version=256.1", nil
					}
					if managerCalls == 2 && change == "manager-package" {
						return "Version=255.4-1ubuntu8.19", nil
					}
					return "Version=255.4-1ubuntu8.18", nil
				}
				profileCalls++
				output := generationProfileText("42")
				switch change {
				case "pid":
					if profileCalls == 2 {
						output = generationProfileText("43")
					}
				case "invocation":
					if profileCalls == 2 {
						output = strings.Replace(output, "0123456789abcdef0123456789abcdef", "1123456789abcdef0123456789abcdef", 1)
					}
				case "cgroup":
					if profileCalls == 2 {
						output = strings.Replace(output, "/system.slice/", "/other.slice/", 1)
					}
				case "unknown":
					output += "Unexpected=yes\n"
				case "missing":
					output = strings.ReplaceAll(output, "KillMode=control-group\n", "")
				case "inactive":
					output = generationProfileText("0")
				case "duplicate":
					output += "MainPID=42\n"
				}
				return output, nil
			}}
			if _, err := NewExecSystemctl(runner).ReadGenerationProfile(generationTestContext(t), "alpha"); !errors.Is(err, ErrGenerationProfile) {
				t.Fatalf("未知/变化事实%s未拒绝：%v", change, err)
			}
		})
	}
}

func TestGenerationManagerVersionRejectsClientAndMalformedOutput(t *testing.T) {
	for _, output := range []string{"", "systemd 255 (255.4-1ubuntu8.18)", "Version=systemd 255", "Version=", "version=255",
		"Other=255", "Version=255\nVersion=255", "Version=255\nOther=x", "Version=245", "Version=0255", "Version=4294967296", "Version=255foo", "Version=255.", "Version=255..4", "Version=255.4;echo"} {
		if _, _, err := parseGenerationManagerVersion(output); !errors.Is(err, ErrGenerationProfile) {
			t.Fatalf("非实际/未知manager版本被接受：%q %v", output, err)
		}
	}
}

func TestGenerationProfileGetterHonorsDeadlineAndValidatesBeforeRunner(t *testing.T) {
	systemctl := &ExecSystemctl{Runner: blockingRunner{}, Timeout: 10 * time.Millisecond}
	if _, err := systemctl.ReadGenerationProfile(generationTestContext(t), "alpha"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("getter重新放大runner预算：%v", err)
	}
	runner := &fakeRunner{}
	if _, err := NewExecSystemctl(runner).ReadGenerationProfile(generationTestContext(t), "../bad"); err == nil || len(runner.calls) != 0 {
		t.Fatalf("非法ID在argv构造前未拒绝：calls=%v %v", runner.calls, err)
	}
}
