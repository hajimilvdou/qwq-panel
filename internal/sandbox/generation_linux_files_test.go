// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ======================== 目录 FD 回归使用普通文件 fixture；真实 v2 检查另有明确用例 ========================

func openGenerationCgroupFixture(t *testing.T, directory string) *pinnedGenerationCgroup {
	t.Helper()
	fd, err := unix.Open(directory, generationDirectoryFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	eventsFD, err := openPinnedGenerationFile(generationTestContext(t), fd, "cgroup.events")
	if err != nil {
		t.Fatal(errors.Join(err, closeGenerationFD(fd)))
	}
	pinned := &pinnedGenerationCgroup{fd: fd, eventsFD: eventsFD}
	t.Cleanup(func() {
		if err := pinned.Close(); err != nil {
			t.Errorf("关闭 cgroup 文件 fixture：%v", err)
		}
	})
	return pinned
}

func writeGenerationEventsFixture(t *testing.T, directory, events string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "cgroup.events"), []byte(events), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationCgroupFDDoesNotFollowReplacedPath(t *testing.T) {
	root := t.TempDir()
	active, original := filepath.Join(root, "active"), filepath.Join(root, "original")
	writeGenerationEventsFixture(t, active, "populated 1\nfrozen 0\n")
	pinned := openGenerationCgroupFixture(t, active)
	if err := os.Rename(active, original); err != nil {
		t.Fatal(err)
	}
	writeGenerationEventsFixture(t, active, "populated 0\nfrozen 0\n")
	empty, err := pinned.empty(generationTestContext(t))
	if err != nil || empty {
		t.Fatalf("原 FD 追到替换目录的 populated=0：empty=%v %v", empty, err)
	}
	writeGenerationEventsFixture(t, original, "populated 0\nfrozen 0\n")
	empty, err = pinned.empty(generationTestContext(t))
	if err != nil || !empty {
		t.Fatalf("原目录的明确 populated=0 未识别：empty=%v %v", empty, err)
	}
}

func TestGenerationRemovedCgroupFDCannotInferEmptyFromNewPath(t *testing.T) {
	active := filepath.Join(t.TempDir(), "active")
	writeGenerationEventsFixture(t, active, "populated 1\n")
	pinned := openGenerationCgroupFixture(t, active)
	if err := os.Remove(filepath.Join(active, "cgroup.events")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(active); err != nil {
		t.Fatal(err)
	}
	writeGenerationEventsFixture(t, active, "populated 0\n")
	if empty, err := pinned.empty(generationTestContext(t)); empty || (err != nil && !errors.Is(err, ErrGenerationUnconfirmed)) {
		t.Fatalf("旧目录消失被推断为完成：empty=%v %v", empty, err)
	}
}

func TestGenerationCgroupEventsFDDoesNotFollowReplacementFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "original")
	writeGenerationEventsFixture(t, directory, "populated 1\n")
	pinned := openGenerationCgroupFixture(t, directory)
	if err := os.Rename(filepath.Join(directory, "cgroup.events"), filepath.Join(directory, "old.events")); err != nil {
		t.Fatal(err)
	}
	writeGenerationEventsFixture(t, directory, "populated 0\n")
	if empty, err := pinned.empty(generationTestContext(t)); err != nil || empty {
		t.Fatalf("目录内同名新文件替代原 eventsFD：empty=%v %v", empty, err)
	}
}

func TestGenerationCgroupClosePreventsReadOfReusedFDNumber(t *testing.T) {
	root := t.TempDir()
	original, replacement := filepath.Join(root, "original"), filepath.Join(root, "replacement")
	writeGenerationEventsFixture(t, original, "populated 1\n")
	writeGenerationEventsFixture(t, replacement, "populated 0\n")
	oldPinned, newPinned := openGenerationCgroupFixture(t, original), openGenerationCgroupFixture(t, replacement)
	staleFD := oldPinned.eventsFD
	if err := oldPinned.Close(); err != nil {
		t.Fatal(err)
	}
	reusedFD, err := unix.FcntlInt(uintptr(newPinned.eventsFD), unix.F_DUPFD_CLOEXEC, staleFD)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeGenerationFD(reusedFD); err != nil {
			t.Errorf("关闭 cgroup 复用测试 FD：%v", err)
		}
	})
	if reusedFD != staleFD {
		t.Skip("原 FD 已被 runtime 占用，不能安全覆盖；此分支须在独立 Linux 门禁重跑")
	}
	if empty, err := oldPinned.empty(generationTestContext(t)); empty || !errors.Is(err, ErrGenerationClosed) {
		t.Fatalf("Close 后误读替换组：empty=%v %v", empty, err)
	}
}

func TestGenerationCgroupEventsRequireExplicitUniquePopulated(t *testing.T) {
	for _, data := range []string{"", "frozen 0\n", "populated\n", "populated 0\npopulated 1\n", "populated 2\n", "populated 0 extra\n"} {
		if empty, err := parseGenerationCgroupEvents(data); empty || !errors.Is(err, ErrGenerationUnconfirmed) {
			t.Fatalf("歧义 cgroup.events 未拒绝：%q empty=%v %v", data, empty, err)
		}
	}
	active := filepath.Join(t.TempDir(), "active")
	writeGenerationEventsFixture(t, active, strings.Repeat("frozen 0\n", 600)+"populated 0\n")
	pinned := openGenerationCgroupFixture(t, active)
	if empty, err := pinned.empty(generationTestContext(t)); empty || !errors.Is(err, ErrGenerationUnconfirmed) {
		t.Fatalf("超界 events 未拒绝：empty=%v %v", empty, err)
	}
	ctx, cancel := context.WithCancel(generationTestContext(t))
	cancel()
	if _, err := pinned.empty(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消的旧组读取未停止：%v", err)
	}
	fd, eventsFD := pinned.fd, pinned.eventsFD
	if err := pinned.Close(); err != nil {
		t.Fatal(err)
	}
	requireGenerationFDClosed(t, fd)
	requireGenerationFDClosed(t, eventsFD)
}

// ======================== 真实 v2：普通子进程退出后，与测试宿主共用的组仍 populated=1 ========================

func TestGenerationRealPIDFDExitDoesNotMeanRealCgroupEmpty(t *testing.T) {
	child := startGenerationKernelChild(t)
	process, snapshot := pinGenerationTestKernel(t, child)
	cgroupPath, err := UnifiedCgroupPath(snapshot.cgroupData)
	if err != nil {
		t.Skipf("普通子进程未处于可固定的非根 v2 组；真实插件组须另测：%v", err)
	}
	// 构建机245使用hybrid，v2实测挂在unified；只测试入口允许显式选择已核挂载点。
	rootPath := os.Getenv("QWQ_GENERATION_TEST_CGROUP_ROOT")
	if rootPath == "" {
		rootPath = "/sys/fs/cgroup"
	}
	cgroup, err := pinGenerationCgroup(generationTestContext(t), rootPath, cgroupPath)
	if err != nil {
		t.Fatalf("真实只读 v2 目录 Pin 失败：%v", err)
	}
	t.Cleanup(func() {
		if err := cgroup.Close(); err != nil {
			t.Errorf("关闭真实 v2 目录：%v", err)
		}
	})
	ctx, cancel := context.WithTimeout(generationTestContext(t), 2*time.Second)
	defer cancel()
	if err := child.exitNormally(ctx); err != nil {
		t.Fatal(err)
	}
	exited, err := process.exited(ctx)
	if err != nil || !exited {
		t.Fatalf("原真正 pidfd 未退出：%v %v", exited, err)
	}
	empty, err := cgroup.empty(ctx)
	if err != nil || empty {
		t.Fatalf("包含测试宿主的真实 v2 组意外为空：%v %v", empty, err)
	}
	// 这里只验证完成谓词；完整 proof fixture 不充当真实插件身份或弱生产 profile。
	proof := generationStopTestProof()
	observation := StopObservation{Proof: proof, OriginalExited: exited, OriginalCgroupEmpty: empty}
	if !errors.Is(observation.ValidateCompleted("alpha", proof), ErrGenerationUnconfirmed) {
		t.Fatal("真正主 pidfd 退出被误当成真实 v2 组清空")
	}
}

// ======================== 生产门禁：普通目录、普通子进程和未解析 profile 均不获停止授权 ========================

type generationProfileReaderFunc func(context.Context, string) (LoadedGenerationProfile, error)

func (read generationProfileReaderFunc) ReadGenerationProfile(ctx context.Context, pluginID string) (LoadedGenerationProfile, error) {
	return read(ctx, pluginID)
}

func TestGenerationProductionPinRejectsUnparsedProfileBeforeProcOpen(t *testing.T) {
	reader := generationProfileReaderFunc(func(context.Context, string) (LoadedGenerationProfile, error) {
		return LoadedGenerationProfile{}, nil
	})
	pinner, err := NewGenerationPinner(GenerationKernelPaths{ProcRoot: "/qwq-generation-test-does-not-exist"}, reader)
	if err != nil {
		t.Fatal(err)
	}
	if pinned, err := pinner.Pin(generationTestContext(t), "alpha", nil); pinned != nil || !errors.Is(err, ErrGenerationProfile) {
		t.Fatalf("未解析 profile 未在内核读取前拒绝：pinned=%v %v", pinned, err)
	}
	if _, err := NewGenerationPinner(GenerationKernelPaths{}, nil); !errors.Is(err, ErrGenerationProfile) {
		t.Fatalf("空 reader 产生默认弱 Pin：%v", err)
	}
}

func TestGenerationProductionPinRejectsOrdinaryChildAsPlugin(t *testing.T) {
	child := startGenerationKernelChild(t)
	process, _ := pinGenerationTestKernel(t, child)
	pluginID := "fdprobe-" + strconv.Itoa(child.cmd.Process.Pid)
	text := strings.ReplaceAll(generationProfileText(strconv.Itoa(child.cmd.Process.Pid)), "alpha", pluginID)
	profile, err := ParseGenerationProfile(pluginID, 255, text)
	if err != nil {
		t.Fatal(err)
	}
	reader := generationProfileReaderFunc(func(context.Context, string) (LoadedGenerationProfile, error) { return profile, nil })
	pinner, err := NewGenerationPinner(GenerationKernelPaths{}, reader)
	if err != nil {
		t.Fatal(err)
	}
	if pinned, err := pinner.Pin(generationTestContext(t), pluginID, nil); pinned != nil || !errors.Is(err, ErrGenerationIdentity) {
		t.Fatalf("普通子进程绕过插件 UID/cgroup 门禁：pinned=%v %v", pinned, err)
	}
	requireGenerationKernelAlive(t, process)
}

func TestGenerationProcAndCgroupPinsRejectOrdinaryFilesystem(t *testing.T) {
	root := t.TempDir()
	opened := false
	process, _, err := pinKernelProcess(generationTestContext(t), root, os.Getpid(), func(int, int) (int, error) { opened = true; return -1, nil })
	if process != nil || !errors.Is(err, ErrGenerationIdentity) || opened {
		t.Fatalf("普通目录被当作 procfs：process=%v opened=%v %v", process, opened, err)
	}
	if pinned, err := pinGenerationCgroup(generationTestContext(t), root, "/system.slice/qwq-plugin@alpha.service"); pinned != nil || !errors.Is(err, ErrGenerationIdentity) {
		t.Fatalf("普通目录被当作 cgroup2：pinned=%v %v", pinned, err)
	}
}

func TestGenerationBootIDRequiresRealProcfsAndCanonicalUUID(t *testing.T) {
	canonical := "01234567-89ab-cdef-0123-456789abcdef\n"
	if got, err := parseGenerationBootID(canonical); err != nil || got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("内核 UUID 规范化失败：%q %v", got, err)
	}
	for _, data := range []string{"", strings.ToUpper(canonical), "00000000-0000-0000-0000-000000000000\n", canonical + "extra", " " + canonical} {
		if _, err := parseGenerationBootID(data); !errors.Is(err, ErrGenerationIdentity) {
			t.Fatalf("非规范 Boot ID 未拒绝：%q %v", data, err)
		}
	}
	file := filepath.Join(t.TempDir(), "boot-id")
	if err := os.WriteFile(file, []byte(canonical), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readGenerationBootID(generationTestContext(t), file); !errors.Is(err, ErrGenerationIdentity) {
		t.Fatalf("普通文件被当作可信 Boot ID：%v", err)
	}
}

func TestGenerationPIDFDInfoRequiresUniqueLivePid(t *testing.T) {
	if pid, err := parseGenerationPIDFDInfo("pos:\t0\nflags:\t02000002\nmnt_id:\t5\nPid:\t42\nNSpid:\t42\n"); err != nil || pid != 42 {
		t.Fatalf("真实 pidfd fdinfo 未解析：%d %v", pid, err)
	}
	for _, data := range []string{"", "Pid:\t-1\n", "Pid:\t1\n", "Pid:\t42\nPid:\t43\n", "Pid:\t42 43\n"} {
		if _, err := parseGenerationPIDFDInfo(data); !errors.Is(err, ErrGenerationIdentity) {
			t.Fatalf("歧义 pidfd fdinfo 未拒绝：%q %v", data, err)
		}
	}
}
