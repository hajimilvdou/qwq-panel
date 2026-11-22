// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ======================== 独立真机门禁：必须在 Root 自有 32M/16Tasks/六 capability helper 中运行 ========================

func TestGenerationPerfNativeSystemd(t *testing.T) {
	if os.Getenv("QWQ_GENERATION_PERF_NATIVE") != "1" {
		t.Skip("需要 Root 自有 helper namespace；普通构建机不替代真实 Go 停止门禁")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 24*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		t.Fatal("native helper must be root with the exact narrow bounding set")
	}
	source, runtime := os.Getenv("QWQ_GENERATION_PROBE_SOURCE"), os.Getenv("QWQ_GENERATION_PROBE_RUNTIME")
	if !strings.HasPrefix(source, "/run/qwq-perf-source-") || !strings.HasPrefix(runtime, "/run/qwq-perf-sandbox-") ||
		filepath.Clean(source) != source || filepath.Clean(runtime) != runtime {
		t.Fatal("explicit owned helper source/runtime are required")
	}
	nativeGenerationPerfCapabilities(t)
	nativeGenerationPerfResources(t, ctx, "before-native")
	for _, name := range []string{"normal", "child", "restart"} {
		t.Run(name, func(t *testing.T) { nativeGenerationPerfCase(t, ctx, source, runtime, name) })
	}
	nativeGenerationPerfResources(t, ctx, "after-native")
}

func nativeGenerationPerfCommand(ctx context.Context, name string, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("owned native command failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func nativeGenerationPerfProperties(ctx context.Context, unit string) (map[string]string, error) {
	output, err := nativeGenerationPerfCommand(ctx, "systemctl", "show", "--no-pager", "--property=LoadState", "--property=Description", "--property=MainPID", "--property=ControlGroup", unit)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			return nil, errors.New("owned native profile is malformed")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("owned native profile has duplicate fields")
		}
		values[key] = value
	}
	return values, nil
}

func nativeGenerationPerfCleanup(t *testing.T, unit, runtime, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	profile, err := nativeGenerationPerfProperties(ctx, unit)
	if err != nil {
		t.Errorf("owned native cleanup profile: %v", err)
		return
	}
	if profile["LoadState"] != "not-found" {
		if profile["Description"] != marker || (profile["ControlGroup"] != "" && CgroupUnit("0::"+profile["ControlGroup"]) != unit) {
			t.Error("owned native cleanup marker changed; refusing named stop")
			return
		}
		if _, err := nativeGenerationPerfCommand(ctx, "systemctl", "stop", unit); err != nil {
			t.Errorf("owned native cleanup stop: %v", err)
			return
		}
	}
	for {
		profile, err = nativeGenerationPerfProperties(ctx, unit)
		_, runtimeErr := os.Lstat(runtime)
		if err == nil && profile["LoadState"] == "not-found" && errors.Is(runtimeErr, os.ErrNotExist) {
			t.Log("owned_native_target_cleanup=pass")
			return
		}
		select {
		case <-ctx.Done():
			t.Error("owned native unit/runtime did not get collected")
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func nativeGenerationPerfCase(t *testing.T, ctx context.Context, source, helperRuntime, name string) {
	t.Helper()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(random[:])
	id := "genprobe." + token
	unit, _, err := UnitNames(id)
	if err != nil {
		t.Fatal(err)
	}
	runtimeName := "qwq-gen-native-" + token
	runtime := filepath.Join("/run", runtimeName)
	marker := "owned Go populated probe " + token
	profile, err := nativeGenerationPerfProperties(ctx, unit)
	if err != nil || profile["LoadState"] != "not-found" {
		t.Fatalf("owned native target already exists or could not be checked: %v", err)
	}
	if _, err := os.Lstat(runtime); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned native runtime already exists or could not be checked")
	}
	owned, err := json.Marshal(map[string]string{"unit": unit, "runtime": runtime, "marker": marker, "case": name})
	if err != nil {
		t.Fatal(err)
	}
	// 先把自有目标交给外部 Root launcher；OOM/SIGKILL 无法运行 Go defer 时仍可受检清理。
	fmt.Printf("native_owned_target=%s\n", owned)
	// 使用已冻结 Python fixture 的 TARGET 单一来源，避免重写子进程/TERM 行为。
	fixtureProgram, err := nativeGenerationPerfCommand(ctx, "python3", "-I", "-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import fixture; print(fixture.TARGET)", source)
	if err != nil {
		t.Fatal(err)
	}
	restart, mode := "no", "normal"
	if name == "restart" {
		restart = "always"
	}
	if name == "child" {
		mode = "child"
	}
	args := []string{"--quiet", "--collect", "--unit=" + unit, "--description=" + marker, "--service-type=exec"}
	for _, property := range []string{"DynamicUser=yes", "KillMode=control-group", "RemainAfterExit=no", "SendSIGKILL=yes", "ExitType=main", "TimeoutStopSec=1500ms", "RuntimeMaxSec=12s", "RuntimeDirectory=" + runtimeName, "RuntimeDirectoryMode=0700", "TasksMax=16", "MemoryMax=32M", "Restart=" + restart, "RestartSec=50ms"} {
		args = append(args, "--property", property)
	}
	args = append(args, "--", "/usr/bin/python3", "-u", "-c", fixtureProgram, mode, runtime)
	defer nativeGenerationPerfCleanup(t, unit, runtime, marker)
	if _, err := nativeGenerationPerfCommand(ctx, "systemd-run", args...); err != nil {
		t.Fatal(err)
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	var ready struct {
		PID   int  `json:"pid"`
		UID   int  `json:"uid"`
		Child *int `json:"child"`
	}
	for {
		body, readErr := os.ReadFile(filepath.Join(runtime, "ready.json"))
		if readErr == nil && len(body) <= 8192 && json.Unmarshal(body, &ready) == nil && ready.PID > 1 && ready.UID > 0 {
			break
		}
		select {
		case <-readyCtx.Done():
			t.Fatal("owned native nonroot target did not become ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	pinner, err := NewGenerationPinner(GenerationKernelPaths{BootIDPath: filepath.Join(helperRuntime, "kernel-boot-id")}, NewExecSystemctl(ExecRunner{}))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := pinner.Pin(ctx, id, nil)
	if err != nil {
		t.Fatalf("native observe Pin: %v", err)
	}
	proof := observed.Proof()
	if err := observed.Close(); err != nil {
		t.Fatal(err)
	}
	if proof.PID != ready.PID || int(proof.UID) != ready.UID {
		t.Fatal("native proof differs from the owned ready process")
	}
	pinned, err := pinner.PinForStop(ctx, id, proof)
	if err != nil {
		t.Fatalf("native PinForStop: %v", err)
	}
	native := pinned.(*linuxPinnedGeneration)
	delayed := &nativeGenerationPerfDelay{PinnedGeneration: pinned, until: time.Now().Add(120 * time.Millisecond)}
	observation, err := StopPinnedGeneration(ctx, id, proof, delayed, GenerationStopPolicy{})
	if err != nil {
		t.Fatalf("native original stop: %v", err)
	}
	if observation.ValidateCompleted(id, proof) != nil || !native.watcher.sealed || !native.watcher.closed {
		t.Fatal("native stop did not produce full original pidfd/zero evidence")
	}
	if name == "child" && !delayed.blockedPopulated {
		t.Fatal("native child did not exercise original-exited/still-populated rejection")
	}
	var samples uint64
	for _, ring := range native.watcher.rings {
		samples += ring.consumed
		if ring.mapping != nil || !ring.closed || ring.captureFD != -1 || ring.guardFD != -1 || ring.bufferFD != -1 {
			t.Fatal("native owned mmap/FD were not closed")
		}
	}
	if samples != 1 {
		t.Fatalf("native expected one explicit zero, got %d samples", samples)
	}
	if name == "restart" {
		current, err := nativeGenerationPerfProperties(ctx, unit)
		if err != nil {
			t.Fatal(err)
		}
		newPID, err := strconv.Atoi(current["MainPID"])
		if err != nil || newPID <= 1 || newPID == proof.PID {
			t.Fatal("native new generation is not independently live")
		}
		newFD, err := unix.PidfdOpen(newPID, 0)
		if err != nil {
			t.Fatal(err)
		}
		fds := []unix.PollFd{{Fd: int32(newFD), Events: unix.POLLIN}}
		_, pollErr := unix.Poll(fds, 0)
		closeErr := closeGenerationFD(newFD)
		if pollErr != nil || closeErr != nil || fds[0].Revents != 0 {
			t.Fatal("native replacement process exited or was touched")
		}
		newGroup, err := pinGenerationCgroup(ctx, "/sys/fs/cgroup", current["ControlGroup"])
		if err != nil {
			t.Fatal(err)
		}
		newInode := newGroup.inode
		if err := newGroup.Close(); err != nil || newInode == proof.CgroupInode {
			t.Fatal("native new cgroup was not independent")
		}
	}
	t.Logf("native_original_zero=pass case=%s samples=%d late_read_ms=120 original_exited=%v child_negative=%v no_named_stop=true", name, samples, observation.OriginalExited, delayed.blockedPopulated)
	nativeGenerationPerfResources(t, ctx, "after-"+name)
}

type nativeGenerationPerfDelay struct {
	PinnedGeneration
	until            time.Time
	blockedPopulated bool
}

func (delayed *nativeGenerationPerfDelay) OriginalCgroupEmpty(ctx context.Context) (bool, error) {
	if remaining := time.Until(delayed.until); remaining > 0 {
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
		}
	}
	empty, err := delayed.PinnedGeneration.OriginalCgroupEmpty(ctx)
	if err == nil && !empty {
		exited, exitErr := delayed.PinnedGeneration.OriginalExited(ctx)
		if exitErr != nil {
			return false, exitErr
		}
		delayed.blockedPopulated = delayed.blockedPopulated || exited
	}
	return empty, err
}

func nativeGenerationPerfCapabilities(t *testing.T) {
	t.Helper()
	body, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	wanted := uint64(1<<0 | 1<<1 | 1<<5 | 1<<6 | 1<<7 | 1<<38)
	values := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		if key, value, found := strings.Cut(line, ":"); found {
			values[key] = strings.TrimSpace(value)
		}
	}
	for _, name := range []string{"CapEff", "CapBnd"} {
		actual, err := strconv.ParseUint(values[name], 16, 64)
		if err != nil || actual != wanted {
			t.Fatal("native actual capabilities differ from the exact six requested capabilities")
		}
	}
	if values["NoNewPrivs"] != "1" || values["Seccomp"] != "2" {
		t.Fatal("native helper lacks NoNewPrivileges/seccomp")
	}
	t.Log("native_exact_six_caps=pass no_SYS_ADMIN=true no_SYS_PTRACE=true no_BPF=true")
}

func nativeGenerationPerfResources(t *testing.T, ctx context.Context, stage string) {
	t.Helper()
	body, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	path, err := UnifiedCgroupPath(string(body))
	if err != nil {
		t.Fatal(err)
	}
	group, err := pinGenerationCgroup(ctx, "/sys/fs/cgroup", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := group.Close(); err != nil {
			t.Error(err)
		}
	}()
	values := make(map[string]uint64)
	for _, name := range []string{"memory.current", "memory.max", "memory.peak", "pids.current", "pids.max"} {
		body, err := readPinnedGenerationFile(ctx, group.fd, name, 128)
		if err != nil {
			t.Fatal(err)
		}
		values[name], err = strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
	}
	if values["memory.max"] != 32<<20 || values["pids.max"] != 16 {
		t.Fatal("native helper resource ceiling differs from 32M/16Tasks")
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native_resources stage=%s values=%s", stage, encoded)
}
