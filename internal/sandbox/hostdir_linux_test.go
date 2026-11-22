// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestHostDirWithLimitedCapabilities 使用与安装 helper 相同的能力缺口，
// 防止普通 root 单测持有 CAP_FOWNER 时掩盖“先移交属主再 chmod”的错误。
func TestHostDirWithLimitedCapabilities(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("restricted-capability probe requires root")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("util-linux setpriv is unavailable")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, setpriv, "--bounding-set=-fowner,-fsetid", "--", executable, "-test.run=^TestHostDirLimitedCapabilitiesChild$")
	command.Env = append(os.Environ(), "QWQ_HOSTDIR_LIMITED_CAPS=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("limited helper capabilities: %v\n%s", err, output)
	}
}

func TestHostDirLimitedCapabilitiesChild(t *testing.T) {
	if os.Getenv("QWQ_HOSTDIR_LIMITED_CAPS") != "1" {
		t.Skip("subprocess probe")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, hostDirName), 0o750); err != nil {
		t.Fatal(err)
	}
	rt, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := ensureHostDir(rt, "limited", 65534, 65534); err != nil {
			t.Fatalf("create/reuse host directory: %v", err)
		}
		info, err := os.Stat(filepath.Join(root, hostDirName, "limited"))
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != 65534 || stat.Gid != 65534 || stat.Mode&0o7777 != hostDirMode {
			t.Fatal("host directory lost its target owner or setgid")
		}
	}
}
