// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// 删除前校验所有固定根与 ID；取消、不可信根和路径穿越不得影响其他文件。
// ============================================================================

func TestPurgePluginDataRejectsUnsafeInput(t *testing.T) {
	root := t.TempDir()
	trust := TrustPolicy{UID: os.Getuid(), StopAt: root}
	for _, id := range []string{"", "..", "../alpha", "alpha/beta"} {
		if _, err := PurgePluginData(t.Context(), trust, id, root); err == nil {
			t.Fatalf("accepted id %q", id)
		}
	}
	for _, path := range []string{"", "/", "relative", root + "/../other"} {
		if _, err := PurgePluginData(t.Context(), trust, "alpha", path); err == nil {
			t.Fatalf("accepted root %q", path)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := PurgePluginData(ctx, trust, "alpha", root); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled purge=%v", err)
	}
}

func TestPurgePluginDataRefusesWritableRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "data")
	if err := os.MkdirAll(filepath.Join(root, "alpha"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgePluginData(t.Context(), TrustPolicy{UID: os.Getuid(), StopAt: base}, "alpha", root); err == nil {
		t.Fatal("accepted a writable root")
	}
	if _, err := os.Stat(filepath.Join(root, "alpha")); err != nil {
		t.Fatalf("untrusted-root rejection removed data: %v", err)
	}
}
