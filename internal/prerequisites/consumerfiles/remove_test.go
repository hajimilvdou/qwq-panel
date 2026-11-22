// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ======================== 幂等清理与多代多许可完整删除 ========================

func TestRemoveIdempotentOnEmptyRootAndMissingBinding(t *testing.T) {
	store, root, _ := testStore(t)
	if err := store.Remove(context.Background(), "binding-missing"); err != nil {
		t.Fatalf("空 state 根下 Remove 应幂等成功：%v", err)
	}
	if _, err := root.Stat("tls"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("幂等 Remove 不应创建 tls 目录")
	}
	one := stage(t, store, testBinding(1), testMaterial(t))
	if err := store.Remove(context.Background(), "binding-other"); err != nil {
		t.Fatalf("不存在的绑定 Remove 应幂等成功：%v", err)
	}
	requireLoaded(t, store, one)
}

func TestRemoveDeletesMultiGenerationAndMultiProofBindingLeavesSiblingIntact(t *testing.T) {
	store, root, directory := testStore(t)
	mat1 := testMaterial(t)
	mat2 := testMaterial(t)

	// binding-a: g1 有两条同代许可（policy-r1 / policy-r2），g2 已激活。
	gen1Policy1 := stage(t, store, testBinding(1), mat1)
	b1Policy2 := testBinding(1)
	b1Policy2.PolicyRevision = "policy-r2"
	gen1Policy2 := stage(t, store, b1Policy2, mat1)
	gen2 := stage(t, store, testBinding(2), mat2)
	if _, err := store.Activate(context.Background(), nil, gen1Policy1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(context.Background(), &gen1Policy1, gen2); err != nil {
		t.Fatal(err)
	}

	// 同级 sibling 绑定 binding-b。
	siblingBinding := testBinding(1)
	siblingBinding.ID = "binding-b"
	sibling := stage(t, store, siblingBinding, testMaterial(t))
	if _, err := store.Activate(context.Background(), nil, sibling); err != nil {
		t.Fatal(err)
	}

	before := descriptorCount(t)
	if err := store.Remove(context.Background(), gen1Policy1.Binding.ID); err != nil {
		t.Fatalf("Remove 失败：%v", err)
	}
	if err := store.Remove(context.Background(), gen1Policy1.Binding.ID); err != nil {
		t.Fatalf("重复 Remove 应幂等成功：%v", err)
	}
	if after := descriptorCount(t); after != before {
		t.Fatalf("Remove 泄漏 FD：before=%d after=%d", before, after)
	}

	if _, err := os.Stat(bindingPath(directory, gen1Policy1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("绑定目录未被移除：%v", err)
	}
	if _, err := root.Stat("tls/bindings"); err != nil {
		t.Fatalf("父目录 tls/bindings 不应被移除：%v", err)
	}
	current, err := store.Current(context.Background(), gen1Policy1.Binding.ID)
	if err != nil || current != nil {
		t.Fatalf("删除后 Current 应为 nil：%v %v", current, err)
	}
	for _, removed := range []Proof{gen1Policy1, gen1Policy2, gen2} {
		_, err := store.Load(context.Background(), removed)
		requireCode(t, err, "NOT_FOUND")
	}

	siblingCurrent, err := store.Current(context.Background(), sibling.Binding.ID)
	if err != nil || !sameProof(siblingCurrent, &sibling) {
		t.Fatalf("同级绑定 current 受影响：%v", err)
	}
	requireLoaded(t, store, sibling)
}

func TestRemoveRejectsInvalidBindingIDAndClosedStore(t *testing.T) {
	store, _, _ := testStore(t)
	for _, id := range []string{"", ".", "..", "../outside", "tls/binding", "binding\\other", strings.Repeat("a", 129)} {
		err := store.Remove(context.Background(), id)
		requireCode(t, err, "CONSUMER_FILES_INVALID")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	err := store.Remove(context.Background(), "binding-a")
	requireCode(t, err, "CONSUMER_FILES_CLOSED")
}

// ======================== 篡改、软链接、陌生条目与父目录攻击防护 ========================

func TestRemoveRefusesTamperedEntriesWithoutTouchingOutsideTargets(t *testing.T) {
	sentinelContent := []byte("outside-sentinel-keep")

	setupBinding := func(t *testing.T) (*Store, string, Proof) {
		t.Helper()
		store, _, directory := testStore(t)
		one := stage(t, store, testBinding(1), testMaterial(t))
		if _, err := store.Activate(context.Background(), nil, one); err != nil {
			t.Fatal(err)
		}
		return store, directory, one
	}

	t.Run("symlink_current", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		outside := filepath.Join(t.TempDir(), "secret.txt")
		if err := os.WriteFile(outside, sentinelContent, materialMode); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(bindingPath(directory, one), currentName)
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		raw, err := os.ReadFile(outside)
		if err != nil || string(raw) != string(sentinelContent) {
			t.Fatalf("外部软链接目标被触碰：%v", err)
		}
		if _, err := os.Lstat(target); err != nil {
			t.Fatalf("可疑软链接不应被删除：%v", err)
		}
	})

	t.Run("symlink_material", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		outside := filepath.Join(t.TempDir(), "secret.pem")
		if err := os.WriteFile(outside, sentinelContent, materialMode); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(generationPath(directory, one), chainName)
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		raw, err := os.ReadFile(outside)
		if err != nil || string(raw) != string(sentinelContent) {
			t.Fatalf("外部软链接目标被触碰：%v", err)
		}
	})

	t.Run("symlink_generations", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		outsideDir := t.TempDir()
		outsideFile := filepath.Join(outsideDir, "keep.txt")
		if err := os.WriteFile(outsideFile, sentinelContent, materialMode); err != nil {
			t.Fatal(err)
		}
		genRoot := filepath.Join(bindingPath(directory, one), "generations")
		if err := os.Rename(genRoot, filepath.Join(t.TempDir(), "saved-generations")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideDir, genRoot); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		raw, err := os.ReadFile(outsideFile)
		if err != nil || string(raw) != string(sentinelContent) {
			t.Fatalf("外部目录目标被触碰：%v", err)
		}
	})

	t.Run("symlink_proof", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		outside := filepath.Join(t.TempDir(), "proof.json")
		if err := os.WriteFile(outside, sentinelContent, materialMode); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(generationPath(directory, one), proofsName, proofSnapshotName(one))
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		raw, err := os.ReadFile(outside)
		if err != nil || string(raw) != string(sentinelContent) {
			t.Fatalf("外部软链接目标被触碰：%v", err)
		}
	})

	t.Run("hardlink_material", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		extra := filepath.Join(t.TempDir(), "extra.key")
		key := filepath.Join(generationPath(directory, one), keyName)
		if err := os.Link(key, extra); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		if _, err := os.Lstat(key); err != nil {
			t.Fatalf("多硬链接文件不应被删除：%v", err)
		}
	})

	t.Run("fifo_current", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		target := filepath.Join(bindingPath(directory, one), currentName)
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(target, materialMode); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		requireCode(t, store.Remove(ctx, one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		if _, err := os.Lstat(target); err != nil {
			t.Fatalf("FIFO 不应被删除：%v", err)
		}
	})

	t.Run("wrong_mode_file", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		target := filepath.Join(generationPath(directory, one), materialName)
		if err := os.Chmod(target, 0o644); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		if _, err := os.Lstat(target); err != nil {
			t.Fatalf("权限异常文件不应被删除：%v", err)
		}
	})

	t.Run("foreign_file_in_binding", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		foreign := filepath.Join(bindingPath(directory, one), "foreign.txt")
		if err := os.WriteFile(foreign, sentinelContent, materialMode); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		if _, err := os.Stat(foreign); err != nil {
			t.Fatalf("陌生文件不应被删除：%v", err)
		}
		requireLoaded(t, store, one)
	})

	t.Run("unexpected_subdir_in_binding", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		extraDir := filepath.Join(bindingPath(directory, one), "unexpected-subdir")
		if err := os.Mkdir(extraDir, directoryMode); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		if _, err := os.Stat(extraDir); err != nil {
			t.Fatalf("陌生子目录不应被删除：%v", err)
		}
		requireLoaded(t, store, one)
	})

	for _, badGen := range []string{".stage-g9-deadbeef", "g0", "g01"} {
		t.Run("unexpected_generation_"+badGen, func(t *testing.T) {
			store, directory, one := setupBinding(t)
			extraDir := filepath.Join(bindingPath(directory, one), "generations", badGen)
			if err := os.Mkdir(extraDir, directoryMode); err != nil {
				t.Fatal(err)
			}
			requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
			if _, err := os.Stat(extraDir); err != nil {
				t.Fatalf("非规范 generation 目录不应被删除：%v", err)
			}
		})
	}

	t.Run("unexpected_file_in_generation", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		extraFile := filepath.Join(generationPath(directory, one), "extra.txt")
		if err := os.WriteFile(extraFile, sentinelContent, materialMode); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		if _, err := os.Stat(extraFile); err != nil {
			t.Fatalf("generation 内陌生文件不应被删除：%v", err)
		}
	})

	t.Run("unexpected_file_in_proofs", func(t *testing.T) {
		store, directory, one := setupBinding(t)
		extraFile := filepath.Join(generationPath(directory, one), proofsName, "p-invalid.json")
		if err := os.WriteFile(extraFile, sentinelContent, materialMode); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		if _, err := os.Stat(extraFile); err != nil {
			t.Fatalf("proofs 内陌生文件不应被删除：%v", err)
		}
	})
}

func TestRemoveRefusesTamperedParentDirectories(t *testing.T) {
	for _, relative := range []string{".", "tls", "tls/bindings", "tls/bindings/binding-a"} {
		t.Run("mode_"+relative, func(t *testing.T) {
			store, _, directory := testStore(t)
			one := stage(t, store, testBinding(1), testMaterial(t))
			target := filepath.Join(directory, filepath.FromSlash(relative))
			if err := os.Chmod(target, 0o750); err != nil {
				t.Fatal(err)
			}
			requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
			if err := os.Chmod(target, directoryMode); err != nil {
				t.Fatal(err)
			}
			requireLoaded(t, store, one)
		})
	}

	t.Run("symlink_bindings_parent", func(t *testing.T) {
		store, _, directory := testStore(t)
		one := stage(t, store, testBinding(1), testMaterial(t))
		outside := t.TempDir()
		outsideBinding := filepath.Join(outside, one.Binding.ID)
		if err := os.Mkdir(outsideBinding, directoryMode); err != nil {
			t.Fatal(err)
		}
		bindingsPath := filepath.Join(directory, "tls", "bindings")
		if err := os.Rename(bindingsPath, bindingsPath+".saved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, bindingsPath); err != nil {
			t.Fatal(err)
		}
		requireCode(t, store.Remove(context.Background(), one.Binding.ID), "CONSUMER_FILES_UNSAFE")
		if _, err := os.Stat(outsideBinding); err != nil {
			t.Fatalf("父目录软链接外部目标被触碰：%v", err)
		}
	})
}

// ======================== 取消阻塞锁与真实 backing owner 清理 ========================

func TestRemoveCancelledWhileBlockedOnBindingLock(t *testing.T) {
	store, root, _ := testStore(t)
	other := secondStore(t, root)
	one := stage(t, store, testBinding(1), testMaterial(t))
	if _, err := store.Activate(context.Background(), nil, one); err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	before := descriptorCount(t)
	err := other.Remove(cancelled, one.Binding.ID)
	requireCode(t, err, "CANCELLED")
	if !errors.Is(err, context.Canceled) {
		t.Fatal("预取消 Remove 原因不可检索")
	}
	if after := descriptorCount(t); after != before {
		t.Fatalf("预取消 Remove 泄漏 FD：before=%d after=%d", before, after)
	}

	path, err := store.openBinding(context.Background(), one.Binding.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	defer path.close()
	if err := unix.Flock(int(path.last().Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(path.last().Fd()), unix.LOCK_UN)

	before = descriptorCount(t)
	bounded, stop := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer stop()
	started := time.Now()
	err = other.Remove(bounded, one.Binding.ID)
	requireCode(t, err, "CANCELLED")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("Remove 阻塞等待绑定锁未在 context 到期后及时结束")
	}
	if after := descriptorCount(t); after != before {
		t.Fatalf("锁阻塞取消 Remove 泄漏 FD：before=%d after=%d", before, after)
	}

	current, err := store.Current(context.Background(), one.Binding.ID)
	if err != nil || !sameProof(current, &one) {
		t.Fatalf("取消的 Remove 破坏了现有绑定：%v", err)
	}
	requireLoaded(t, store, one)
}

func TestRootRemoveUsesActualStateBackingOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("真实 root→backing owner 清理须由 Root Linux 执行；普通用户测试不冒充 systemd idmap 验证")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, directoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mat := testMaterial(t)
	one := stage(t, store, testBinding(1), mat)
	b2 := testBinding(1)
	b2.PolicyRevision = "policy-r2"
	_ = stage(t, store, b2, mat)
	two := stage(t, store, testBinding(2), testMaterial(t))
	if _, err := store.Activate(context.Background(), nil, one); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(context.Background(), &one, two); err != nil {
		t.Fatal(err)
	}

	siblingBinding := testBinding(1)
	siblingBinding.ID = "binding-b"
	sibling := stage(t, store, siblingBinding, testMaterial(t))

	if err := store.Remove(context.Background(), one.Binding.ID); err != nil {
		t.Fatalf("root 清理 nobody backing owner 绑定失败：%v", err)
	}
	if _, err := os.Stat(bindingPath(directory, one)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nobody backing owner 绑定目录未删除：%v", err)
	}
	current, err := store.Current(context.Background(), one.Binding.ID)
	if err != nil || current != nil {
		t.Fatalf("删除后 Current 不为 nil：%v %v", current, err)
	}
	requireLoaded(t, store, sibling)
}

func TestRemoveNameValidators(t *testing.T) {
	for _, valid := range []string{"g1", "g2", "g18446744073709551615"} {
		if !isGenerationDirName(valid) {
			t.Fatalf("应接受规范 generation 名：%s", valid)
		}
	}
	for _, invalid := range []string{"", "g", "g0", "g01", "g-1", "g+1", ".stage-g1-abc", "1", "G1"} {
		if isGenerationDirName(invalid) {
			t.Fatalf("不应接受非规范 generation 名：%s", invalid)
		}
	}
	validProof := "p-" + strings.Repeat("a", 64) + ".json"
	if !isProofFileName(validProof) {
		t.Fatalf("应接受规范 proof 名：%s", validProof)
	}
	for _, invalid := range []string{
		"",
		"p-.json",
		"p-" + strings.Repeat("A", 64) + ".json",
		"p-" + strings.Repeat("a", 63) + ".json",
		"p-" + strings.Repeat("a", 65) + ".json",
		"p-" + strings.Repeat("g", 64) + ".json",
		"x-" + strings.Repeat("a", 64) + ".json",
		"p-" + strings.Repeat("a", 64) + ".txt",
	} {
		if isProofFileName(invalid) {
			t.Fatalf("不应接受非规范 proof 名：%s", invalid)
		}
	}
}
