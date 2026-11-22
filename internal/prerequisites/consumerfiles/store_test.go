// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 真实 os.Root 与受控 PEM 夹具 ========================

func testStore(t *testing.T) (*Store, *os.Root, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, directoryMode); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, root, directory
}

func secondStore(t *testing.T, root *os.Root) *Store {
	t.Helper()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testBinding(generation uint64) certificates.HostBinding {
	return certificates.HostBinding{
		ID: "binding-a", CertificateID: "certificate-a", Generation: generation,
		Consumer: certificates.Consumer{
			PluginID: "core.xray", ProfileID: "logical-profile", NodeID: "local",
			SNI: "consumer.example", Purpose: "proxy.hysteria2", Test: true,
		},
		PolicyRevision: "policy-r1",
	}
}

func testMaterial(t *testing.T) tlsmgr.Material {
	t.Helper()
	material, err := tlsmgr.GenerateTestMaterial(time.Now().UTC(), []string{"consumer.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(material.Clear)
	return material
}

func stage(t *testing.T, store *Store, binding certificates.HostBinding, material tlsmgr.Material) Proof {
	t.Helper()
	proof, err := store.Stage(context.Background(), binding, material)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || fault.Code(err) != code {
		t.Fatalf("错误码=%s，期望=%s；error=%v", fault.Code(err), code, err)
	}
}

func verifyMaterial(material tlsmgr.Material, wanted Proof) error {
	chain, key := material.CertificatePEM(), material.PrivateKeyPEM()
	defer clear(key)
	if digest(chain) != wanted.FullchainSHA256 || digest(key) != wanted.PrivateKeySHA256 {
		return errors.New("读出的 pair 与固定代证明不符")
	}
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		return errors.New("读出的证书和私钥发生混代")
	}
	return nil
}

func requireLoaded(t *testing.T, store *Store, wanted Proof) {
	t.Helper()
	material, err := store.Load(context.Background(), wanted)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	if err := verifyMaterial(material, wanted); err != nil {
		t.Fatal(err)
	}
}

func generationPath(directory string, proof Proof) string {
	return filepath.Join(directory, "tls", "bindings", proof.Binding.ID, "generations", generationName(proof.Binding.Generation))
}

func bindingPath(directory string, proof Proof) string {
	return filepath.Join(directory, "tls", "bindings", proof.Binding.ID)
}

// ======================== 代重试、精确证明、CAS 与回滚 ========================

func TestStageRetryAndDifferentMaterialConflict(t *testing.T) {
	store, root, _ := testStore(t)
	material := testMaterial(t)
	wanted := stage(t, store, testBinding(1), material)
	repeated, err := store.Stage(context.Background(), testBinding(1), material)
	if err != nil || repeated != wanted {
		t.Fatalf("同代重试未得到同一证明：%v", err)
	}
	_, err = store.Stage(context.Background(), testBinding(1), testMaterial(t))
	requireCode(t, err, "CONSUMER_FILES_CONFLICT")
	current, err := store.Current(context.Background(), wanted.Binding.ID)
	if err != nil || current != nil {
		t.Fatalf("Stage 提前修改 current：%v", err)
	}
	if _, err := root.Stat("logical-profile"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("逻辑 ProfileID 被错误用于 state 实例路径")
	}
	requireLoaded(t, store, wanted)
}

func TestActivateCASRetriesAndPreciseRollback(t *testing.T) {
	store, _, _ := testStore(t)
	one := stage(t, store, testBinding(1), testMaterial(t))
	two := stage(t, store, testBinding(2), testMaterial(t))
	previous, err := store.Activate(context.Background(), nil, one)
	if err != nil || previous != nil {
		t.Fatalf("首次 CAS 结果错误：%v", err)
	}
	previous, err = store.Activate(context.Background(), nil, one)
	if err != nil || previous != nil {
		t.Fatalf("首次 CAS 重试结果错误：%v", err)
	}
	_, err = store.Activate(context.Background(), nil, two)
	requireCode(t, err, "CONSUMER_FILES_CONFLICT")
	previous, err = store.Activate(context.Background(), &one, two)
	if err != nil || !sameProof(previous, &one) {
		t.Fatalf("换代未保留完整前代：%v", err)
	}
	previous, err = store.Activate(context.Background(), &one, two)
	if err != nil || !sameProof(previous, &one) {
		t.Fatalf("重复换代丢失原前代：%v", err)
	}
	previous, err = store.Activate(context.Background(), &two, two)
	if err != nil || !sameProof(previous, &one) {
		t.Fatalf("当前代 no-op 丢失保存前代：%v", err)
	}
	wrong := one
	wrong.Binding.Generation = 99
	_, err = store.Activate(context.Background(), &wrong, two)
	requireCode(t, err, "CONSUMER_FILES_CONFLICT")
	previous, err = store.Activate(context.Background(), &two, one)
	if err != nil || !sameProof(previous, &two) {
		t.Fatalf("精确回滚失败：%v", err)
	}
	current, err := store.Current(context.Background(), one.Binding.ID)
	if err != nil || !sameProof(current, &one) {
		t.Fatalf("回滚后 current 不符：%v", err)
	}
	requireLoaded(t, store, one)
	requireLoaded(t, store, two)
}

func TestLoadChecksEveryHostProofField(t *testing.T) {
	store, _, _ := testStore(t)
	one := stage(t, store, testBinding(1), testMaterial(t))
	mutations := map[string]func(*Proof){
		"certificate":  func(p *Proof) { p.Binding.CertificateID = "certificate-b" },
		"policy":       func(p *Proof) { p.Binding.PolicyRevision = "policy-r2" },
		"plugin":       func(p *Proof) { p.Binding.Consumer.PluginID = "core.other" },
		"profile":      func(p *Proof) { p.Binding.Consumer.ProfileID = "another-profile" },
		"node":         func(p *Proof) { p.Binding.Consumer.NodeID = "another-node" },
		"purpose":      func(p *Proof) { p.Binding.Consumer.Purpose = "panel.https" },
		"sni":          func(p *Proof) { p.Binding.Consumer.SNI = "different.example" },
		"test":         func(p *Proof) { p.Binding.Consumer.Test = false },
		"chain_digest": func(p *Proof) { p.FullchainSHA256 = strings.Repeat("0", 64) },
		"key_digest":   func(p *Proof) { p.PrivateKeySHA256 = strings.Repeat("0", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wanted := one
			mutate(&wanted)
			_, err := store.Load(context.Background(), wanted)
			code := "CONSUMER_FILES_CONFLICT"
			if name == "policy" {
				code = "NOT_FOUND" // 不存在的新许可不能由材料记录补出。
			}
			requireCode(t, err, code)
		})
	}
	requireLoaded(t, store, one)
}

func TestTamperedBindingMetadataDoesNotAuthorizeLoad(t *testing.T) {
	store, _, directory := testStore(t)
	one := stage(t, store, testBinding(1), testMaterial(t))
	other := one
	other.Binding.ID = "binding-b"
	raw, err := encodeMetadata(generationDescriptor(other))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generationPath(directory, one), materialName), raw, materialMode); err != nil {
		t.Fatal(err)
	}
	_, err = store.Load(context.Background(), one)
	requireCode(t, err, "CONSUMER_FILES_CONFLICT")
	_, err = store.Activate(context.Background(), nil, one)
	requireCode(t, err, "CONSUMER_FILES_CONFLICT")
	current, err := store.Current(context.Background(), one.Binding.ID)
	if err != nil || current != nil {
		t.Fatalf("坏代被激活：%v", err)
	}
}

func TestMaterialBytesMustMatchTrustedDigestBeforeActivation(t *testing.T) {
	for _, name := range []string{chainName, keyName} {
		t.Run(name, func(t *testing.T) {
			store, _, directory := testStore(t)
			one := stage(t, store, testBinding(1), testMaterial(t))
			other := testMaterial(t)
			raw := other.CertificatePEM()
			if name == keyName {
				raw = other.PrivateKeyPEM()
				defer clear(raw)
			}
			if err := os.WriteFile(filepath.Join(generationPath(directory, one), name), raw, materialMode); err != nil {
				t.Fatal(err)
			}
			_, err := store.Load(context.Background(), one)
			requireCode(t, err, "CONSUMER_FILES_CONFLICT")
			_, err = store.Activate(context.Background(), nil, one)
			requireCode(t, err, "CONSUMER_FILES_CONFLICT")
			current, err := store.Current(context.Background(), one.Binding.ID)
			if err != nil || current != nil {
				t.Fatalf("摘要失配的材料进入 current：%v", err)
			}
		})
	}
}

func TestCurrentIsUnauthorisedFactAndLoadIgnoresIt(t *testing.T) {
	store, _, directory := testStore(t)
	one := stage(t, store, testBinding(1), testMaterial(t))
	fake := one
	fake.Binding.PolicyRevision = "plugin-self-report"
	raw, err := encodeMetadata(currentMetadata{Version: metadataVersion, Active: fake})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindingPath(directory, one), currentName), raw, materialMode); err != nil {
		t.Fatal(err)
	}
	observed, err := store.Current(context.Background(), one.Binding.ID)
	if err != nil || !sameProof(observed, &fake) {
		t.Fatalf("未返回当前文件事实：%v", err)
	}
	_, err = store.Load(context.Background(), fake)
	requireCode(t, err, "NOT_FOUND")
	requireLoaded(t, store, one)
}

func TestMismatchedPEMPairIsRejectedBeforeStage(t *testing.T) {
	store, root, _ := testStore(t)
	one, two := testMaterial(t), testMaterial(t)
	key := two.PrivateKeyPEM()
	defer clear(key)
	wrong, err := tlsmgr.NewMaterial(one.CertificatePEM(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Clear()
	_, err = store.Stage(context.Background(), testBinding(1), wrong)
	requireCode(t, err, "PRIVATE_KEY_MISMATCH")
	if _, err := root.Stat("tls"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("无效 pair 触发了目录或材料写入")
	}
}

// ======================== 多实例并发：只允许完整、可核对的代 ========================

func TestConcurrentStagesAndCASHaveOneWinner(t *testing.T) {
	for name, sameGeneration := range map[string]bool{"different-generations": false, "same-generation-new-policy": true} {
		t.Run(name, func(t *testing.T) { runConcurrentStageCAS(t, sameGeneration) })
	}
}

func runConcurrentStageCAS(t *testing.T, sameGeneration bool) {
	t.Helper()
	first, root, _ := testStore(t)
	second := secondStore(t, root)
	materials := make([]tlsmgr.Material, 2)
	materials[0] = testMaterial(t)
	bindings := []certificates.HostBinding{testBinding(1), testBinding(2)}
	if sameGeneration {
		materials[1] = materials[0]
		bindings[1] = testBinding(1)
		bindings[1].PolicyRevision = "policy-r2"
	} else {
		materials[1] = testMaterial(t)
	}
	stores := []*Store{first, second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type stageResult struct {
		index int
		proof Proof
		err   error
	}
	staged := make(chan stageResult, 2)
	start := make(chan struct{})
	for index := range stores {
		go func(index int) {
			<-start
			proof, err := stores[index].Stage(ctx, bindings[index], materials[index])
			staged <- stageResult{index: index, proof: proof, err: err}
		}(index)
	}
	close(start)
	proofs := make([]Proof, 2)
	for range stores {
		result := <-staged
		if result.err != nil {
			t.Fatal(result.err)
		}
		proofs[result.index] = result.proof
	}
	results := make(chan error, 2)
	start = make(chan struct{})
	for index := range stores {
		go func(index int) {
			<-start
			_, err := stores[index].Activate(ctx, nil, proofs[index])
			results <- err
		}(index)
	}
	close(start)
	successes, conflicts := 0, 0
	for range stores {
		err := <-results
		if err == nil {
			successes++
		} else if fault.Code(err) == "CONSUMER_FILES_CONFLICT" {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("竞争 CAS 成功=%d 冲突=%d，期望各 1", successes, conflicts)
	}
	current, err := first.Current(ctx, proofs[0].Binding.ID)
	if err != nil || (!sameProof(current, &proofs[0]) && !sameProof(current, &proofs[1])) {
		t.Fatalf("竞争 CAS 产生了未知代：%v", err)
	}
	for _, proof := range proofs {
		requireLoaded(t, second, proof)
	}
}

func TestConcurrentSwitchAndPinnedLoadNeverMixPair(t *testing.T) {
	first, root, _ := testStore(t)
	second := secondStore(t, root)
	one := stage(t, first, testBinding(1), testMaterial(t))
	two := stage(t, second, testBinding(2), testMaterial(t))
	if _, err := first.Activate(context.Background(), nil, one); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// 将文件事实与测试中的可信账本精确比对后，才把账本值传给 Load/CAS。
	trusted := func(observed *Proof) (Proof, error) {
		if sameProof(observed, &one) {
			return one, nil
		}
		if sameProof(observed, &two) {
			return two, nil
		}
		return Proof{}, errors.New("current 产生未登记文件事实")
	}
	var wait sync.WaitGroup
	failures := make(chan error, 6)
	start := make(chan struct{})
	for index, store := range []*Store{first, second} {
		wait.Add(1)
		go func(index int, store *Store) {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 60; iteration++ {
				observed, err := store.Current(ctx, one.Binding.ID)
				if err != nil {
					failures <- err
					return
				}
				before, err := trusted(observed)
				if err != nil {
					failures <- err
					return
				}
				wanted := one
				if (iteration+index)%2 == 0 {
					wanted = two
				}
				if _, err := store.Activate(ctx, &before, wanted); err != nil && fault.Code(err) != "CONSUMER_FILES_CONFLICT" {
					failures <- err
					return
				}
			}
		}(index, store)
	}
	for index := 0; index < 4; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 120; iteration++ {
				observed, err := second.Current(ctx, one.Binding.ID)
				if err != nil {
					failures <- err
					return
				}
				wanted, err := trusted(observed)
				if err != nil {
					failures <- err
					return
				}
				material, err := second.Load(ctx, wanted)
				if err != nil {
					failures <- err
					return
				}
				err = verifyMaterial(material, wanted)
				material.Clear()
				if err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	close(start)
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	requireLoaded(t, first, one)
	requireLoaded(t, first, two)
}

// ======================== 链接、特殊文件、权限与元数据攻击 ========================

func TestEveryDirectoryLayerRejectsSymlink(t *testing.T) {
	for _, relative := range []string{
		"tls", "tls/bindings", "tls/bindings/binding-a", "tls/bindings/binding-a/generations",
		"tls/bindings/binding-a/generations/g1",
		"tls/bindings/binding-a/generations/g1/proofs",
	} {
		t.Run(relative, func(t *testing.T) {
			store, _, directory := testStore(t)
			one := stage(t, store, testBinding(1), testMaterial(t))
			outside := t.TempDir()
			absolute := filepath.Join(directory, filepath.FromSlash(relative))
			if err := os.Rename(absolute, absolute+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, absolute); err != nil {
				t.Fatal(err)
			}
			_, err := store.Load(context.Background(), one)
			requireCode(t, err, "CONSUMER_FILES_UNSAFE")
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 0 {
				t.Fatalf("材料读取触及链接外部：%v", err)
			}
		})
	}
}

func TestEveryMaterialFileRejectsUnsafeInode(t *testing.T) {
	attacks := map[string]func(string) error{
		"symlink": func(path string) error {
			if err := os.Rename(path, path+".saved"); err != nil {
				return err
			}
			return os.Symlink(path+".saved", path)
		},
		"hardlink": func(path string) error { return os.Link(path, path+".extra") },
		"fifo": func(path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return unix.Mkfifo(path, materialMode)
		},
		"directory": func(path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Mkdir(path, directoryMode)
		},
		"world_readable": func(path string) error { return os.Chmod(path, 0o644) },
		"group_readable": func(path string) error { return os.Chmod(path, 0o640) },
		"setuid":         func(path string) error { return unix.Chmod(path, 0o4600) },
	}
	for _, fileName := range []string{chainName, keyName, materialName, currentName, "permission_snapshot"} {
		for attackName, attack := range attacks {
			t.Run(fileName+"/"+attackName, func(t *testing.T) {
				store, _, directory := testStore(t)
				one := stage(t, store, testBinding(1), testMaterial(t))
				if _, err := store.Activate(context.Background(), nil, one); err != nil {
					t.Fatal(err)
				}
				parent := generationPath(directory, one)
				if fileName == currentName {
					parent = bindingPath(directory, one)
				}
				leaf := fileName
				if fileName == "permission_snapshot" {
					parent = filepath.Join(parent, proofsName)
					leaf = proofSnapshotName(one)
				}
				if err := attack(filepath.Join(parent, leaf)); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()
				var err error
				if fileName == currentName {
					_, err = store.Current(ctx, one.Binding.ID)
				} else {
					_, err = store.Load(ctx, one)
				}
				requireCode(t, err, "CONSUMER_FILES_UNSAFE")
				if strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), one.PrivateKeySHA256) {
					t.Fatal("错误文本泄漏材料或私钥摘要")
				}
			})
		}
	}
}

func TestDirectoryModesAndStateOwnerChangesAreRejected(t *testing.T) {
	for _, relative := range []string{".", "tls", "tls/bindings", "tls/bindings/binding-a", "tls/bindings/binding-a/generations", "tls/bindings/binding-a/generations/g1", "tls/bindings/binding-a/generations/g1/proofs"} {
		t.Run(relative, func(t *testing.T) {
			store, _, directory := testStore(t)
			one := stage(t, store, testBinding(1), testMaterial(t))
			if err := os.Chmod(filepath.Join(directory, filepath.FromSlash(relative)), 0o750); err != nil {
				t.Fatal(err)
			}
			_, err := store.Load(context.Background(), one)
			requireCode(t, err, "CONSUMER_FILES_UNSAFE")
		})
	}
	if os.Geteuid() != 0 {
		return
	}
	store, _, directory := testStore(t)
	one := stage(t, store, testBinding(1), testMaterial(t))
	if err := os.Chown(directory, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load(context.Background(), one)
	requireCode(t, err, "CONSUMER_FILES_UNSAFE")
}

func TestMetadataIsBoundedAndStrictlyDecoded(t *testing.T) {
	for name, raw := range map[string][]byte{
		"oversize": []byte(strings.Repeat("x", maxMetadataBytes+1)),
		"invalid":  []byte("{broken}"),
		"unknown":  []byte(`{"version":1,"arbitrary_path":"/etc"}`),
		"trailing": []byte("{}\n{}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			store, _, directory := testStore(t)
			one := stage(t, store, testBinding(1), testMaterial(t))
			if err := os.WriteFile(filepath.Join(bindingPath(directory, one), currentName), raw, materialMode); err != nil {
				t.Fatal(err)
			}
			_, err := store.Current(context.Background(), one.Binding.ID)
			if err == nil || (fault.Code(err) != "CONSUMER_FILES_INVALID" && fault.Code(err) != "CONSUMER_FILES_UNSAFE") {
				t.Fatalf("不可信元数据未明确拒绝：%v", err)
			}
		})
	}
}

// ======================== 取消、独立根生命周期与真实 backing owner ========================

func descriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestCancelledCallsAndHeldDirectoryLockCloseDescriptors(t *testing.T) {
	store, root, _ := testStore(t)
	other := secondStore(t, root)
	material := testMaterial(t)
	one := stage(t, store, testBinding(1), material)
	two := stage(t, store, testBinding(2), testMaterial(t))
	if _, err := store.Activate(context.Background(), nil, one); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := descriptorCount(t)
	for iteration := 0; iteration < 20; iteration++ {
		_, err := other.Stage(ctx, testBinding(1), material)
		requireCode(t, err, "CANCELLED")
		if !errors.Is(err, context.Canceled) {
			t.Fatal("取消原因不可检索")
		}
		_, err = other.Activate(ctx, &one, two)
		requireCode(t, err, "CANCELLED")
		_, err = other.Current(ctx, one.Binding.ID)
		requireCode(t, err, "CANCELLED")
		_, err = other.Load(ctx, one)
		requireCode(t, err, "CANCELLED")
	}
	if after := descriptorCount(t); after != before {
		t.Fatalf("预取消调用泄漏 FD：before=%d after=%d", before, after)
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
	_, err = other.Activate(bounded, &one, two)
	requireCode(t, err, "CANCELLED")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("目录锁等待未在 context 到期后及时结束")
	}
	if after := descriptorCount(t); after != before {
		t.Fatalf("等待目录锁取消泄漏 FD：before=%d after=%d", before, after)
	}
	current, err := store.Current(context.Background(), one.Binding.ID)
	if err != nil || !sameProof(current, &one) {
		t.Fatalf("取消的 CAS 改动 current：%v", err)
	}
}

func TestCloseKeepsBorrowedCallSafeAndDoesNotCloseInputRoot(t *testing.T) {
	store, root, _ := testStore(t)
	borrowed, err := store.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer borrowed.close()
	rootFD := int(store.root.Fd())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal("重复 Close 失败")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(rootFD, &stat); !errors.Is(err, unix.EBADF) {
		t.Fatal("Store 自有根 FD 未关闭")
	}
	if err := borrowed.check(context.Background()); err != nil {
		t.Fatal("已开始调用的独立 FD 被 Close 破坏")
	}
	if _, err := root.Stat("."); err != nil {
		t.Fatal("Store Close 关闭了调用方 os.Root")
	}
	_, err = store.Current(context.Background(), "binding-a")
	requireCode(t, err, "CONSUMER_FILES_CLOSED")
}

func TestInputRootCanCloseAfterNew(t *testing.T) {
	store, root, _ := testStore(t)
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	one := stage(t, store, testBinding(1), testMaterial(t))
	requireLoaded(t, store, one)
}

func TestRejectedFileLoadsDoNotLeakDescriptors(t *testing.T) {
	store, _, directory := testStore(t)
	one := stage(t, store, testBinding(1), testMaterial(t))
	key := filepath.Join(generationPath(directory, one), keyName)
	if err := os.Link(key, key+".extra"); err != nil {
		t.Fatal(err)
	}
	before := descriptorCount(t)
	for iteration := 0; iteration < 40; iteration++ {
		_, err := store.Load(context.Background(), one)
		requireCode(t, err, "CONSUMER_FILES_UNSAFE")
	}
	if after := descriptorCount(t); after != before {
		t.Fatalf("拒绝材料路径泄漏 FD：before=%d after=%d", before, after)
	}
}

func TestRootWriterUsesActualStateBackingOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("真实 root→backing owner 移交须由 Root Linux 执行；普通用户测试不冒充 systemd idmap 验证")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, directoryMode); err != nil {
		t.Fatal(err)
	}
	// 65534 仅是测试中的 nobody backing owner，不进入任何生产 UID 推断逻辑。
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
	material := testMaterial(t)
	one := stage(t, store, testBinding(1), material)
	if _, err := store.Activate(context.Background(), nil, one); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		directory,
		filepath.Join(directory, "tls"), filepath.Join(directory, "tls", "bindings"),
		bindingPath(directory, one), filepath.Join(bindingPath(directory, one), "generations"), generationPath(directory, one),
		filepath.Join(generationPath(directory, one), chainName), filepath.Join(generationPath(directory, one), keyName),
		filepath.Join(generationPath(directory, one), materialName), filepath.Join(bindingPath(directory, one), currentName),
		filepath.Join(generationPath(directory, one), proofsName), filepath.Join(generationPath(directory, one), proofsName, proofSnapshotName(one)),
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		err = unix.Fstat(int(file.Fd()), &stat)
		_ = file.Close()
		mode := uint32(materialMode)
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			mode = directoryMode
		}
		if err != nil || stat.Uid != 65534 || stat.Gid != 65534 || stat.Mode&0o7777 != mode {
			t.Fatalf("实际 backing owner 或精确 mode 未继承：%s", path)
		}
	}
	loaded, err := store.Load(context.Background(), one)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Clear()
	chain := loaded.CertificatePEM()
	if !bytes.Equal(chain, material.CertificatePEM()) {
		t.Fatal("backing owner 移交后材料变化")
	}
}

func TestInvalidRootAndPathComponentsAreRejected(t *testing.T) {
	_, err := New(nil)
	requireCode(t, err, "CONSUMER_FILES_INVALID")
	store, root, directory := testStore(t)
	for _, id := range []string{".", "..", "../outside", "tls/binding", "binding\\other", "", strings.Repeat("a", 129)} {
		_, err := store.Current(context.Background(), id)
		requireCode(t, err, "CONSUMER_FILES_INVALID")
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	_, err = New(root)
	requireCode(t, err, "CONSUMER_FILES_UNSAFE")
}
