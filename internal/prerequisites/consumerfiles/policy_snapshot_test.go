// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// ======================== 材料 generation 与授权版本分别保持不可覆盖 ========================

func TestSameMaterialGenerationAcceptsNewPolicySnapshot(t *testing.T) {
	store, _, directory := testStore(t)
	material := testMaterial(t)
	old := stage(t, store, testBinding(1), material)
	if _, err := store.Activate(context.Background(), nil, old); err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(generationPath(directory, old), chainName)
	before, err := os.Stat(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	binding := old.Binding
	binding.PolicyRevision = "policy-r2"
	fresh, err := store.Stage(context.Background(), binding, material)
	if err != nil {
		t.Fatalf("同一材料 generation 的新合法许可不能保存：%v", err)
	}
	if fresh.Binding != binding || fresh.FullchainSHA256 != old.FullchainSHA256 || fresh.PrivateKeySHA256 != old.PrivateKeySHA256 {
		t.Fatal("新许可改变了同代材料或丢失完整绑定")
	}
	after, err := os.Stat(chainPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("新增许可替换了已发布材料 inode")
	}
	requireLoaded(t, store, old)
	requireLoaded(t, store, fresh)
	previous, err := store.Activate(context.Background(), &old, fresh)
	if err != nil || !sameProof(previous, &old) {
		t.Fatalf("同 generation 许可 CAS 丢失完整前代：%v", err)
	}
	previous, err = store.Activate(context.Background(), &fresh, old)
	if err != nil || !sameProof(previous, &fresh) {
		t.Fatalf("同 generation 许可精确回滚失败：%v", err)
	}
	requireLoaded(t, store, old)
	requireLoaded(t, store, fresh)
}

func TestNewPolicyCannotReplaceSameGenerationMaterial(t *testing.T) {
	store, _, _ := testStore(t)
	old := stage(t, store, testBinding(1), testMaterial(t))
	binding := old.Binding
	binding.PolicyRevision = "policy-r2"
	_, err := store.Stage(context.Background(), binding, testMaterial(t))
	requireCode(t, err, "CONSUMER_FILES_CONFLICT")
	requireLoaded(t, store, old)
}

func TestMaterialRecordCannotSubstituteMissingPermissionSnapshot(t *testing.T) {
	store, _, directory := testStore(t)
	proof := stage(t, store, testBinding(1), testMaterial(t))
	generation := generationPath(directory, proof)
	if _, err := os.Stat(filepath.Join(generation, materialName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(generation, proofsName, proofSnapshotName(proof))); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load(context.Background(), proof)
	requireCode(t, err, "NOT_FOUND")
	_, err = store.Activate(context.Background(), nil, proof)
	requireCode(t, err, "NOT_FOUND")
	current, err := store.Current(context.Background(), proof.Binding.ID)
	if err != nil || current != nil {
		t.Fatalf("缺少精确许可仍修改了 current：%v", err)
	}
}

func TestTamperedPermissionSnapshotCannotAuthorizeLoad(t *testing.T) {
	store, _, directory := testStore(t)
	proof := stage(t, store, testBinding(1), testMaterial(t))
	fake := proof
	fake.Binding.PolicyRevision = "plugin-self-report"
	raw, err := encodeMetadata(proofMetadata{Version: metadataVersion, Proof: fake})
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(generationPath(directory, proof), proofsName, proofSnapshotName(proof))
	if err := os.WriteFile(destination, raw, materialMode); err != nil {
		t.Fatal(err)
	}
	_, err = store.Load(context.Background(), proof)
	requireCode(t, err, "CONSUMER_FILES_CONFLICT")
	_, err = store.Activate(context.Background(), nil, proof)
	requireCode(t, err, "CONSUMER_FILES_CONFLICT")
}
