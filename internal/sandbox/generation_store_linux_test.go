// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/ids"
)

// ======================== 真实root文件fixture：仅缩短/tmp祖先检查，不替代权限与inode事实 ========================

func generationRecordTestStore(t *testing.T) (*GenerationRecordStore, string, TrustPolicy) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("generation记录的真实root权限/硬链接/flock测试须由Root Linux运行")
	}
	arena := t.TempDir()
	trust := TrustPolicy{UID: 0, StopAt: arena}
	directory := filepath.Join(arena, "private", "generation-stops")
	store, err := newGenerationRecordStore(directory, trust.Open, trust.StopAt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("记录store句柄未完整关闭：%v", err)
		}
	})
	return store, directory, trust
}

func generationRecordTestPath(t *testing.T, directory, targetRef string) string {
	t.Helper()
	name, err := generationRecordName(targetRef)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, name)
}

func generationRecordTestRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func generationRecordRetireRequest(completed GenerationCompletion) GenerationRetireRequest {
	reference := completed.Reference
	return GenerationRetireRequest{Op: HelperOpGenerationRetire, ID: reference.ID, OperationID: reference.OperationID,
		TargetRef: reference.TargetRef, ProofDigest: reference.ProofDigest, ReceiptDigest: reference.ReceiptDigest}
}

func TestGenerationRecordStoreDurableReplayAndPermanentCompactGuard(t *testing.T) {
	store, directory, trust := generationRecordTestStore(t)
	request := generationProtocolStopFixture()
	completed := generationProtocolCompletionFixture(t)
	writes := 0
	writeAtomic := store.io.writeAtomic
	store.io.writeAtomic = func(root *os.Root, name string, raw []byte, mode fs.FileMode) error {
		writes++
		return writeAtomic(root, name, raw, mode)
	}
	if witness, err := store.Bind(t.Context(), request); err != nil || witness != nil {
		t.Fatalf("首次Bind错误或自行声称完成：witness=%v err=%v", witness != nil, err)
	}
	path := generationRecordTestPath(t, directory, request.TargetRef)
	info, err := os.Lstat(path)
	if err != nil || checkGenerationRecordFile(info) != nil {
		t.Fatalf("真实记录权限/属主/nlink不满足要求：%v", err)
	}
	if witness, err := store.Bind(t.Context(), request); err != nil || witness != nil || writes != 1 {
		t.Fatalf("bound重放改写记录或伪造完成：writes=%d err=%v", writes, err)
	}
	if witness, err := store.Complete(t.Context(), request, completed); err != nil || witness != completed {
		t.Fatalf("完整耐久见证未返回：%v", err)
	}
	full := generationRecordTestRead(t, path)
	if witness, err := store.Complete(t.Context(), request, completed); err != nil || witness != completed || writes != 2 {
		t.Fatalf("完成重放重复写入：writes=%d err=%v", writes, err)
	}
	if witness, err := store.Bind(t.Context(), request); err != nil || witness == nil || *witness != completed || writes != 2 {
		t.Fatalf("已完成绑定没有准确重放：writes=%d err=%v", writes, err)
	}
	retire := generationRecordRetireRequest(completed)
	if reference, err := store.Retire(t.Context(), retire); err != nil || reference != completed.Reference {
		t.Fatalf("准确完成记录不能退休：%v", err)
	}
	compact := generationRecordTestRead(t, path)
	var fields map[string]json.RawMessage
	if json.Unmarshal(compact, &fields) != nil || fields["expected"] != nil || len(compact) >= len(full) {
		t.Fatal("退休未压缩原proof或丢失永久guard")
	}
	for _, field := range []string{"reference", "original_exited", "original_cgroup_empty", "completed_at"} {
		if fields[field] == nil {
			t.Fatalf("压缩guard缺少%s", field)
		}
	}
	if reference, err := store.Retire(t.Context(), retire); err != nil || reference != completed.Reference || writes != 3 {
		t.Fatalf("退休重放改写永久guard：writes=%d err=%v", writes, err)
	}
	if witness, err := store.Bind(t.Context(), request); err != nil || witness == nil || *witness != completed || writes != 3 {
		t.Fatalf("压缩后原proof不能重放：writes=%d err=%v", writes, err)
	}
	if witness, err := store.Complete(t.Context(), request, completed); err != nil || witness != completed || writes != 3 {
		t.Fatalf("压缩后原完整见证不能重放：writes=%d err=%v", writes, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := newGenerationRecordStore(directory, trust.Open, trust.StopAt)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if witness, err := reopened.Bind(t.Context(), request); err != nil || witness == nil || *witness != completed {
		t.Fatalf("重启后永久guard不能恢复原见证：%v", err)
	}
	changed := request
	changed.Expected.KernelStartTicks++
	if _, err := reopened.Bind(t.Context(), changed); !errors.Is(err, ErrGenerationBinding) {
		t.Fatalf("压缩并重启后同ref异proof被重新绑定：%v", err)
	}
	if !bytes.Equal(compact, generationRecordTestRead(t, path)) {
		t.Fatal("拒绝重新绑定时覆盖了永久guard")
	}
}

func TestGenerationRecordStoreRejectsAnotherTupleWithoutOverwriting(t *testing.T) {
	for _, sample := range []struct {
		name string
		edit func(*GenerationStopRequest)
	}{
		{"operation", func(request *GenerationStopRequest) { request.OperationID = ids.New(nil).New(ids.Operation) }},
		{"proof", func(request *GenerationStopRequest) { request.Expected.KernelStartTicks++ }},
		{"plugin", func(request *GenerationStopRequest) {
			request.ID = "bravo"
			request.Expected.Unit = "qwq-plugin@bravo.service"
			request.Expected.Cgroup = "/system.slice/qwq-plugin@bravo.service"
		}},
	} {
		t.Run(sample.name, func(t *testing.T) {
			store, directory, _ := generationRecordTestStore(t)
			request := generationProtocolStopFixture()
			if _, err := store.Bind(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			path := generationRecordTestPath(t, directory, request.TargetRef)
			before := generationRecordTestRead(t, path)
			changed := request
			sample.edit(&changed)
			if changed.Validate() != nil {
				t.Fatal("错误元组fixture本身非法，不能验证永久绑定")
			}
			if _, err := store.Bind(t.Context(), changed); !errors.Is(err, ErrGenerationBinding) {
				t.Fatalf("同ref换元组未被拒绝：%v", err)
			}
			if !bytes.Equal(before, generationRecordTestRead(t, path)) {
				t.Fatal("错绑定覆盖了原完整proof")
			}
		})
	}
}

func TestGenerationRecordStoreRejectsIncompleteAndWrongReceipt(t *testing.T) {
	store, directory, _ := generationRecordTestStore(t)
	request := generationProtocolStopFixture()
	completed := generationProtocolCompletionFixture(t)
	if _, err := store.Complete(t.Context(), request, completed); !errors.Is(err, ErrGenerationRecordMissing) {
		t.Fatalf("未Bind就发布完成：%v", err)
	}
	if _, err := store.Bind(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	path := generationRecordTestPath(t, directory, request.TargetRef)
	bound := generationRecordTestRead(t, path)
	retire := generationRecordRetireRequest(completed)
	if _, err := store.Retire(t.Context(), retire); !errors.Is(err, ErrGenerationUnconfirmed) {
		t.Fatalf("bound-only记录被退休：%v", err)
	}
	for _, edit := range []func(*GenerationCompletion){
		func(value *GenerationCompletion) { value.Observation.OriginalCgroupEmpty = false },
		func(value *GenerationCompletion) { value.Observation.OriginalExited = false },
		func(value *GenerationCompletion) { value.Reference.ReceiptDigest = "sha256:" + strings.Repeat("a", 64) },
		func(value *GenerationCompletion) { value.CompletedAt = "2026-11-21T10:00:00.123+00:00" },
	} {
		changed := completed
		edit(&changed)
		if _, err := store.Complete(t.Context(), request, changed); !errors.Is(err, ErrGenerationDocument) {
			t.Fatalf("部分事实/错误摘要/非规范时间被持久为完成：%v", err)
		}
	}
	if !bytes.Equal(bound, generationRecordTestRead(t, path)) {
		t.Fatal("失败完成或退休覆盖了bound正文")
	}
	if _, err := store.Complete(t.Context(), request, completed); err != nil {
		t.Fatal(err)
	}
	full := generationRecordTestRead(t, path)
	retire.ReceiptDigest = "sha256:" + strings.Repeat("a", 64)
	if _, err := store.Retire(t.Context(), retire); !errors.Is(err, ErrGenerationBinding) {
		t.Fatalf("错误receipt压缩了原完成记录：%v", err)
	}
	later, err := NewGenerationCompletion(request, completed.Observation, time.Date(2026, 11, 21, 10, 0, 1, 123000000, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Complete(t.Context(), request, later); !errors.Is(err, ErrGenerationBinding) {
		t.Fatalf("换规范时间覆盖了原完成receipt：%v", err)
	}
	if !bytes.Equal(full, generationRecordTestRead(t, path)) {
		t.Fatal("错误receipt或重放覆盖了原见证")
	}
}

// ======================== 故障文件必须留下：不得通过覆盖或删除使同ref重新变成可写 ========================

func TestGenerationRecordStorePreservesUntrustedAndCorruptFiles(t *testing.T) {
	for _, sample := range []struct {
		name   string
		damage func(*testing.T, string, []byte)
	}{
		{"mode", func(t *testing.T, path string, _ []byte) {
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"owner", func(t *testing.T, path string, _ []byte) {
			if err := os.Chown(path, 65534, -1); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, path string, _ []byte) {
			if err := os.Link(path, filepath.Join(filepath.Dir(path), "hardlink")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string, _ []byte) {
			target := filepath.Join(filepath.Dir(path), "symlink-body")
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("symlink-body", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"partial-json", func(t *testing.T, path string, raw []byte) {
			if err := os.WriteFile(path, raw[:len(raw)/2], 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"presence", func(t *testing.T, path string, raw []byte) {
			changed := generationProtocolDrop(t, raw, "expected", "cgroup_device")
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate", func(t *testing.T, path string, raw []byte) {
			changed := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"state":"bound"}`)...)
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversize-padding", func(t *testing.T, path string, raw []byte) {
			changed := append(bytes.Repeat([]byte{' '}, MaxGenerationMessage+1-len(raw)), raw...)
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(sample.name, func(t *testing.T) {
			store, directory, _ := generationRecordTestStore(t)
			request := generationProtocolStopFixture()
			completed := generationProtocolCompletionFixture(t)
			if _, err := store.Bind(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			path := generationRecordTestPath(t, directory, request.TargetRef)
			raw := generationRecordTestRead(t, path)
			sample.damage(t, path, raw)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			content := generationRecordTestRead(t, path)
			if _, err := store.Bind(t.Context(), request); !errors.Is(err, ErrGenerationRecord) {
				t.Fatalf("坏文件被接受为绑定：%v", err)
			}
			if _, err := store.Complete(t.Context(), request, completed); !errors.Is(err, ErrGenerationRecord) {
				t.Fatalf("坏文件被覆盖为完成：%v", err)
			}
			if _, err := store.Retire(t.Context(), generationRecordRetireRequest(completed)); !errors.Is(err, ErrGenerationRecord) {
				t.Fatalf("坏文件被覆盖为退休：%v", err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || !bytes.Equal(content, generationRecordTestRead(t, path)) {
				t.Fatal("故障证据被覆盖或删除")
			}
		})
	}
}

func TestGenerationRecordStoreRejectsUnsafeDirectoryAndClosedUse(t *testing.T) {
	store, directory, trust := generationRecordTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bind(context.Background(), generationProtocolStopFixture()); !errors.Is(err, ErrGenerationStoreClosed) {
		t.Fatalf("关闭后仍访问root目录：%v", err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if reopened, err := newGenerationRecordStore(directory, trust.Open, trust.StopAt); err == nil {
		_ = reopened.Close()
		t.Fatal("不符合0700的旧目录被自动修复或接受")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatal("拒绝旧目录时修改了权限")
	}
}
