// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"strings"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// ======================== 宿主加密私有仓库到公开视图 StateStore 的适配 ========================

const maxViewKeyBytes = 256

// RepositoryViews 将宿主加密私有 store.Repository 适配为 hostsvc.StateStore，仅用于公开资源索引视图。
type RepositoryViews struct {
	repo store.Repository
}

// NewRepositoryViews 创建基于 store.Repository 的公开资源视图存储适配器。
func NewRepositoryViews(repo store.Repository) *RepositoryViews {
	return &RepositoryViews{repo: repo}
}

var _ hostsvc.StateStore = (*RepositoryViews)(nil)

func validViewKey(key string) bool {
	if len(key) == 0 || len(key) > maxViewKeyBytes {
		return false
	}
	if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") || strings.Contains(key, "//") {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '/' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func viewStorageKey(key string) string {
	return "views/" + key
}

func (v *RepositoryViews) currentRevision(ctx context.Context, storageKey string) string {
	entry, found, err := v.repo.Get(ctx, storageKey)
	if err != nil || !found {
		return ""
	}
	return entry.Revision
}

// Get 读取单个公开视图键；缺失键返回 found=false 且不报错。
func (v *RepositoryViews) Get(ctx context.Context, key string) (hostsvc.StateEntry, bool, error) {
	if v == nil || v.repo == nil {
		return hostsvc.StateEntry{}, false, fault.New("BACKEND_REQUIRED", "公开视图存储后端未配置")
	}
	if ctx == nil {
		return hostsvc.StateEntry{}, false, fault.New("VALIDATION_FAILED", "公开视图读取需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return hostsvc.StateEntry{}, false, err
	}
	if !validViewKey(key) {
		return hostsvc.StateEntry{}, false, fault.New("VALIDATION_FAILED", "公开视图键格式无效")
	}
	entry, found, err := v.repo.Get(ctx, viewStorageKey(key))
	if err != nil || !found {
		return hostsvc.StateEntry{}, false, err
	}
	return hostsvc.StateEntry{
		Key:      key,
		Revision: entry.Revision,
		Value:    append([]byte(nil), entry.Value...),
	}, true, nil
}

// Put 按乐观并发守卫写入公开视图；冲突统一映射为 *hostsvc.StateConflictError（匹配 ErrStateConflict）。
func (v *RepositoryViews) Put(ctx context.Context, key string, valueJSON []byte, guard hostsvc.StateGuard) (string, error) {
	if v == nil || v.repo == nil {
		return "", fault.New("BACKEND_REQUIRED", "公开视图存储后端未配置")
	}
	if ctx == nil {
		return "", fault.New("VALIDATION_FAILED", "公开视图写入需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !validViewKey(key) {
		return "", fault.New("VALIDATION_FAILED", "公开视图键格式无效")
	}
	storageKey := viewStorageKey(key)
	expected := ""
	switch {
	case guard.MustNotExist:
		expected = ""
	case guard.ExpectedRevision != "":
		expected = guard.ExpectedRevision
	default:
		entry, found, err := v.repo.Get(ctx, storageKey)
		if err != nil {
			return "", err
		}
		if found {
			expected = entry.Revision
		}
	}
	revision, err := v.repo.Put(ctx, storageKey, expected, valueJSON)
	if err != nil {
		if fault.Code(err) == "REVISION_CONFLICT" {
			return "", &hostsvc.StateConflictError{Key: key, Current: v.currentRevision(ctx, storageKey)}
		}
		return "", err
	}
	return revision, nil
}

// Delete 按期望版本或无条件删除公开视图键；CAS 冲突映射为 *hostsvc.StateConflictError。
func (v *RepositoryViews) Delete(ctx context.Context, key, expectedRevision string) error {
	if v == nil || v.repo == nil {
		return fault.New("BACKEND_REQUIRED", "公开视图存储后端未配置")
	}
	if ctx == nil {
		return fault.New("VALIDATION_FAILED", "公开视图删除需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validViewKey(key) {
		return fault.New("VALIDATION_FAILED", "公开视图键格式无效")
	}
	storageKey := viewStorageKey(key)
	if expectedRevision == "" {
		entry, found, err := v.repo.Get(ctx, storageKey)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		expectedRevision = entry.Revision
	}
	if err := v.repo.Delete(ctx, storageKey, expectedRevision); err != nil {
		if fault.Code(err) == "REVISION_CONFLICT" {
			return &hostsvc.StateConflictError{Key: key, Current: v.currentRevision(ctx, storageKey)}
		}
		return err
	}
	return nil
}

// List 不由 store.Repository 支持；公开目录使用单键索引读取。
func (v *RepositoryViews) List(ctx context.Context, _, _ string, _ int, _ bool) (hostsvc.StatePage, error) {
	if v == nil || v.repo == nil {
		return hostsvc.StatePage{}, fault.New("BACKEND_REQUIRED", "公开视图存储后端未配置")
	}
	if ctx == nil {
		return hostsvc.StatePage{}, fault.New("VALIDATION_FAILED", "公开视图枚举需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return hostsvc.StatePage{}, err
	}
	return hostsvc.StatePage{}, fault.New("UNSUPPORTED", "公开视图适配器不支持范围枚举")
}
