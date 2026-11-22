// SPDX-License-Identifier: AGPL-3.0-only

// Package store 复用插件 KV 的乐观并发语义，不添加宿主业务表。
package store

import (
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 持久状态边界 ========================

// Entry 是带版本的私有 JSON 状态，不用于公开输出。
type Entry struct {
	Value    []byte
	Revision string
}

func (Entry) String() string   { return "prerequisites.Entry{[REDACTED]}" }
func (Entry) GoString() string { return "prerequisites.Entry{[REDACTED]}" }

// Repository 每次写入都必须带版本；expected 为空表示该键必须不存在。
// 实现需把并发失败转换为 REVISION_CONFLICT，不能降级为无条件覆盖。
type Repository interface {
	Get(context.Context, string) (Entry, bool, error)
	Put(context.Context, string, string, []byte) (string, error)
	Delete(context.Context, string, string) error
}

// Load 校验外部持久状态，缺失状态保留调用方的零值。
func Load[T any](ctx context.Context, repository Repository, key string, dst *T) (string, bool, error) {
	entry, found, err := repository.Get(ctx, key)
	if err != nil || !found {
		return "", found, err
	}
	if entry.Revision == "" || len(entry.Value) > 1<<20 || json.Unmarshal(entry.Value, dst) != nil {
		return "", false, fault.New("STATE_INVALID", "准备模块的持久状态无效")
	}
	return entry.Revision, true, nil
}

// Save 将完整资源状态一次提交，避免跨多个 KV 键的部分更新。
func Save[T any](ctx context.Context, repository Repository, key, expected string, value T) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 1<<20 {
		return "", fault.New("STATE_INVALID", "准备模块状态无法安全保存")
	}
	return repository.Put(ctx, key, expected, raw)
}
