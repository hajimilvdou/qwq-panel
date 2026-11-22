// SPDX-License-Identifier: AGPL-3.0-only

// Package testsupport 只供显式测试注入，不是生产状态后端。
package testsupport

import (
	"context"
	"strconv"
	"sync"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/store"
)

// MemoryStore 模拟宿主 KV 的 CAS 与失败注入。
type MemoryStore struct {
	mu      sync.Mutex
	data    map[string]store.Entry
	next    uint64
	FailPut func(int) error
	puts    int
}

func (m *MemoryStore) Get(ctx context.Context, key string) (store.Entry, bool, error) {
	if err := ctx.Err(); err != nil {
		return store.Entry{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, found := m.data[key]
	entry.Value = append([]byte(nil), entry.Value...)
	return entry, found, nil
}

func (m *MemoryStore) Put(ctx context.Context, key, expected string, value []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if m.FailPut != nil {
		if err := m.FailPut(m.puts); err != nil {
			return "", err
		}
	}
	entry, found := m.data[key]
	if (expected == "" && found) || (expected != "" && (!found || entry.Revision != expected)) {
		return "", fault.New("REVISION_CONFLICT", "状态版本已变化")
	}
	if m.data == nil {
		m.data = make(map[string]store.Entry)
	}
	m.next++
	revision := strconv.FormatUint(m.next, 10)
	m.data[key] = store.Entry{Value: append([]byte(nil), value...), Revision: revision}
	return revision, nil
}

func (m *MemoryStore) Delete(ctx context.Context, key, expected string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, found := m.data[key]
	if expected == "" || !found || entry.Revision != expected {
		return fault.New("REVISION_CONFLICT", "状态版本已变化")
	}
	delete(m.data, key)
	return nil
}
