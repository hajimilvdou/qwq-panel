// SPDX-License-Identifier: AGPL-3.0-only

package coreproc

import (
	"context"
	"time"
)

// CounterSnapshot 的值与 epoch/digest 同属于一次已提交进程读取。
type CounterSnapshot struct {
	Epoch  string
	Digest string
	Values map[string]int64
}

// ReadCounters 仅读取，持有原 slot 身份并在查询后复核，拒绝跨代拼接结果。
func (m *Manager) ReadCounters(parent context.Context) (CounterSnapshot, error) {
	m.mu.Lock()
	slot := m.current
	if slot == nil || !slot.committed || slot.state != "RUNNING" || slot.context.Err() != nil || slotDone(slot) {
		m.mu.Unlock()
		return CounterSnapshot{}, ErrUnhealthy
	}
	epoch, digest := slot.epoch, slot.spec.Digest
	m.mu.Unlock()
	client, err := m.client(slot)
	if err != nil {
		return CounterSnapshot{}, ErrUnhealthy
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	values, err := client.Counters(ctx)
	if err != nil {
		return CounterSnapshot{}, ErrUnhealthy
	}
	m.mu.Lock()
	valid := m.current == slot && slot.committed && slot.state == "RUNNING" && slot.context.Err() == nil && !slotDone(slot) && slot.epoch == epoch
	m.mu.Unlock()
	if !valid {
		return CounterSnapshot{}, ErrUnhealthy
	}
	return CounterSnapshot{Epoch: epoch, Digest: digest, Values: values}, nil
}
