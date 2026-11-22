// SPDX-License-Identifier: AGPL-3.0-only

package coreproc

import (
	"context"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/sdk/coreapi"
)

// Snapshot 总是保留独立进程状态；API 失败不会把活 PID 解释为可用代理。
func (m *Manager) Snapshot(ctx context.Context) Snapshot {
	m.mu.Lock()
	slot := m.current
	result := Snapshot{State: "STOPPED", APIState: "UNAVAILABLE"}
	if slot != nil {
		result.State, result.Epoch, result.Digest = slot.state, slot.epoch, slot.spec.Digest
		if slot.context.Err() != nil && !slotDone(slot) {
			result.State = "STOPPING"
		}
		if slot.command != nil && slot.command.Process != nil {
			result.PID = slot.command.Process.Pid
		}
	}
	m.mu.Unlock()
	if slot != nil && result.State == "RUNNING" && m.probe(ctx, slot) == nil {
		result.APIState = "READY"
	}
	m.mu.Lock()
	if slot != m.current {
		result.State, result.APIState = "STOPPED", "UNAVAILABLE"
	} else if slot != nil {
		currentState := slot.state
		if slot.context.Err() != nil && !slotDone(slot) {
			currentState = "STOPPING"
		}
		if currentState != result.State {
			result.State, result.APIState = currentState, "UNAVAILABLE"
		}
	}
	m.mu.Unlock()
	return result
}

// WaitHealthy 限制等待预算，每次只验证真实入站的只读零值或累计计数器。
func (m *Manager) WaitHealthy(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	for {
		m.mu.Lock()
		slot := m.current
		alive := slot != nil && slot.state == "RUNNING" && slot.context.Err() == nil && !slotDone(slot)
		m.mu.Unlock()
		if !alive {
			return ErrUnhealthy
		}
		if err := m.probe(ctx, slot); err == nil {
			return nil
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ErrUnhealthy, ctx.Err())
		case <-slot.done:
			timer.Stop()
			return ErrUnhealthy
		case <-timer.C:
		}
	}
}

func (m *Manager) probe(parent context.Context, slot *processSlot) error {
	if err := parent.Err(); err != nil {
		return err
	}
	client, err := m.client(slot)
	if err != nil {
		return ErrUnhealthy
	}
	tag, err := coreapi.InboundTag(slot.spec.InboundID)
	if err != nil {
		return ErrUnhealthy
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if _, err := client.Get(ctx, "inbound>>>"+tag+">>>traffic>>>uplink"); err != nil {
		return ErrUnhealthy
	}
	m.mu.Lock()
	alive := m.current == slot && slot.state == "RUNNING" && slot.context.Err() == nil && !slotDone(slot)
	m.mu.Unlock()
	if !alive {
		return ErrUnhealthy
	}
	return nil
}

func (m *Manager) client(slot *processSlot) (Stats, error) {
	m.mu.Lock()
	if m.current != slot || slot.state != "RUNNING" || slot.context.Err() != nil || slotDone(slot) {
		m.mu.Unlock()
		return nil, ErrUnhealthy
	}
	if client := slot.api; client != nil {
		m.mu.Unlock()
		return client, nil
	}
	m.mu.Unlock()
	created, err := m.options.API(m.options.Socket)
	if err != nil || created == nil {
		return nil, ErrUnhealthy
	}
	m.mu.Lock()
	if m.current != slot || slot.state != "RUNNING" || slot.context.Err() != nil || slotDone(slot) {
		m.mu.Unlock()
		if created.Close() != nil {
			return nil, ErrUnhealthy
		}
		return nil, ErrUnhealthy
	}
	if client := slot.api; client != nil {
		m.mu.Unlock()
		if created.Close() != nil {
			return nil, ErrUnhealthy
		}
		return client, nil
	}
	slot.api = created
	m.mu.Unlock()
	return created, nil
}
