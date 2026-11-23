// SPDX-License-Identifier: AGPL-3.0-only

package anytls

import (
	"context"
	"sync"
	"time"
)

// Supervisor 统一管理实例内全部 AnyTLS v1/v2 监听器的启停、证书热重载与流量计数器汇总。
type Supervisor struct {
	mu      sync.RWMutex
	servers map[string]*Server
	lastErr string
}

// NewSupervisor 创建空的 AnyTLS 监管器。
func NewSupervisor() *Supervisor {
	return &Supervisor{servers: make(map[string]*Server)}
}

// StartAll 原子替换全部 AnyTLS 监听器；任一监听失败会清理已启动的新监听并返回错误。
func (sup *Supervisor) StartAll(ctx context.Context, specs []ProfileSpec) error {
	sup.StopAll(3 * time.Second)
	if len(specs) == 0 {
		sup.mu.Lock()
		sup.lastErr = ""
		sup.mu.Unlock()
		return nil
	}
	started := make(map[string]*Server, len(specs))
	for _, spec := range specs {
		srv, err := NewServer(spec)
		if err != nil {
			for _, s := range started {
				s.Stop(2 * time.Second)
			}
			sup.mu.Lock()
			sup.lastErr = err.Error()
			sup.mu.Unlock()
			return err
		}
		if err := srv.Start(ctx); err != nil {
			for _, s := range started {
				s.Stop(2 * time.Second)
			}
			sup.mu.Lock()
			sup.lastErr = err.Error()
			sup.mu.Unlock()
			return err
		}
		started[spec.ProfileID] = srv
	}
	sup.mu.Lock()
	sup.servers = started
	sup.lastErr = ""
	sup.mu.Unlock()
	return nil
}

// StopAll 关闭全部运行中的 AnyTLS 监听器。
func (sup *Supervisor) StopAll(timeout time.Duration) {
	sup.mu.Lock()
	current := sup.servers
	sup.servers = make(map[string]*Server)
	sup.mu.Unlock()
	for _, srv := range current {
		srv.Stop(timeout)
	}
}

// ReloadCertificate 为运行中的指定 AnyTLS 入站无中断热更新 TLS 证书。
func (sup *Supervisor) ReloadCertificate(profileID, bindingRef string, certPEM, keyPEM []byte) (bool, error) {
	sup.mu.RLock()
	srv := sup.servers[profileID]
	sup.mu.RUnlock()
	if srv == nil || (bindingRef != "" && srv.bindingRef != bindingRef) {
		return false, nil
	}
	if err := srv.UpdateCertificate(certPEM, keyPEM); err != nil {
		return false, err
	}
	return true, nil
}

// Counters 返回所有运行中 AnyTLS 实例的 Xray 兼容格式流量计数器快照。
func (sup *Supervisor) Counters() map[string]int64 {
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	if len(sup.servers) == 0 {
		return nil
	}
	out := make(map[string]int64, len(sup.servers)*4)
	for _, srv := range sup.servers {
		srv.AddCounters(out)
	}
	return out
}

// Status 返回监管器健康状态。
func (sup *Supervisor) Status() (bool, string) {
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	return sup.lastErr == "", sup.lastErr
}

// IsRunning 查询指定 profile 是否正在监听。
func (sup *Supervisor) IsRunning(profileID string) bool {
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	_, ok := sup.servers[profileID]
	return ok
}
