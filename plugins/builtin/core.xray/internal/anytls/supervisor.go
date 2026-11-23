// SPDX-License-Identifier: AGPL-3.0-only

package anytls

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// Supervisor 统一管理实例内全部 AnyTLS v1/v2 监听器的无损热更新、启停、证书热重载与单调计数器汇总。
type Supervisor struct {
	mu      sync.RWMutex
	servers map[string]*Server
	lastErr string
}

// NewSupervisor 创建空的 AnyTLS 监管器。
func NewSupervisor() *Supervisor {
	return &Supervisor{servers: make(map[string]*Server)}
}

// StartAll 差量热更新或原子切换全部 AnyTLS 监听器：
//   - 若同 ProfileID 的监听地址未变且监听存活，直接调用 HotUpdate 零断连刷新用户、填充方案与证书，保留实时会话与计数器；
//   - 若端口或监听地址变更，先校验新配置、再优雅释放旧端口并迁移历史流量计数；
//   - 任一新配置校验失败不会提前误杀仍在运行的旧监听器。
func (sup *Supervisor) StartAll(ctx context.Context, specs []ProfileSpec) error {
	if len(specs) == 0 {
		sup.StopAll(3 * time.Second)
		sup.mu.Lock()
		sup.lastErr = ""
		sup.mu.Unlock()
		return nil
	}

	// 第 1 阶段：无副作用预校验全部新规格，避免因单个配置非法误杀现网监听器
	prepared := make(map[string]*Server, len(specs))
	for _, spec := range specs {
		srv, err := NewServer(spec)
		if err != nil {
			sup.mu.Lock()
			sup.lastErr = err.Error()
			sup.mu.Unlock()
			return err
		}
		prepared[spec.ProfileID] = srv
	}

	sup.mu.Lock()
	existing := sup.servers
	sup.mu.Unlock()

	nextServers := make(map[string]*Server, len(specs))
	newlyStarted := make([]*Server, 0, len(specs))
	var toStop []*Server

	// 先释放已被移除或监听地址发生变更的旧监听器，避免同端口重绑冲突
	desiredByID := make(map[string]ProfileSpec, len(specs))
	for _, spec := range specs {
		desiredByID[spec.ProfileID] = spec
	}
	for id, oldSrv := range existing {
		spec, keep := desiredByID[id]
		targetAddr := net.JoinHostPort(spec.Listen, strconv.Itoa(spec.Port))
		if !keep || oldSrv.listenAddr != targetAddr || !oldSrv.IsAlive() {
			toStop = append(toStop, oldSrv)
		}
	}
	for _, oldSrv := range toStop {
		oldSrv.Stop(3 * time.Second)
	}

	// 第 2 阶段：对保留同端口的实例执行零断连 HotUpdate，对新增/换端口实例执行 Start + 计数器继承
	for _, spec := range specs {
		targetAddr := net.JoinHostPort(spec.Listen, strconv.Itoa(spec.Port))
		if oldSrv, ok := existing[spec.ProfileID]; ok && oldSrv.listenAddr == targetAddr && oldSrv.IsAlive() {
			if err := oldSrv.HotUpdate(spec); err != nil {
				for _, s := range newlyStarted {
					s.Stop(2 * time.Second)
				}
				sup.mu.Lock()
				sup.lastErr = err.Error()
				sup.mu.Unlock()
				return err
			}
			nextServers[spec.ProfileID] = oldSrv
			continue
		}

		newSrv := prepared[spec.ProfileID]
		if oldSrv, ok := existing[spec.ProfileID]; ok {
			newSrv.InheritCountersFrom(oldSrv)
		}
		if err := newSrv.Start(ctx); err != nil {
			for _, s := range newlyStarted {
				s.Stop(2 * time.Second)
			}
			sup.mu.Lock()
			sup.lastErr = err.Error()
			sup.mu.Unlock()
			return err
		}
		newlyStarted = append(newlyStarted, newSrv)
		nextServers[spec.ProfileID] = newSrv
	}

	sup.mu.Lock()
	sup.servers = nextServers
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
	if srv == nil || (bindingRef != "" && srv.bindingRefValue() != bindingRef) {
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

// Status 返回监管器真实健康状态（含底层监听协程存活核验）。
func (sup *Supervisor) Status() (bool, string) {
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	if sup.lastErr != "" {
		return false, sup.lastErr
	}
	for id, srv := range sup.servers {
		if !srv.IsAlive() {
			return false, "anytls listener exited unexpectedly: " + id
		}
	}
	return true, ""
}

// IsRunning 查询指定 profile 是否正在真实存活监听。
func (sup *Supervisor) IsRunning(profileID string) bool {
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	srv, ok := sup.servers[profileID]
	return ok && srv.IsAlive()
}
