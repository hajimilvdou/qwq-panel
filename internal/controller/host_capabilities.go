// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"os"
	"path/filepath"
	"sort"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/internal/sandbox"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// ======================== 派发绑定：复用宿主事实 ========================
type hostCapabilityResolver struct {
	operations                   operationReader
	pluginID, instanceID, nodeID string
}

func (h *hostCapabilityResolver) Resolve(ctx context.Context, instanceID, operationID string) (hostsvc.OperationBinding, error) {
	if instanceID != h.instanceID {
		return hostsvc.OperationBinding{}, nil
	}
	operation, ok := dispatchedOperation(ctx, h.operations, h.pluginID, h.instanceID, h.nodeID, operationID)
	if !ok {
		return hostsvc.OperationBinding{}, nil
	}
	capabilities := make([]*platformv1.Capability, 0, len(operation.Meta.Capabilities))
	for _, capability := range operation.Meta.Capabilities {
		capabilities = append(capabilities, &platformv1.Capability{Name: capability.Name, Scope: capability.Scope})
	}
	effect := operation.Meta.Effect
	if effect == "" {
		effect = operation.Effect
	}
	return hostsvc.OperationBinding{Dispatched: true, Capabilities: capabilities, Effect: effect}, nil
}

// ConfigureHostCapabilities 只接收宿主已验签的版本 manifest 能力。
// 新版本启动前重建发生授权变化的常驻通道，避免继续使用旧版能力或服务注册表。
// 同一插件的调用由 updater 插件锁串行化；没有变化时不打断健康连接。
func (rt *PluginRuntime) ConfigureHostCapabilities(pluginID string, capabilities []manifest.Capability) error {
	if rt == nil {
		return problem.New(problem.Unavailable, "The plugin runtime is not configured.")
	}
	if err := sandbox.ValidateID(pluginID); err != nil {
		return problem.New(problem.ValidationFailed, "Invalid plugin id.")
	}
	if err := rt.startedError(); err != nil {
		return err
	}
	snapshot := make([]manifest.Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		snapshot = append(snapshot, manifest.Capability{Name: capability.Name, Scope: capability.Scope})
	}
	sort.Slice(snapshot, func(i, j int) bool {
		if snapshot[i].Name == snapshot[j].Name {
			return snapshot[i].Scope < snapshot[j].Scope
		}
		return snapshot[i].Name < snapshot[j].Name
	})
	// 关闭旧 listener、发布授权和新服务注册必须形成同一临界区。
	// 锁顺序与 Ensure 一致：hostMu -> hostCapabilitiesMu / runtime.mu。
	rt.hostMu.Lock()
	defer rt.hostMu.Unlock()
	if err := rt.startedError(); err != nil {
		return err
	}
	rt.hostCapabilitiesMu.RLock()
	previous, exists := rt.hostCapabilities[pluginID]
	same := exists && sameHostCapabilities(previous, snapshot)
	rt.hostCapabilitiesMu.RUnlock()
	if same {
		return rt.ensureHostChannelLocked(pluginID)
	}
	rt.releaseHostChannelLocked(pluginID)
	rt.hostCapabilitiesMu.Lock()
	if rt.hostCapabilities == nil {
		rt.hostCapabilities = make(map[string][]manifest.Capability)
	}
	rt.hostCapabilities[pluginID] = snapshot
	rt.hostCapabilitiesMu.Unlock()
	return rt.ensureHostChannelLocked(pluginID)
}

func sameHostCapabilities(left, right []manifest.Capability) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Name != right[index].Name || left[index].Scope != right[index].Scope {
			return false
		}
	}
	return true
}

func (rt *PluginRuntime) hostCapabilityGrants(deps HostDeps, pluginID string) []*platformv1.Capability {
	rt.hostCapabilitiesMu.RLock()
	snapshot, configured := rt.hostCapabilities[pluginID]
	grants := make([]*platformv1.Capability, 0, len(snapshot))
	for _, capability := range snapshot {
		grants = append(grants, &platformv1.Capability{Name: capability.Name, Scope: capability.Scope})
	}
	rt.hostCapabilitiesMu.RUnlock()
	if configured {
		return grants
	}
	if deps.Catalog != nil {
		capabilities, _, ok := deps.Catalog.PluginGrants(pluginID)
		if ok {
			for _, capability := range capabilities {
				grants = append(grants, &platformv1.Capability{Name: capability.Name, Scope: capability.Scope})
			}
		}
	}
	return grants
}

// configureHostChannelForSpec 保持原 HostChannels 接口兼容；生产 runtime 实现可选
// 的能力配置接口，旧 fake/无能力宿主仍走原通道路径。
func configureHostChannelForSpec(hosts HostChannels, spec updater.InstanceSpec) error {
	if configurable, ok := hosts.(interface {
		ConfigureHostCapabilities(string, []manifest.Capability) error
	}); ok {
		if err := configurable.ConfigureHostCapabilities(spec.PluginID, spec.Manifest.Capabilities); err != nil {
			return &problem.Error{Code: problem.PluginUnavailable, Detail: "The plugin capability channel could not be configured.", Cause: err}
		}
	}
	return nil
}

func ensureHostChannelForSpec(hosts HostChannels, spec updater.InstanceSpec) error {
	if err := configureHostChannelForSpec(hosts, spec); err != nil {
		return err
	}
	return ensureHostChannel(hosts, spec.PluginID)
}

// IsActiveBackgroundInstance implements hostsvc.AutonomousInstanceChecker:
// returns true only when the active installed manifest of pluginID declares
// lifecycle.background == true and the supervisor currently holds a live client
// for the instance.
func (rt *PluginRuntime) IsActiveBackgroundInstance(pluginID, instanceID string) bool {
	if rt == nil || instanceID != DefaultInstanceID || sandbox.ValidateID(pluginID) != nil {
		return false
	}
	if _, err := rt.live(pluginID); err != nil {
		return false
	}
	if rt.opts.PluginDir == nil {
		return false
	}
	dir, err := rt.opts.PluginDir(pluginID)
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return false
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return false
	}
	return m.Lifecycle.Background
}

var _ hostsvc.OperationResolver = (*hostCapabilityResolver)(nil)
var _ hostsvc.AutonomousInstanceChecker = (*PluginRuntime)(nil)
