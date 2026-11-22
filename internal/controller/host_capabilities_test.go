// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/pluginhost/updater"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

type capabilityOperationReader struct{ operation *operations.Operation }

func (r capabilityOperationReader) Get(_ context.Context, _ actor.Actor, id string) (*operations.Operation, error) {
	if r.operation == nil || r.operation.ID != id {
		return nil, problem.New(problem.NotFound, "Missing operation.")
	}
	return r.operation, nil
}

func TestCapabilityResolverUsesDispatchedMetadata(t *testing.T) {
	operation := &operations.Operation{
		ID: "op_known", Status: operations.Running,
		Target: operations.Target{PluginID: "security.basic", InstanceID: "default", NodeID: "local"},
		Meta:   operations.Action{Effect: "write", Capabilities: []operations.Capability{{Name: "system.account.keys", Scope: "alice"}}},
	}
	resolver := &hostCapabilityResolver{operations: capabilityOperationReader{operation}, pluginID: "security.basic", instanceID: "default", nodeID: "local"}
	binding, err := resolver.Resolve(t.Context(), "default", "op_known")
	if err != nil || !binding.Dispatched || binding.Effect != "write" || len(binding.Capabilities) != 1 || binding.Capabilities[0].Scope != "alice" {
		t.Fatal("宿主派发/能力快照未正确绑定")
	}
	binding.Capabilities[0].Scope = "all"
	if operation.Meta.Capabilities[0].Scope != "alice" {
		t.Fatal("调用方修改了宿主 operation 元数据")
	}
	for _, state := range []operations.Status{operations.Pending, operations.AwaitingApproval, operations.Approved, operations.Succeeded, operations.Failed, operations.Canceled} {
		operation.Status = state
		binding, err := resolver.Resolve(t.Context(), "default", "op_known")
		if err != nil || binding.Dispatched {
			t.Fatalf("非 RUNNING 状态获得写绑定：%s", state)
		}
	}
	operation.Status = operations.Running
	for _, change := range []func(){
		func() { operation.Target.PluginID = "another" },
		func() { operation.Target.InstanceID = "other" },
		func() { operation.Target.NodeID = "other" },
	} {
		operation.Target = operations.Target{PluginID: "security.basic", InstanceID: "default", NodeID: "local"}
		change()
		binding, err := resolver.Resolve(t.Context(), "default", "op_known")
		if err != nil || binding.Dispatched {
			t.Fatal("跨插件/实例/节点 operation 获得能力绑定")
		}
	}
}

type capabilityHost struct{ starts, stops *atomic.Int32 }

func (h capabilityHost) Serve(context.Context, string) (func(), error) {
	h.starts.Add(1)
	return func() { h.stops.Add(1) }, nil
}

func TestCapabilityChannelRefreshesVerifiedGrants(t *testing.T) {
	starts, stops := &atomic.Int32{}, &atomic.Int32{}
	runtime := &PluginRuntime{
		opts:    PluginRuntimeOptions{Logger: slog.New(slog.DiscardHandler)},
		started: true, lifetime: t.Context(), hosts: make(map[string]func()),
		hostFactory: func(string) (supervisor.HostServer, error) { return capabilityHost{starts, stops}, nil },
	}
	t.Cleanup(func() { runtime.ReleaseHostChannel("security.basic") })
	caps := []manifest.Capability{{Name: "system.account.keys", Scope: "alice"}, {Name: "metrics.read", Scope: "self"}}
	if err := runtime.ConfigureHostCapabilities("security.basic", caps); err != nil {
		t.Fatal(err)
	}
	caps[0].Scope = "all"
	grants := runtime.hostCapabilityGrants(HostDeps{}, "security.basic")
	for _, grant := range grants {
		if grant.Name == "system.account.keys" && grant.Scope != "alice" {
			t.Fatal("原始 manifest 修改污染了授权快照")
		}
	}
	if err := runtime.ConfigureHostCapabilities("security.basic", []manifest.Capability{{Name: "metrics.read", Scope: "self"}, {Name: "system.account.keys", Scope: "alice"}}); err != nil {
		t.Fatal(err)
	}
	if starts.Load() != 1 || stops.Load() != 0 {
		t.Fatal("相同能力的排序变化重启了健康通道")
	}
	if err := runtime.ConfigureHostCapabilities("security.basic", []manifest.Capability{{Name: "metrics.read", Scope: "self"}}); err != nil {
		t.Fatal(err)
	}
	if starts.Load() != 2 || stops.Load() != 1 {
		t.Fatal("撤权没有重建服务注册表")
	}
	grants = runtime.hostCapabilityGrants(HostDeps{}, "security.basic")
	if len(grants) != 1 || grants[0].Name != "metrics.read" {
		t.Fatal("撤权后仍保留了旧能力")
	}
	runtime.ReleaseHostChannel("security.basic")
	if len(runtime.hostCapabilityGrants(HostDeps{}, "security.basic")) != 0 {
		t.Fatal("卸载未清理宿主授权快照")
	}
}

type configurableCapabilityChannels struct {
	configured, ensured bool
	caps                []manifest.Capability
}

func (c *configurableCapabilityChannels) EnsureHostChannel(string) error {
	c.ensured = true
	return nil
}
func (*configurableCapabilityChannels) ReleaseHostChannel(string) {}
func (c *configurableCapabilityChannels) ConfigureHostCapabilities(_ string, caps []manifest.Capability) error {
	c.configured = true
	c.caps = append([]manifest.Capability(nil), caps...)
	return nil
}

func TestCapabilityBootstrapUsesVerifiedManifest(t *testing.T) {
	host := &configurableCapabilityChannels{}
	spec := updater.InstanceSpec{PluginID: "security.basic", Manifest: &manifest.Manifest{Capabilities: []manifest.Capability{{Name: "system.account.keys", Scope: "alice"}}}}
	if err := ensureHostChannelForSpec(host, spec); err != nil || !host.configured || !host.ensured || len(host.caps) != 1 || host.caps[0].Scope != "alice" {
		t.Fatal("bootstrap 未传递验签版本能力")
	}
}

type callbackCapabilityHost struct{ start, stop func() }

func (h callbackCapabilityHost) Serve(context.Context, string) (func(), error) {
	h.start()
	return h.stop, nil
}

func TestCapabilityChannelRebindIsAtomic(t *testing.T) {
	entered := make(chan struct{})
	unblock := make(chan struct{})
	created := make(chan string, 3)
	var stops atomic.Int32
	var releaseOnce atomic.Bool
	release := func() {
		if releaseOnce.CompareAndSwap(false, true) {
			close(unblock)
		}
	}
	defer release()
	runtime := &PluginRuntime{
		opts:    PluginRuntimeOptions{Logger: slog.New(slog.DiscardHandler)},
		started: true, lifetime: t.Context(), hosts: make(map[string]func()),
	}
	runtime.hostFactory = func(string) (supervisor.HostServer, error) {
		return callbackCapabilityHost{
			start: func() {
				grants := runtime.hostCapabilityGrants(HostDeps{}, "security.basic")
				created <- grants[0].Name
			},
			stop: func() {
				if stops.Add(1) == 1 {
					close(entered)
					<-unblock
				}
			},
		}, nil
	}
	t.Cleanup(func() { release(); runtime.ReleaseHostChannel("security.basic") })
	if err := runtime.ConfigureHostCapabilities("security.basic", []manifest.Capability{{Name: "system.account.keys", Scope: "all"}}); err != nil {
		t.Fatal(err)
	}
	<-created
	rebound := make(chan error, 1)
	go func() {
		rebound <- runtime.ConfigureHostCapabilities("security.basic", []manifest.Capability{{Name: "metrics.read", Scope: "self"}})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("未进入通道重建")
	}
	ensured := make(chan error, 1)
	go func() { ensured <- runtime.EnsureHostChannel("security.basic") }()
	premature := ""
	select {
	case premature = <-created:
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if err := <-rebound; err != nil {
		t.Fatal(err)
	}
	if err := <-ensured; err != nil {
		t.Fatal(err)
	}
	if premature != "" {
		t.Fatal("撤权期间并发 Ensure 注册了旧能力")
	}
	if name := <-created; name != "metrics.read" {
		t.Fatal("重建后未按新授权注册")
	}
}
