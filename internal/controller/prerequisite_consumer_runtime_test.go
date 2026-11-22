// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 宿主能力注册与内部续期作业分发测试 ========================

type stubCapabilityForwarder struct{}

func (stubCapabilityForwarder) Forward(context.Context, hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	return hostsvc.CapabilityResult{}, nil
}

func newTestPluginRuntimeForPrereq(t *testing.T) *PluginRuntime {
	t.Helper()
	dir := t.TempDir()
	rt, err := NewPluginRuntime(PluginRuntimeOptions{
		Units:     &fakeSupervisorUnits{},
		PluginDir: PluginDirResolver(filepath.Join(dir, "plugins")),
		RunDir:    filepath.Join(dir, "run"),
		StateDir:  filepath.Join(dir, "state"),
		Host: func(string) (supervisor.HostServer, error) {
			return fakeHostServer{}, nil
		},
	})
	if err != nil {
		t.Fatalf("构造测试 PluginRuntime 失败：%v", err)
	}
	t.Cleanup(rt.Stop)
	return rt
}

func TestPluginRuntimeSetCapabilityServiceBoundaries(t *testing.T) {
	var nilRT *PluginRuntime
	if err := nilRT.SetCapabilityService("dns", stubCapabilityForwarder{}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("nil runtime 未拒绝能力注册：%v", err)
	}
	if nilRT.HasCapabilityService("dns") {
		t.Fatal("nil runtime 报告存在能力服务")
	}

	rt := newTestPluginRuntimeForPrereq(t)
	if err := rt.SetCapabilityService("", stubCapabilityForwarder{}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("空服务名未被拒绝：%v", err)
	}
	if err := rt.SetCapabilityService("dns", nil); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("nil forwarder 未被拒绝：%v", err)
	}
	if err := rt.SetCapabilityService("dns", stubCapabilityForwarder{}); err != nil {
		t.Fatalf("注册 dns 失败：%v", err)
	}
	if err := rt.SetCapabilityService("certificates", stubCapabilityForwarder{}); err != nil {
		t.Fatalf("注册 certificates 失败：%v", err)
	}
	if !rt.HasCapabilityService("dns") || !rt.HasCapabilityService("certificates") {
		t.Fatal("已注册的 dns/certificates 未体现在 HasCapabilityService")
	}
	if err := rt.SetCapabilityService("dns", stubCapabilityForwarder{}); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("重复注册 dns 未返回 StateConflict：%v", err)
	}

	if err := rt.Start(t.Context(), HostDeps{}); err != nil {
		t.Fatalf("启动 PluginRuntime 失败：%v", err)
	}
	if err := rt.SetCapabilityService("late", stubCapabilityForwarder{}); !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("Start 后注册能力未被拒绝：%v", err)
	}
}

type stubPluginClients struct {
	attachCalls int
	liveCalls   int
}

func (s *stubPluginClients) attach(context.Context, string) (PluginClient, error) {
	s.attachCalls++
	return nil, problem.New(problem.PluginUnavailable, "stub plugin not attached")
}

func (s *stubPluginClients) live(string) (PluginClient, error) {
	s.liveCalls++
	return nil, problem.New(problem.PluginUnavailable, "stub plugin not live")
}

func TestPluginRuntimeSetRenewalJobHandlerDispatch(t *testing.T) {
	rt := newTestPluginRuntimeForPrereq(t)
	clients := &stubPluginClients{}
	rt.dispatcher.clients = clients

	var seenOpID string
	wantErr := errors.New("renewal coordinator error")
	handledFlag := true
	rt.SetRenewalJobHandler(func(_ context.Context, req operations.PluginRunJobRequest) (bool, error) {
		seenOpID = req.OperationID
		if !handledFlag {
			return false, nil
		}
		return true, wantErr
	})

	// 命中 tls.certificates/renew_existing 且 handled=true 时拦截，绝不触发外部插件 attach。
	err := rt.dispatcher.RunJob(t.Context(), operations.PluginRunJobRequest{
		PluginID:    "tls.certificates",
		Operation:   "renew_existing",
		OperationID: "op-renew-01",
	}, func(operations.JobProgress) error { return nil })
	if !errors.Is(err, wantErr) || seenOpID != "op-renew-01" || clients.attachCalls != 0 {
		t.Fatalf("续期作业未被拦截或误触发外部插件：err=%v op=%q attach=%d", err, seenOpID, clients.attachCalls)
	}

	// handled=false 时必须透明回退至常规插件分发。
	handledFlag = false
	err = rt.dispatcher.RunJob(t.Context(), operations.PluginRunJobRequest{
		PluginID:    "tls.certificates",
		Operation:   "renew_existing",
		OperationID: "op-renew-02",
	}, func(operations.JobProgress) error { return nil })
	if !problem.HasCode(err, problem.PluginUnavailable) || clients.attachCalls != 1 {
		t.Fatalf("handled=false 未回退到常规分发：err=%v attach=%d", err, clients.attachCalls)
	}

	// 其他插件或操作绝不被续期拦截器截获。
	handledFlag = true
	seenOpID = ""
	err = rt.dispatcher.RunJob(t.Context(), operations.PluginRunJobRequest{
		PluginID:    "core.xray",
		Operation:   "core.apply",
		OperationID: "op-other-01",
	}, func(operations.JobProgress) error { return nil })
	if !problem.HasCode(err, problem.PluginUnavailable) || seenOpID != "" || clients.attachCalls != 2 {
		t.Fatalf("非续期操作被错误拦截：err=%v seen=%q attach=%d", err, seenOpID, clients.attachCalls)
	}
}

// ======================== PluginConsumerRuntime Apply / Inspect / InUse 回归测试 ========================

func testConsumerBindingAndProof(consumer certificates.Consumer) (certificates.HostBinding, consumerfiles.Proof) {
	binding := certificates.HostBinding{
		ID:             "certbind_fixture",
		CertificateID:  "cert_fixture",
		Generation:     4,
		Consumer:       consumer,
		PolicyRevision: "rev_04",
	}
	proof := consumerfiles.Proof{
		Binding:          binding,
		FullchainSHA256:  strings.Repeat("a", 64),
		PrivateKeySHA256: strings.Repeat("b", 64),
	}
	return binding, proof
}

func TestPluginConsumerRuntimeApplySendsReloadPayloadWithoutPEM(t *testing.T) {
	c, _, consumer := prerequisiteConsumerFixture(t)
	binding, proof := testConsumerBindingAndProof(consumer)

	var gotPlugin, gotOp string
	var gotPayload []byte
	rt := &PluginConsumerRuntime{
		Controller: c,
		invoke: func(_ context.Context, pluginID, operation string, payload []byte) ([]byte, error) {
			gotPlugin = pluginID
			gotOp = operation
			gotPayload = append([]byte(nil), payload...)
			return []byte(`{"ok":true}`), nil
		},
	}

	if err := rt.Apply(t.Context(), binding, proof); err != nil {
		t.Fatalf("Apply 合法绑定失败：%v", err)
	}
	if gotPlugin != "core.xray" || gotOp != ConsumerTLSReloadOperation {
		t.Fatalf("Apply 路由目标错误：plugin=%q op=%q", gotPlugin, gotOp)
	}
	var decoded ConsumerTLSReloadPayload
	if err := json.Unmarshal(gotPayload, &decoded); err != nil {
		t.Fatalf("解析下发 reload 载荷失败：%v", err)
	}
	if decoded.BindingRef != binding.ID ||
		decoded.ProfileID != consumer.ProfileID ||
		decoded.Generation != binding.Generation ||
		decoded.PolicyRevision != binding.PolicyRevision ||
		decoded.FullchainSHA256 != proof.FullchainSHA256 ||
		decoded.PrivateKeySHA256 != proof.PrivateKeySHA256 ||
		decoded.SNI != consumer.SNI {
		t.Fatalf("Apply 载荷字段不匹配：%+v", decoded)
	}
	if strings.Contains(string(gotPayload), "BEGIN") || strings.Contains(string(gotPayload), "base64") {
		t.Fatalf("Apply 载荷不应携带 PEM 原文：%s", string(gotPayload))
	}

	// binding 与 proof 不一致必须直接拒绝，不发起插件 RPC。
	badProof := proof
	badProof.Binding.Generation = 99
	if err := rt.Apply(t.Context(), binding, badProof); fault.Code(err) != "CONSUMER_RUNTIME_INVALID" {
		t.Fatalf("不匹配的 proof 未被拒绝：%v", err)
	}
}

func TestPluginConsumerRuntimeInspectStrictDecodeAndStoppedPlugin(t *testing.T) {
	c, _, consumer := prerequisiteConsumerFixture(t)

	t.Run("valid-result", func(t *testing.T) {
		rt := &PluginConsumerRuntime{
			Controller: c,
			invoke: func(_ context.Context, pluginID, operation string, payload []byte) ([]byte, error) {
				if pluginID != "core.xray" || operation != ConsumerTLSInspectOperation {
					t.Fatalf("unexpected invoke target %s/%s", pluginID, operation)
				}
				var req ConsumerTLSInspectPayload
				if err := json.Unmarshal(payload, &req); err != nil || req.BindingRef != "certbind_fixture" || req.ProfileID != consumer.ProfileID {
					t.Fatalf("inspect 请求载荷错误：%s %v", string(payload), err)
				}
				return json.Marshal(ConsumerTLSInspectResult{
					Running:         true,
					BindingRef:      "certbind_fixture",
					Generation:      4,
					PolicyRevision:  "rev_04",
					FullchainSHA256: strings.Repeat("a", 64),
					LeafFingerprint: strings.Repeat("f", 64),
					SNI:             consumer.SNI,
					Endpoint:        "127.0.0.1:18443",
				})
			},
		}
		obs, err := rt.Inspect(t.Context(), consumer, "certbind_fixture")
		if err != nil {
			t.Fatalf("Inspect 合法响应失败：%v", err)
		}
		if !obs.Running || obs.BindingID != "certbind_fixture" || obs.ActiveGeneration != 4 ||
			obs.PolicyRevision != "rev_04" || obs.FullchainSHA256 != strings.Repeat("a", 64) ||
			obs.LeafFingerprint != strings.Repeat("f", 64) || obs.SNI != consumer.SNI || obs.Endpoint != "127.0.0.1:18443" {
			t.Fatalf("Inspect 映射结果不符：%+v", obs)
		}
	})

	t.Run("stopped-plugin-returns-not-running", func(t *testing.T) {
		rt := &PluginConsumerRuntime{
			Controller: c,
			invoke: func(context.Context, string, string, []byte) ([]byte, error) {
				return nil, problem.New(problem.PluginUnavailable, "plugin not running")
			},
		}
		obs, err := rt.Inspect(t.Context(), consumer, "certbind_fixture")
		if err != nil || obs.Running {
			t.Fatalf("未运行插件未返回 Running=false：obs=%+v err=%v", obs, err)
		}
	})

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unknown-field", []byte(`{"running":true,"extra":1}`)},
		{"trailing-garbage", []byte(`{"running":true}{"running":false}`)},
		{"null-body", []byte(`null`)},
		{"oversize", []byte(`{"running":true,"endpoint":"` + strings.Repeat("x", maxConsumerTLSInspectResponse) + `"}`)},
	} {
		t.Run("reject-"+tc.name, func(t *testing.T) {
			rt := &PluginConsumerRuntime{
				Controller: c,
				invoke: func(context.Context, string, string, []byte) ([]byte, error) {
					return tc.raw, nil
				},
			}
			if _, err := rt.Inspect(t.Context(), consumer, "certbind_fixture"); fault.Code(err) != "CONSUMER_RUNTIME_INVALID" {
				t.Fatalf("非法 inspect 响应 (%s) 未返回 CONSUMER_RUNTIME_INVALID：%v", tc.name, err)
			}
		})
	}
}

func TestPluginConsumerRuntimeInUseChecksConfigAndLiveRuntime(t *testing.T) {
	c, _, consumer := prerequisiteConsumerFixture(t)
	binding, _ := testConsumerBindingAndProof(consumer)

	// 1. 已提交配置引用 binding.ID 时直接判定占用，即使插件未运行。
	rt := &PluginConsumerRuntime{
		Controller: c,
		invoke: func(context.Context, string, string, []byte) ([]byte, error) {
			t.Fatal("已提交配置已命中占用时不应多余调用 Inspect")
			return nil, nil
		},
	}
	inUse, err := rt.InUse(t.Context(), binding)
	if err != nil || !inUse {
		t.Fatalf("已提交配置引用绑定未返回 inUse=true：inUse=%v err=%v", inUse, err)
	}

	// 将已提交配置改绑到其他 binding_ref，解除配置占用。
	detached := prerequisiteFixtureIntent(t)
	detached.Profiles[0].Hysteria2.TLS.BindingRef = "certbind_other"
	rawDetached, err := json.Marshal(detached)
	if err != nil {
		t.Fatal(err)
	}
	storeAppliedPluginConfig(t, c.db, "core.xray", 2, string(rawDetached))
	c.SetUpdater(loadStoredPluginUpdater(t, c.db))

	// 2. 配置已解绑，但运行时仍在活跃使用非零代次 -> 仍判定 inUse=true。
	rtRunning := &PluginConsumerRuntime{
		Controller: c,
		invoke: func(context.Context, string, string, []byte) ([]byte, error) {
			return json.Marshal(ConsumerTLSInspectResult{Running: true, BindingRef: binding.ID, Generation: 4})
		},
	}
	inUse, err = rtRunning.InUse(t.Context(), binding)
	if err != nil || !inUse {
		t.Fatalf("配置解绑但运行时仍活跃时未返回 inUse=true：inUse=%v err=%v", inUse, err)
	}

	// 3. 配置已解绑且运行时已停机/无生效代次 -> inUse=false。
	rtStopped := &PluginConsumerRuntime{
		Controller: c,
		invoke: func(context.Context, string, string, []byte) ([]byte, error) {
			return nil, problem.New(problem.PluginUnavailable, "stopped")
		},
	}
	inUse, err = rtStopped.InUse(t.Context(), binding)
	if err != nil || inUse {
		t.Fatalf("配置解绑且运行时未运行时未返回 inUse=false：inUse=%v err=%v", inUse, err)
	}

	// 4. Inspect 发生传输/协议错误时必须 fail-closed 返回 true, err。
	rtErr := &PluginConsumerRuntime{
		Controller: c,
		invoke: func(context.Context, string, string, []byte) ([]byte, error) {
			return nil, errors.New("rpc timeout")
		},
	}
	inUse, err = rtErr.InUse(t.Context(), binding)
	if err == nil || !inUse {
		t.Fatalf("Inspect 出错时未 fail-closed：inUse=%v err=%v", inUse, err)
	}

	// 5. 缺少 Updater 时必须 fail-closed 返回 BACKEND_REQUIRED。
	noUpdater, _ := newVisibilityController(t)
	rtNoUpdater := &PluginConsumerRuntime{Controller: noUpdater}
	inUse, err = rtNoUpdater.InUse(t.Context(), binding)
	if !inUse || fault.Code(err) != "BACKEND_REQUIRED" {
		t.Fatalf("缺少 Updater 时未 fail-closed 返回 BACKEND_REQUIRED：inUse=%v err=%v", inUse, err)
	}
}
