// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== 宿主准备能力端到端装配与生命周期测试 ========================

func TestWirePrerequisitesIntegrationAndLifecycle(t *testing.T) {
	cfg := testConfig(t)
	pluginsDir := filepath.Join(t.TempDir(), "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)

	rt, err := controller.NewPluginRuntime(controller.PluginRuntimeOptions{
		Units:       fakeUnitManager{},
		PluginDir:   (&controller.PluginDirs{Root: pluginsDir}).Resolve,
		PluginsRoot: pluginsDir,
		RunDir:      cfg.RunDir,
		StateDir:    filepath.Join(cfg.DataDir, "plugin-state"),
		Logger:      logger,
		NodeID:      "local",
	})
	if err != nil {
		t.Fatalf("NewPluginRuntime: %v", err)
	}

	life, cancelLife := context.WithCancel(context.Background())
	defer cancelLife()

	c, err := controller.New(life, controller.Options{
		Config:          cfg,
		Logger:          logger,
		PluginRuntime:   rt,
		DeferOperations: true,
	})
	if err != nil {
		rt.Stop()
		t.Fatalf("controller.New: %v", err)
	}
	t.Cleanup(func() {
		cancelLife()
		_ = c.Close()
	})

	prereqs, err := wirePrerequisites(c, rt, nil, logger)
	if err != nil {
		t.Fatalf("wirePrerequisites: %v", err)
	}
	if prereqs == nil || prereqs.Authority == nil || prereqs.Forwarder == nil || prereqs.Renewals == nil || prereqs.RenewalOps == nil {
		t.Fatalf("wirePrerequisites returned incomplete stack: %+v", prereqs)
	}

	if !rt.HasCapabilityService("dns") {
		t.Fatal("expected dns capability service to be registered on PluginRuntime")
	}
	if !rt.HasCapabilityService("certificates") {
		t.Fatal("expected certificates capability service to be registered on PluginRuntime")
	}

	// 二次装配必须返回 StateConflict，证明宿主授权与续期策略源确已绑定。
	if err := c.SetPrerequisiteAuthority(prereqs.Authority); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("second SetPrerequisiteAuthority = %v, want StateConflict", err)
	}
	if err := c.SetRenewalPolicySource(prereqs.Authority); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("second SetRenewalPolicySource = %v, want StateConflict", err)
	}

	if err := rt.Start(life, c.HostDeps()); err != nil {
		t.Fatalf("rt.Start after wirePrerequisites: %v", err)
	}
	c.StartOperations(life)

	// 短暂运行后台续期循环后取消并安全关闭，确保无竞态与协程泄漏。
	runCtx, cancelRun := context.WithCancel(life)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		prereqs.Renewals.Run(runCtx, func(err error) {
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("unexpected renewal tick error: %v", err)
			}
		})
	}()

	time.Sleep(20 * time.Millisecond)
	cancelRun()
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("prereqs.Renewals.Run did not exit after cancellation")
	}

	closeCtx, cancelClose := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelClose()
	if err := prereqs.Close(closeCtx); err != nil {
		t.Fatalf("prereqs.Close: %v", err)
	}

	// 防御边界：nil controller 拒绝装配，nil stack Close 幂等安全。
	if _, err := wirePrerequisites(nil, nil, nil, nil); err == nil {
		t.Fatal("wirePrerequisites(nil) should fail")
	}
	var nilStack *prerequisiteStack
	if err := nilStack.Close(context.Background()); err != nil {
		t.Fatalf("nil prerequisiteStack.Close = %v, want nil", err)
	}
}

// ======================== SSRF 拨号边界与受控出站 HTTP 客户端校验 ========================

func TestIsBlockedPrerequisiteIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"::",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.169.254",
		"fe80::1",
		"fe80::1%eth0",
		"100.64.0.1",
		"100.127.255.254",
		"fc00::1",
		"fd12:3456:789a::1",
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
		"::ffff:169.254.169.254",
		"192.0.2.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"240.0.0.1",
		"255.255.255.255",
		"224.0.0.1",
		"ff02::1",
		"64:ff9b::1.1.1.1",
		"64:ff9b:1::1",
		"100::1",
		"2001::1",
		"2001:db8::1",
		"2002::1",
		"fec0::1",
	}
	for _, raw := range blocked {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", raw, err)
		}
		if !isBlockedPrerequisiteIP(addr) {
			t.Errorf("isBlockedPrerequisiteIP(%q) = false, want true", raw)
		}
	}
	if !isBlockedPrerequisiteIP(netip.Addr{}) {
		t.Error("isBlockedPrerequisiteIP(invalid) = false, want true")
	}

	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
	}
	for _, raw := range allowed {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", raw, err)
		}
		if isBlockedPrerequisiteIP(addr) {
			t.Errorf("isBlockedPrerequisiteIP(%q) = true, want false", raw)
		}
	}
}

func TestPrerequisiteEgressClientHardening(t *testing.T) {
	client := newPrerequisiteEgressClient()
	if client.Jar != nil {
		t.Fatal("egress client must not hold a cookie jar")
	}
	if client.Timeout != 15*time.Second {
		t.Fatalf("egress timeout = %v, want 15s", client.Timeout)
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr == nil || tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("egress transport TLS config not hardened: %#v", client.Transport)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("egress client must block loopback dials")
	}
}
