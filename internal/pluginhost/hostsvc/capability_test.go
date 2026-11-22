// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	accountv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/account/v1"
	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

type capabilityResolver struct {
	mu                  sync.Mutex
	binding             hostsvc.OperationBinding
	instance, operation string
	err                 error
}

func (r *capabilityResolver) Resolve(_ context.Context, instance, operation string) (hostsvc.OperationBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.instance, r.operation = instance, operation
	return r.binding, r.err
}

type capabilityForwarder struct {
	mu          sync.Mutex
	calls       []hostsvc.CapabilityCall
	response    proto.Message
	domainError *hostsvc.DomainError
	err         error
}

func (f *capabilityForwarder) Forward(_ context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	return hostsvc.CapabilityResult{Response: f.response, Error: f.domainError}, f.err
}

func (f *capabilityForwarder) snapshot() []hostsvc.CapabilityCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostsvc.CapabilityCall(nil), f.calls...)
}

func capability(name, scope string) *platformv1.Capability {
	return &platformv1.Capability{Name: name, Scope: scope}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestCapabilitySelectiveRegistration(t *testing.T) {
	server := startServer(t, nil)
	_, err := metricsv1.NewMetricsServiceClient(server.Conn()).ReadMetrics(testContext(t), &metricsv1.ReadMetricsRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("未授予的服务已注册：%v", err)
	}
	for _, tc := range []struct {
		name     string
		cap      *platformv1.Capability
		response proto.Message
		call     func(*testServer) error
	}{
		{"firewall", capability("system.firewall.manage", "self"), &firewallv1.GetRulesetResponse{}, func(s *testServer) error {
			_, e := firewallv1.NewFirewallServiceClient(s.Conn()).GetRuleset(testContext(t), &firewallv1.GetRulesetRequest{})
			return e
		}},
		{"sshd", capability("system.sshd.configure", "self"), &sshdv1.GetDropInResponse{}, func(s *testServer) error {
			_, e := sshdv1.NewSshdServiceClient(s.Conn()).GetDropIn(testContext(t), &sshdv1.GetDropInRequest{})
			return e
		}},
		{"account", capability("system.account.keys", "all"), &accountv1.ListKeysResponse{}, func(s *testServer) error {
			_, e := accountv1.NewAccountServiceClient(s.Conn()).ListKeys(testContext(t), &accountv1.ListKeysRequest{User: "alice"})
			return e
		}},
		{"ban", capability("system.ban.manage", "self"), &banv1.ListBansResponse{}, func(s *testServer) error {
			_, e := banv1.NewBanServiceClient(s.Conn()).ListBans(testContext(t), &banv1.ListBansRequest{})
			return e
		}},
		{"metrics", capability("metrics.read", "self"), &metricsv1.ReadMetricsResponse{}, func(s *testServer) error {
			_, e := metricsv1.NewMetricsServiceClient(s.Conn()).ReadMetrics(testContext(t), &metricsv1.ReadMetricsRequest{})
			return e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forwarder := &capabilityForwarder{response: tc.response}
			s := startServer(t, func(c *hostsvc.Config) {
				c.GrantedCapabilities = []*platformv1.Capability{tc.cap}
				c.CapabilityForwarder = forwarder
			})
			if err := tc.call(s); err != nil || len(forwarder.snapshot()) != 1 {
				t.Fatalf("已授予服务不可调用：%v", err)
			}
		})
	}
}

func TestCapabilityScopeBinding(t *testing.T) {
	for _, tc := range []struct {
		scope, user string
		code        codes.Code
	}{
		{"alice", "alice", codes.OK}, {"alice", "bob", codes.PermissionDenied}, {"all", "bob", codes.OK},
		{"all", "../../outside", codes.InvalidArgument}, {"all", "", codes.InvalidArgument},
	} {
		t.Run(tc.scope+"/"+tc.user, func(t *testing.T) {
			forwarder := &capabilityForwarder{response: &accountv1.ListKeysResponse{}}
			s := startServer(t, func(c *hostsvc.Config) {
				c.GrantedCapabilities = []*platformv1.Capability{capability("system.account.keys", tc.scope)}
				c.CapabilityForwarder = forwarder
			})
			_, err := accountv1.NewAccountServiceClient(s.Conn()).ListKeys(testContext(t), &accountv1.ListKeysRequest{User: tc.user})
			if status.Code(err) != tc.code {
				t.Fatalf("scope 检查：%v", err)
			}
			if tc.code != codes.OK && len(forwarder.snapshot()) != 0 {
				t.Fatal("被拒绝的请求已转发")
			}
		})
	}
}

func TestCapabilityWriteOperationBinding(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation string
		binding   hostsvc.OperationBinding
		code      codes.Code
	}{
		{"running", "op_test", hostsvc.OperationBinding{Dispatched: true, Effect: "write", Capabilities: []*platformv1.Capability{capability("system.account.keys", "all")}}, codes.OK},
		{"missing-id", "", hostsvc.OperationBinding{Dispatched: true, Effect: "write", Capabilities: []*platformv1.Capability{capability("system.account.keys", "all")}}, codes.FailedPrecondition},
		{"not-dispatched", "op_other", hostsvc.OperationBinding{Effect: "write", Capabilities: []*platformv1.Capability{capability("system.account.keys", "all")}}, codes.PermissionDenied},
		{"read-cannot-write", "op_test", hostsvc.OperationBinding{Dispatched: true, Effect: "read", Capabilities: []*platformv1.Capability{capability("system.account.keys", "all")}}, codes.PermissionDenied},
		{"missing-capability", "op_test", hostsvc.OperationBinding{Dispatched: true, Effect: "write"}, codes.PermissionDenied},
		{"wrong-scope", "op_test", hostsvc.OperationBinding{Dispatched: true, Effect: "write", Capabilities: []*platformv1.Capability{capability("system.account.keys", "bob")}}, codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forwarder := &capabilityForwarder{response: &accountv1.ImportKeyResponse{Revision: "2"}}
			resolver := &capabilityResolver{binding: tc.binding}
			s := startServer(t, func(c *hostsvc.Config) {
				c.PluginID = "security.basic"
				c.GrantedCapabilities = []*platformv1.Capability{capability("system.account.keys", "all")}
				c.OperationResolver = resolver
				c.CapabilityForwarder = forwarder
			})
			_, err := accountv1.NewAccountServiceClient(s.Conn()).ImportKey(testContext(t), &accountv1.ImportKeyRequest{
				Context: &platformv1.HostCallContext{OperationId: tc.operation, InstanceHandle: "forged-other-instance"}, User: "alice", PublicKey: "PUBLIC_TEST_VALUE", ExpectedRevision: "1",
			})
			if status.Code(err) != tc.code {
				t.Fatalf("operation 绑定：%v", err)
			}
			calls := forwarder.snapshot()
			if tc.code != codes.OK && len(calls) != 0 {
				t.Fatal("越权请求已转发")
			}
			if tc.code == codes.OK {
				if len(calls) != 1 || calls[0].PluginID != "security.basic" || calls[0].InstanceID != "default" || calls[0].OperationID != "op_test" || !calls[0].Write {
					t.Fatal("转发使用了插件伪造的身份")
				}
				if resolver.instance != "default" || resolver.operation != "op_test" {
					t.Fatal("resolver 未绑定宿主实例")
				}
				if len(s.bundle.audit.snapshot()) < 2 {
					t.Fatal("能力写入缺少执行前后审计")
				}
			}
		})
	}
}

func TestCapabilityAuditFailurePreventsForwarding(t *testing.T) {
	b := newBundle()
	b.audit.err = errors.New("storage unavailable")
	forwarder := &capabilityForwarder{response: &firewallv1.ResetRulesetResponse{}}
	s := startServerWith(t, b, func(c *hostsvc.Config) {
		c.GrantedCapabilities = []*platformv1.Capability{capability("system.firewall.manage", "self")}
		c.OperationResolver = &capabilityResolver{binding: hostsvc.OperationBinding{Dispatched: true, Effect: "destructive", Capabilities: c.GrantedCapabilities}}
		c.CapabilityForwarder = forwarder
	})
	_, err := firewallv1.NewFirewallServiceClient(s.Conn()).ResetRuleset(testContext(t), &firewallv1.ResetRulesetRequest{Context: callContext()})
	if status.Code(err) != codes.Unavailable || len(forwarder.snapshot()) != 0 {
		t.Fatal("无法审计时仍执行了写请求")
	}
}

func TestCapabilityRateLimits(t *testing.T) {
	for _, name := range []string{"metrics", "ban"} {
		t.Run(name, func(t *testing.T) {
			forwarder := &capabilityForwarder{}
			s := startServer(t, func(c *hostsvc.Config) {
				c.CapabilityForwarder = forwarder
				if name == "metrics" {
					c.GrantedCapabilities = []*platformv1.Capability{capability("metrics.read", "self")}
					forwarder.response = &metricsv1.ReadMetricsResponse{}
				} else {
					c.GrantedCapabilities = []*platformv1.Capability{capability("system.ban.manage", "self")}
					forwarder.response = &banv1.ScanAuthFailuresResponse{}
				}
			})
			count := 2
			call := func() error {
				_, err := metricsv1.NewMetricsServiceClient(s.Conn()).ReadMetrics(testContext(t), &metricsv1.ReadMetricsRequest{})
				return err
			}
			if name == "ban" {
				count = 1
				call = func() error {
					_, err := banv1.NewBanServiceClient(s.Conn()).ScanAuthFailures(testContext(t), &banv1.ScanAuthFailuresRequest{})
					return err
				}
			}
			for range count {
				if err := call(); err != nil {
					t.Fatal(err)
				}
			}
			if status.Code(call()) != codes.ResourceExhausted {
				t.Fatal("能力调用没有限频")
			}
		})
	}
}

func TestCapabilityBusinessErrorAndSafeFormatting(t *testing.T) {
	forwarder := &capabilityForwarder{domainError: &hostsvc.DomainError{Code: "CONFLICT", Message: "其他管理器仍在运行"}}
	s := startServer(t, func(c *hostsvc.Config) {
		c.GrantedCapabilities = []*platformv1.Capability{capability("system.firewall.manage", "self")}
		c.CapabilityForwarder = forwarder
	})
	response, err := firewallv1.NewFirewallServiceClient(s.Conn()).GetRuleset(testContext(t), &firewallv1.GetRulesetRequest{})
	if err != nil || response.GetError().GetCode() != "CONFLICT" {
		t.Fatal("业务错误未使用 ErrorDetail")
	}
	call := hostsvc.CapabilityCall{Request: &accountv1.ImportKeyRequest{PublicKey: "CANARY_PRIVATE_MATERIAL"}}
	if strings.Contains(call.String(), "CANARY_PRIVATE_MATERIAL") {
		t.Fatal("能力调用格式化展开了请求体")
	}
}

func TestCapabilityGrantSnapshotImmutable(t *testing.T) {
	grant := capability("system.account.keys", "alice")
	forwarder := &capabilityForwarder{response: &accountv1.ListKeysResponse{}}
	s := startServer(t, func(c *hostsvc.Config) {
		c.GrantedCapabilities = []*platformv1.Capability{grant}
		c.CapabilityForwarder = forwarder
	})
	grant.Scope = "all"
	_, err := accountv1.NewAccountServiceClient(s.Conn()).ListKeys(testContext(t), &accountv1.ListKeysRequest{User: "bob"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatal("调用方修改了已授予能力快照")
	}
}

func TestCapabilityGenerateKeyRevisionField(t *testing.T) {
	field := (&accountv1.GenerateKeyResponse{}).ProtoReflect().Descriptor().Fields().ByName("revision")
	if field == nil || field.Number() != 5 {
		t.Fatal("GenerateKey 响应未追加 revision=5")
	}
}

func TestCapabilityAllWritesRequireOperation(t *testing.T) {
	cases := []struct {
		method            string
		request, response proto.Message
	}{
		{firewallv1.FirewallService_ApplyRuleset_FullMethodName, &firewallv1.ApplyRulesetRequest{}, &firewallv1.ApplyRulesetResponse{}},
		{firewallv1.FirewallService_ResetRuleset_FullMethodName, &firewallv1.ResetRulesetRequest{}, &firewallv1.ResetRulesetResponse{}},
		{sshdv1.SshdService_SetPort_FullMethodName, &sshdv1.SetPortRequest{}, &sshdv1.SetPortResponse{}},
		{sshdv1.SshdService_SetLoginPolicy_FullMethodName, &sshdv1.SetLoginPolicyRequest{}, &sshdv1.SetLoginPolicyResponse{}},
		{sshdv1.SshdService_RemoveDropIn_FullMethodName, &sshdv1.RemoveDropInRequest{}, &sshdv1.RemoveDropInResponse{}},
		{sshdv1.SshdService_RecoverDropIn_FullMethodName, &sshdv1.RecoverDropInRequest{}, &sshdv1.RecoverDropInResponse{}},
		{accountv1.AccountService_ImportKey_FullMethodName, &accountv1.ImportKeyRequest{User: "alice"}, &accountv1.ImportKeyResponse{}},
		{accountv1.AccountService_RemoveKey_FullMethodName, &accountv1.RemoveKeyRequest{User: "alice"}, &accountv1.RemoveKeyResponse{}},
		{accountv1.AccountService_GenerateKey_FullMethodName, &accountv1.GenerateKeyRequest{User: "alice"}, &accountv1.GenerateKeyResponse{}},
		{accountv1.AccountService_SetPassword_FullMethodName, &accountv1.SetPasswordRequest{User: "alice"}, &accountv1.SetPasswordResponse{}},
		{banv1.BanService_ApplyBans_FullMethodName, &banv1.ApplyBansRequest{}, &banv1.ApplyBansResponse{}},
		{banv1.BanService_RemoveBan_FullMethodName, &banv1.RemoveBanRequest{}, &banv1.RemoveBanResponse{}},
	}
	forwarder := &capabilityForwarder{}
	s := startServer(t, func(c *hostsvc.Config) {
		c.GrantedCapabilities = []*platformv1.Capability{
			capability("system.firewall.manage", "self"), capability("system.sshd.configure", "self"),
			capability("system.account.keys", "all"), capability("system.account.password", "all"), capability("system.ban.manage", "self"),
		}
		c.CapabilityForwarder = forwarder
	})
	for _, tc := range cases {
		if err := s.Conn().Invoke(testContext(t), tc.method, tc.request, tc.response); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("写 RPC 未要求 operation：%s，%v", tc.method, err)
		}
	}
	if len(forwarder.snapshot()) != 0 {
		t.Fatal("未绑定的写 RPC 已到达执行器")
	}
}

func TestCapabilityUsesExistingTokenGate(t *testing.T) {
	const token = "capability-fixture-token"
	digest := sha256.Sum256([]byte(token))
	forwarder := &capabilityForwarder{response: &metricsv1.ReadMetricsResponse{}}
	s := startServer(t, func(c *hostsvc.Config) {
		c.GrantedCapabilities = []*platformv1.Capability{capability("metrics.read", "self")}
		c.CapabilityForwarder = forwarder
		c.TokenDigest = func(context.Context) ([]byte, error) { return digest[:], nil }
	})
	client := metricsv1.NewMetricsServiceClient(s.Conn())
	if _, err := client.ReadMetrics(testContext(t), &metricsv1.ReadMetricsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("新服务绕过了既有 token 校验")
	}
	ctx := metadata.NewOutgoingContext(testContext(t), metadata.Pairs("qwq-plugin-token", token))
	if _, err := client.ReadMetrics(ctx, &metricsv1.ReadMetricsRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(forwarder.snapshot()) != 1 {
		t.Fatal("缺 token 的调用进入了执行器")
	}
}
