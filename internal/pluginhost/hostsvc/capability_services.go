// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"

	accountv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/account/v1"
	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
	dnsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/dns/v1"
	dockerv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/docker/v1"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	trafficv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/traffic/v1"
)

// ======================== 按授予选择性注册 ========================
// 未授予的服务不进入 gRPC registry；同一服务内的 RPC 仍逐项过能力门。
func (s *Server) registerCapabilityServices() {
	var firewall, sshd, account, ban, metrics, dns, certificates, pluginconfig, traffic, docker bool
	for _, capability := range s.cfg.GrantedCapabilities {
		switch capability.Name {
		case "system.firewall.manage":
			firewall = true
		case "system.sshd.configure":
			sshd = true
		case "system.account.keys", "system.account.password":
			account = true
		case "system.ban.manage":
			ban = true
		case "metrics.read":
			metrics = true
		case "dns.read", "system.dns.manage":
			dns = true
		case "certificates.read", "system.certificates.manage", "certificates.renew_existing":
			certificates = true
		case "plugin.config.read", "plugin.config.write":
			pluginconfig = true
		case "system.traffic.shape":
			traffic = true
		case "system.docker.read", "system.docker.manage":
			docker = true
		}
	}
	if firewall {
		firewallv1.RegisterFirewallServiceServer(s.gs, &firewallCapabilityService{s: s})
	}
	if sshd {
		sshdv1.RegisterSshdServiceServer(s.gs, &sshdCapabilityService{s: s})
	}
	if account {
		accountv1.RegisterAccountServiceServer(s.gs, &accountCapabilityService{s: s})
	}
	if ban {
		banv1.RegisterBanServiceServer(s.gs, &banCapabilityService{s: s})
	}
	if metrics {
		metricsv1.RegisterMetricsServiceServer(s.gs, &metricsCapabilityService{s: s})
	}
	if dns {
		dnsv1.RegisterDnsServiceServer(s.gs, &dnsCapabilityService{s: s})
	}
	if certificates {
		certificatesv1.RegisterCertificatesServiceServer(s.gs, &certificatesCapabilityService{s: s})
	}
	if pluginconfig {
		pluginconfigv1.RegisterPluginConfigServiceServer(s.gs, &pluginConfigCapabilityService{s: s})
	}
	if traffic {
		trafficv1.RegisterTrafficServiceServer(s.gs, &trafficCapabilityService{s: s})
	}
	if docker {
		dockerv1.RegisterDockerServiceServer(s.gs, &dockerCapabilityService{s: s})
	}
}

// ======================== Firewall RPC 适配 ========================
type firewallCapabilityService struct {
	firewallv1.UnimplementedFirewallServiceServer
	s *Server
}

func (x *firewallCapabilityService) GetRuleset(ctx context.Context, req *firewallv1.GetRulesetRequest) (*firewallv1.GetRulesetResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "firewall", method: "GetRuleset", verb: "firewall.get", name: "system.firewall.manage"}, new(firewallv1.GetRulesetResponse))
}
func (x *firewallCapabilityService) ApplyRuleset(ctx context.Context, req *firewallv1.ApplyRulesetRequest) (*firewallv1.ApplyRulesetResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "firewall", method: "ApplyRuleset", verb: "firewall.apply", name: "system.firewall.manage", write: true}, new(firewallv1.ApplyRulesetResponse))
}
func (x *firewallCapabilityService) ResetRuleset(ctx context.Context, req *firewallv1.ResetRulesetRequest) (*firewallv1.ResetRulesetResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "firewall", method: "ResetRuleset", verb: "firewall.reset", name: "system.firewall.manage", write: true}, new(firewallv1.ResetRulesetResponse))
}
func (x *firewallCapabilityService) DetectManagers(ctx context.Context, req *firewallv1.DetectManagersRequest) (*firewallv1.DetectManagersResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "firewall", method: "DetectManagers", verb: "firewall.detect", name: "system.firewall.manage"}, new(firewallv1.DetectManagersResponse))
}

// ======================== SSHD RPC 适配 ========================
type sshdCapabilityService struct {
	sshdv1.UnimplementedSshdServiceServer
	s *Server
}

func (x *sshdCapabilityService) GetEffectiveConfig(ctx context.Context, req *sshdv1.GetEffectiveConfigRequest) (*sshdv1.GetEffectiveConfigResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "sshd", method: "GetEffectiveConfig", verb: "sshd.get-effective", name: "system.sshd.configure"}, new(sshdv1.GetEffectiveConfigResponse))
}
func (x *sshdCapabilityService) GetDropIn(ctx context.Context, req *sshdv1.GetDropInRequest) (*sshdv1.GetDropInResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "sshd", method: "GetDropIn", verb: "sshd.get-dropin", name: "system.sshd.configure"}, new(sshdv1.GetDropInResponse))
}
func (x *sshdCapabilityService) SetPort(ctx context.Context, req *sshdv1.SetPortRequest) (*sshdv1.SetPortResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "sshd", method: "SetPort", verb: "sshd.set-port", name: "system.sshd.configure", write: true}, new(sshdv1.SetPortResponse))
}
func (x *sshdCapabilityService) VerifyPort(ctx context.Context, req *sshdv1.VerifyPortRequest) (*sshdv1.VerifyPortResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "sshd", method: "VerifyPort", verb: "sshd.verify-port", name: "system.sshd.configure"}, new(sshdv1.VerifyPortResponse))
}
func (x *sshdCapabilityService) SetLoginPolicy(ctx context.Context, req *sshdv1.SetLoginPolicyRequest) (*sshdv1.SetLoginPolicyResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "sshd", method: "SetLoginPolicy", verb: "sshd.set-login", name: "system.sshd.configure", write: true}, new(sshdv1.SetLoginPolicyResponse))
}
func (x *sshdCapabilityService) RemoveDropIn(ctx context.Context, req *sshdv1.RemoveDropInRequest) (*sshdv1.RemoveDropInResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "sshd", method: "RemoveDropIn", verb: "sshd.remove-dropin", name: "system.sshd.configure", write: true}, new(sshdv1.RemoveDropInResponse))
}

func (x *sshdCapabilityService) RecoverDropIn(ctx context.Context, req *sshdv1.RecoverDropInRequest) (*sshdv1.RecoverDropInResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "sshd", method: "RecoverDropIn", verb: "sshd.recover-dropin", name: "system.sshd.configure", write: true}, new(sshdv1.RecoverDropInResponse))
}

// ======================== Account RPC 适配 ========================
type accountCapabilityService struct {
	accountv1.UnimplementedAccountServiceServer
	s *Server
}

func (x *accountCapabilityService) ListKeys(ctx context.Context, req *accountv1.ListKeysRequest) (*accountv1.ListKeysResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "account", method: "ListKeys", verb: "account.list-keys", name: "system.account.keys", account: true}, new(accountv1.ListKeysResponse))
}
func (x *accountCapabilityService) ImportKey(ctx context.Context, req *accountv1.ImportKeyRequest) (*accountv1.ImportKeyResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "account", method: "ImportKey", verb: "account.import-key", name: "system.account.keys", write: true, account: true}, new(accountv1.ImportKeyResponse))
}
func (x *accountCapabilityService) RemoveKey(ctx context.Context, req *accountv1.RemoveKeyRequest) (*accountv1.RemoveKeyResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "account", method: "RemoveKey", verb: "account.remove-key", name: "system.account.keys", write: true, account: true}, new(accountv1.RemoveKeyResponse))
}
func (x *accountCapabilityService) GenerateKey(ctx context.Context, req *accountv1.GenerateKeyRequest) (*accountv1.GenerateKeyResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "account", method: "GenerateKey", verb: "account.generate-key", name: "system.account.keys", write: true, account: true}, new(accountv1.GenerateKeyResponse))
}
func (x *accountCapabilityService) SetPassword(ctx context.Context, req *accountv1.SetPasswordRequest) (*accountv1.SetPasswordResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "account", method: "SetPassword", verb: "account.set-password", name: "system.account.password", write: true, account: true}, new(accountv1.SetPasswordResponse))
}

// ======================== Ban RPC 适配 ========================
type banCapabilityService struct {
	banv1.UnimplementedBanServiceServer
	s *Server
}

func (x *banCapabilityService) ScanAuthFailures(ctx context.Context, req *banv1.ScanAuthFailuresRequest) (*banv1.ScanAuthFailuresResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "ban", method: "ScanAuthFailures", verb: "ban.scan", name: "system.ban.manage"}, new(banv1.ScanAuthFailuresResponse))
}
func (x *banCapabilityService) ApplyBans(ctx context.Context, req *banv1.ApplyBansRequest) (*banv1.ApplyBansResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "ban", method: "ApplyBans", verb: "ban.apply", name: "system.ban.manage", write: true}, new(banv1.ApplyBansResponse))
}
func (x *banCapabilityService) RemoveBan(ctx context.Context, req *banv1.RemoveBanRequest) (*banv1.RemoveBanResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "ban", method: "RemoveBan", verb: "ban.remove", name: "system.ban.manage", write: true}, new(banv1.RemoveBanResponse))
}
func (x *banCapabilityService) ListBans(ctx context.Context, req *banv1.ListBansRequest) (*banv1.ListBansResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "ban", method: "ListBans", verb: "ban.list", name: "system.ban.manage"}, new(banv1.ListBansResponse))
}

// ======================== Metrics RPC 适配 ========================
type metricsCapabilityService struct {
	metricsv1.UnimplementedMetricsServiceServer
	s *Server
}

func (x *metricsCapabilityService) ReadMetrics(ctx context.Context, req *metricsv1.ReadMetricsRequest) (*metricsv1.ReadMetricsResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "metrics", method: "ReadMetrics", verb: "metrics.read", name: "metrics.read"}, new(metricsv1.ReadMetricsResponse))
}

// ======================== PluginConfig RPC 适配（ADR-0023 H2） ========================
type pluginConfigCapabilityService struct {
	pluginconfigv1.UnimplementedPluginConfigServiceServer
	s *Server
}

func (x *pluginConfigCapabilityService) GetConfig(ctx context.Context, req *pluginconfigv1.GetConfigRequest) (*pluginconfigv1.GetConfigResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "pluginconfig", method: "GetConfig", verb: "pluginconfig.get", name: "plugin.config.read", targetPlugin: true}, new(pluginconfigv1.GetConfigResponse))
}

func (x *pluginConfigCapabilityService) PutConfig(ctx context.Context, req *pluginconfigv1.PutConfigRequest) (*pluginconfigv1.PutConfigResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "pluginconfig", method: "PutConfig", verb: "pluginconfig.put", name: "plugin.config.write", write: true, targetPlugin: true}, new(pluginconfigv1.PutConfigResponse))
}

// ======================== Traffic RPC 适配（ADR-0023 H4） ========================
type trafficCapabilityService struct {
	trafficv1.UnimplementedTrafficServiceServer
	s *Server
}

func (x *trafficCapabilityService) GetShapingStatus(ctx context.Context, req *trafficv1.GetShapingStatusRequest) (*trafficv1.GetShapingStatusResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "traffic", method: "GetShapingStatus", verb: "traffic.status", name: "system.traffic.shape"}, new(trafficv1.GetShapingStatusResponse))
}

func (x *trafficCapabilityService) ApplyShapingRules(ctx context.Context, req *trafficv1.ApplyShapingRulesRequest) (*trafficv1.ApplyShapingRulesResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "traffic", method: "ApplyShapingRules", verb: "traffic.apply", name: "system.traffic.shape", write: true}, new(trafficv1.ApplyShapingRulesResponse))
}

func (x *trafficCapabilityService) ClearShapingRules(ctx context.Context, req *trafficv1.ClearShapingRulesRequest) (*trafficv1.ClearShapingRulesResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "traffic", method: "ClearShapingRules", verb: "traffic.clear", name: "system.traffic.shape", write: true}, new(trafficv1.ClearShapingRulesResponse))
}

// ======================== Docker 受控代理与编排 RPC 适配（PLG-FIX-04 / PLG-FIX-05） ========================
type dockerCapabilityService struct {
	dockerv1.UnimplementedDockerServiceServer
	s *Server
}

func (x *dockerCapabilityService) ProxyRead(ctx context.Context, req *dockerv1.ProxyReadRequest) (*dockerv1.ProxyReadResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "docker", method: "ProxyRead", verb: "docker.api.read", name: "system.docker.read"}, new(dockerv1.ProxyReadResponse))
}

func (x *dockerCapabilityService) ProxyWrite(ctx context.Context, req *dockerv1.ProxyWriteRequest) (*dockerv1.ProxyWriteResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "docker", method: "ProxyWrite", verb: "docker.api.write", name: "system.docker.manage", write: true}, new(dockerv1.ProxyWriteResponse))
}

func (x *dockerCapabilityService) ComposeAction(ctx context.Context, req *dockerv1.ComposeActionRequest) (*dockerv1.ComposeActionResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "docker", method: "ComposeAction", verb: "docker.compose", name: "system.docker.manage", write: true}, new(dockerv1.ComposeActionResponse))
}

func (x *dockerCapabilityService) ListBindableIPs(ctx context.Context, req *dockerv1.ListBindableIPsRequest) (*dockerv1.ListBindableIPsResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "docker", method: "ListBindableIPs", verb: "docker.bindable_ips", name: "system.docker.read"}, new(dockerv1.ListBindableIPsResponse))
}

func (x *dockerCapabilityService) CreateNetwork(ctx context.Context, req *dockerv1.CreateNetworkRequest) (*dockerv1.CreateNetworkResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "docker", method: "CreateNetwork", verb: "docker.network.create", name: "system.docker.manage", write: true}, new(dockerv1.CreateNetworkResponse))
}

func (x *dockerCapabilityService) MutateContainerNetwork(ctx context.Context, req *dockerv1.MutateContainerNetworkRequest) (*dockerv1.MutateContainerNetworkResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "docker", method: "MutateContainerNetwork", verb: "docker.network.membership", name: "system.docker.manage", write: true}, new(dockerv1.MutateContainerNetworkResponse))
}

func (x *dockerCapabilityService) RecreateContainerPorts(ctx context.Context, req *dockerv1.RecreateContainerPortsRequest) (*dockerv1.RecreateContainerPortsResponse, error) {
	return forwardCapability(x.s, ctx, req, capabilityPolicy{service: "docker", method: "RecreateContainerPorts", verb: "docker.recreate_ports", name: "system.docker.manage", write: true}, new(dockerv1.RecreateContainerPortsResponse))
}
