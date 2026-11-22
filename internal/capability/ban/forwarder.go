// SPDX-License-Identifier: AGPL-3.0-only

package ban

import (
	"context"
	"net"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ======================== Ban Host Capability 转发器 ========================

// ProtectedAddresses 返回当前管理会话源 IP 与宿主机受保护地址，由宿主强制注入防自锁。
type ProtectedAddresses func(ctx context.Context, call hostsvc.CapabilityCall) ([]string, error)

// Forwarder 转发经过能力门校验的 4 个 BanService RPC，并强制向 ApplyBans 注入受保护 IP。
type Forwarder struct {
	Helper    bridge.Caller
	Protected ProtectedAddresses
}

func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if call.Service != "ban" || f.Helper == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "封禁能力执行器未接入")
	}
	switch call.Method {
	case "ScanAuthFailures":
		req, ok := call.Request.(*banv1.ScanAuthFailuresRequest)
		if !ok || req == nil {
			return invalidBanCall()
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "ban.scan", scanParams{
			Cursor:       req.GetCursor(),
			SinceSeconds: req.GetSinceSeconds(),
			Unit:         req.GetUnit(),
		}, new(banv1.ScanAuthFailuresResponse))

	case "ListBans":
		if req, ok := call.Request.(*banv1.ListBansRequest); !ok || req == nil {
			return invalidBanCall()
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "ban.list", struct{}{}, new(banv1.ListBansResponse))

	case "ApplyBans":
		req, ok := call.Request.(*banv1.ApplyBansRequest)
		if !ok || req == nil {
			return invalidBanCall()
		}
		protected := collectHostProtectedIPs()
		if f.Protected != nil {
			extra, err := f.Protected(ctx, call)
			if err != nil {
				return hostsvc.CapabilityResult{}, err
			}
			protected = append(protected, extra...)
		}
		entries := make([]banEntryParam, 0, len(req.GetEntries()))
		for _, e := range req.GetEntries() {
			entries = append(entries, banEntryParam{IP: e.GetIp(), TTLSeconds: e.GetTtlSeconds()})
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "ban.apply", applyBansParams{
			Entries:          entries,
			ExpectedRevision: req.GetExpectedRevision(),
			ProtectedIPs:     protected,
		}, new(banv1.ApplyBansResponse))

	case "RemoveBan":
		req, ok := call.Request.(*banv1.RemoveBanRequest)
		if !ok || req == nil {
			return invalidBanCall()
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "ban.remove", removeBanParams{
			IP:               req.GetIp(),
			ExpectedRevision: req.GetExpectedRevision(),
		}, new(banv1.RemoveBanResponse))

	default:
		return hostsvc.CapabilityResult{}, status.Error(codes.Unimplemented, "封禁能力方法不受支持")
	}
}

func collectHostProtectedIPs() []string {
	out := []string{"127.0.0.1", "::1"}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP != nil {
			out = append(out, ipNet.IP.String())
		}
	}
	return out
}

func invalidBanCall() (hostsvc.CapabilityResult, error) {
	return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "封禁能力请求类型无效")
}
