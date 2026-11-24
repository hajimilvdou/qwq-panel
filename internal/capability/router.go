// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"

	"github.com/qwq-panel/qwq/internal/capability/account"
	"github.com/qwq-panel/qwq/internal/capability/ban"
	"github.com/qwq-panel/qwq/internal/capability/firewall"
	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/capability/sshd"
	"github.com/qwq-panel/qwq/internal/capability/traffic"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Forwarder 按宿主能力门确定的服务名派发；注册后不再修改 Services。
type Forwarder struct {
	Services map[string]hostsvc.CapabilityForwarder
}

func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	service := f.Services[call.Service]
	if service == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "该宿主能力执行器尚未接入")
	}
	return service.Forward(ctx, call)
}

// Runner 只路由精确 verb；未知或未实现的能力继续失败关闭。
type Runner struct {
	Firewall *firewall.Service
	Sshd     *sshd.Service
	Account  *account.Service
	Ban      *ban.Service
	Traffic  *traffic.Service
}

func (r Runner) Run(ctx context.Context, request sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	if sandbox.ValidateCapabilityRequest(request) != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "能力请求无效"}, nil
	}
	switch request.Op {
	case "firewall.get", "firewall.apply", "firewall.reset", "firewall.detect", "firewall.restore", "firewall.sync-panel-port":
		if r.Firewall != nil {
			return r.Firewall.Run(ctx, request)
		}
	case "sshd.get-effective", "sshd.get-dropin", "sshd.write-dropin", "sshd.remove-dropin", "sshd.recover-dropin", "sshd.verify-port":
		if r.Sshd != nil {
			return r.Sshd.Run(ctx, request)
		}
	case "account.list-keys", "account.import-key", "account.remove-key", "account.generate-key", "account.set-password":
		if r.Account != nil {
			return r.Account.Run(ctx, request)
		}
	case "ban.scan", "ban.apply", "ban.remove", "ban.list":
		if r.Ban != nil {
			return r.Ban.Run(ctx, request)
		}
	case "traffic.status", "traffic.apply", "traffic.clear":
		if r.Traffic != nil {
			return r.Traffic.Run(ctx, request)
		}
	}
	return sandbox.CapabilityResponse{Code: "UNIMPLEMENTED", Error: "该能力执行器尚未接入"}, nil
}

// SystemRunner 使用安装器创建的固定 root 路径；构造本身没有 I/O。
func SystemRunner() Runner {
	executor := local.ExecTools{}
	state := local.FileState{Directory: "/etc/nftables.d", Name: "qwq.nft", LockDirectory: "/run/qwq", LockName: "capability.lock"}
	guard := firewall.SystemGuard{Executor: executor, Config: local.FileState{Directory: "/etc/qwq", Name: "qwq.json"}}
	transactions := local.FileState{Directory: "/var/lib/qwq-capability", Name: "sshd-transaction.json", LockDirectory: "/run/qwq", LockName: "capability.lock", Mode: 0600}
	sshConfig := sshd.FileRepository{ConfigDir: "/etc/ssh", TempDir: "/run/qwq", Executor: executor}
	panelPortState := local.FileState{Directory: "/var/lib/qwq-capability", Name: "panel-port.json", LockDirectory: "/run/qwq", LockName: "capability.lock", Mode: 0644}
	firewallService := &firewall.Service{Executor: executor, State: state, Guard: guard, PanelPortState: panelPortState}
	sshRuntime := sshd.SystemRuntime{Executor: executor, Guard: guard, Firewall: firewallService}
	accountService := account.NewService(sshConfig)
	banService := ban.NewService()
	trafficService := traffic.NewService()
	return Runner{
		Firewall: firewallService,
		Sshd:     &sshd.Service{Repository: sshConfig, Runtime: sshRuntime, Transactions: transactions, Recovery: accountService.RecoveryGuard()},
		Account:  accountService,
		Ban:      banService,
		Traffic:  trafficService,
	}
}
