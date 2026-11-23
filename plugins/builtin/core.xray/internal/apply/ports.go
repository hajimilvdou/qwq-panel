// SPDX-License-Identifier: AGPL-3.0-only

package apply

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

var errPortIdentity = errors.New("apply: original listener ownership is unavailable")

// ======================== 先确认目标监听，再触碰旧进程 ========================

func (e *Engine) preflightPort(ctx context.Context, intent *coreapi.Intent, old *state.Metadata) error {
	if !*intent.Enabled {
		return nil
	}
	addr, err := netip.ParseAddr(intent.Inbound.Listen)
	if err != nil {
		return err
	}
	target := netip.AddrPortFrom(addr.Unmap(), uint16(intent.Inbound.Port))
	var listen net.ListenConfig
	probe, err := listen.Listen(ctx, "tcp", target.String())
	if err == nil {
		return probe.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) || old == nil || old.Current == nil || old.Current.Summary == nil {
		return err
	}
	original := e.options.Process.Snapshot(ctx)
	if !runtimeMatches(old, original) || original.PID <= 0 {
		return errPortIdentity
	}
	summary := old.Current.Summary
	addr, err = netip.ParseAddr(summary.Listen)
	if err != nil {
		return err
	}
	previous := netip.AddrPortFrom(addr.Unmap(), uint16(summary.Port))
	scope, err := tcpBindingScope(ctx, target)
	if err != nil {
		return err
	}
	if err := verifyOwnedPortConflict(ctx, netip.AddrPortFrom(scope, target.Port()), previous, e.ownedPIDs(original.PID)...); err != nil {
		return err
	}
	// /proc 读取期间旧 slot 若已结束或替换，不能继续用刚才的归属证明。
	if current := e.options.Process.Snapshot(ctx); current != original {
		return errPortIdentity
	}
	return ctx.Err()
}

// tcpBindingScope 实测通配地址的绑定族；Go 的 tcp 通配绑定可能使用双栈 socket。
func tcpBindingScope(ctx context.Context, target netip.AddrPort) (netip.Addr, error) {
	if !target.Addr().IsUnspecified() {
		return target.Addr(), nil
	}
	var listen net.ListenConfig
	probe, err := listen.Listen(ctx, "tcp", netip.AddrPortFrom(target.Addr(), 0).String())
	if err != nil {
		return netip.Addr{}, err
	}
	scope := probe.Addr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	return scope, probe.Close()
}

// ownedPIDs 返回当前实例持有的 Xray 主进程与所有受控 simple-obfs 子进程 PID，供端口占用归属核验。
func (e *Engine) ownedPIDs(xrayPID int) []int {
	pids := make([]int, 0, 4)
	if xrayPID > 0 {
		pids = append(pids, xrayPID)
	}
	if e.options.Obfs != nil {
		for _, pid := range e.options.Obfs.OwnedPIDs() {
			if pid > 0 {
				pids = append(pids, pid)
			}
		}
	}
	if e.options.AnyTLS != nil {
		if selfPID := os.Getpid(); selfPID > 0 {
			pids = append(pids, selfPID)
		}
	}
	return pids
}
