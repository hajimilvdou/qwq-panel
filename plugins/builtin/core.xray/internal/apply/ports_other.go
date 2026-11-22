// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package apply

import (
	"context"
	"net/netip"
)

// 非 Linux 不猜测忙端口归属；实际插件的受支持平台仍为 Linux。
func verifyOwnedPortConflict(context.Context, netip.AddrPort, netip.AddrPort, int) error {
	return errPortIdentity
}
