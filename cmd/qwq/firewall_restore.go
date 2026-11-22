// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

type capabilityCaller interface {
	Call(context.Context, sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error)
}

// runFirewallRestore 只请求恢复既有策略，不接受规则、路径或任意 helper verb。
// 开机单元以 qwq 身份调用，实际写入仍由独立 socket 激活 root helper 完成。
func runFirewallRestore(args []string, stderr io.Writer, client capabilityCaller) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "qwq firewall-restore: no arguments are accepted")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := client.Call(ctx, sandbox.CapabilityRequest{Op: "firewall.restore", ID: "qwq.bootstrap"})
	if err != nil || !response.OK {
		fmt.Fprintln(stderr, "qwq firewall-restore: saved policy could not be restored; inspect the live firewall state")
		return 1
	}
	return 0
}
