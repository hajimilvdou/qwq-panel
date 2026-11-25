// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"net/netip"
	"slices"
	"strings"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ---- 外层计划不携带路径、argv 或任意执行器 ----------------------------------

// ObfsPlan 固定外层公开声明和驱动分配的同一回环目标；仅供受控进程适配器使用。
type ObfsPlan struct {
	ProfileID string
	Mode      string
	Host      string
	External  corev2.Listener
	Target    ObfsTarget
}

// PlanObfs 只创建纯计划；任何外层程序启动仍须供应链与生命周期验证。
func PlanObfs(intent *corev2.Intent, options V2Options) ([]ObfsPlan, error) {
	if err := corev2.Validate(intent); err != nil {
		return nil, err
	}
	return planObfs(intent, options)
}

func planObfs(intent *corev2.Intent, options V2Options) ([]ObfsPlan, error) {
	// 顶层停用仍预检候选；各 profile 的停用状态继续生效。
	enabled := true
	preflight := *intent
	preflight.Enabled = &enabled
	claims, err := corev2.Listeners(&preflight)
	if err != nil {
		return nil, err
	}
	plans := make([]ObfsPlan, 0, len(options.ObfsTargets))
	expected := 0
	for _, profile := range intent.Profiles {
		if profile.Protocol != corev2.ProtocolShadowsocks2022 || profile.Shadowsocks2022.Obfs.Mode == corev2.ObfsNone {
			continue
		}
		expected++
		target, found := options.ObfsTargets[profile.ID]
		addr, err := netip.ParseAddr(target.Listen)
		if !found || err != nil || !addr.IsLoopback() || addr.Zone() != "" || target.Port < 1024 || target.Port > 65535 {
			return nil, ErrObfsTarget
		}
		if !*profile.Enabled {
			continue
		}
		external := corev2.Listener{ProfileID: profile.ID, Network: "tcp", Listen: profile.Listen, Port: profile.Port}
		claims = append(claims, corev2.Listener{ProfileID: profile.ID, Network: "tcp", Listen: target.Listen, Port: target.Port})
		plans = append(plans, ObfsPlan{ProfileID: profile.ID, Mode: profile.Shadowsocks2022.Obfs.Mode, Host: profile.Shadowsocks2022.Obfs.Host,
			External: external, Target: target})
	}
	if expected != len(options.ObfsTargets) {
		return nil, ErrObfsTarget
	}
	if err := corev2.CheckListenerConflicts(claims); err != nil {
		return nil, err
	}
	slices.SortFunc(plans, func(left, right ObfsPlan) int { return strings.Compare(left.ProfileID, right.ProfileID) })
	return plans, nil
}
