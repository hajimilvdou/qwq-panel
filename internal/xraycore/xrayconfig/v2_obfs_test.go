// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"testing"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ---- 外层声明与驱动私有回环地址必须一起校验 --------------------------------

func TestRenderV2ObfsRequiresPrivateTargetAndPlan(t *testing.T) {
	for _, mode := range []string{corev2.ObfsHTTP, corev2.ObfsTLS} {
		t.Run(mode, func(t *testing.T) {
			intent, materials, options := v2Fixture(t)
			ss := &intent.Profiles[2]
			ss.Listen = "192.0.2.10"
			ss.Shadowsocks2022.Obfs = &corev2.Obfs{Mode: mode, Host: "obfs.example.com"}
			requireV2Rejected(t, intent, materials, options)
			options.ObfsTargets = map[string]ObfsTarget{"ss": {Listen: "127.0.0.1", Port: 20444}}
			raw, err := RenderV2(intent, materials, options)
			if err != nil {
				t.Fatal(err)
			}
			inbound := profileInbound(t, decodeV2Inbounds(t, raw), "ss")
			if inbound.Listen != "127.0.0.1" || inbound.Port != 20444 {
				t.Fatal("核心必须监听驱动私有回环，不能抢占 obfs 外层")
			}
			plans, err := PlanObfs(intent, options)
			if err != nil || len(plans) != 1 || plans[0].ProfileID != "ss" || plans[0].Mode != mode || plans[0].Host != "obfs.example.com" ||
				plans[0].External.Listen != "192.0.2.10" || plans[0].External.Port != 10444 || plans[0].External.Network != "tcp" || plans[0].Target != options.ObfsTargets["ss"] {
				t.Fatal("受控外层计划必须保留原外部监听和同一私有目标")
			}
			ss.Shadowsocks2022.UDP = true
			requireV2Rejected(t, intent, materials, options)
		})
	}
}

func TestRenderV2RejectsObfsTargetEscapeAndCollisions(t *testing.T) {
	for _, target := range []ObfsTarget{{Listen: "0.0.0.0", Port: 20444}, {Listen: "::", Port: 20444}, {Listen: "192.0.2.10", Port: 20444},
		{Listen: "localhost", Port: 20444}, {Listen: "::1%lo", Port: 20444}, {Listen: "127.0.0.1", Port: 443},
		{Listen: "127.0.0.1", Port: 65536}, {Listen: "127.0.0.1", Port: 10443}, {Listen: "127.0.0.1", Port: 10444}} {
		intent, materials, options := v2Fixture(t)
		intent.Profiles[2].Shadowsocks2022.Obfs = &corev2.Obfs{Mode: corev2.ObfsHTTP, Host: "obfs.example.com"}
		options.ObfsTargets = map[string]ObfsTarget{"ss": target}
		requireV2Rejected(t, intent, materials, options)
	}
	intent, materials, options := v2Fixture(t)
	options.ObfsTargets = map[string]ObfsTarget{"main": {Listen: "127.0.0.1", Port: 20444}}
	requireV2Rejected(t, intent, materials, options)
}
