// SPDX-License-Identifier: Apache-2.0

package coreapi

import "testing"

func TestTransportPortOverlap(t *testing.T) {
	cases := []struct {
		name, first, second string
		conflict            bool
	}{
		{"同 IPv4", "127.0.0.1", "127.0.0.1", true},
		{"不同 IPv4", "127.0.0.1", "127.0.0.2", false},
		{"IPv4 wildcard", "0.0.0.0", "127.0.0.1", true},
		{"IPv6 wildcard 与 IPv4", "::", "127.0.0.1", true},
		{"IPv6 wildcard 与 IPv6", "::", "2001:db8::1", true},
		{"IPv4 mapped", "::ffff:127.0.0.1", "127.0.0.1", true},
		{"不同地址族", "127.0.0.1", "2001:db8::1", false},
		{"IPv4 wildcard 不占 IPv6 specific", "0.0.0.0", "2001:db8::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intent := validIntent(t)
			intent.Profiles = []Profile{intent.Profiles[0], intent.Profiles[2]}
			intent.Profiles[0].Listen = tc.first
			intent.Profiles[1].Listen = tc.second
			intent.Profiles[1].Port = intent.Profiles[0].Port
			err := Validate(intent)
			if tc.conflict {
				requireViolation(t, err, "/profiles/1/port", "PORT_CONFLICT")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPAndUDPPortsAreIndependent(t *testing.T) {
	intent := validIntent(t)
	intent.Profiles = intent.Profiles[:2]
	if _, err := Listeners(intent); err != nil {
		t.Fatal("TCP/UDP 共享外部端口被拒绝")
	}
	intent = validIntent(t)
	intent.Profiles = []Profile{intent.Profiles[1], intent.Profiles[2]}
	intent.Profiles[1].Port = intent.Profiles[0].Port
	if err := Validate(intent); err != nil {
		t.Fatal("SS TCP 与 H2 UDP 共享端口被拒绝")
	}
	intent.Profiles[1].Shadowsocks2022.UDP = true
	requireViolation(t, Validate(intent), "/profiles/1/port", "PORT_CONFLICT")
}

func TestDisabledProfileAndTopLevelPortRules(t *testing.T) {
	intent := validIntent(t)
	intent.Profiles = []Profile{intent.Profiles[0], intent.Profiles[2]}
	intent.Profiles[1].Port = intent.Profiles[0].Port
	intent.Profiles[1].Enabled = boolValue(false)
	listeners, err := Listeners(intent)
	if err != nil || len(listeners) != 1 || listeners[0].ProfileID != intent.Profiles[0].ID {
		t.Fatal("停用 profile 仍声明监听")
	}
	intent.Enabled = boolValue(false)
	listeners, err = Listeners(intent)
	if err != nil || listeners == nil || len(listeners) != 0 {
		t.Fatal("顶层停用必须返回空声明数组")
	}
	intent.Profiles[1].Enabled = boolValue(true)
	requireViolation(t, Validate(intent), "/profiles/1/port", "PORT_CONFLICT")
}

func TestSSUDPAndObfsListenerDeclarations(t *testing.T) {
	intent := validIntent(t)
	intent.Profiles = intent.Profiles[2:]
	intent.Profiles[0].Shadowsocks2022.UDP = true
	listeners, err := Listeners(intent)
	if err != nil || len(listeners) != 2 || listeners[0].Network != "tcp" || listeners[1].Network != "udp" {
		t.Fatal("SS UDP 声明未与 TCP 分开")
	}
	intent.Profiles[0].Shadowsocks2022.UDP = false
	intent.Profiles[0].Shadowsocks2022.Obfs = &Obfs{Mode: ObfsTLS, Host: "example.test"}
	listeners, err = Listeners(intent)
	if err != nil || len(listeners) != 1 || listeners[0].Port != 18444 || listeners[0].Listen != "127.0.0.1" {
		t.Fatal("obfs 公开声明改变了外部端口或暴露内部端口")
	}
	_, err = Listeners(nil)
	requireViolation(t, err, "", "REQUIRED")
}
