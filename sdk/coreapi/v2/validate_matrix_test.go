// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"testing"
)

func TestValidateFullNineProtocolMatrix(t *testing.T) {
	sec := func(id string) *SecretRef { return &SecretRef{ID: id} }
	reality := func() *Reality {
		return &Reality{
			Mode:        "reality",
			Target:      "www.microsoft.com:443",
			ServerNames: []string{"www.microsoft.com"},
			PrivateKey:  *sec("sec_00000000000000000000000010"),
			ShortIDs:    []string{"01234567"},
		}
	}
	tlsBind := func() *TLSBinding {
		return &TLSBinding{
			BindingRef: "certbind_matrix_test_01",
			ServerName: "node.example.test",
		}
	}

	intent := &Intent{
		SchemaVersion: "2",
		Enabled:       boolValue(true),
		Outbound:      &Outbound{Type: "direct"},
		Profiles: []Profile{
			{
				ID: "p-vless-xhttp", Enabled: boolValue(true), Listen: "0.0.0.0", Port: 20001, Protocol: ProtocolVLESS,
				Users: []User{{ID: "u1", UUID: sec("sec_00000000000000000000000001")}},
				VLESS: &VLESS{
					Transport: "xhttp", SecurityMode: "reality", Security: reality(),
					Path: "/xhttp-path", Host: "cdn.example.test", XHTTPMode: "auto",
					Decryption: sec("sec_00000000000000000000000011"), Encryption: "none",
				},
			},
			{
				ID: "p-vless-tls-ws", Enabled: boolValue(true), Listen: "0.0.0.0", Port: 20002, Protocol: ProtocolVLESS,
				Users: []User{{ID: "u2", UUID: sec("sec_00000000000000000000000002")}},
				VLESS: &VLESS{
					Transport: "ws", SecurityMode: "tls", TLS: tlsBind(),
					Path: "/ws", Host: "node.example.test",
				},
			},
			{
				ID: "p-vmess-ws", Enabled: boolValue(true), Listen: "0.0.0.0", Port: 20003, Protocol: ProtocolVMess,
				Users: []User{{ID: "u3", UUID: sec("sec_00000000000000000000000003")}},
				VMess: &VMess{Transport: "ws", SecurityMode: "none", Path: "/vmess"},
			},
			{
				ID: "p-trojan-grpc", Enabled: boolValue(true), Listen: "0.0.0.0", Port: 20004, Protocol: ProtocolTrojan,
				Users:  []User{{ID: "u4", Auth: sec("sec_00000000000000000000000004")}},
				Trojan: &Trojan{Transport: "grpc", SecurityMode: "tls", TLS: tlsBind(), ServiceName: "trojan-grpc"},
			},
			{
				ID: "p-ss-aead", Enabled: boolValue(true), Listen: "0.0.0.0", Port: 20005, Protocol: ProtocolShadowsocks,
				Users:       []User{{ID: "u5", Auth: sec("sec_00000000000000000000000005")}},
				Shadowsocks: &Shadowsocks{Method: MethodAEADAES256GCM, UDP: true},
			},
			{
				ID: "p-ss2022-chacha", Enabled: boolValue(true), Listen: "0.0.0.0", Port: 20006, Protocol: ProtocolShadowsocks2022,
				Users: []User{{ID: "u6", PSK: sec("sec_00000000000000000000000006")}},
				Shadowsocks2022: &Shadowsocks2022{
					Method:    MethodChaCha20,
					ServerKey: *sec("sec_00000000000000000000000012"),
					Obfs:      &Obfs{Mode: ObfsNone},
					UDP:       true,
				},
			},
			{
				ID: "p-hy2-obfs", Enabled: boolValue(true), Listen: "0.0.0.0", Port: 20007, Protocol: ProtocolHysteria2,
				Users: []User{{ID: "u7", Auth: sec("sec_00000000000000000000000007")}},
				Hysteria2: &Hysteria2{
					TLS:          tlsBind(),
					ObfsPassword: sec("sec_00000000000000000000000013"),
					PortHopping:  "25000-26000",
				},
			},
			{
				ID: "p-anytls", Enabled: boolValue(true), Listen: "0.0.0.0", Port: 20008, Protocol: ProtocolAnyTLS,
				Users:  []User{{ID: "u8", Auth: sec("sec_00000000000000000000000008")}},
				AnyTLS: &AnyTLS{TLS: tlsBind(), PaddingScheme: DefaultAnyTLSPaddingScheme()},
			},
			{
				ID: "p-socks5", Enabled: boolValue(true), Listen: "127.0.0.1", Port: 20009, Protocol: ProtocolSOCKS5,
				Users:  []User{{ID: "u9", Username: "socks_user", Auth: sec("sec_00000000000000000000000009")}},
				SOCKS5: &SOCKS5{UDP: true},
			},
			{
				ID: "p-http", Enabled: boolValue(true), Listen: "127.0.0.1", Port: 20010, Protocol: ProtocolHTTP,
				Users: []User{{ID: "u10", Username: "http_user", Auth: sec("sec_00000000000000000000000014")}},
				HTTP:  &HTTP{},
			},
		},
	}

	if err := Validate(intent); err != nil {
		t.Fatalf("9 协议全矩阵合法快照被拒绝: %v", err)
	}

	listeners, err := Listeners(intent)
	if err != nil {
		t.Fatalf("Listeners 失败: %v", err)
	}
	// 10 profiles: p-ss-aead (tcp+udp), p-ss2022-chacha (tcp+udp), p-socks5 (tcp+udp), p-hy2-obfs (udp), 其余 6 个各 1 tcp => 共 13 条监听
	if len(listeners) != 13 {
		t.Fatalf("期望 13 条监听声明，实际 %d: %+v", len(listeners), listeners)
	}

	// Vision 禁止在 ws/grpc/xhttp 或 none 安全下启用
	intent.Profiles[0].VLESS.Flow = "xtls-rprx-vision"
	requireViolation(t, Validate(intent), "/profiles/0/vless/flow", "FORBIDDEN")
	intent.Profiles[0].VLESS.Flow = ""

	// 非 SOCKS5/HTTP 不允许设置 username
	intent.Profiles[2].Users[0].Username = "bad"
	requireViolation(t, Validate(intent), "/profiles/2/users/0/username", "FORBIDDEN")
	intent.Profiles[2].Users[0].Username = ""

	// 非法 port_hopping 拒绝
	intent.Profiles[6].Hysteria2.PortHopping = "30000-20000"
	requireViolation(t, Validate(intent), "/profiles/6/hysteria2/port_hopping", "FORMAT")
}
