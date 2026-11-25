// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

func TestRenderV2FullNineProtocolMatrix(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	cert, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Clear)

	makeTLSMat := func() TLSMaterials {
		m, err := tlsmgr.NewMaterial(cert.Chain, cert.Key)
		if err != nil {
			t.Fatal(err)
		}
		return TLSMaterials{
			BindingRef:     "certbind_matrix_1",
			Generation:     1,
			PolicyRevision: "pol-v1",
			SANs:           []string{"proxy.example.com"},
			Material:       m,
			Purpose:        tlsmgr.ServerTLS,
			Trust:          tlsmgr.PublicTrust,
			Roots:          cert.Roots,
		}
	}

	enabled := true
	sniffOn := true
	ref := func(i int) *corev2.SecretRef { return &corev2.SecretRef{ID: fmt.Sprintf("sec_%026d", i)} }
	tlsBind := &corev2.TLSBinding{BindingRef: "certbind_matrix_1", ServerName: "proxy.example.com"}
	privKey := []byte("KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio")
	reality := &corev2.Reality{
		Mode:        "reality",
		Target:      "www.microsoft.com:443",
		ServerNames: []string{"www.microsoft.com"},
		PrivateKey:  *ref(90),
		ShortIDs:    []string{"aabbccdd"},
	}

	intent := &corev2.Intent{
		SchemaVersion: "2",
		Enabled:       &enabled,
		Outbound:      &corev2.Outbound{Type: "direct"},
		Profiles: []corev2.Profile{
			{
				ID: "p-vless-xhttp", Enabled: &enabled, Listen: "0.0.0.0", Port: 21001, Protocol: corev2.ProtocolVLESS,
				Users: []corev2.User{{ID: "u-vless", UUID: ref(1)}},
				VLESS: &corev2.VLESS{
					Transport: "xhttp", SecurityMode: "reality", Security: reality,
					Path: "/xh", Host: "cdn.example.com", XHTTPMode: "packet-up",
					Decryption: ref(91), Sniffing: &sniffOn,
				},
			},
			{
				ID: "p-vmess-ws", Enabled: &enabled, Listen: "0.0.0.0", Port: 21002, Protocol: corev2.ProtocolVMess,
				Users: []corev2.User{{ID: "u-vmess", UUID: ref(2)}},
				VMess: &corev2.VMess{Transport: "ws", SecurityMode: "tls", TLS: tlsBind, Path: "/vm", Host: "proxy.example.com"},
			},
			{
				ID: "p-trojan-grpc", Enabled: &enabled, Listen: "0.0.0.0", Port: 21003, Protocol: corev2.ProtocolTrojan,
				Users:  []corev2.User{{ID: "u-trojan", Auth: ref(3)}},
				Trojan: &corev2.Trojan{Transport: "grpc", SecurityMode: "tls", TLS: tlsBind, ServiceName: "tr-svc"},
			},
			{
				ID: "p-ss-aead", Enabled: &enabled, Listen: "0.0.0.0", Port: 21004, Protocol: corev2.ProtocolShadowsocks,
				Users:       []corev2.User{{ID: "u-ss", Auth: ref(4)}},
				Shadowsocks: &corev2.Shadowsocks{Method: corev2.MethodAEADAES256GCM, UDP: true},
			},
			{
				ID: "p-ss2022-chacha", Enabled: &enabled, Listen: "0.0.0.0", Port: 21005, Protocol: corev2.ProtocolShadowsocks2022,
				Users: []corev2.User{{ID: "u-ss22", PSK: ref(5)}},
				Shadowsocks2022: &corev2.Shadowsocks2022{
					Method:    corev2.MethodChaCha20,
					ServerKey: *ref(92),
					Obfs:      &corev2.Obfs{Mode: corev2.ObfsNone},
					UDP:       true,
				},
			},
			{
				ID: "p-hy2-obfs", Enabled: &enabled, Listen: "0.0.0.0", Port: 21006, Protocol: corev2.ProtocolHysteria2,
				Users: []corev2.User{{ID: "u-hy2", Auth: ref(6)}},
				Hysteria2: &corev2.Hysteria2{
					TLS:          tlsBind,
					ObfsPassword: ref(93),
					PortHopping:  "25000-26000",
				},
			},
			{
				ID: "p-anytls", Enabled: &enabled, Listen: "0.0.0.0", Port: 21007, Protocol: corev2.ProtocolAnyTLS,
				Users:  []corev2.User{{ID: "u-anytls", Auth: ref(7)}},
				AnyTLS: &corev2.AnyTLS{TLS: tlsBind},
			},
			{
				ID: "p-socks5", Enabled: &enabled, Listen: "127.0.0.1", Port: 21008, Protocol: corev2.ProtocolSOCKS5,
				Users:  []corev2.User{{ID: "u-socks", Username: "suser", Auth: ref(8)}},
				SOCKS5: &corev2.SOCKS5{UDP: true},
			},
			{
				ID: "p-http", Enabled: &enabled, Listen: "127.0.0.1", Port: 21009, Protocol: corev2.ProtocolHTTP,
				Users: []corev2.User{{ID: "u-http", Username: "huser", Auth: ref(9)}},
				HTTP:  &corev2.HTTP{},
			},
		},
	}

	vmTLS := makeTLSMat()
	trTLS := makeTLSMat()
	materials := V2Materials{
		Profiles: map[string]ProfileMaterials{
			"p-vless-xhttp": {
				VLESS: &Secrets{
					PrivateKey: append([]byte(nil), privKey...),
					UUIDs:      map[string][]byte{"u-vless": []byte("00000000-0000-4000-8000-000000000001")},
				},
				VLESSDecryption: []byte("mlkem768x25519plus.native.600s.testkey"),
			},
			"p-vmess-ws": {
				VMess: &VMessMaterials{
					UUIDs: map[string][]byte{"u-vmess": []byte("00000000-0000-4000-8000-000000000002")},
					TLS:   &vmTLS,
				},
			},
			"p-trojan-grpc": {
				Trojan: &TrojanMaterials{
					Auth: map[string][]byte{"u-trojan": []byte("trojan-pass-123456")},
					TLS:  &trTLS,
				},
			},
			"p-ss-aead": {
				Shadowsocks: &ShadowsocksMaterials{
					Auth: map[string][]byte{"u-ss": []byte("ss-aead-pass-123456")},
				},
			},
			"p-ss2022-chacha": {
				Shadowsocks2022: &SS2022Materials{
					ServerKey: testPSK(1, 32),
					PSKs:      map[string][]byte{"u-ss22": testPSK(2, 32)},
				},
			},
			"p-hy2-obfs": {
				Hysteria2: &HysteriaMaterials{
					Auth:         map[string][]byte{"u-hy2": []byte("hy2-super-secret-auth-1234")},
					TLS:          makeTLSMat(),
					ObfsPassword: []byte("salamander-obfs-pwd"),
				},
			},
			"p-anytls": {
				AnyTLS: &AnyTLSMaterials{
					Auth: map[string][]byte{"u-anytls": []byte("anytls-secret-password")},
					TLS:  makeTLSMat(),
				},
			},
			"p-socks5": {
				SOCKS5: &AccountMaterials{
					Auth: map[string][]byte{"u-socks": []byte("socks-pass")},
				},
			},
			"p-http": {
				HTTP: &AccountMaterials{
					Auth: map[string][]byte{"u-http": []byte("http-pass")},
				},
			},
		},
	}
	t.Cleanup(materials.Clear)

	raw, err := RenderV2(intent, materials, V2Options{
		Options: Options{APISocket: "/tmp/qwq-test/api.sock"},
		Now:     now,
	})
	if err != nil {
		t.Fatalf("RenderV2 9 协议矩阵失败: %v", err)
	}

	inbounds := decodeV2Inbounds(t, raw)
	// 8 个 Xray 业务入站（AnyTLS 不写入 Xray config.json）+ 1 个 qwq-api-in = 9 个
	if len(inbounds) != 9 {
		t.Fatalf("期望 9 个 Xray 入站（不含 anytls），实际 %d", len(inbounds))
	}
	if _, hasAnyTLS := inbounds["qwq-in-p-anytls"]; hasAnyTLS {
		t.Fatal("AnyTLS 不应写入 Xray 原生 inbounds")
	}

	// 验证 VLESS XHTTP + Decryption
	vlessIn := profileInbound(t, inbounds, "p-vless-xhttp")
	if vlessIn.Stream == nil || vlessIn.Stream.Network != "xhttp" || vlessIn.Stream.XHTTP == nil || vlessIn.Stream.XHTTP.Mode != "packet-up" {
		t.Fatalf("VLESS XHTTP streamSettings 不符: %+v", vlessIn.Stream)
	}
	var vs vlessSettings
	if err := json.Unmarshal(vlessIn.Settings, &vs); err != nil || vs.Decryption != "mlkem768x25519plus.native.600s.testkey" {
		t.Fatalf("VLESS Decryption 不符: %+v", vs)
	}

	// 验证 Hysteria2 finalmask salamander
	hy2In := profileInbound(t, inbounds, "p-hy2-obfs")
	if hy2In.Stream == nil || hy2In.Stream.FinalMask == nil || len(hy2In.Stream.FinalMask.UDP) != 1 || hy2In.Stream.FinalMask.UDP[0].Type != "salamander" {
		t.Fatalf("Hysteria2 finalmask 不符: %+v", hy2In.Stream)
	}

	// 验证 SS2022 ChaCha20 为单用户结构（无 users 字段）
	ss22In := profileInbound(t, inbounds, "p-ss2022-chacha")
	var ss22Map map[string]any
	if err := json.Unmarshal(ss22In.Settings, &ss22Map); err != nil {
		t.Fatal(err)
	}
	if _, hasUsers := ss22Map["users"]; hasUsers {
		t.Fatal("SS2022 ChaCha20 不应包含多用户 users 字段")
	}

	// 验证 SOCKS5 与 HTTP
	socksIn := profileInbound(t, inbounds, "p-socks5")
	if socksIn.Protocol != "socks" {
		t.Fatalf("SOCKS5 协议名应为 socks，实际 %s", socksIn.Protocol)
	}
	httpIn := profileInbound(t, inbounds, "p-http")
	if httpIn.Protocol != "http" {
		t.Fatalf("HTTP 协议名应为 http，实际 %s", httpIn.Protocol)
	}
}
