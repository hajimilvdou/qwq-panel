// SPDX-License-Identifier: AGPL-3.0-only

package export

import (
	"strings"
	"testing"
)

func TestBuildExtraProtocolsExport(t *testing.T) {
	ep := ExportEndpoint{Host: "node.example.com", Port: 20443, Label: "test-node"}

	vless := BuildVLESS(ep, "p1", "u1", "00000000-0000-4000-8000-000000000001", VLESSOptions{
		Transport: "xhttp", SecurityMode: "reality", ServerName: "www.microsoft.com",
		PublicKey: "pubKey123", ShortID: "abcd", Path: "/x", Host: "cdn.example.com", XHTTPMode: "auto",
		Encryption: "mlkem768x25519plus.native.0rtt.pub",
	})
	if !strings.HasPrefix(vless.ShareURI, "vless://") || !strings.Contains(vless.ShareURI, "type=xhttp") ||
		vless.ClashNode["encryption"] != "mlkem768x25519plus.native.0rtt.pub" || vless.SingboxOutbound != nil {
		t.Fatalf("VLESS XHTTP/Encryption 导出异常: %+v", vless)
	}

	vmess := BuildVMess(ep, "p2", "u2", "00000000-0000-4000-8000-000000000002", VMessOptions{
		Transport: "ws", SecurityMode: "tls", ServerName: "node.example.com", PublicTrusted: true, Path: "/ws",
	})
	if !strings.HasPrefix(vmess.ShareURI, "vmess://") || vmess.ClashNode["type"] != "vmess" {
		t.Fatalf("VMess 导出异常: %+v", vmess)
	}

	trojan := BuildTrojan(ep, "p3", "u3", "tr-secret", TrojanOptions{
		Transport: "grpc", SecurityMode: "tls", ServerName: "node.example.com", PublicTrusted: true, ServiceName: "svc",
	})
	if !strings.HasPrefix(trojan.ShareURI, "trojan://") || !strings.Contains(trojan.ShareURI, "serviceName=svc") {
		t.Fatalf("Trojan 导出异常: %s", trojan.ShareURI)
	}

	ss := BuildShadowsocks(ep, "p4", "u4", "aes-256-gcm", "ss-secret", true)
	if !strings.HasPrefix(ss.ShareURI, "ss://") || ss.Protocol != "shadowsocks" {
		t.Fatalf("SS AEAD 导出异常: %+v", ss)
	}

	hy2 := BuildHysteria2WithOptions(ep, "p5", "u5", "hy2:p@ss", "node.example.com", true, "", "obfs-pass", "20000-30000,40000-40500")
	if !strings.Contains(hy2.ShareURI, "obfs=salamander") || !strings.Contains(hy2.ShareURI, "mport=20000-30000") || !strings.Contains(hy2.ShareURI, "hy2%3Ap%40ss@") {
		t.Fatalf("Hysteria2 扩展导出异常: %s", hy2.ShareURI)
	}
	sbPorts, _ := hy2.SingboxOutbound["server_ports"].([]string)
	if len(sbPorts) != 2 || sbPorts[0] != "20000:30000" || sbPorts[1] != "40000:40500" {
		t.Fatalf("Hysteria2 server_ports 多段拆分异常: %+v", hy2.SingboxOutbound["server_ports"])
	}

	anytls := BuildAnyTLS(ep, "p6", "u6", "anytls:p@ss", "node.example.com", true)
	if !strings.HasPrefix(anytls.ShareURI, "anytls://anytls%3Ap%40ss@") || anytls.ClashNode["type"] != "anytls" || anytls.ClashNode["udp"] != true || anytls.SingboxOutbound["type"] != "anytls" {
		t.Fatalf("AnyTLS 导出异常: %+v", anytls)
	}

	s5 := BuildSOCKS5(ep, "p7", "u7", "myuser", "mypass", true)
	if !strings.HasPrefix(s5.ShareURI, "socks5://myuser:mypass@") || s5.SingboxOutbound["type"] != "socks" {
		t.Fatalf("SOCKS5 导出异常: %+v", s5)
	}

	httpB := BuildHTTP(ep, "p8", "u8", "huser", "hpass")
	if !strings.HasPrefix(httpB.ShareURI, "http://huser:hpass@") || httpB.ClashNode["type"] != "http" {
		t.Fatalf("HTTP 导出异常: %+v", httpB)
	}
}
