// SPDX-License-Identifier: AGPL-3.0-only

package export

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// ======================== 三协议标准客户端导出与 IPv4/IPv6 校验 ========================

func TestBuildVLESSRealityIPv4AndIPv6(t *testing.T) {
	ep := ExportEndpoint{Host: "2001:db8::10", Port: 443, Label: "node-vless"}
	bundle := BuildVLESSReality(ep, "prof-vless", "u-1", "11111111-2222-3333-4444-555555555555", "www.apple.com", "PubKeyBase64URL", "a1b2c3d4")

	if bundle.Protocol != "vless-reality" || bundle.ProfileID != "prof-vless" || bundle.UserID != "u-1" {
		t.Fatalf("元数据不符: %+v", bundle)
	}
	if !strings.Contains(bundle.ShareURI, "@[2001:db8::10]:443?") {
		t.Fatalf("IPv6 地址必须自动加方括号: %s", bundle.ShareURI)
	}
	parsed, err := url.Parse(bundle.ShareURI)
	if err != nil {
		t.Fatalf("VLESS URI 解析失败: %v", err)
	}
	if parsed.Scheme != "vless" || parsed.User.Username() != "11111111-2222-3333-4444-555555555555" || parsed.Fragment != "node-vless" {
		t.Fatalf("VLESS URI 头部或备注不符: %+v", parsed)
	}
	q := parsed.Query()
	for k, want := range map[string]string{
		"encryption": "none",
		"flow":       "xtls-rprx-vision",
		"security":   "reality",
		"sni":        "www.apple.com",
		"fp":         "chrome",
		"pbk":        "PubKeyBase64URL",
		"sid":        "a1b2c3d4",
		"type":       "tcp",
	} {
		if got := q.Get(k); got != want {
			t.Fatalf("VLESS query[%s]=%q, want %q", k, got, want)
		}
	}

	// 验证 Clash YAML 包含规范缩进与带引号 IPv6 server。
	if !strings.Contains(bundle.ClashYAML, `server: "2001:db8::10"`) ||
		!strings.Contains(bundle.ClashYAML, "reality-opts:\n  public-key: PubKeyBase64URL\n  short-id: a1b2c3d4\n") {
		t.Fatalf("Clash YAML 格式不符:\n%s", bundle.ClashYAML)
	}

	// 验证 sing-box outbound JSON 结构完整。
	rawSB, err := json.Marshal(bundle.SingboxOutbound)
	if err != nil {
		t.Fatalf("sing-box JSON 序列化失败: %v", err)
	}
	var sb struct {
		Type       string `json:"type"`
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		Flow       string `json:"flow"`
		TLS        struct {
			Enabled    bool   `json:"enabled"`
			ServerName string `json:"server_name"`
			UTLS       struct {
				Enabled     bool   `json:"enabled"`
				Fingerprint string `json:"fingerprint"`
			} `json:"utls"`
			Reality struct {
				Enabled   bool   `json:"enabled"`
				PublicKey string `json:"public_key"`
				ShortID   string `json:"short_id"`
			} `json:"reality"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(rawSB, &sb); err != nil {
		t.Fatal(err)
	}
	if sb.Type != "vless" || sb.Server != "2001:db8::10" || sb.ServerPort != 443 || sb.Flow != "xtls-rprx-vision" ||
		!sb.TLS.Enabled || sb.TLS.ServerName != "www.apple.com" || !sb.TLS.UTLS.Enabled || sb.TLS.UTLS.Fingerprint != "chrome" ||
		!sb.TLS.Reality.Enabled || sb.TLS.Reality.PublicKey != "PubKeyBase64URL" || sb.TLS.Reality.ShortID != "a1b2c3d4" {
		t.Fatalf("sing-box VLESS 结构不符: %+v", sb)
	}
}

func TestBuildHysteria2TrustedAndSelfSigned(t *testing.T) {
	ep := ExportEndpoint{Host: "203.0.113.20", Port: 8443, Label: "hy2-trusted"}
	trusted := BuildHysteria2(ep, "prof-hy2", "u-hy", "secret-pass", "hy2.example.com", true, "ignored-pin")

	parsedTrusted, err := url.Parse(trusted.ShareURI)
	if err != nil {
		t.Fatalf("Hysteria2 trusted URI 解析失败: %v", err)
	}
	if parsedTrusted.Scheme != "hysteria2" || parsedTrusted.Host != "203.0.113.20:8443" {
		t.Fatalf("Hysteria2 URI host 不符: %s", trusted.ShareURI)
	}
	if parsedTrusted.Query().Get("insecure") != "0" || parsedTrusted.Query().Get("pinSHA256") != "" {
		t.Fatalf("公信证书必须强制 insecure=0 且不附带 pinSHA256: %s", trusted.ShareURI)
	}
	if trusted.ClashNode["skip-cert-verify"] != false {
		t.Fatalf("公信证书 Clash skip-cert-verify 必须为 false: %+v", trusted.ClashNode)
	}
	if !strings.Contains(trusted.ClashYAML, "skip-cert-verify: false\n") {
		t.Fatalf("Clash YAML 缺少 skip-cert-verify: false:\n%s", trusted.ClashYAML)
	}

	selfSigned := BuildHysteria2(
		ExportEndpoint{Host: "[2001:db8::99]", Port: 9443, Label: "hy2-self"},
		"prof-hy2", "u-hy", "secret-pass", "hy2.internal", false, "sha256:abcdef0123456789",
	)
	parsedSelf, err := url.Parse(selfSigned.ShareURI)
	if err != nil {
		t.Fatalf("Hysteria2 self-signed URI 解析失败: %v", err)
	}
	if !strings.Contains(selfSigned.ShareURI, "@[2001:db8::99]:9443?") {
		t.Fatalf("已带方括号的 IPv6 不应重复包裹: %s", selfSigned.ShareURI)
	}
	if parsedSelf.Query().Get("insecure") != "1" || parsedSelf.Query().Get("pinSHA256") != "sha256:abcdef0123456789" {
		t.Fatalf("自签证书必须设 insecure=1 并附带 pinSHA256: %s", selfSigned.ShareURI)
	}
	if selfSigned.ClashNode["skip-cert-verify"] != true || selfSigned.ClashNode["fingerprint"] != "sha256:abcdef0123456789" {
		t.Fatalf("自签 ClashNode 缺少字段: %+v", selfSigned.ClashNode)
	}
	sbTLS, ok := selfSigned.SingboxOutbound["tls"].(map[string]any)
	if !ok || sbTLS["insecure"] != true || sbTLS["server_name"] != "hy2.internal" {
		t.Fatalf("自签 sing-box tls 不符: %+v", selfSigned.SingboxOutbound)
	}
}

func TestBuildSS2022WithAndWithoutObfs(t *testing.T) {
	ep := ExportEndpoint{Host: "ss.example.com", Port: 18388, Label: "ss-plain"}
	plain := BuildSS2022(ep, "prof-ss", "u-ss", "2022-blake3-aes-128-gcm", "serverPSK==", "userPSK==", "", "", true)

	parsedPlain, err := url.Parse(plain.ShareURI)
	if err != nil {
		t.Fatalf("SS2022 plain URI 解析失败: %v", err)
	}
	if parsedPlain.Scheme != "ss" || parsedPlain.Host != "ss.example.com:18388" || parsedPlain.RawQuery != "" {
		t.Fatalf("无 obfs 的 SS2022 URI 不符: %s", plain.ShareURI)
	}
	decodedUserInfo, err := base64.RawURLEncoding.DecodeString(parsedPlain.User.Username())
	if err != nil {
		t.Fatalf("SIP002 base64url 解码失败: %v", err)
	}
	if string(decodedUserInfo) != "2022-blake3-aes-128-gcm:serverPSK==:userPSK==" {
		t.Fatalf("SIP002 userinfo 解码不符: %q", string(decodedUserInfo))
	}
	if _, hasPlugin := plain.ClashNode["plugin"]; hasPlugin {
		t.Fatalf("无 obfs 时不应出现 plugin 字段: %+v", plain.ClashNode)
	}

	// 开启 simple-obfs tls 且缺省 host 时应默认回退 www.bing.com，并保持公网端口 18388。
	obfs := BuildSS2022(
		ExportEndpoint{Host: "2001:db8::88", Port: 18388, Label: "ss-obfs"},
		"prof-ss", "u-ss", "2022-blake3-aes-128-gcm", "serverPSK==", "userPSK==", "tls", "", false,
	)
	if !strings.Contains(obfs.ShareURI, "@[2001:db8::88]:18388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dwww.bing.com#ss-obfs") {
		t.Fatalf("带 simple-obfs 的 SIP002 URI 格式不符: %s", obfs.ShareURI)
	}
	if obfs.ClashNode["plugin"] != "obfs" || obfs.ClashNode["port"] != 18388 || obfs.ClashNode["udp"] != false {
		t.Fatalf("带 obfs 的 ClashNode 不符: %+v", obfs.ClashNode)
	}
	if !strings.Contains(obfs.ClashYAML, "plugin: obfs\nplugin-opts:\n  host: www.bing.com\n  mode: tls\n") {
		t.Fatalf("带 obfs 的 Clash YAML 不符:\n%s", obfs.ClashYAML)
	}
	if obfs.SingboxOutbound["plugin"] != "obfs-local" ||
		obfs.SingboxOutbound["plugin_opts"] != "obfs=tls;obfs-host=www.bing.com" ||
		obfs.SingboxOutbound["network"] != "tcp" ||
		obfs.SingboxOutbound["server_port"] != 18388 {
		t.Fatalf("带 obfs 的 sing-box outbound 不符: %+v", obfs.SingboxOutbound)
	}
}
