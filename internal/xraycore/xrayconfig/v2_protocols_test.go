// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ---- 真实密码学夹具与稳定假引用 --------------------------------------------

func v2Fixture(t *testing.T) (*corev2.Intent, V2Materials, V2Options) {
	t.Helper()
	v1, vless := fixture()
	intent, err := corev2.FromV1(v1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	certificate, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(certificate.Clear)
	material, err := tlsmgr.NewMaterial(certificate.Chain, certificate.Key)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	ref := func(index int) *corev2.SecretRef {
		return &corev2.SecretRef{ID: fmt.Sprintf("sec_%026d", index)}
	}
	intent.Profiles = append(intent.Profiles,
		corev2.Profile{ID: "h2", Enabled: &enabled, Listen: "127.0.0.1", Port: 10443, Protocol: corev2.ProtocolHysteria2,
			Users:     []corev2.User{{ID: "h-bob", Auth: ref(4)}, {ID: "h-alice", Auth: ref(3)}},
			Hysteria2: &corev2.Hysteria2{TLS: &corev2.TLSBinding{BindingRef: "certbind_fixture", ServerName: "proxy.example.com"}}},
		corev2.Profile{ID: "ss", Enabled: &enabled, Listen: "127.0.0.1", Port: 10444, Protocol: corev2.ProtocolShadowsocks2022,
			Users:           []corev2.User{{ID: "s-bob", PSK: ref(7)}, {ID: "s-alice", PSK: ref(6)}},
			Shadowsocks2022: &corev2.Shadowsocks2022{Method: corev2.MethodAES128, ServerKey: *ref(5), Obfs: &corev2.Obfs{Mode: corev2.ObfsNone}}},
	)
	materials := V2Materials{Profiles: map[string]ProfileMaterials{
		"main": {VLESS: &vless},
		"h2": {Hysteria2: &HysteriaMaterials{Auth: map[string][]byte{"h-alice": []byte("fixture-hysteria-auth-alice"), "h-bob": []byte("fixture-hysteria-auth-bob")},
			TLS: TLSMaterials{BindingRef: "certbind_fixture", Generation: 2, PolicyRevision: "fixture-policy-v2", SANs: []string{"proxy.example.com"},
				Material: material, Purpose: tlsmgr.ServerTLS, Trust: tlsmgr.PublicTrust, Roots: certificate.Roots}}},
		"ss": {Shadowsocks2022: &SS2022Materials{ServerKey: testPSK(1, 16), PSKs: map[string][]byte{"s-alice": testPSK(2, 16), "s-bob": testPSK(3, 16)}}},
	}}
	t.Cleanup(materials.Clear)
	return intent, materials, V2Options{Options: Options{APISocket: "/tmp/qwq-test/api.sock"}, Now: now}
}

// testPSK 只生成可辨认的测试字节，不用于生产密钥。
func testPSK(seed, length int) []byte {
	decoded := make([]byte, length)
	for index := range decoded {
		decoded[index] = byte(index*17 + seed)
	}
	defer clear(decoded)
	return []byte(base64.StdEncoding.EncodeToString(decoded))
}

type decodedV2Inbound struct {
	Tag      string          `json:"tag"`
	Listen   string          `json:"listen"`
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
	Stream   *nativeStream   `json:"streamSettings"`
}

func decodeV2Inbounds(t *testing.T, raw []byte) map[string]decodedV2Inbound {
	t.Helper()
	var candidate struct {
		Inbounds []decodedV2Inbound `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &candidate); err != nil {
		t.Fatal(err)
	}
	result := make(map[string]decodedV2Inbound, len(candidate.Inbounds))
	for _, inbound := range candidate.Inbounds {
		result[inbound.Tag] = inbound
	}
	return result
}

func profileInbound(t *testing.T, values map[string]decodedV2Inbound, id string) decodedV2Inbound {
	t.Helper()
	tag, err := corev1.InboundTag(id)
	if err != nil {
		t.Fatal(err)
	}
	value, found := values[tag]
	if !found {
		t.Fatalf("缺失 profile %s 的原生监听", id)
	}
	return value
}

func requireV2Rejected(t *testing.T, intent *corev2.Intent, materials V2Materials, options V2Options) {
	t.Helper()
	raw, err := RenderV2(intent, materials, options)
	if err == nil || len(raw) != 0 || strings.Contains(err.Error(), "CANARY") {
		t.Fatal("无效输入必须脱敏拒绝且没有候选配置")
	}
}

// ---- 锁定协议字段、输入不变与顺序无关 --------------------------------------

func TestRenderV2NativeProtocolsAndDeterminism(t *testing.T) {
	intent, materials, options := v2Fixture(t)
	before, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	authBefore := bytes.Clone(materials.Profiles["h2"].Hysteria2.Auth["h-alice"])
	keyBefore := bytes.Clone(materials.Profiles["ss"].Shadowsocks2022.ServerKey)
	raw, err := RenderV2(intent, materials, options)
	if err != nil {
		t.Fatal(err)
	}
	values := decodeV2Inbounds(t, raw)
	if len(values) != 4 {
		t.Fatal("三个业务监听必须共用一个私有 API")
	}
	h2 := profileInbound(t, values, "h2")
	var h2Settings hysteriaSettings
	if err := json.Unmarshal(h2.Settings, &h2Settings); err != nil {
		t.Fatal(err)
	}
	if h2.Protocol != "hysteria" || h2Settings.Version != 2 || len(h2Settings.Users) != 2 ||
		h2Settings.Users[0].Auth != string(authBefore) || h2Settings.Users[0].Email != "qwq-user-h-alice" ||
		h2.Stream == nil || h2.Stream.Network != "hysteria" || h2.Stream.Security != "tls" ||
		h2.Stream.Hysteria == nil || h2.Stream.Hysteria.Version != 2 {
		t.Fatal("Hysteria2 原生协议、传输版本或稳定用户身份错误")
	}
	tls := h2.Stream.TLS
	if tls == nil || tls.ServerName != "proxy.example.com" || tls.MinVersion != "1.3" || !tls.RejectUnknownSNI ||
		!slices.Equal(tls.ALPN, []string{"h3"}) || len(tls.Certificates) != 1 ||
		tls.Certificates[0].Usage != "encipherment" || !tls.Certificates[0].OneTimeLoading ||
		len(tls.Certificates[0].Certificate) == 0 || len(tls.Certificates[0].Key) == 0 {
		t.Fatal("Hysteria2 TLS 必须是受控内联证书、TLS1.3 和 h3")
	}
	ss := profileInbound(t, values, "ss")
	var ssSettings ss2022Settings
	if err := json.Unmarshal(ss.Settings, &ssSettings); err != nil {
		t.Fatal(err)
	}
	if ss.Protocol != "shadowsocks" || ssSettings.Method != corev2.MethodAES128 || ssSettings.Password != string(keyBefore) ||
		ssSettings.Network != "tcp" || len(ssSettings.Users) != 2 || ssSettings.Users[0].Email != "qwq-user-s-alice" || ss.Stream != nil {
		t.Fatal("SS2022 必须使用独立服务端密钥、AES 多用户及显式网络")
	}
	for _, forbidden := range []string{"\"certificateFile\"", "\"keyFile\"", "\"allowInsecure\"", "\"clients\"", "sec_", "certbind_fixture", "fixture-policy-v2"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("原生配置不能携带 %s", forbidden)
		}
	}
	after, err := json.Marshal(intent)
	if err != nil || !bytes.Equal(before, after) || !bytes.Equal(authBefore, materials.Profiles["h2"].Hysteria2.Auth["h-alice"]) ||
		!bytes.Equal(keyBefore, materials.Profiles["ss"].Shadowsocks2022.ServerKey) {
		t.Fatal("纯渲染不能修改配置或调用方材料")
	}
	slices.Reverse(intent.Profiles)
	for index := range intent.Profiles {
		slices.Reverse(intent.Profiles[index].Users)
	}
	again, err := RenderV2(intent, materials, options)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("profile 或用户顺序改变了原生候选")
	}
}

func TestRenderV2DisabledProfilesRemainValidated(t *testing.T) {
	intent, materials, options := v2Fixture(t)
	disabled := false
	intent.Profiles[1].Enabled = &disabled
	raw, err := RenderV2(intent, materials, options)
	if err != nil || len(decodeV2Inbounds(t, raw)) != 3 {
		t.Fatal("停用 profile 不能创建业务监听")
	}
	materials.Profiles["h2"].Hysteria2.TLS.Generation = 0
	requireV2Rejected(t, intent, materials, options)
	materials.Profiles["h2"].Hysteria2.TLS.Generation = 2
	intent.Enabled = &disabled
	raw, err = RenderV2(intent, materials, options)
	if err != nil || len(decodeV2Inbounds(t, raw)) != 3 {
		t.Fatal("顶层停用仍需保留已启用 profiles 的完整预检")
	}
}

// ---- 密钥、认证、绑定与真实证书拒绝路径 ------------------------------------

func TestRenderV2RejectsHysteriaMaterialBoundaries(t *testing.T) {
	changes := map[string]func(*HysteriaMaterials, *V2Options){
		"missing-auth":          func(m *HysteriaMaterials, _ *V2Options) { delete(m.Auth, "h-alice") },
		"extra-auth":            func(m *HysteriaMaterials, _ *V2Options) { m.Auth["other"] = []byte("fixture-other-hysteria-auth") },
		"duplicate-auth":        func(m *HysteriaMaterials, _ *V2Options) { m.Auth["h-bob"] = bytes.Clone(m.Auth["h-alice"]) },
		"invalid-auth":          func(m *HysteriaMaterials, _ *V2Options) { m.Auth["h-alice"] = []byte("CANARY\x00") },
		"short-auth":            func(m *HysteriaMaterials, _ *V2Options) { m.Auth["h-alice"] = []byte("short") },
		"long-auth":             func(m *HysteriaMaterials, _ *V2Options) { m.Auth["h-alice"] = bytes.Repeat([]byte("x"), 257) },
		"wrong-binding":         func(m *HysteriaMaterials, _ *V2Options) { m.TLS.BindingRef = "other_binding" },
		"missing-generation":    func(m *HysteriaMaterials, _ *V2Options) { m.TLS.Generation = 0 },
		"missing-policy":        func(m *HysteriaMaterials, _ *V2Options) { m.TLS.PolicyRevision = "" },
		"wrong-sans":            func(m *HysteriaMaterials, _ *V2Options) { m.TLS.SANs = []string{"other.example.com"} },
		"missing-roots":         func(m *HysteriaMaterials, _ *V2Options) { m.TLS.Roots = nil },
		"wrong-roots":           func(m *HysteriaMaterials, _ *V2Options) { m.TLS.Roots = x509.NewCertPool() },
		"not-yet-valid":         func(_ *HysteriaMaterials, o *V2Options) { o.Now = o.Now.Add(-2 * time.Hour) },
		"expired":               func(_ *HysteriaMaterials, o *V2Options) { o.Now = o.Now.Add(91 * 24 * time.Hour) },
		"missing-time":          func(_ *HysteriaMaterials, o *V2Options) { o.Now = time.Time{} },
		"test-purpose-mismatch": func(m *HysteriaMaterials, _ *V2Options) { m.TLS.Purpose = tlsmgr.TestServerTLS },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			intent, materials, options := v2Fixture(t)
			change(materials.Profiles["h2"].Hysteria2, &options)
			requireV2Rejected(t, intent, materials, options)
		})
	}
	intent, materials, options := v2Fixture(t)
	intent.Profiles[1].Hysteria2.TLS.ServerName = "other.example.com"
	requireV2Rejected(t, intent, materials, options)
}

func TestRenderV2RejectsPrivateKeyMismatch(t *testing.T) {
	intent, materials, options := v2Fixture(t)
	other, err := testsupport.SignedCertificate(options.Now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Clear()
	h2 := materials.Profiles["h2"].Hysteria2
	chain := h2.TLS.Material.CertificatePEM()
	defer clear(chain)
	h2.TLS.Material.Clear()
	h2.TLS.Material, err = tlsmgr.NewMaterial(chain, other.Key)
	if err != nil {
		t.Fatal(err)
	}
	requireV2Rejected(t, intent, materials, options)
}

func TestRenderV2TestCertificatesRequirePrivatePermission(t *testing.T) {
	intent, materials, options := v2Fixture(t)
	h2 := materials.Profiles["h2"].Hysteria2
	h2.TLS.Material.Clear()
	var err error
	h2.TLS.Material, err = tlsmgr.GenerateTestMaterial(options.Now, h2.TLS.SANs)
	if err != nil {
		t.Fatal(err)
	}
	h2.TLS.Purpose, h2.TLS.Trust, h2.TLS.Roots = tlsmgr.TestServerTLS, tlsmgr.TestTrust, nil
	requireV2Rejected(t, intent, materials, options)
	options.PermitTestCertificates = true
	if _, err := RenderV2(intent, materials, options); err != nil {
		t.Fatal("明确宿主测试授权应允许受控测试材料")
	}
}

func TestRenderV2ShadowsocksKeyAndNetworkBoundaries(t *testing.T) {
	for _, method := range []string{corev2.MethodAES128, corev2.MethodAES256} {
		t.Run(method, func(t *testing.T) {
			intent, materials, options := v2Fixture(t)
			length := 16
			if method == corev2.MethodAES256 {
				length = 32
			}
			ss := materials.Profiles["ss"].Shadowsocks2022
			intent.Profiles[2].Shadowsocks2022.Method = method
			intent.Profiles[2].Shadowsocks2022.UDP = true
			ss.ServerKey, ss.PSKs["s-alice"], ss.PSKs["s-bob"] = testPSK(1, length), testPSK(2, length), testPSK(3, length)
			raw, err := RenderV2(intent, materials, options)
			if err != nil {
				t.Fatal(err)
			}
			inbound := profileInbound(t, decodeV2Inbounds(t, raw), "ss")
			if !bytes.Contains(inbound.Settings, []byte(`"network": "tcp,udp"`)) {
				t.Fatal("UDP 必须是明确的独立选择")
			}
			for _, bad := range [][]byte{[]byte("CANARY_NOT_BASE64"), testPSK(4, length-1), testPSK(4, length+1),
				[]byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, length))), append(testPSK(4, length), '\n')} {
				ss.PSKs["s-alice"] = bad
				requireV2Rejected(t, intent, materials, options)
			}
			ss.PSKs["s-alice"] = bytes.Clone(ss.PSKs["s-bob"])
			requireV2Rejected(t, intent, materials, options)
			ss.PSKs["s-alice"] = bytes.Clone(ss.ServerKey)
			requireV2Rejected(t, intent, materials, options)
			ss.PSKs["s-alice"] = testPSK(2, length)
			ss.ServerKey = []byte("CANARY_SERVER_KEY")
			requireV2Rejected(t, intent, materials, options)
		})
	}
}

func TestRenderV2MaterialClearAndFormatting(t *testing.T) {
	_, materials, _ := v2Fixture(t)
	vless := materials.Profiles["main"].VLESS
	h2 := materials.Profiles["h2"].Hysteria2
	ss := materials.Profiles["ss"].Shadowsocks2022
	key, auth, psk := vless.PrivateKey, h2.Auth["h-alice"], ss.ServerKey
	for _, value := range []any{materials, materials.Profiles["h2"], h2, h2.TLS, ss} {
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("私有材料不能通过 JSON 自动展开")
		}
		formatted := fmt.Sprintf("%v %#v", value, value)
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, "fixture-hysteria") || strings.Contains(formatted, string(psk)) {
			t.Fatal("材料默认格式必须脱敏")
		}
	}
	materials.Clear()
	if len(materials.Profiles) != 0 || len(h2.Auth) != 0 || len(ss.PSKs) != 0 || len(ss.ServerKey) != 0 ||
		!bytes.Equal(key, make([]byte, len(key))) || !bytes.Equal(auth, make([]byte, len(auth))) || !bytes.Equal(psk, make([]byte, len(psk))) ||
		len(h2.TLS.Material.PrivateKeyPEM()) != 0 {
		t.Fatal("材料清理必须清除底层短期缓冲和映射")
	}
}
