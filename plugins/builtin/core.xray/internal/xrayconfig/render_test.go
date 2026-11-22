// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/sdk/coreapi"
)

// fixture 使用显眼的假引用、固定测试字节和测试 UUID；不对应任何宿主秘密。
func fixture() (*coreapi.Intent, Secrets) {
	enabled := true
	intent := &coreapi.Intent{SchemaVersion: "1", Enabled: &enabled,
		Inbound: &coreapi.Inbound{ID: "main", Listen: "127.0.0.1", Port: 10443, Protocol: "vless", Transport: "raw", Flow: "xtls-rprx-vision",
			Security: &coreapi.Reality{Mode: "reality", Target: "127.0.0.1:11443", ServerNames: []string{"example.test"}, PrivateKey: coreapi.SecretRef{ID: "sec_00000000000000000000000000"}, ShortIDs: []string{"0123456789abcdef"}},
			Users:    []coreapi.User{{ID: "bob", UUID: coreapi.SecretRef{ID: "sec_00000000000000000000000002"}}, {ID: "alice", UUID: coreapi.SecretRef{ID: "sec_00000000000000000000000001"}}}},
		Outbound: &coreapi.Outbound{Type: "direct"},
	}
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	secrets := Secrets{PrivateKey: []byte(key), UUIDs: map[string][]byte{
		"alice": []byte("00000000-0000-4000-8000-000000000001"),
		"bob":   []byte("00000000-0000-4000-8000-000000000002"),
	}}
	return intent, secrets
}

func TestRenderNativeGoldenAndDeterminism(t *testing.T) {
	intent, material := fixture()
	before, _ := json.Marshal(intent)
	result, err := Render(intent, material, Options{APISocket: "/tmp/qwq-test/api.sock"})
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("testdata/vless.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, golden) {
		t.Fatal("原生渲染与锁定版本黄金配置不同")
	}
	after, _ := json.Marshal(intent)
	if !bytes.Equal(before, after) {
		t.Fatal("渲染修改了 desired")
	}
	slices.Reverse(intent.Inbound.Users)
	*intent.Enabled = false
	again, err := Render(intent, material, Options{APISocket: "/tmp/qwq-test/api.sock"})
	if err != nil || !bytes.Equal(result, again) {
		t.Fatal("用户顺序或停止状态改变了预检配置")
	}
	for _, forbidden := range []string{"HandlerService", "\"clients\"", "\"dest\"", "$secret", "sec_", "api.listen", "sockopt"} {
		if bytes.Contains(result, []byte(forbidden)) {
			t.Fatalf("原生配置包含禁止项 %s", forbidden)
		}
	}
}

func TestInvalidMaterialAndSocketFailClosed(t *testing.T) {
	for _, change := range []func(*coreapi.Intent, *Secrets){
		func(_ *coreapi.Intent, s *Secrets) { s.PrivateKey = []byte("CANARY_PRIVATE_MATERIAL") },
		func(_ *coreapi.Intent, s *Secrets) { s.UUIDs["alice"] = []byte("CANARY_UUID_MATERIAL") },
		func(_ *coreapi.Intent, s *Secrets) { delete(s.UUIDs, "alice") },
		func(_ *coreapi.Intent, s *Secrets) { s.UUIDs["bob"] = slices.Clone(s.UUIDs["alice"]) },
		func(i *coreapi.Intent, _ *Secrets) { i.Outbound.Type = "untrusted" },
	} {
		intent, material := fixture()
		change(intent, &material)
		result, err := Render(intent, material, Options{APISocket: "/tmp/qwq-test/api.sock"})
		if err == nil || len(result) != 0 || strings.Contains(err.Error(), "CANARY") || strings.Contains(fmt.Sprintf("%v %#v", material, material), "CANARY") {
			t.Fatal("无效材料未脱敏拒绝")
		}
	}
	for _, socket := range []string{"@api.sock", "relative/api.sock", "/tmp/../api.sock", "/tmp/api.sock,0666", "/tmp/other.sock", "/tmp/" + strings.Repeat("x", 100) + "/api.sock"} {
		intent, material := fixture()
		if _, err := Render(intent, material, Options{APISocket: socket}); err != ErrSocket {
			t.Fatal("不安全 API 路径未拒绝")
		}
	}
}

func TestMaterialClear(t *testing.T) {
	_, material := fixture()
	key, uuid := material.PrivateKey, material.UUIDs["alice"]
	material.Clear()
	if len(material.PrivateKey) != 0 || len(material.UUIDs) != 0 || !bytes.Equal(key, make([]byte, len(key))) || !bytes.Equal(uuid, make([]byte, len(uuid))) {
		t.Fatal("材料缓冲未清理")
	}
}
