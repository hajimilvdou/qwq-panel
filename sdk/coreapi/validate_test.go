// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func validIntent(t *testing.T) *Intent {
	t.Helper()
	intent, err := Decode([]byte(testJSON))
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestValidateRules(t *testing.T) {
	cases := []struct {
		name, pointer string
		change        func(*Intent)
	}{
		{"版本", "/schema_version", func(i *Intent) { i.SchemaVersion = "2" }},
		{"缺 enabled", "/enabled", func(i *Intent) { i.Enabled = nil }},
		{"缺入站", "/inbound", func(i *Intent) { i.Inbound = nil }},
		{"缺出站", "/outbound", func(i *Intent) { i.Outbound = nil }},
		{"非法入站 ID", "/inbound/id", func(i *Intent) { i.Inbound.ID = "../../outside" }},
		{"ID 长度", "/inbound/id", func(i *Intent) { i.Inbound.ID = strings.Repeat("a", 33) }},
		{"非法监听地址", "/inbound/listen", func(i *Intent) { i.Inbound.Listen = "999.1.1.1" }},
		{"监听不接受 DNS", "/inbound/listen", func(i *Intent) { i.Inbound.Listen = "example.com" }},
		{"监听不接受 zone", "/inbound/listen", func(i *Intent) { i.Inbound.Listen = "fe80::1%eth0" }},
		{"特权端口", "/inbound/port", func(i *Intent) { i.Inbound.Port = 1023 }},
		{"端口超界", "/inbound/port", func(i *Intent) { i.Inbound.Port = 65536 }},
		{"协议", "/inbound/protocol", func(i *Intent) { i.Inbound.Protocol = "vmess" }},
		{"传输", "/inbound/transport", func(i *Intent) { i.Inbound.Transport = "tcp" }},
		{"flow", "/inbound/flow", func(i *Intent) { i.Inbound.Flow = "other" }},
		{"缺 security", "/inbound/security", func(i *Intent) { i.Inbound.Security = nil }},
		{"security mode", "/inbound/security/mode", func(i *Intent) { i.Inbound.Security.Mode = "tls" }},
		{"缺目标端口", "/inbound/security/target", func(i *Intent) { i.Inbound.Security.Target = "example.com" }},
		{"目标 URL", "/inbound/security/target", func(i *Intent) { i.Inbound.Security.Target = "https://example.com:443/path" }},
		{"目标用户信息", "/inbound/security/target", func(i *Intent) { i.Inbound.Security.Target = "user@example.com:443" }},
		{"非法目标 IP", "/inbound/security/target", func(i *Intent) { i.Inbound.Security.Target = "999.1.1.1:443" }},
		{"目标 zone", "/inbound/security/target", func(i *Intent) { i.Inbound.Security.Target = "[fe80::1%eth0]:443" }},
		{"目标端口超界", "/inbound/security/target", func(i *Intent) { i.Inbound.Security.Target = "example.com:65536" }},
		{"目标端口非数字", "/inbound/security/target", func(i *Intent) { i.Inbound.Security.Target = "example.com:+443" }},
		{"空 server names", "/inbound/security/server_names", func(i *Intent) { i.Inbound.Security.ServerNames = nil }},
		{"server names 上限", "/inbound/security/server_names", func(i *Intent) { i.Inbound.Security.ServerNames = make([]string, 9) }},
		{"通配 server name", "/inbound/security/server_names/0", func(i *Intent) { i.Inbound.Security.ServerNames[0] = "*.example.com" }},
		{"非法 DNS", "/inbound/security/server_names/0", func(i *Intent) { i.Inbound.Security.ServerNames[0] = "-bad.example" }},
		{"DNS 上限", "/inbound/security/server_names/0", func(i *Intent) { i.Inbound.Security.ServerNames[0] = strings.Repeat("a", 64) + ".com" }},
		{"目标不在 SNI", "/inbound/security/server_names", func(i *Intent) { i.Inbound.Security.ServerNames[0] = "other.example" }},
		{"空 short IDs", "/inbound/security/short_ids", func(i *Intent) { i.Inbound.Security.ShortIDs = nil }},
		{"short IDs 上限", "/inbound/security/short_ids", func(i *Intent) { i.Inbound.Security.ShortIDs = make([]string, 9) }},
		{"short ID 非空", "/inbound/security/short_ids/0", func(i *Intent) { i.Inbound.Security.ShortIDs[0] = "" }},
		{"short ID 奇数", "/inbound/security/short_ids/0", func(i *Intent) { i.Inbound.Security.ShortIDs[0] = "abc" }},
		{"short ID 非 hex", "/inbound/security/short_ids/0", func(i *Intent) { i.Inbound.Security.ShortIDs[0] = "zz" }},
		{"short ID 过长", "/inbound/security/short_ids/0", func(i *Intent) { i.Inbound.Security.ShortIDs[0] = strings.Repeat("a", 18) }},
		{"重复 short ID", "/inbound/security/short_ids/1", func(i *Intent) { i.Inbound.Security.ShortIDs = []string{"ab", "AB"} }},
		{"缺秘密引用", "/inbound/security/private_key/$secret", func(i *Intent) { i.Inbound.Security.PrivateKey = SecretRef{} }},
		{"秘密引用长度", "/inbound/security/private_key/$secret", func(i *Intent) { i.Inbound.Security.PrivateKey.ID = "sec_example" }},
		{"秘密引用溢出", "/inbound/security/private_key/$secret", func(i *Intent) { i.Inbound.Security.PrivateKey.ID = "sec_80000000000000000000000000" }},
		{"引用不是 secret", "/inbound/security/private_key/$secret", func(i *Intent) { i.Inbound.Security.PrivateKey.ID = "usr_00000000000000000000000000" }},
		{"没有用户", "/inbound/users", func(i *Intent) { i.Inbound.Users = nil }},
		{"用户上限", "/inbound/users", func(i *Intent) { i.Inbound.Users = make([]User, 257) }},
		{"重复用户 ID", "/inbound/users/1/id", func(i *Intent) { i.Inbound.Users = append(i.Inbound.Users, i.Inbound.Users[0]) }},
		{"非法用户 ID", "/inbound/users/0/id", func(i *Intent) { i.Inbound.Users[0].ID = "alice@example.com" }},
		{"非法用户引用", "/inbound/users/0/uuid/$secret", func(i *Intent) { i.Inbound.Users[0].UUID.ID = "CANARY_SECRET" }},
		{"出站类型", "/outbound/type", func(i *Intent) { i.Outbound.Type = "socks" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intent := validIntent(t)
			tc.change(intent)
			assertPointer(t, Validate(intent), tc.pointer)
		})
	}
	assertPointer(t, Validate(nil), "")
}

func TestValidateMinimumMaximumAndDisabled(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		intent := validIntent(t)
		enabled := !disabled
		intent.Enabled = &enabled
		intent.Inbound.Listen = "::"
		intent.Inbound.Port = 1024
		intent.Inbound.Security.Target = "[2001:db8::1]:443"
		if err := Validate(intent); err != nil {
			t.Fatal(err)
		}
		intent.Inbound.Port = 65535
		intent.Inbound.ID = strings.Repeat("a", 32)
		intent.Inbound.Security.ServerNames = make([]string, 8)
		intent.Inbound.Security.ShortIDs = make([]string, 8)
		for n := range 8 {
			intent.Inbound.Security.ServerNames[n] = fmt.Sprintf("s%d.example.com", n)
			intent.Inbound.Security.ShortIDs[n] = fmt.Sprintf("%016x", n)
		}
		intent.Inbound.Users = make([]User, 256)
		for n := range intent.Inbound.Users {
			intent.Inbound.Users[n] = User{ID: fmt.Sprintf("user%d", n), UUID: SecretRef{ID: "sec_00000000000000000000000001"}}
		}
		if err := Validate(intent); err != nil {
			t.Fatal(err)
		}
	}
	intent := validIntent(t)
	intent.Inbound.Security.Target = "EXAMPLE.COM.:443"
	if err := Validate(intent); err != nil {
		t.Fatal(err)
	}
}

func TestStableTags(t *testing.T) {
	for _, tc := range []struct {
		fn     func(string) (string, error)
		prefix string
	}{{InboundTag, "qwq-in-"}, {UserEmail, "qwq-user-"}} {
		if got, err := tc.fn("alice"); err != nil || got != tc.prefix+"alice" {
			t.Fatalf("映射错误：%q，%v", got, err)
		}
		if _, err := tc.fn("../../outside"); err == nil {
			t.Fatal("自由文本进入了原生标识")
		}
	}
}

func TestValidateConcurrentAndImmutable(t *testing.T) {
	intent := validIntent(t)
	before, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 32 {
				if err := Validate(intent); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	after, err := json.Marshal(intent)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("校验修改了输入快照")
	}
}

func TestSharedRealityRulesPreserveV1Paths(t *testing.T) {
	intent := validIntent(t)
	if !ValidID(intent.Inbound.ID) || !ValidSecretRef(intent.Inbound.Users[0].UUID) || !ValidDNSName("EXAMPLE.COM.") {
		t.Fatal("公开纯规则与 v1 有效基线不一致")
	}
	if ValidID("../outside") || ValidSecretRef(SecretRef{ID: "CANARY"}) || ValidDNSName("*.example.com") {
		t.Fatal("公开纯规则扩大了 v1 允许范围")
	}
	assertPointer(t, ValidateReality(nil), "")
	intent.Inbound.Security.ShortIDs = []string{"ab", "AB"}
	assertPointer(t, ValidateReality(intent.Inbound.Security), "/short_ids/1")
	assertPointer(t, Validate(intent), "/inbound/security/short_ids/1")
}
