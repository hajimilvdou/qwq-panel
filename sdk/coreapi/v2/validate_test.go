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

func TestValidateProtocolAndCredentialUnion(t *testing.T) {
	cases := []struct {
		name, pointer, code string
		change              func(*Intent)
	}{
		{"版本", "/schema_version", "VERSION", func(i *Intent) { i.SchemaVersion = "1" }},
		{"顶层 enabled", "/enabled", "REQUIRED", func(i *Intent) { i.Enabled = nil }},
		{"空 profiles", "/profiles", "SIZE", func(i *Intent) { i.Profiles = nil }},
		{"缺出站", "/outbound", "REQUIRED", func(i *Intent) { i.Outbound = nil }},
		{"任意出站", "/outbound/type", "ENUM", func(i *Intent) { i.Outbound.Type = "socks" }},
		{"非法 profile ID", "/profiles/0/id", "ID", func(i *Intent) { i.Profiles[0].ID = "../outside" }},
		{"重复 profile", "/profiles/1/id", "DUPLICATE", func(i *Intent) { i.Profiles[1].ID = i.Profiles[0].ID }},
		{"缺 profile enabled", "/profiles/0/enabled", "REQUIRED", func(i *Intent) { i.Profiles[0].Enabled = nil }},
		{"listen 域名", "/profiles/0/listen", "IP", func(i *Intent) { i.Profiles[0].Listen = "proxy.example.test" }},
		{"listen zone", "/profiles/0/listen", "IP", func(i *Intent) { i.Profiles[0].Listen = "fe80::1%eth0" }},
		{"特权端口", "/profiles/0/port", "RANGE", func(i *Intent) { i.Profiles[0].Port = 1023 }},
		{"端口超界", "/profiles/0/port", "RANGE", func(i *Intent) { i.Profiles[0].Port = 65536 }},
		{"协议大小写", "/profiles/0/protocol", "ENUM", func(i *Intent) { i.Profiles[0].Protocol = "VLESS" }},
		{"缺选定成员", "/profiles/0/vless", "REQUIRED", func(i *Intent) { i.Profiles[0].VLESS = nil }},
		{"混入空成员", "/profiles/0/hysteria2", "FORBIDDEN", func(i *Intent) { i.Profiles[0].Hysteria2 = &Hysteria2{} }},
		{"VLESS 不接受 TCP 别名", "/profiles/0/vless/transport", "ENUM", func(i *Intent) { i.Profiles[0].VLESS.Transport = "tcp" }},
		{"VLESS flow", "/profiles/0/vless/flow", "ENUM", func(i *Intent) { i.Profiles[0].VLESS.Flow = "" }},
		{"缺 REALITY", "/profiles/0/vless/security", "REQUIRED", func(i *Intent) { i.Profiles[0].VLESS.Security = nil }},
		{"REALITY mode", "/profiles/0/vless/security/mode", "ENUM", func(i *Intent) { i.Profiles[0].VLESS.Security.Mode = "tls" }},
		{"REALITY 目标 URL", "/profiles/0/vless/security/target", "TARGET", func(i *Intent) { i.Profiles[0].VLESS.Security.Target = "https://example.test:443/path" }},
		{"REALITY 目标与 SNI", "/profiles/0/vless/security/server_names", "TARGET_SNI", func(i *Intent) { i.Profiles[0].VLESS.Security.ServerNames = []string{"other.test"} }},
		{"REALITY short ID 按字节去重", "/profiles/0/vless/security/short_ids/1", "DUPLICATE", func(i *Intent) { i.Profiles[0].VLESS.Security.ShortIDs = []string{"ab", "AB"} }},
		{"缺 VLESS UUID", "/profiles/0/users/0/uuid", "REQUIRED", func(i *Intent) { i.Profiles[0].Users[0].UUID = nil }},
		{"混入 VLESS auth", "/profiles/0/users/0/auth", "FORBIDDEN", func(i *Intent) { i.Profiles[0].Users[0].Auth = i.Profiles[0].Users[0].UUID }},
		{"跨 profile 用户重复", "/profiles/2/users/0/id", "DUPLICATE", func(i *Intent) { i.Profiles[2].Users[0].ID = i.Profiles[1].Users[0].ID }},
		{"空用户", "/profiles/0/users", "SIZE", func(i *Intent) { i.Profiles[0].Users = nil }},
		{"非法用户 ID", "/profiles/0/users/0/id", "ID", func(i *Intent) { i.Profiles[0].Users[0].ID = "alice@example.test" }},
		{"缺 H2 TLS", "/profiles/1/hysteria2/tls", "REQUIRED", func(i *Intent) { i.Profiles[1].Hysteria2.TLS = nil }},
		{"绑定路径", "/profiles/1/hysteria2/tls/binding_ref", "BINDING_REF", func(i *Intent) { i.Profiles[1].Hysteria2.TLS.BindingRef = "../../key" }},
		{"空绑定", "/profiles/1/hysteria2/tls/binding_ref", "BINDING_REF", func(i *Intent) { i.Profiles[1].Hysteria2.TLS.BindingRef = "" }},
		{"绑定长度", "/profiles/1/hysteria2/tls/binding_ref", "BINDING_REF", func(i *Intent) { i.Profiles[1].Hysteria2.TLS.BindingRef = strings.Repeat("a", 129) }},
		{"绑定 Unicode", "/profiles/1/hysteria2/tls/binding_ref", "BINDING_REF", func(i *Intent) { i.Profiles[1].Hysteria2.TLS.BindingRef = "证书" }},
		{"H2 通配 SNI", "/profiles/1/hysteria2/tls/server_name", "DNS", func(i *Intent) { i.Profiles[1].Hysteria2.TLS.ServerName = "*.example.test" }},
		{"H2 IP SNI", "/profiles/1/hysteria2/tls/server_name", "DNS", func(i *Intent) { i.Profiles[1].Hysteria2.TLS.ServerName = "127.0.0.1" }},
		{"缺 H2 auth", "/profiles/1/users/0/auth", "REQUIRED", func(i *Intent) { i.Profiles[1].Users[0].Auth = nil }},
		{"H2 auth 引用溢出", "/profiles/1/users/0/auth/$secret", "SECRET_REF", func(i *Intent) { i.Profiles[1].Users[0].Auth.ID = "sec_80000000000000000000000000" }},
		{"H2 不接受 UUID", "/profiles/1/users/0/uuid", "FORBIDDEN", func(i *Intent) { i.Profiles[1].Users[0].UUID = i.Profiles[1].Users[0].Auth }},
		{"旧 SS 方法", "/profiles/2/shadowsocks2022/method", "ENUM", func(i *Intent) { i.Profiles[2].Shadowsocks2022.Method = "aes-256-gcm" }},
		{"SS2022 多用户不支持 chacha", "/profiles/2/shadowsocks2022/method", "ENUM", func(i *Intent) { i.Profiles[2].Shadowsocks2022.Method = "2022-blake3-chacha20-poly1305" }},
		{"服务端 key 引用", "/profiles/2/shadowsocks2022/server_key/$secret", "SECRET_REF", func(i *Intent) { i.Profiles[2].Shadowsocks2022.ServerKey = SecretRef{} }},
		{"缺用户 PSK", "/profiles/2/users/0/psk", "REQUIRED", func(i *Intent) { i.Profiles[2].Users[0].PSK = nil }},
		{"缺混淆选择", "/profiles/2/shadowsocks2022/obfs", "REQUIRED", func(i *Intent) { i.Profiles[2].Shadowsocks2022.Obfs = nil }},
		{"任意 obfs", "/profiles/2/shadowsocks2022/obfs/mode", "ENUM", func(i *Intent) { i.Profiles[2].Shadowsocks2022.Obfs.Mode = "plugin" }},
		{"none 不接受 host", "/profiles/2/shadowsocks2022/obfs/host", "FORBIDDEN", func(i *Intent) { i.Profiles[2].Shadowsocks2022.Obfs.Host = "example.test" }},
		{"http 必须有 host", "/profiles/2/shadowsocks2022/obfs/host", "DNS", func(i *Intent) { i.Profiles[2].Shadowsocks2022.Obfs.Mode = ObfsHTTP }},
		{"tls host 不能是 URL", "/profiles/2/shadowsocks2022/obfs/host", "DNS", func(i *Intent) {
			i.Profiles[2].Shadowsocks2022.Obfs = &Obfs{Mode: ObfsTLS, Host: "https://example.test"}
		}},
		{"obfs 不包装 UDP", "/profiles/2/shadowsocks2022/udp", "FORBIDDEN", func(i *Intent) {
			i.Profiles[2].Shadowsocks2022.Obfs = &Obfs{Mode: ObfsHTTP, Host: "example.test"}
			i.Profiles[2].Shadowsocks2022.UDP = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intent := validIntent(t)
			tc.change(intent)
			requireViolation(t, Validate(intent), tc.pointer, tc.code)
		})
	}
	requireViolation(t, Validate(nil), "", "REQUIRED")
}

func TestValidateProfileAndGlobalUserLimits(t *testing.T) {
	base := validIntent(t).Profiles[0]
	ref := *base.Users[0].UUID
	intent := &Intent{SchemaVersion: "2", Enabled: boolValue(true), Outbound: &Outbound{Type: "direct"}}
	for profileIndex := range MaxProfiles {
		profile := base
		profile.ID = fmt.Sprintf("p%d", profileIndex)
		profile.Listen = "::"
		profile.Port = 1024 + profileIndex
		profile.Users = make([]User, MaxUsers/MaxProfiles)
		for userIndex := range profile.Users {
			profile.Users[userIndex] = User{ID: fmt.Sprintf("u%d", profileIndex*len(profile.Users)+userIndex), UUID: &ref}
		}
		intent.Profiles = append(intent.Profiles, profile)
	}
	if err := Validate(intent); err != nil {
		t.Fatal("8 profiles、256 用户或最低端口被拒绝")
	}
	intent.Profiles[0].Port = 65535
	intent.Profiles[0].ID = strings.Repeat("a", 32)
	intent.Profiles[0].Enabled = boolValue(false)
	intent.Enabled = boolValue(false)
	if err := Validate(intent); err != nil {
		t.Fatal("停用完整快照、最大 ID 或最高端口被拒绝")
	}
	intent.Profiles[0].Users = append(intent.Profiles[0].Users, User{ID: "extra", UUID: &ref})
	requireViolation(t, Validate(intent), "/profiles", "SIZE")
	intent.Profiles[0].Users = intent.Profiles[0].Users[:len(intent.Profiles[0].Users)-1]
	intent.Profiles = append(intent.Profiles, base)
	requireViolation(t, Validate(intent), "/profiles", "SIZE")
}

func TestValidateDisabledStillRequiresCompleteMaterial(t *testing.T) {
	intent := validIntent(t)
	intent.Enabled = boolValue(false)
	intent.Profiles[1].Enabled = boolValue(false)
	intent.Profiles[1].Users[0].Auth = nil
	requireViolation(t, Validate(intent), "/profiles/1/users/0/auth", "REQUIRED")
}

func TestValidateSSMethodsAndObfsModes(t *testing.T) {
	for _, method := range []string{MethodAES128, MethodAES256} {
		for _, mode := range []string{ObfsNone, ObfsHTTP, ObfsTLS} {
			intent := validIntent(t)
			ss := intent.Profiles[2].Shadowsocks2022
			ss.Method = method
			ss.Obfs = &Obfs{Mode: mode}
			if mode != ObfsNone {
				ss.Obfs.Host = "Obfs.Example.test."
			}
			if err := Validate(intent); err != nil {
				t.Fatalf("%s/%s 合法组合被拒绝：%v", method, mode, err)
			}
		}
	}
}

func TestValidateSingleProfileMaximumUsers(t *testing.T) {
	intent := validIntent(t)
	intent.Profiles = intent.Profiles[:1]
	ref := *intent.Profiles[0].Users[0].UUID
	intent.Profiles[0].Users = make([]User, MaxUsers)
	for index := range intent.Profiles[0].Users {
		intent.Profiles[0].Users[index] = User{ID: fmt.Sprintf("u%d", index), UUID: &ref}
	}
	intent.Profiles[0].VLESS.Security.ServerNames = make([]string, 8)
	intent.Profiles[0].VLESS.Security.ShortIDs = make([]string, 8)
	for index := range 8 {
		intent.Profiles[0].VLESS.Security.ServerNames[index] = fmt.Sprintf("s%d.example.test", index)
		intent.Profiles[0].VLESS.Security.ShortIDs[index] = fmt.Sprintf("%016x", index)
	}
	intent.Profiles[0].VLESS.Security.Target = "s0.example.test:443"
	if err := Validate(intent); err != nil {
		t.Fatal("单 profile 的 256 用户和 REALITY 数组上限被拒绝")
	}
	intent.Profiles[0].Users = append(intent.Profiles[0].Users, User{ID: "overflow", UUID: &ref})
	requireViolation(t, Validate(intent), "/profiles/0/users", "SIZE")
}

func TestValidateConcurrentAndImmutable(t *testing.T) {
	intent := validIntent(t)
	before, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 32 {
				if err := Validate(intent); err != nil {
					t.Error(err)
				}
				if _, err := Listeners(intent); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	after, err := json.Marshal(intent)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("校验或监听预演修改了共享快照")
	}
}

func TestValidateTrafficMarkBoundsAndUniqueness(t *testing.T) {
	intent := validIntent(t)
	intent.Profiles[0].Users[0].TrafficMark = MinTrafficMark
	if len(intent.Profiles) > 1 {
		intent.Profiles[1].Users[0].TrafficMark = MaxTrafficMark
	}
	if err := Validate(intent); err != nil {
		t.Fatalf("合法范围内的唯一 traffic_mark 不应被拒绝: %v", err)
	}

	outOfLow := validIntent(t)
	outOfLow.Profiles[0].Users[0].TrafficMark = MinTrafficMark - 1
	requireViolation(t, Validate(outOfLow), "/profiles/0/users/0/traffic_mark", "RANGE")

	outOfHigh := validIntent(t)
	outOfHigh.Profiles[0].Users[0].TrafficMark = MaxTrafficMark + 1
	requireViolation(t, Validate(outOfHigh), "/profiles/0/users/0/traffic_mark", "RANGE")

	dup := validIntent(t)
	if len(dup.Profiles) > 1 {
		dup.Profiles[0].Users[0].TrafficMark = MinTrafficMark + 1
		dup.Profiles[1].Users[0].TrafficMark = MinTrafficMark + 1
		requireViolation(t, Validate(dup), "/profiles/1/users/0/traffic_mark", "DUPLICATE")
	}
}
