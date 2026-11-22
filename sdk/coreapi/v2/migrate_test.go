// SPDX-License-Identifier: Apache-2.0

package coreapi

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	v1 "github.com/qwq-panel/qwq/sdk/coreapi"
)

func legacyIntent(t *testing.T) *v1.Intent {
	t.Helper()
	profile := validIntent(t).Profiles[0]
	out := &v1.Intent{
		SchemaVersion: "1", Enabled: boolValue(true),
		Inbound: &v1.Inbound{
			ID: profile.ID, Listen: profile.Listen, Port: profile.Port,
			Protocol: profile.Protocol, Transport: profile.VLESS.Transport,
			Flow: profile.VLESS.Flow, Security: profile.VLESS.Security,
			Users: []v1.User{{ID: profile.Users[0].ID, UUID: *profile.Users[0].UUID}},
		},
		Outbound: &v1.Outbound{Type: "direct"},
	}
	if err := v1.Validate(out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFromV1PreservesIdentityAndDisabledBehavior(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		source := legacyIntent(t)
		source.Enabled = boolValue(enabled)
		// v1 的入站与用户命名空间独立；合法同名配置也必须能迁移。
		source.Inbound.ID = source.Inbound.Users[0].ID
		got, err := FromV1(source)
		if err != nil || Validate(got) != nil {
			t.Fatal(err)
		}
		if got.SchemaVersion != "2" || *got.Enabled != enabled || len(got.Profiles) != 1 || !*got.Profiles[0].Enabled {
			t.Fatal("迁移改变了版本或启停语义")
		}
		profile := got.Profiles[0]
		if profile.ID != source.Inbound.ID || profile.Listen != source.Inbound.Listen || profile.Port != source.Inbound.Port || profile.Users[0].ID != source.Inbound.Users[0].ID {
			t.Fatal("迁移改变了稳定 ID 或外部监听")
		}
		if !reflect.DeepEqual(profile.VLESS.Security, source.Inbound.Security) || *profile.Users[0].UUID != source.Inbound.Users[0].UUID {
			t.Fatal("迁移改变了 REALITY 或 secret 身份")
		}
		oldTag, err := v1.InboundTag(source.Inbound.ID)
		if err != nil {
			t.Fatal(err)
		}
		newTag, err := v1.InboundTag(profile.ID)
		if err != nil || oldTag != newTag {
			t.Fatal("原生入站 tag 改变")
		}
		oldEmail, err := v1.UserEmail(source.Inbound.Users[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		newEmail, err := v1.UserEmail(profile.Users[0].ID)
		if err != nil || oldEmail != newEmail {
			t.Fatal("原生用户统计身份改变")
		}
	}
}

func TestFromV1CreatesIndependentCandidate(t *testing.T) {
	source := legacyIntent(t)
	before, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromV1(source)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled == source.Enabled || got.Profiles[0].Enabled == source.Enabled || got.Profiles[0].VLESS.Security == source.Inbound.Security || got.Profiles[0].Users[0].UUID == &source.Inbound.Users[0].UUID {
		t.Fatal("迁移共享了源对象指针")
	}
	*got.Enabled = false
	got.Profiles[0].ID = "changed"
	got.Profiles[0].VLESS.Security.ServerNames[0] = "changed.test"
	got.Profiles[0].VLESS.Security.ShortIDs[0] = "cd"
	got.Profiles[0].VLESS.Security.PrivateKey.ID = "changed"
	got.Profiles[0].Users[0].UUID.ID = "changed"
	got.Outbound.Type = "changed"
	after, err := json.Marshal(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("编辑迁移候选修改了原始 v1")
	}
}

func TestFromV1RejectsInvalidSource(t *testing.T) {
	got, err := FromV1(nil)
	requireViolation(t, err, "", "REQUIRED")
	if got != nil {
		t.Fatal("非法 v1 仍生成候选")
	}
	source := legacyIntent(t)
	source.SchemaVersion = "2"
	got, err = FromV1(source)
	requireViolation(t, err, "/schema_version", "VERSION")
	if got != nil {
		t.Fatal("错误版本被隐式迁移")
	}
}

func TestDecodersDoNotAutomaticallyMigrate(t *testing.T) {
	_, err := v1.Decode([]byte(fixtureJSON))
	requireViolation(t, err, "/profiles", "UNKNOWN_FIELD")
	data, err := json.Marshal(legacyIntent(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(data)
	requireViolation(t, err, "/inbound", "UNKNOWN_FIELD")
	versionOnly, err := Decode([]byte(strings.Replace(fixtureJSON, `"schema_version":"2"`, `"schema_version":"1"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, Validate(versionOnly), "/schema_version", "VERSION")
}
