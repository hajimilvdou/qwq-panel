// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"bytes"
	"testing"
	"time"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 原v1字节与显式单VLESS迁移保持同一原生行为 ========================

func TestRenderV2MigratedVLESSMatchesV1Golden(t *testing.T) {
	v1, secrets := fixture()
	v2, err := corev2.FromV1(v1)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{APISocket: "/tmp/qwq-test/api.sock"}
	want, err := Render(v1, secrets, options)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RenderV2(v2, V2Materials{Profiles: map[string]ProfileMaterials{"main": {VLESS: &secrets}}}, V2Options{Options: options, Now: time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("v2迁移改变了原v1原生配置: %v", err)
	}
}

func TestRenderV2RejectsWrongMaterialUnionAndMissingProfile(t *testing.T) {
	v1, secrets := fixture()
	v2, err := corev2.FromV1(v1)
	if err != nil {
		t.Fatal(err)
	}
	for _, material := range []V2Materials{{}, {Profiles: map[string]ProfileMaterials{"other": {VLESS: &secrets}}},
		{Profiles: map[string]ProfileMaterials{"main": {VLESS: &secrets, Shadowsocks2022: &SS2022Materials{}}}}} {
		if raw, err := RenderV2(v2, material, V2Options{Options: Options{APISocket: "/tmp/qwq-test/api.sock"}, Now: time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)}); err == nil || len(raw) != 0 {
			t.Fatal("错误材料联合或缺profile材料仍输出原生配置")
		}
	}
}
