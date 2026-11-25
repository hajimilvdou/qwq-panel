// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 原v1迁移保留入站与策略，并默认注入私网黑洞防线 ========================

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
	if err != nil {
		t.Fatalf("RenderV2 迁移失败: %v", err)
	}
	var wantDoc, gotDoc struct {
		Log       json.RawMessage `json:"log"`
		API       json.RawMessage `json:"api"`
		Policy    json.RawMessage `json:"policy"`
		Inbounds  json.RawMessage `json:"inbounds"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
		Routing struct {
			DomainStrategy string `json:"domainStrategy"`
			Rules          []struct {
				InboundTag  []string `json:"inboundTag"`
				Domain      []string `json:"domain"`
				IP          []string `json:"ip"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(want, &wantDoc); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &gotDoc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDoc.Log, wantDoc.Log) || !bytes.Equal(gotDoc.API, wantDoc.API) ||
		!bytes.Equal(gotDoc.Policy, wantDoc.Policy) || !bytes.Equal(gotDoc.Inbounds, wantDoc.Inbounds) {
		t.Fatal("v2 迁移改变了原 v1 入站/API/日志/策略配置")
	}
	if gotDoc.Routing.DomainStrategy != "IPIfNonMatch" {
		t.Fatalf("v2 路由策略应为 IPIfNonMatch，实际 %q", gotDoc.Routing.DomainStrategy)
	}
	hasBlackhole := false
	for _, ob := range gotDoc.Outbounds {
		if ob.Tag == "blocked-private" && ob.Protocol == "blackhole" {
			hasBlackhole = true
		}
	}
	if !hasBlackhole || len(gotDoc.Routing.Rules) < 3 ||
		gotDoc.Routing.Rules[0].OutboundTag != "qwq-api" ||
		gotDoc.Routing.Rules[1].OutboundTag != "blocked-private" ||
		gotDoc.Routing.Rules[2].OutboundTag != "blocked-private" {
		t.Fatalf("v2 未正确在 qwq-api 之后置顶私网黑洞防线: rules=%+v", gotDoc.Routing.Rules)
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
