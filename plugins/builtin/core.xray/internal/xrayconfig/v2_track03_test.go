// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

func TestDeriveRealityPublicKeyDeterministic(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB64 := base64.RawURLEncoding.EncodeToString(priv.Bytes())
	wantPub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	got, err := DeriveRealityPublicKey(privB64)
	if err != nil {
		t.Fatalf("DeriveRealityPublicKey failed: %v", err)
	}
	if got != wantPub {
		t.Fatalf("public key mismatch: got %q want %q", got, wantPub)
	}
	if _, err := DeriveRealityPublicKey("not-valid-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if _, err := DeriveRealityPublicKey(base64.RawURLEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestAllocateObfsTargetsAvoidsCollisions(t *testing.T) {
	intent, _, _ := v2Fixture(t)
	intent.Profiles[0].Port = ObfsBridgePortBase
	intent.Profiles[2].Shadowsocks2022.Obfs = &corev2.Obfs{Mode: corev2.ObfsTLS, Host: "cdn.example.com"}

	targets := AllocateObfsTargets(intent)
	if len(targets) != 1 {
		t.Fatalf("expected 1 obfs target, got %d", len(targets))
	}
	target := targets[intent.Profiles[2].ID]
	if target.Listen != "127.0.0.1" || target.Port != ObfsBridgePortBase+1 {
		t.Fatalf("unexpected allocated target: %+v", target)
	}
}

func TestRenderV2TrafficMarkAndOutboundPolicy(t *testing.T) {
	intent, materials, options := v2Fixture(t)
	intent.Profiles[0].Users[0].TrafficMark = 0x5101
	options.OutboundPolicy = &OutboundPolicy{
		DefaultMode: FamilyPreferIPv6,
		BindIPv4:    "192.0.2.10",
		BindIPv6:    "2001:db8::10",
		Overrides: []DomainOutboundOverride{
			{DomainSuffix: ".example.cn", Mode: FamilyIPv4Only},
		},
	}

	raw, err := RenderV2(intent, materials, options)
	if err != nil {
		t.Fatalf("RenderV2 failed: %v", err)
	}
	var doc struct {
		Outbounds []struct {
			Tag         string         `json:"tag"`
			Protocol    string         `json:"protocol"`
			SendThrough string         `json:"sendThrough"`
			Settings    map[string]any `json:"settings"`
			Stream      *struct {
				Sockopt *struct {
					Mark uint32 `json:"mark"`
				} `json:"sockopt"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
		Routing struct {
			DomainStrategy string `json:"domainStrategy"`
			Rules          []struct {
				User        []string `json:"user"`
				Domain      []string `json:"domain"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	var foundMarkOutbound, foundDirectV4, foundMarkRule, foundDomainRule bool
	wantEmail, err := corev1.UserEmail(intent.Profiles[0].Users[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, ob := range doc.Outbounds {
		if ob.Tag == "direct-mark-20737" && ob.Stream != nil && ob.Stream.Sockopt != nil && ob.Stream.Sockopt.Mark == 0x5101 {
			foundMarkOutbound = true
		}
		if ob.Tag == "direct-v4" && ob.SendThrough == "192.0.2.10" && ob.Settings["domainStrategy"] == "UseIPv4" {
			foundDirectV4 = true
		}
	}
	for _, r := range doc.Routing.Rules {
		if r.OutboundTag == "direct-mark-20737" && len(r.User) == 1 && r.User[0] == wantEmail {
			foundMarkRule = true
		}
		if r.OutboundTag == "direct-v4" && len(r.Domain) == 1 && r.Domain[0] == "domain:example.cn" {
			foundDomainRule = true
		}
	}
	if !foundMarkOutbound || !foundDirectV4 || !foundMarkRule || !foundDomainRule {
		t.Fatalf("missing expected mark/policy artifacts: markOb=%v directV4=%v markRule=%v domainRule=%v",
			foundMarkOutbound, foundDirectV4, foundMarkRule, foundDomainRule)
	}
}
