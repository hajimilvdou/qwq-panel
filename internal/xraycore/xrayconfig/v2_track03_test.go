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

func TestRenderV2WARPOutboundAndPortBinding(t *testing.T) {
	intent, materials, options := v2Fixture(t)
	defer materials.Clear()

	// Valid 32-byte base64 WireGuard private & peer public keys.
	privKey := []byte("gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFA=")
	peerPub := "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	targetProfileID := intent.Profiles[0].ID

	intent.WARP = &corev2.WARPOutbound{
		Enabled:         true,
		PrivateKey:      corev2.SecretRef{ID: "sec_0123456789abcdefghjkmnpqrs"},
		PeerPublicKey:   peerPub,
		Endpoint:        "engage.cloudflareclient.com:2408",
		AddressV4:       "172.16.0.2/32",
		AddressV6:       "2606:4700:110:8a00::2/128",
		Reserved:        []int{12, 34, 56},
		MTU:             1280,
		RoutingMode:     corev2.WARPRoutingDomains,
		BoundProfileIDs: []string{targetProfileID},
		Domains:         []string{"openai.com", "netflix.com"},
	}
	materials.WARP = &WARPMaterials{PrivateKey: append([]byte(nil), privKey...)}

	raw, err := RenderV2(intent, materials, options)
	if err != nil {
		t.Fatalf("RenderV2 with WARP: %v", err)
	}
	var doc struct {
		Inbounds []struct {
			Tag      string          `json:"tag"`
			Sniffing *nativeSniffing `json:"sniffing"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag      string         `json:"tag"`
			Protocol string         `json:"protocol"`
			Settings map[string]any `json:"settings"`
		} `json:"outbounds"`
		Routing struct {
			Rules []struct {
				InboundTag  []string `json:"inboundTag"`
				Domain      []string `json:"domain"`
				IP          []string `json:"ip"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	var foundWARP, foundPrivateBlackhole, foundBadPrivateDirect, foundDomainRule, foundSniff bool
	blackholeIdx := -1
	warpRuleIdx := -1
	for _, in := range doc.Inbounds {
		if in.Sniffing != nil && in.Sniffing.Enabled {
			foundSniff = true
		}
	}
	for _, ob := range doc.Outbounds {
		if ob.Tag == "qwq-warp" && ob.Protocol == "wireguard" {
			if ob.Settings["secretKey"] == string(privKey) && ob.Settings["kernelMode"] == false {
				foundWARP = true
			}
		}
	}
	wantTag, _ := corev1.InboundTag(targetProfileID)
	for idx, r := range doc.Routing.Rules {
		if r.OutboundTag == "qwq-direct" && len(r.IP) > 0 {
			foundBadPrivateDirect = true
		}
		if r.OutboundTag == "blocked-private" && len(r.IP) >= 10 {
			foundPrivateBlackhole = true
			blackholeIdx = idx
		}
		if r.OutboundTag == "qwq-warp" && len(r.Domain) == 2 && len(r.InboundTag) == 1 && r.InboundTag[0] == wantTag {
			foundDomainRule = true
			warpRuleIdx = idx
		}
	}
	if !foundWARP || !foundPrivateBlackhole || foundBadPrivateDirect || !foundDomainRule || !foundSniff || blackholeIdx < 0 || warpRuleIdx < 0 || blackholeIdx >= warpRuleIdx {
		t.Fatalf("missing or misordered WARP/blackhole artifacts: warp=%v privBlackhole=%v badPrivDirect=%v domainRule=%v sniff=%v bhIdx=%d warpIdx=%d",
			foundWARP, foundPrivateBlackhole, foundBadPrivateDirect, foundDomainRule, foundSniff, blackholeIdx, warpRuleIdx)
	}
}

func TestRenderV2DeduplicatesMarkedOutboundsAcrossProfiles(t *testing.T) {
	intent, materials, options := v2Fixture(t)
	defer materials.Clear()
	// 共享用户跨两个 profile 使用相同 TrafficMark，不能生成重复 direct-mark Tag
	sharedUserID := intent.Profiles[0].Users[0].ID
	intent.Profiles[0].Users[0].TrafficMark = 0x5105
	intent.Profiles[1].Users[0].ID = sharedUserID
	intent.Profiles[1].Users[0].TrafficMark = 0x5105
	materials.Profiles["h2"].Hysteria2.Auth[sharedUserID] = materials.Profiles["h2"].Hysteria2.Auth["h-bob"]
	delete(materials.Profiles["h2"].Hysteria2.Auth, "h-bob")

	raw, err := RenderV2(intent, materials, options)
	if err != nil {
		t.Fatalf("RenderV2 failed: %v", err)
	}
	var doc struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
		Routing struct {
			Rules []struct {
				User        []string `json:"user"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	markObCount := 0
	for _, ob := range doc.Outbounds {
		if ob.Tag == "direct-mark-20741" {
			markObCount++
		}
	}
	markRuleCount := 0
	for _, r := range doc.Routing.Rules {
		if r.OutboundTag == "direct-mark-20741" {
			markRuleCount++
		}
	}
	if markObCount != 1 || markRuleCount != 1 {
		t.Fatalf("跨 profile 共享 TrafficMark 未去重: obCount=%d ruleCount=%d", markObCount, markRuleCount)
	}
}
