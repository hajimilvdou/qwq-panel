// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== Core Intent v2 无秘密运行摘要 ========================

// PublicProfileSummary 是单个 v2 profile 的公开投影，不含任何秘密值或秘密引用 ID。
type PublicProfileSummary struct {
	ID         string   `json:"id"`
	Enabled    bool     `json:"enabled"`
	Listen     string   `json:"listen"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	ServerName string   `json:"server_name,omitempty"`
	BindingRef string   `json:"binding_ref,omitempty"`
	Method     string   `json:"method,omitempty"`
	ObfsMode   string   `json:"obfs_mode,omitempty"`
	UDP        bool     `json:"udp,omitempty"`
	UserIDs    []string `json:"user_ids"`
}

// V2IntentSummary 保存 v2 期望配置的公开投影与不可逆引用摘要，用于幂等判定与 Plan 预演。
type V2IntentSummary struct {
	SchemaVersion string                 `json:"schema_version"`
	OutboundType  string                 `json:"outbound_type"`
	Profiles      []PublicProfileSummary `json:"profiles"`
	RefsDigest    string                 `json:"refs_digest"`
}

// SummarizeV2 在纯校验后构造规范排序的 v2 摘要，顺序变化不影响等价判定。
func SummarizeV2(intent *corev2.Intent) (*V2IntentSummary, error) {
	if err := corev2.Validate(intent); err != nil {
		return nil, err
	}
	profiles := slices.Clone(intent.Profiles)
	slices.SortFunc(profiles, func(a, b corev2.Profile) int { return strings.Compare(a.ID, b.ID) })

	refsHash := sha256.New()
	_, _ = io.WriteString(refsHash, "v2\x00"+intent.Outbound.Type+"\x00")
	out := make([]PublicProfileSummary, 0, len(profiles))
	for _, p := range profiles {
		users := slices.Clone(p.Users)
		slices.SortFunc(users, func(a, b corev2.User) int { return strings.Compare(a.ID, b.ID) })
		userIDs := make([]string, 0, len(users))

		ps := PublicProfileSummary{
			ID:       p.ID,
			Enabled:  *p.Enabled,
			Listen:   p.Listen,
			Port:     p.Port,
			Protocol: p.Protocol,
		}
		_, _ = io.WriteString(refsHash, p.ID+"\x00"+p.Protocol+"\x00"+p.Listen+"\x00")
		if *p.Enabled {
			_, _ = io.WriteString(refsHash, "1\x00")
		} else {
			_, _ = io.WriteString(refsHash, "0\x00")
		}

		switch p.Protocol {
		case corev2.ProtocolVLESS:
			if p.VLESS != nil && p.VLESS.Security != nil {
				_, _ = io.WriteString(refsHash, p.VLESS.Security.Target+"\x00"+p.VLESS.Security.PrivateKey.ID+"\x00")
				sniList := slices.Clone(p.VLESS.Security.ServerNames)
				slices.Sort(sniList)
				for _, s := range sniList {
					_, _ = io.WriteString(refsHash, s+"\x00")
				}
				shortIDs := slices.Clone(p.VLESS.Security.ShortIDs)
				slices.Sort(shortIDs)
				for _, sid := range shortIDs {
					_, _ = io.WriteString(refsHash, sid+"\x00")
				}
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.UUID != nil {
					_, _ = io.WriteString(refsHash, u.UUID.ID+"\x00")
				}
			}
		case corev2.ProtocolHysteria2:
			if p.Hysteria2 != nil && p.Hysteria2.TLS != nil {
				ps.BindingRef = p.Hysteria2.TLS.BindingRef
				ps.ServerName = p.Hysteria2.TLS.ServerName
				_, _ = io.WriteString(refsHash, ps.BindingRef+"\x00"+ps.ServerName+"\x00")
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.Auth != nil {
					_, _ = io.WriteString(refsHash, u.Auth.ID+"\x00")
				}
			}
		case corev2.ProtocolShadowsocks2022:
			if p.Shadowsocks2022 != nil {
				ps.Method = p.Shadowsocks2022.Method
				ps.UDP = p.Shadowsocks2022.UDP
				_, _ = io.WriteString(refsHash, p.Shadowsocks2022.Method+"\x00"+p.Shadowsocks2022.ServerKey.ID+"\x00")
				if p.Shadowsocks2022.Obfs != nil {
					ps.ObfsMode = p.Shadowsocks2022.Obfs.Mode
					_, _ = io.WriteString(refsHash, p.Shadowsocks2022.Obfs.Mode+"\x00"+p.Shadowsocks2022.Obfs.Host+"\x00")
				}
			}
			for _, u := range users {
				userIDs = append(userIDs, u.ID)
				_, _ = io.WriteString(refsHash, u.ID+"\x00"+strconv.FormatUint(uint64(u.TrafficMark), 10)+"\x00")
				if u.PSK != nil {
					_, _ = io.WriteString(refsHash, u.PSK.ID+"\x00")
				}
			}
		}
		ps.UserIDs = userIDs
		out = append(out, ps)
	}

	return &V2IntentSummary{
		SchemaVersion: "2",
		OutboundType:  intent.Outbound.Type,
		Profiles:      out,
		RefsDigest:    "sha256:" + hex.EncodeToString(refsHash.Sum(nil)),
	}, nil
}

// AllUserIDs 返回全部 profile 的去重排序用户列表，供 Plan 差异计算使用。
func (s V2IntentSummary) AllUserIDs() []string {
	seen := make(map[string]struct{})
	ids := make([]string, 0)
	for _, p := range s.Profiles {
		for _, id := range p.UserIDs {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	return ids
}

// FindHysteriaProfile 按 profileID 与 bindingRef 查找对应的 Hysteria2 profile 摘要。
func (s V2IntentSummary) FindHysteriaProfile(profileID, bindingRef string) (PublicProfileSummary, bool) {
	for _, p := range s.Profiles {
		if p.Protocol == corev2.ProtocolHysteria2 && p.ID == profileID && p.BindingRef == bindingRef {
			return p, true
		}
	}
	return PublicProfileSummary{}, false
}

// Validate 约束持久化 v2 摘要的规范形状与界限。
func (s V2IntentSummary) Validate() error {
	if s.SchemaVersion != "2" || s.OutboundType != "direct" || len(s.Profiles) < 1 || len(s.Profiles) > corev2.MaxProfiles {
		return ErrCorrupt
	}
	if !ValidDigest(s.RefsDigest) {
		return ErrCorrupt
	}
	for idx, p := range s.Profiles {
		if idx > 0 && s.Profiles[idx-1].ID >= p.ID {
			return ErrCorrupt
		}
		if _, err := coreapi.InboundTag(p.ID); err != nil {
			return ErrCorrupt
		}
		if _, err := netip.ParseAddr(p.Listen); err != nil || p.Port < 1024 || p.Port > 65535 {
			return ErrCorrupt
		}
		switch p.Protocol {
		case corev2.ProtocolVLESS, corev2.ProtocolHysteria2, corev2.ProtocolShadowsocks2022:
		default:
			return ErrCorrupt
		}
		if p.Protocol == corev2.ProtocolHysteria2 && (p.BindingRef == "" || p.ServerName == "") {
			return ErrCorrupt
		}
		if len(p.UserIDs) < 1 || len(p.UserIDs) > corev2.MaxUsers || !slices.IsSorted(p.UserIDs) {
			return ErrCorrupt
		}
		for ui, uid := range p.UserIDs {
			if _, err := coreapi.UserEmail(uid); err != nil || (ui > 0 && p.UserIDs[ui-1] == uid) {
				return ErrCorrupt
			}
		}
	}
	return nil
}
