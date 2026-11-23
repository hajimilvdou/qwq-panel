// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/qwq-panel/qwq/sdk/coreapi"
)

// PublicIntentSummary 是可用于预演的公开投影，不包含认证材料或引用身份。
type PublicIntentSummary struct {
	InboundID    string   `json:"inbound_id"`
	Listen       string   `json:"listen"`
	Port         int      `json:"port"`
	Protocol     string   `json:"protocol"`
	Transport    string   `json:"transport"`
	Flow         string   `json:"flow"`
	SecurityMode string   `json:"security_mode"`
	Target       string   `json:"target"`
	ServerNames  []string `json:"server_names"`
	ShortIDCount int      `json:"short_id_count"`
	UserIDs      []string `json:"user_ids"`
	OutboundType string   `json:"outbound_type"`
}

// IntentSummary 用摘要比较引用集合，重启后的 Plan 也无需揭示秘密。
// 指纹仅保存在私有状态文件；对外只使用 PublicIntentSummary。
type IntentSummary struct {
	PublicIntentSummary
	PrivateKeyRefDigest string `json:"private_key_ref_digest"`
	UserRefsDigest      string `json:"user_refs_digest"`
	ShortIDsDigest      string `json:"short_ids_digest"`
}

// Summarize 在纯校验后构造有界摘要，用户顺序不影响引用集合身份。
func Summarize(intent *coreapi.Intent) (*IntentSummary, error) {
	if err := coreapi.Validate(intent); err != nil {
		return nil, err
	}
	inbound := intent.Inbound
	security := inbound.Security
	users := slices.Clone(inbound.Users)
	slices.SortFunc(users, func(a, b coreapi.User) int { return strings.Compare(a.ID, b.ID) })
	userIDs := make([]string, 0, len(users))
	userRefs := sha256.New()
	for _, user := range users {
		userIDs = append(userIDs, user.ID)
		_, _ = io.WriteString(userRefs, user.ID)
		_, _ = userRefs.Write([]byte{0})
		_, _ = io.WriteString(userRefs, user.UUID.ID)
		_, _ = userRefs.Write([]byte{0})
	}
	shortIDs := slices.Clone(security.ShortIDs)
	slices.Sort(shortIDs)
	shortRefs := sha256.New()
	for _, id := range shortIDs {
		_, _ = io.WriteString(shortRefs, id)
		_, _ = shortRefs.Write([]byte{0})
	}
	privateRef := sha256.Sum256([]byte(security.PrivateKey.ID))
	return &IntentSummary{
		PublicIntentSummary: PublicIntentSummary{InboundID: inbound.ID, Listen: inbound.Listen, Port: inbound.Port,
			Protocol: inbound.Protocol, Transport: inbound.Transport, Flow: inbound.Flow, SecurityMode: security.Mode,
			Target: security.Target, ServerNames: slices.Clone(security.ServerNames), ShortIDCount: len(shortIDs), UserIDs: userIDs, OutboundType: intent.Outbound.Type},
		PrivateKeyRefDigest: "sha256:" + hex.EncodeToString(privateRef[:]),
		UserRefsDigest:      "sha256:" + hex.EncodeToString(userRefs.Sum(nil)), ShortIDsDigest: "sha256:" + hex.EncodeToString(shortRefs.Sum(nil)),
	}, nil
}

// Validate 只约束持久摘要的形状、大小和固定协议；完整 Intent 由 coreapi 校验。
func (s IntentSummary) Validate() error {
	if _, err := coreapi.InboundTag(s.InboundID); err != nil {
		return ErrCorrupt
	}
	if _, err := netip.ParseAddr(s.Listen); err != nil || s.Port < 1 || s.Port > 65535 {
		return ErrCorrupt
	}
	if s.Protocol != "vless" || s.Transport != "raw" || s.Flow != "xtls-rprx-vision" || s.SecurityMode != "reality" || s.OutboundType != "direct" {
		return ErrCorrupt
	}
	host, port, err := net.SplitHostPort(s.Target)
	number, portErr := strconv.Atoi(port)
	if err != nil || host == "" || len(s.Target) > 280 || portErr != nil || number < 1 || number > 65535 || strings.ContainsAny(s.Target, "\\\x00\r\n/") {
		return ErrCorrupt
	}
	if len(s.ServerNames) < 1 || len(s.ServerNames) > coreapi.MaxNames || s.ShortIDCount < 1 || s.ShortIDCount > coreapi.MaxNames {
		return ErrCorrupt
	}
	for _, name := range s.ServerNames {
		if len(name) == 0 || len(name) > coreapi.MaxDNSNameLength || strings.ContainsAny(name, "\\\x00\r\n/ ") {
			return ErrCorrupt
		}
	}
	if len(s.UserIDs) < 1 || len(s.UserIDs) > coreapi.MaxUsers || !slices.IsSorted(s.UserIDs) {
		return ErrCorrupt
	}
	for index, id := range s.UserIDs {
		if _, err := coreapi.UserEmail(id); err != nil || index > 0 && s.UserIDs[index-1] == id {
			return ErrCorrupt
		}
	}
	if !ValidDigest(s.PrivateKeyRefDigest) || !ValidDigest(s.UserRefsDigest) || !ValidDigest(s.ShortIDsDigest) {
		return ErrCorrupt
	}
	return nil
}
