// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/tlsmgr"
	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ---- Hysteria2 只消费宿主固定的绑定、运行代与信任 ----------------------------

func hysteriaInbound(profile corev2.Profile, materials HysteriaMaterials, options V2Options) (nativeInbound, error) {
	users, err := hysteriaUsers(profile, materials.Auth)
	if err != nil {
		return nativeInbound{}, err
	}
	tls, err := hysteriaTLS(profile.Hysteria2.TLS, materials.TLS, options)
	if err != nil {
		return nativeInbound{}, err
	}
	tag, err := corev1.InboundTag(profile.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	port := profile.Port
	return nativeInbound{Tag: tag, Listen: profile.Listen, Port: &port, Protocol: "hysteria",
		Settings: hysteriaSettings{Version: 2, Users: users},
		Stream:   &nativeStream{Network: "hysteria", Security: "tls", Hysteria: &nativeHysteriaTransport{Version: 2}, TLS: tls}}, nil
}

// ValidHysteriaAuth 限定 16 至 256 字节 UTF-8 认证值，拒绝空白和控制字符。
// 高熵凭据由生成入口产生；此处不声称从口令长度推算真实熵。
func ValidHysteriaAuth(value []byte) bool {
	if len(value) < 16 || len(value) > 256 || !utf8.Valid(value) {
		return false
	}
	for _, char := range string(value) {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func hysteriaUsers(profile corev2.Profile, auth map[string][]byte) ([]hysteriaUser, error) {
	if len(auth) != len(profile.Users) {
		return nil, ErrV2Materials
	}
	users := slices.Clone(profile.Users)
	slices.SortFunc(users, func(left, right corev2.User) int { return strings.Compare(left.ID, right.ID) })
	result := make([]hysteriaUser, 0, len(users))
	seen := make(map[string]bool, len(users))
	for _, user := range users {
		value, found := auth[user.ID]
		if !found || !ValidHysteriaAuth(value) || seen[string(value)] {
			return nil, ErrV2Materials
		}
		seen[string(value)] = true
		email, err := corev1.UserEmail(user.ID)
		if err != nil {
			return nil, err
		}
		result = append(result, hysteriaUser{Auth: string(value), Email: email, Level: 0})
	}
	return result, nil
}

func hysteriaTLS(binding *corev2.TLSBinding, materials TLSMaterials, options V2Options) (*nativeTLS, error) {
	if materials.BindingRef != binding.BindingRef || materials.Generation == 0 || materials.PolicyRevision == "" ||
		len(materials.PolicyRevision) > 256 || strings.ContainsAny(materials.PolicyRevision, "\x00\r\n") || options.Now.IsZero() {
		return nil, ErrV2Materials
	}
	if materials.Trust == tlsmgr.TestTrust {
		if !options.PermitTestCertificates || materials.Purpose != tlsmgr.TestServerTLS {
			return nil, ErrV2Materials
		}
	} else if materials.Roots == nil {
		// 纯渲染不能触发 ValidateMaterial 的系统根读取；根在宿主启动时准备。
		return nil, ErrV2Materials
	}
	metadata, err := tlsmgr.ValidateMaterial(materials.Material, tlsmgr.MaterialOptions{SANs: materials.SANs, Now: options.Now,
		Purpose: materials.Purpose, Trust: materials.Trust, Roots: materials.Roots})
	if err != nil {
		return nil, err
	}
	if err := tlsmgr.Covers(metadata, binding.ServerName); err != nil {
		return nil, err
	}
	chain, key := materials.Material.CertificatePEM(), materials.Material.PrivateKeyPEM()
	defer clear(chain)
	defer clear(key)
	return &nativeTLS{ServerName: binding.ServerName, ALPN: []string{"h3"}, MinVersion: "1.3", RejectUnknownSNI: true,
		Certificates: []nativeTLSCertificate{{Certificate: pemLines(chain), Key: pemLines(key), Usage: "encipherment", OneTimeLoading: true}}}, nil
}

func pemLines(raw []byte) []string {
	return strings.Split(strings.TrimSpace(strings.ReplaceAll(string(raw), "\r\n", "\n")), "\n")
}
