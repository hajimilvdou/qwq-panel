// SPDX-License-Identifier: AGPL-3.0-only

package secretmap

import (
	"context"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayconfig"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== Core Intent v2 秘密与宿主 TLS 材料映射 ========================

// Hysteria2 认证值最长 256 字节；JSON 极端转义上限 6*256+2。
const maxV2EncodedMaterial = 6*256 + 2

// TLSLoader 从消费者私有落盘目录加载已由宿主验证部署的证书材料，不经由 gRPC 传输私钥。
type TLSLoader interface {
	LoadTLS(ctx context.Context, profileID, bindingRef, serverName string) (xrayconfig.TLSMaterials, error)
}

// LoadV2 按固定审计 purpose 揭示 v2 期望配置全部协议材料，任何失败或取消均清零已分配缓冲区。
func LoadV2(ctx context.Context, intent *corev2.Intent, revealer Revealer, tlsLoader TLSLoader) (materials xrayconfig.V2Materials, err error) {
	if err := ctx.Err(); err != nil {
		return materials, err
	}
	if revealer == nil || corev2.Validate(intent) != nil {
		return materials, ErrUnavailable
	}
	materials.Profiles = make(map[string]xrayconfig.ProfileMaterials, len(intent.Profiles))
	defer func() {
		if err != nil {
			materials.Clear()
		}
	}()

	for _, profile := range intent.Profiles {
		if err := ctx.Err(); err != nil {
			return materials, err
		}
		switch profile.Protocol {
		case corev2.ProtocolVLESS:
			vless := &xrayconfig.Secrets{UUIDs: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{VLESS: vless}
			vless.PrivateKey, err = revealBounded(ctx, revealer, profile.VLESS.Security.PrivateKey.ID, maxEncodedMaterial)
			if err != nil {
				return materials, err
			}
			if !xrayconfig.ValidPrivateKey(vless.PrivateKey) {
				return materials, ErrUnavailable
			}
			for _, user := range profile.Users {
				if err := ctx.Err(); err != nil {
					return materials, err
				}
				if user.UUID == nil {
					return materials, ErrUnavailable
				}
				val, rerr := revealBounded(ctx, revealer, user.UUID.ID, maxEncodedMaterial)
				if rerr != nil {
					return materials, rerr
				}
				if !xrayconfig.ValidUUID(val) {
					clear(val)
					return materials, ErrUnavailable
				}
				vless.UUIDs[user.ID] = val
			}

		case corev2.ProtocolHysteria2:
			if tlsLoader == nil || profile.Hysteria2 == nil || profile.Hysteria2.TLS == nil {
				return materials, ErrUnavailable
			}
			h2 := &xrayconfig.HysteriaMaterials{Auth: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{Hysteria2: h2}
			for _, user := range profile.Users {
				if err := ctx.Err(); err != nil {
					return materials, err
				}
				if user.Auth == nil {
					return materials, ErrUnavailable
				}
				val, rerr := revealBounded(ctx, revealer, user.Auth.ID, maxV2EncodedMaterial)
				if rerr != nil {
					return materials, rerr
				}
				if !xrayconfig.ValidHysteriaAuth(val) {
					clear(val)
					return materials, ErrUnavailable
				}
				h2.Auth[user.ID] = val
			}
			tlsMat, terr := tlsLoader.LoadTLS(ctx, profile.ID, profile.Hysteria2.TLS.BindingRef, profile.Hysteria2.TLS.ServerName)
			if terr != nil {
				return materials, terr
			}
			h2.TLS = tlsMat

		case corev2.ProtocolShadowsocks2022:
			if profile.Shadowsocks2022 == nil {
				return materials, ErrUnavailable
			}
			ss := &xrayconfig.SS2022Materials{PSKs: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{Shadowsocks2022: ss}
			ss.ServerKey, err = revealBounded(ctx, revealer, profile.Shadowsocks2022.ServerKey.ID, maxV2EncodedMaterial)
			if err != nil {
				return materials, err
			}
			if !xrayconfig.ValidSS2022Key(ss.ServerKey, profile.Shadowsocks2022.Method) {
				return materials, ErrUnavailable
			}
			for _, user := range profile.Users {
				if err := ctx.Err(); err != nil {
					return materials, err
				}
				if user.PSK == nil {
					return materials, ErrUnavailable
				}
				val, rerr := revealBounded(ctx, revealer, user.PSK.ID, maxV2EncodedMaterial)
				if rerr != nil {
					return materials, rerr
				}
				if !xrayconfig.ValidSS2022Key(val, profile.Shadowsocks2022.Method) {
					clear(val)
					return materials, ErrUnavailable
				}
				ss.PSKs[user.ID] = val
			}

		default:
			return materials, ErrUnavailable
		}
	}
	return materials, nil
}

func revealBounded(parent context.Context, revealer Revealer, reference string, limit int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	raw, err := revealer.RevealSecret(ctx, reference, "core.xray.apply")
	defer clear(raw)
	if err != nil || ctx.Err() != nil {
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		return nil, ErrUnavailable
	}
	if len(raw) > limit {
		return nil, ErrUnavailable
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || value == "" {
		return nil, ErrUnavailable
	}
	return []byte(value), nil
}
