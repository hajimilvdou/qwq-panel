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

// Hysteria2/通用口令认证值最长 256 字节；JSON 极端转义上限 6*256+2。
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
	dedup := newCachedRevealer(revealer)
	defer dedup.Clear()
	revealer = dedup
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
			if profile.VLESS == nil {
				return materials, ErrUnavailable
			}
			vless := &xrayconfig.Secrets{UUIDs: make(map[string][]byte, len(profile.Users))}
			pm := xrayconfig.ProfileMaterials{VLESS: vless}
			materials.Profiles[profile.ID] = pm

			secMode := profile.VLESS.EffectiveSecurityMode()
			switch secMode {
			case "reality":
				if profile.VLESS.Security == nil {
					return materials, ErrUnavailable
				}
				vless.PrivateKey, err = revealBounded(ctx, revealer, profile.VLESS.Security.PrivateKey.ID, maxEncodedMaterial)
				if err != nil {
					return materials, err
				}
				if !xrayconfig.ValidPrivateKey(vless.PrivateKey) {
					return materials, ErrUnavailable
				}
			case "tls":
				if tlsLoader == nil || profile.VLESS.TLS == nil {
					return materials, ErrUnavailable
				}
				tlsMat, terr := tlsLoader.LoadTLS(ctx, profile.ID, profile.VLESS.TLS.BindingRef, profile.VLESS.TLS.ServerName)
				if terr != nil {
					return materials, terr
				}
				pm.VLESSTLS = &tlsMat
			case "none":
			default:
				return materials, ErrUnavailable
			}
			if profile.VLESS.Decryption != nil {
				dec, rerr := revealBounded(ctx, revealer, profile.VLESS.Decryption.ID, maxV2EncodedMaterial)
				if rerr != nil {
					return materials, rerr
				}
				if !xrayconfig.ValidPasswordMaterial(dec, 1) {
					clear(dec)
					return materials, ErrUnavailable
				}
				pm.VLESSDecryption = dec
			}
			materials.Profiles[profile.ID] = pm
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

		case corev2.ProtocolVMess:
			if profile.VMess == nil {
				return materials, ErrUnavailable
			}
			vm := &xrayconfig.VMessMaterials{UUIDs: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{VMess: vm}
			if profile.VMess.SecurityMode == "tls" {
				if tlsLoader == nil || profile.VMess.TLS == nil {
					return materials, ErrUnavailable
				}
				tlsMat, terr := tlsLoader.LoadTLS(ctx, profile.ID, profile.VMess.TLS.BindingRef, profile.VMess.TLS.ServerName)
				if terr != nil {
					return materials, terr
				}
				vm.TLS = &tlsMat
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
				vm.UUIDs[user.ID] = val
			}

		case corev2.ProtocolTrojan:
			if profile.Trojan == nil {
				return materials, ErrUnavailable
			}
			tr := &xrayconfig.TrojanMaterials{Auth: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{Trojan: tr}
			switch profile.Trojan.SecurityMode {
			case "tls":
				if tlsLoader == nil || profile.Trojan.TLS == nil {
					return materials, ErrUnavailable
				}
				tlsMat, terr := tlsLoader.LoadTLS(ctx, profile.ID, profile.Trojan.TLS.BindingRef, profile.Trojan.TLS.ServerName)
				if terr != nil {
					return materials, terr
				}
				tr.TLS = &tlsMat
			case "reality":
				if profile.Trojan.Reality == nil {
					return materials, ErrUnavailable
				}
				tr.PrivateKey, err = revealBounded(ctx, revealer, profile.Trojan.Reality.PrivateKey.ID, maxEncodedMaterial)
				if err != nil {
					return materials, err
				}
				if !xrayconfig.ValidPrivateKey(tr.PrivateKey) {
					return materials, ErrUnavailable
				}
			default:
				return materials, ErrUnavailable
			}
			if err = revealAuthMap(ctx, revealer, profile.Users, tr.Auth, 1); err != nil {
				return materials, err
			}

		case corev2.ProtocolShadowsocks:
			if profile.Shadowsocks == nil {
				return materials, ErrUnavailable
			}
			ss := &xrayconfig.ShadowsocksMaterials{Auth: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{Shadowsocks: ss}
			if err = revealAuthMap(ctx, revealer, profile.Users, ss.Auth, 1); err != nil {
				return materials, err
			}

		case corev2.ProtocolHysteria2:
			if tlsLoader == nil || profile.Hysteria2 == nil || profile.Hysteria2.TLS == nil {
				return materials, ErrUnavailable
			}
			h2 := &xrayconfig.HysteriaMaterials{Auth: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{Hysteria2: h2}
			if err = revealAuthMap(ctx, revealer, profile.Users, h2.Auth, 16); err != nil {
				return materials, err
			}
			if profile.Hysteria2.ObfsPassword != nil {
				obfs, rerr := revealBounded(ctx, revealer, profile.Hysteria2.ObfsPassword.ID, maxV2EncodedMaterial)
				if rerr != nil {
					return materials, rerr
				}
				if !xrayconfig.ValidPasswordMaterial(obfs, 1) {
					clear(obfs)
					return materials, ErrUnavailable
				}
				h2.ObfsPassword = obfs
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

		case corev2.ProtocolAnyTLS:
			if tlsLoader == nil || profile.AnyTLS == nil || profile.AnyTLS.TLS == nil {
				return materials, ErrUnavailable
			}
			at := &xrayconfig.AnyTLSMaterials{Auth: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{AnyTLS: at}
			if err = revealAuthMap(ctx, revealer, profile.Users, at.Auth, 1); err != nil {
				return materials, err
			}
			tlsMat, terr := tlsLoader.LoadTLS(ctx, profile.ID, profile.AnyTLS.TLS.BindingRef, profile.AnyTLS.TLS.ServerName)
			if terr != nil {
				return materials, terr
			}
			at.TLS = tlsMat

		case corev2.ProtocolSOCKS5:
			if profile.SOCKS5 == nil {
				return materials, ErrUnavailable
			}
			acc := &xrayconfig.AccountMaterials{Auth: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{SOCKS5: acc}
			if err = revealAuthMap(ctx, revealer, profile.Users, acc.Auth, 1); err != nil {
				return materials, err
			}

		case corev2.ProtocolHTTP:
			if profile.HTTP == nil {
				return materials, ErrUnavailable
			}
			acc := &xrayconfig.AccountMaterials{Auth: make(map[string][]byte, len(profile.Users))}
			materials.Profiles[profile.ID] = xrayconfig.ProfileMaterials{HTTP: acc}
			if err = revealAuthMap(ctx, revealer, profile.Users, acc.Auth, 1); err != nil {
				return materials, err
			}

		default:
			return materials, ErrUnavailable
		}
	}
	if intent.WARP != nil {
		if err := ctx.Err(); err != nil {
			return materials, err
		}
		val, rerr := revealBounded(ctx, revealer, intent.WARP.PrivateKey.ID, maxV2EncodedMaterial)
		if rerr != nil {
			return materials, rerr
		}
		if !xrayconfig.ValidWireGuardKey(val) {
			clear(val)
			return materials, ErrUnavailable
		}
		materials.WARP = &xrayconfig.WARPMaterials{PrivateKey: val}
	}
	return materials, nil
}

func revealAuthMap(ctx context.Context, revealer Revealer, users []corev2.User, dest map[string][]byte, minLen int) error {
	for _, user := range users {
		if err := ctx.Err(); err != nil {
			return err
		}
		if user.Auth == nil {
			return ErrUnavailable
		}
		val, rerr := revealBounded(ctx, revealer, user.Auth.ID, maxV2EncodedMaterial)
		if rerr != nil {
			return rerr
		}
		if !xrayconfig.ValidPasswordMaterial(val, minLen) {
			clear(val)
			return ErrUnavailable
		}
		dest[user.ID] = val
	}
	return nil
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

type cachedRevealer struct {
	base  Revealer
	cache map[string][]byte
}

func newCachedRevealer(base Revealer) *cachedRevealer {
	return &cachedRevealer{base: base, cache: make(map[string][]byte)}
}

func (c *cachedRevealer) RevealSecret(ctx context.Context, ref, purpose string) ([]byte, error) {
	key := purpose + "\x00" + ref
	if cached, ok := c.cache[key]; ok {
		cp := make([]byte, len(cached))
		copy(cp, cached)
		return cp, nil
	}
	raw, err := c.base.RevealSecret(ctx, ref, purpose)
	if err != nil {
		return nil, err
	}
	stored := make([]byte, len(raw))
	copy(stored, raw)
	c.cache[key] = stored
	return raw, nil
}

func (c *cachedRevealer) Clear() {
	for k, buf := range c.cache {
		clear(buf)
		delete(c.cache, k)
	}
}
