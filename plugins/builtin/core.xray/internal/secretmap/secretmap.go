// SPDX-License-Identifier: AGPL-3.0-only

// Package secretmap 只为已经派发的 Apply 映射本次 Intent 的秘密材料。
package secretmap

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/internal/xraycore/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

var ErrUnavailable = errors.New("secretmap: required material is unavailable")

// 最长材料为 43 字节私钥；每个 ASCII 字节最多使用一个六字节 JSON 转义。
const maxEncodedMaterial = 6*43 + 2

// Revealer 由当前 operation 的 Host 提供；owner 和存储 purpose 仍由宿主固定。
type Revealer interface {
	RevealSecret(context.Context, string, string) ([]byte, error)
}

// Load 按固定审计 purpose 揭示有限材料，失败和取消都清除所有已接收缓冲区。
// 成功时缓冲区交给调用方，调用方必须在使用后调用 Secrets.Clear。
func Load(ctx context.Context, intent *coreapi.Intent, revealer Revealer) (materials xrayconfig.Secrets, err error) {
	if err := ctx.Err(); err != nil {
		return materials, err
	}
	if revealer == nil || coreapi.Validate(intent) != nil {
		return materials, ErrUnavailable
	}
	materials.UUIDs = make(map[string][]byte, len(intent.Inbound.Users))
	defer func() {
		if err != nil {
			materials.Clear()
		}
	}()
	materials.PrivateKey, err = reveal(ctx, revealer, intent.Inbound.Security.PrivateKey.ID)
	if err != nil {
		return materials, err
	}
	if !xrayconfig.ValidPrivateKey(materials.PrivateKey) {
		return materials, ErrUnavailable
	}
	for _, user := range intent.Inbound.Users {
		if err := ctx.Err(); err != nil {
			return materials, err
		}
		value, err := reveal(ctx, revealer, user.UUID.ID)
		if err != nil {
			return materials, err
		}
		if !xrayconfig.ValidUUID(value) {
			clear(value)
			return materials, ErrUnavailable
		}
		materials.UUIDs[user.ID] = value
	}
	if xrayconfig.ValidateSecrets(intent, materials) != nil {
		return materials, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return materials, err
	}
	return materials, nil
}

func reveal(parent context.Context, revealer Revealer, reference string) ([]byte, error) {
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
	// --------------------------- 配置秘密解码 ---------------------------------
	// ExtractSecrets 加密保存 JSON 值，Reveal 保留该字节契约；只接受完整字符串。
	// 原生渲染需要字符串内容，传输缓冲区在本次调用结束前清零。
	if len(raw) > maxEncodedMaterial {
		return nil, ErrUnavailable
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || value == "" {
		return nil, ErrUnavailable
	}
	return []byte(value), nil
}
