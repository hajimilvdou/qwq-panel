// SPDX-License-Identifier: AGPL-3.0-only

// Package xrayconfig 将受限 Core Intent 转为锁定版本的原生配置，不执行 I/O。
package xrayconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/sdk/coreapi"
)

var (
	ErrSecrets = errors.New("xrayconfig: invalid secret material")
	ErrSocket  = errors.New("xrayconfig: invalid private API socket")
)

// Secrets 只在已授权 Apply 中短时持有材料，按稳定用户 ID 关联，不接受自由原生字段。
type Secrets struct {
	PrivateKey []byte
	UUIDs      map[string][]byte
}

func (Secrets) String() string   { return "XraySecrets{[REDACTED]}" }
func (Secrets) GoString() string { return "XraySecrets{[REDACTED]}" }

// Clear 清理调用方拥有的缓冲区；Render 自身保持纯函数，不修改材料或期望快照。
func (s *Secrets) Clear() {
	clear(s.PrivateKey)
	s.PrivateKey = nil
	for id, value := range s.UUIDs {
		clear(value)
		delete(s.UUIDs, id)
	}
}

// Options 由驱动从私有 DataDir 构造，用户配置不能提供 API 路径。
type Options struct{ APISocket string }

// ValidSocket 检查文件系统 socket 的固定名称和 Linux 路径上限，拒绝抽象地址与权限注入。
func ValidSocket(socket string) bool {
	return path.IsAbs(socket) && path.Clean(socket) == socket && path.Base(socket) == "api.sock" && len(socket) <= 103 && !strings.ContainsAny(socket, ",\\\x00\r\n")
}

// Render 保留完整预检配置，即使 enabled=false 也不省略入站校验。
// v26.11.9 使用 users/target/RAW；API 用传统入站与 routing，仅开放 StatsService。
func Render(intent *coreapi.Intent, secrets Secrets, options Options) ([]byte, error) {
	if err := coreapi.Validate(intent); err != nil {
		return nil, err
	}
	if !ValidSocket(options.APISocket) {
		return nil, ErrSocket
	}
	inbound, err := vlessInbound(intent, secrets)
	if err != nil {
		return nil, err
	}
	return encodeNativeConfig(baseNativeConfig([]nativeInbound{inbound}, options))
}

func vlessInbound(intent *coreapi.Intent, secrets Secrets) (nativeInbound, error) {
	nativeUsers, err := validatedUsers(intent, secrets)
	if err != nil {
		return nativeInbound{}, err
	}
	tag, err := coreapi.InboundTag(intent.Inbound.ID)
	if err != nil {
		return nativeInbound{}, err
	}
	port := intent.Inbound.Port
	reality := intent.Inbound.Security
	return nativeInbound{Tag: tag, Listen: intent.Inbound.Listen, Port: &port, Protocol: "vless", Settings: vlessSettings{Decryption: "none", Users: nativeUsers}, Stream: &nativeStream{
		Network: "raw", Security: "reality", Reality: &nativeReality{Target: reality.Target, ServerNames: slices.Clone(reality.ServerNames), PrivateKey: string(secrets.PrivateKey), ShortIDs: slices.Clone(reality.ShortIDs)},
	}}, nil
}

// 共用受控API/日志/统计和direct出站；业务入站始终位于API入站之前。
func baseNativeConfig(inbounds []nativeInbound, options Options) nativeConfig {
	return nativeConfig{
		Log:    nativeLog{Access: "none", Error: "none", Level: "none"},
		API:    nativeAPI{Tag: "qwq-api", Services: []string{"StatsService"}},
		Stats:  struct{}{},
		Policy: nativePolicy{Levels: map[string]userPolicy{"0": {Uplink: true, Downlink: true}}, System: systemPolicy{Uplink: true, Downlink: true}},
		// 上游 system_listener 明确支持路径后缀 ,0600；port 必须省略。
		Inbounds:  append(inbounds, nativeInbound{Tag: "qwq-api-in", Listen: options.APISocket + ",0600", Protocol: "dokodemo-door", Settings: apiSettings{Address: "127.0.0.1", Network: "tcp"}}),
		Outbounds: []nativeOutbound{{Tag: "qwq-direct", Protocol: "freedom", Settings: struct{}{}}},
		Routing:   nativeRouting{Rules: []nativeRule{{Type: "field", InboundTags: []string{"qwq-api-in"}, OutboundTag: "qwq-api"}}},
	}
}

func encodeNativeConfig(config nativeConfig) ([]byte, error) {
	result, err := json.MarshalIndent(config, "", "  ")
	if err != nil || len(result) > coreapi.MaxSize {
		clear(result)
		return nil, errors.New("xrayconfig: candidate cannot be encoded")
	}
	return append(result, '\n'), nil
}

// ValidPrivateKey 只检查锁定原生格式，临时解码缓冲区在返回前清零。
func ValidPrivateKey(value []byte) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(value))
	defer clear(decoded)
	return err == nil && len(decoded) == 32
}

// ValidUUID 与原生渲染共用规范形状，避免映射层和渲染层采用不同规则。
func ValidUUID(value []byte) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := bytes.ReplaceAll(value, []byte("-"), nil)
	defer clear(compact)
	if len(compact) != 32 {
		return false
	}
	decoded := make([]byte, 16)
	_, err := hex.Decode(decoded, compact)
	clear(decoded)
	return err == nil
}

// ValidateSecrets 同时检查材料数量、格式和重复身份，不产生任何 I/O。
func ValidateSecrets(intent *coreapi.Intent, secrets Secrets) error {
	if err := coreapi.Validate(intent); err != nil {
		return err
	}
	_, err := validatedUsers(intent, secrets)
	return err
}

func validatedUsers(intent *coreapi.Intent, secrets Secrets) ([]nativeUser, error) {
	if !ValidPrivateKey(secrets.PrivateKey) || len(secrets.UUIDs) != len(intent.Inbound.Users) {
		return nil, ErrSecrets
	}
	users := slices.Clone(intent.Inbound.Users)
	slices.SortFunc(users, func(a, b coreapi.User) int { return strings.Compare(a.ID, b.ID) })
	result := make([]nativeUser, 0, len(users))
	seen := make(map[string]struct{}, len(users))
	for _, user := range users {
		value, exists := secrets.UUIDs[user.ID]
		if !exists || !ValidUUID(value) {
			return nil, ErrSecrets
		}
		uuid := strings.ToLower(string(value))
		if _, duplicate := seen[uuid]; duplicate {
			return nil, ErrSecrets
		}
		seen[uuid] = struct{}{}
		email, err := coreapi.UserEmail(user.ID)
		if err != nil {
			return nil, err
		}
		result = append(result, nativeUser{ID: uuid, Email: email, Level: 0, Flow: intent.Inbound.Flow})
	}
	return result, nil
}
