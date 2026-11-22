// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/secrets"
)

// ======================== 有界 JSON 与宿主事实完整性 ========================

// strictObject 拒绝 null、重复成员、未知字段、无效 UTF-8 与尾随文档。
// 参数和私有登记共用这条边界；错误信息由调用方按验证/状态分类，不展开输入。
func strictObject(raw []byte, destination any, limit int) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(raw) > limit || len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(raw) {
		return false
	}
	scanner := json.NewDecoder(bytes.NewReader(raw))
	if !uniqueJSONValue(scanner, 0) {
		return false
	}
	if _, err := scanner.Token(); err != io.EOF {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}

func uniqueJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 64 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			member, err := decoder.Token()
			key, ok := member.(string)
			if err != nil || !ok || seen[key] {
				return false
			}
			seen[key] = true
			if !uniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !uniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validRevision(value string) bool { return value == "absent" || validDigest(value) }

func validInitiator(who actor.Actor) bool {
	if who.Valid() != nil || who.SessionID != "" || who.MFA {
		return false
	}
	switch who.Kind {
	case actor.Human:
		return ids.Valid(who.ID, ids.User)
	case actor.AIAgent:
		return ids.Valid(who.ID, ids.Delegation) && ids.Valid(who.OnBehalfOf, ids.User)
	default:
		return false
	}
}

// operationSecret 只接受真实 ExtractSecrets 生成的单成员引用对象。
// 字符串形式或插件构造的 owner/purpose 不能替代宿主私有参数。
func operationSecret(raw json.RawMessage) (secrets.Ref, bool) {
	var document map[string]any
	if !strictObject(raw, &document, 256) {
		return "", false
	}
	return secrets.RefFromObject(document)
}
