// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"encoding/base64"
	"slices"
	"strings"

	corev1 "github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ---- SS2022 规范编码与多用户材料 --------------------------------------------

// ValidSS2022Key 拒绝非规范标准 base64、错误长度与单字节重复弱值。
// 生产生成器仍须使用 crypto/rand；格式校验不替代真实随机性。
func ValidSS2022Key(value []byte, method string) bool {
	length := 0
	switch method {
	case corev2.MethodAES128:
		length = 16
	case corev2.MethodAES256:
		length = 32
	default:
		return false
	}
	if len(value) != base64.StdEncoding.EncodedLen(length) {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(value))
	defer clear(decoded)
	if err != nil || len(decoded) != length || base64.StdEncoding.EncodeToString(decoded) != string(value) {
		return false
	}
	for _, next := range decoded[1:] {
		if next != decoded[0] {
			return true
		}
	}
	return false
}

func ss2022Users(profile corev2.Profile, materials SS2022Materials) ([]ss2022User, error) {
	method := profile.Shadowsocks2022.Method
	if !ValidSS2022Key(materials.ServerKey, method) || len(materials.PSKs) != len(profile.Users) {
		return nil, ErrV2Materials
	}
	users := slices.Clone(profile.Users)
	slices.SortFunc(users, func(left, right corev2.User) int { return strings.Compare(left.ID, right.ID) })
	result := make([]ss2022User, 0, len(users))
	seen := map[string]bool{string(materials.ServerKey): true}
	for _, user := range users {
		value, found := materials.PSKs[user.ID]
		if !found || !ValidSS2022Key(value, method) || seen[string(value)] {
			return nil, ErrV2Materials
		}
		seen[string(value)] = true
		email, err := corev1.UserEmail(user.ID)
		if err != nil {
			return nil, err
		}
		result = append(result, ss2022User{Password: string(value), Email: email, Level: 0})
	}
	return result, nil
}
