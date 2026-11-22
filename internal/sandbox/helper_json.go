// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// validateHelperDocument 在绑定正式结构前检查每层重复键与资源边界；错误不回显
// 键和值，避免恶意 JSON 通过解码错误把 token、口令或私钥带入日志。
func validateHelperDocument(data []byte) error {
	if len(data) > MaxHelperMessage || !utf8.Valid(data) {
		return errors.New("sandbox: invalid helper JSON encoding or size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("sandbox: helper message must be an object")
	}
	if err := scanHelperValue(decoder, token, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("sandbox: helper message contains trailing data")
	}
	return nil
}

func scanHelperValue(decoder *json.Decoder, token json.Token, depth int) error {
	if depth > 64 {
		return errors.New("sandbox: helper JSON nesting exceeds limit")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return errors.New("sandbox: invalid helper object")
			}
			if seen[key] {
				return errors.New("sandbox: duplicate helper JSON field")
			}
			seen[key] = true
			value, err := decoder.Token()
			if err != nil {
				return errors.New("sandbox: invalid helper JSON value")
			}
			if err := scanHelperValue(decoder, value, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return errors.New("sandbox: invalid helper array")
			}
			if err := scanHelperValue(decoder, value, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("sandbox: invalid helper delimiter")
	}
	end, err := decoder.Token()
	if err != nil || (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) {
		return errors.New("sandbox: unterminated helper JSON")
	}
	return nil
}
