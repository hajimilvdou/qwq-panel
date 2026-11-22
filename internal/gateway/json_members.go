// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"unicode/utf8"
)

// ======================== 字段/深度单遍检查；语法继续由标准 JSON 扫描器负责 ========================

const maxPooledJSONMemberKeys = 128

var jsonMemberKeyPool sync.Pool

type jsonMemberFrame struct {
	closing   byte
	pointer   string
	key       string
	index     int
	expectKey bool
	keys      map[string]struct{}
}

// validateJSONMembers 复用标准语法验证，只在已合法的字节上遍历字段和层级。
// 字符串值/数字不构造 Token；转义或非法 UTF-8 字段名仍由标准解码器规范化。
func validateJSONMembers(data []byte, maxDepth int) error {
	if maxDepth < 0 || !json.Valid(data) {
		return validateInvalidJSONMembers(data, maxDepth)
	}
	frames := make([]jsonMemberFrame, 0, min(maxDepth, 16))
	defer func() {
		for _, frame := range frames {
			releaseJSONMemberKeys(frame.keys)
		}
	}()
	for offset := 0; offset < len(data); {
		switch data[offset] {
		case ' ', '\t', '\r', '\n', ':':
			offset++
		case '{', '[':
			if len(frames)+1 > maxDepth {
				return jsonMemberFailure(data, maxDepth, payloadTooLarge("max_json_depth", int64(maxDepth)))
			}
			pointer := ""
			if len(frames) > 0 {
				parent := &frames[len(frames)-1]
				component := parent.key
				if parent.closing == ']' {
					component = strconv.Itoa(parent.index)
				}
				pointer = joinPointer(parent.pointer, component)
			}
			frame := jsonMemberFrame{closing: ']', pointer: pointer}
			if data[offset] == '{' {
				frame.closing, frame.expectKey, frame.keys = '}', true, acquireJSONMemberKeys()
			}
			frames = append(frames, frame)
			offset++
		case '}', ']':
			last := len(frames) - 1
			releaseJSONMemberKeys(frames[last].keys)
			frames[last] = jsonMemberFrame{}
			frames = frames[:last]
			offset++
		case ',':
			frame := &frames[len(frames)-1]
			if frame.closing == '}' {
				frame.key, frame.expectKey = "", true
			} else {
				frame.index++
			}
			offset++
		case '"':
			end, escaped := jsonMemberStringEnd(data, offset)
			if len(frames) > 0 {
				frame := &frames[len(frames)-1]
				if frame.expectKey {
					key, err := jsonMemberName(data[offset:end+1], escaped)
					if err != nil {
						return jsonMemberFailure(data, maxDepth, invalidJSONMembers())
					}
					if _, duplicate := frame.keys[key]; duplicate {
						return jsonMemberFailure(data, maxDepth, badRequest("body", joinPointer(frame.pointer, key), codeDuplicateKey, "对象字段不能重复。"))
					}
					frame.keys[key] = struct{}{}
					frame.key, frame.expectKey = key, false
				}
			}
			offset = end + 1
		default:
			// 标准语法已确认当前是一个数字或字面量；跳过它，不创建临时值。
			for offset < len(data) && data[offset] != ',' && data[offset] != '}' && data[offset] != ']' &&
				data[offset] != ' ' && data[offset] != '\t' && data[offset] != '\r' && data[offset] != '\n' {
				offset++
			}
		}
	}
	return nil
}

func jsonMemberStringEnd(data []byte, start int) (int, bool) {
	escaped := false
	for offset := start + 1; offset < len(data); offset++ {
		switch data[offset] {
		case '\\':
			escaped = true
			offset++
		case '"':
			return offset, escaped
		}
	}
	return len(data) - 1, escaped
}

func jsonMemberName(quoted []byte, escaped bool) (string, error) {
	plain := quoted[1 : len(quoted)-1]
	if !escaped && utf8.Valid(plain) {
		return string(plain), nil
	}
	var key string
	err := json.Unmarshal(quoted, &key)
	return key, err
}

func acquireJSONMemberKeys() map[string]struct{} {
	if pooled := jsonMemberKeyPool.Get(); pooled != nil {
		return pooled.(map[string]struct{})
	}
	return make(map[string]struct{})
}

func releaseJSONMemberKeys(keys map[string]struct{}) {
	if keys == nil {
		return
	}
	retain := len(keys) <= maxPooledJSONMemberKeys
	clear(keys)
	if retain {
		jsonMemberKeyPool.Put(keys)
	}
}

// ======================== 拒绝路径：保留原深度优先级和畸形 JSON 的具体错误 ========================

func jsonMemberFailure(data []byte, maxDepth int, failure error) error {
	depth, err := jsonDepth(data)
	if err != nil {
		return badRequest("body", "/", codeInvalidJSON, "The request body is not valid JSON.")
	}
	if depth > maxDepth {
		return payloadTooLarge("max_json_depth", int64(maxDepth))
	}
	return failure
}

func validateInvalidJSONMembers(data []byte, maxDepth int) error {
	if err := jsonMemberFailure(data, maxDepth, nil); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := checkJSONMembers(decoder, ""); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return invalidJSONMembers()
	}
	return nil
}

func checkJSONMembers(decoder *json.Decoder, pointer string) error {
	token, err := decoder.Token()
	if err != nil {
		return invalidJSONMembers()
	}
	opening, container := token.(json.Delim)
	if !container {
		return nil
	}
	var closing json.Delim
	switch opening {
	case '{':
		closing = '}'
		seen := acquireJSONMemberKeys()
		defer releaseJSONMemberKeys(seen)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return invalidJSONMembers()
			}
			key, ok := token.(string)
			if !ok {
				return invalidJSONMembers()
			}
			child := joinPointer(pointer, key)
			if _, duplicate := seen[key]; duplicate {
				return badRequest("body", child, codeDuplicateKey, "对象字段不能重复。")
			}
			seen[key] = struct{}{}
			if err := checkJSONMembers(decoder, child); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for index := 0; decoder.More(); index++ {
			if err := checkJSONMembers(decoder, joinPointer(pointer, strconv.Itoa(index))); err != nil {
				return err
			}
		}
	default:
		return invalidJSONMembers()
	}
	if token, err := decoder.Token(); err != nil || token != closing {
		return invalidJSONMembers()
	}
	return nil
}

func invalidJSONMembers() error {
	return badRequest("body", "/", codeInvalidJSON, "请求正文必须是单个有效 JSON 值。")
}
