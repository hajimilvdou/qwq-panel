// SPDX-License-Identifier: Apache-2.0

// Package strictjson 为 SDK 固定契约提供有界 token 解码，不接受自由 map 或接口字段。
package strictjson

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits 固定每份契约的字节数、数组长度和嵌套深度上限。
type Limits struct {
	MaxBytes int
	MaxItems int
	MaxDepth int
}

// Error 只保存规则与 RFC 6901 字段路径，不回显输入值或底层 JSON 错误。
type Error struct {
	Pointer string
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return "strictjson: invalid JSON (" + e.Code + ")"
}

func invalid(path, code, message string) *Error {
	return &Error{Pointer: path, Code: code, Message: message}
}

// Decode 只写入非 nil 的固定 struct 指针；调用方在失败时丢弃该局部候选。
// 拒绝未知字段、大小写回退、重复键、null 和尾随 JSON，不调用自定义反序列化器。
func Decode(data []byte, dst any, limits Limits) *Error {
	if limits.MaxBytes <= 0 || limits.MaxItems <= 0 || limits.MaxDepth < 0 {
		return invalid("", "TYPE", "解码上限无效")
	}
	if len(data) > limits.MaxBytes {
		return invalid("", "SIZE", "配置不得超过 1 MiB")
	}
	if !utf8.Valid(data) {
		return invalid("", "UTF8", "配置必须是有效 UTF-8")
	}
	value := reflect.ValueOf(dst)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return invalid("", "TYPE", "解码目标必须是固定对象指针")
	}
	d := decoder{Decoder: json.NewDecoder(bytes.NewReader(data)), limits: limits}
	d.UseNumber()
	if err := d.read(value.Elem(), "", 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid("", "TRAILING_JSON", "配置必须恰好包含一个 JSON 对象")
	}
	return nil
}

// ======================== 有界 token 解码 ========================
// 直接写入正式类型；每个对象的重复键集合仅在当前递归调用中存在。
type decoder struct {
	*json.Decoder
	limits Limits
}

func (d decoder) read(dst reflect.Value, path string, depth int) *Error {
	if depth > d.limits.MaxDepth {
		return invalid(path, "DEPTH", "配置嵌套过深")
	}
	token, err := d.Token()
	if err != nil {
		return invalid(path, "JSON", "JSON 语法无效")
	}
	if token == nil {
		return invalid(path, "TYPE", "字段不能为 null")
	}
	if dst.Kind() == reflect.Pointer {
		dst.Set(reflect.New(dst.Type().Elem()))
		dst = dst.Elem()
	}
	switch dst.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return invalid(path, "TYPE", "字段必须是对象")
		}
		seen := make(map[string]struct{}, dst.NumField())
		for d.More() {
			keyToken, err := d.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return invalid(path, "JSON", "对象字段名无效")
			}
			childPath := Pointer(path, key)
			if _, duplicate := seen[key]; duplicate {
				return invalid(childPath, "DUPLICATE_KEY", "对象字段不能重复")
			}
			seen[key] = struct{}{}
			field := fieldForJSON(dst, key)
			if !field.IsValid() {
				return invalid(childPath, "UNKNOWN_FIELD", "契约未声明此字段")
			}
			if err := d.read(field, childPath, depth+1); err != nil {
				return err
			}
		}
		return d.closeObject(path, '}')
	case reflect.Slice:
		if token != json.Delim('[') {
			return invalid(path, "TYPE", "字段必须是数组")
		}
		items := reflect.MakeSlice(dst.Type(), 0, 0)
		for d.More() {
			if items.Len() >= d.limits.MaxItems {
				return invalid(path, "SIZE", "数组长度超过上限")
			}
			item := reflect.New(dst.Type().Elem()).Elem()
			if err := d.read(item, Pointer(path, strconv.Itoa(items.Len())), depth+1); err != nil {
				return err
			}
			items = reflect.Append(items, item)
		}
		dst.Set(items)
		return d.closeObject(path, ']')
	case reflect.String:
		value, ok := token.(string)
		if !ok {
			return invalid(path, "TYPE", "字段必须是字符串")
		}
		dst.SetString(value)
	case reflect.Bool:
		value, ok := token.(bool)
		if !ok {
			return invalid(path, "TYPE", "字段必须是布尔值")
		}
		dst.SetBool(value)
	case reflect.Int:
		value, ok := token.(json.Number)
		if !ok {
			return invalid(path, "TYPE", "字段必须是整数")
		}
		number, err := value.Int64()
		if err != nil || dst.OverflowInt(number) {
			return invalid(path, "TYPE", "字段必须是可表示的整数")
		}
		dst.SetInt(number)
	case reflect.Uint, reflect.Uint32, reflect.Uint64:
		value, ok := token.(json.Number)
		if !ok {
			return invalid(path, "TYPE", "字段必须是非负整数")
		}
		number, err := strconv.ParseUint(value.String(), 10, 64)
		if err != nil || dst.OverflowUint(number) {
			return invalid(path, "TYPE", "字段必须是可表示的非负整数")
		}
		dst.SetUint(number)
	default:
		return invalid(path, "TYPE", "字段类型不受此契约支持")
	}
	return nil
}

func (d decoder) closeObject(path string, want json.Delim) *Error {
	token, err := d.Token()
	if err != nil || token != want {
		return invalid(path, "JSON", "对象或数组未正确结束")
	}
	return nil
}

func fieldForJSON(dst reflect.Value, key string) reflect.Value {
	for index := range dst.NumField() {
		field := dst.Type().Field(index)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if field.IsExported() && name != "" && name != "-" && name == key {
			return dst.Field(index)
		}
	}
	return reflect.Value{}
}

// Pointer 拼接 RFC 6901 路径；键转义顺序不可交换。
func Pointer(parent, key string) string {
	return parent + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}
