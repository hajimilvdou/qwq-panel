// SPDX-License-Identifier: AGPL-3.0-only

// Package fault 定义准备模块的稳定错误；上游响应和秘密不进入错误文本。
package fault

import (
	"errors"
	"time"
)

// ======================== 稳定业务错误 ========================

// Error 只公开可操作的错误码和说明，避免泄漏提供商响应或私钥。
type Error struct {
	Code       string    `json:"code"`
	Detail     string    `json:"detail"`
	RetryAt    time.Time `json:"retry_at,omitempty"`
	Uncertain  bool      `json:"uncertain,omitempty"`
	NotApplied bool      `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

// New 构造不携带底层响应的业务错误。
func New(code, detail string) *Error { return &Error{Code: code, Detail: detail} }

// Code 返回稳定错误码，未分类错误统一按内部错误处理。
func Code(err error) string {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Code
	}
	return "INTERNAL"
}

// Retry 返回上游明确允许的下一次尝试时间。
func Retry(err error) time.Time {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.RetryAt
	}
	return time.Time{}
}
