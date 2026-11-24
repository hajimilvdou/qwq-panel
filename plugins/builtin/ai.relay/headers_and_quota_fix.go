// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"math"
	"net"
	"net/http"
	"strings"
)

// ExtractPortalSessionToken 优先读取 X-Relay-Session，同时兼容宿主公开网关归一化的 X-QWQ-Relay-Token，
// 并严格拦截任何 qwq_* 面板管理令牌。
func ExtractPortalSessionToken(r *http.Request) (string, error) {
	tok := strings.TrimSpace(r.Header.Get("X-Relay-Session"))
	if tok == "" {
		cand := strings.TrimSpace(r.Header.Get("X-QWQ-Relay-Token"))
		if strings.HasPrefix(cand, "rly_sess_") {
			tok = cand
		} else if strings.HasPrefix(cand, "qwq_") {
			return "", errors.New("拒绝面板管理凭据访问分发门户")
		}
	}
	if strings.HasPrefix(tok, "qwq_") {
		return "", errors.New("拒绝面板管理凭据访问分发门户")
	}
	if !strings.HasPrefix(tok, "rly_sess_") {
		return "", errors.New("缺少有效的门户登录会话")
	}
	return tok, nil
}

// ExtractTrustedClientIP 优先采用宿主公开网关注入的受信 X-QWQ-Client-IP，
// 不盲信客户端可伪造的 X-Forwarded-For，避免子令牌 IP 白名单误拒或绕过。
func ExtractTrustedClientIP(r *http.Request) string {
	if gwIP := strings.TrimSpace(r.Header.Get("X-QWQ-Client-IP")); gwIP != "" {
		return gwIP
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// DynamicReserveInput 汇总单次请求的预估输入 Token、最大输出上限与模型价格。
type DynamicReserveInput struct {
	DefaultReserveMicros int64
	EstimatedInputTokens int
	RequestedMaxTokens   int
	BillingMode          string // "token" | "per_call"
	InputMicrosPer1K     int64
	OutputMicrosPer1K    int64
	PerCallMicros        int64
	GroupRatio           float64
}

// ComputeSafeOutputTokenReserve 计算安全的输出 Token 预冻结上限：
// 绝不允许把用户显式请求的 max_tokens 反向截小成 2048 造成并发穿透余额；
// 未传 max_tokens 时按稳健默认 4096 预冻结，上限 128000，流结束后按实际消耗多退少补。
func ComputeSafeOutputTokenReserve(requestedMaxTokens int) int {
	switch {
	case requestedMaxTokens <= 0:
		return 4096
	case requestedMaxTokens > 128_000:
		return 128_000
	default:
		return requestedMaxTokens
	}
}

// ComputeDynamicReserveMicros 基于上下文长度与模型倍率计算动态预扣微点额，
// 防止余额仅剩极少额度的账号发送百万 Token 上下文透支昂贵上游渠道。
func ComputeDynamicReserveMicros(in DynamicReserveInput) int64 {
	ratio := in.GroupRatio
	if ratio <= 0 {
		ratio = 1.0
	}
	floor := in.DefaultReserveMicros
	if floor < 1000 {
		floor = 50_000
	}
	if in.BillingMode == "per_call" {
		callCost := int64(math.Ceil(float64(in.PerCallMicros) * ratio))
		return max(floor, callCost)
	}
	inTok := max(in.EstimatedInputTokens, 256)
	estOutTok := ComputeSafeOutputTokenReserve(in.RequestedMaxTokens)
	rawMicros := (float64(inTok)*float64(in.InputMicrosPer1K)/1000.0 +
		float64(estOutTok)*float64(in.OutputMicrosPer1K)/1000.0) * ratio
	est := int64(math.Ceil(rawMicros))
	return max(floor, est)
}
