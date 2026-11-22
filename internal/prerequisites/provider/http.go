// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 有界 HTTP 与脱敏错误 ========================

type apiClient struct {
	source CredentialSource
	http   *http.Client
	clock  clock.Clock
	random io.Reader
}

func newAPIClient(options Options) (*apiClient, error) {
	defaultOptions(&options)
	client := http.Client{Timeout: 10 * time.Second}
	if options.Client != nil {
		client = *options.Client
		if client.Timeout <= 0 || client.Timeout > 30*time.Second {
			client.Timeout = 10 * time.Second
		}
	}
	if client.Transport == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		client.Transport = transport
	} else if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, fault.New("VALIDATION_FAILED", "DNS 提供商必须校验 TLS")
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	return &apiClient{source: options.Source, http: &client, clock: options.Clock, random: options.Random}, nil
}

type requestBuilder func(Credentials) (*http.Request, error)

func (c *apiClient) request(ctx context.Context, scope dns.Scope, mutation bool, build requestBuilder) ([]byte, http.Header, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	credentials, err := c.source.Read(ctx, scope)
	defer credentials.Clear()
	if err != nil {
		return nil, nil, notSent(err)
	}
	if err := credentials.Validate(scope.Kind); err != nil {
		return nil, nil, notSent(err)
	}
	request, err := build(credentials)
	if err != nil {
		return nil, nil, notSent(fault.New("VALIDATION_FAILED", "DNS 请求无法安全构造"))
	}
	request = request.WithContext(ctx)
	request.Header.Set("User-Agent", "qwq-dns/1")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		if !mutation && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return nil, nil, ctxError(ctx)
		}
		return nil, nil, apiFailure("PROVIDER_UNAVAILABLE", mutation, time.Time{})
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil || len(data) > maxResponseBytes {
		return nil, response.Header, apiFailure("PROVIDER_INVALID", mutation, time.Time{})
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return data, response.Header, statusFailure(response.StatusCode, mutation, retryAt(c.clock.Now(), response.Header.Get("Retry-After")))
	}
	return data, response.Header, nil
}

func ctxError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fault.New("PROVIDER_UNAVAILABLE", "DNS 提供商请求超时")
}

func apiFailure(code string, uncertain bool, retry time.Time) error {
	if uncertain {
		code = "OUTCOME_UNKNOWN"
	}
	return &fault.Error{Code: code, Detail: "DNS 提供商结果未确认或服务暂不可用", RetryAt: retry, Uncertain: uncertain, NotApplied: !uncertain}
}

// notSent 仅用于明确尚未发送 HTTP 写入的本地/授权拒绝。
func notSent(err error) error {
	var original *fault.Error
	if errors.As(err, &original) {
		failure := *original
		failure.NotApplied, failure.Uncertain = true, false
		failure.Detail = "DNS 请求在发送前被宿主拒绝"
		return &failure
	}
	return apiFailure("PROVIDER_UNAVAILABLE", false, time.Time{})
}

func statusFailure(status int, mutation bool, retry time.Time) error {
	switch status {
	case http.StatusTooManyRequests:
		return apiFailure("RATE_LIMITED", false, retry)
	case http.StatusUnauthorized, http.StatusForbidden:
		return apiFailure("CREDENTIAL_REVOKED", false, retry)
	case http.StatusNotFound:
		return apiFailure("NOT_FOUND", false, retry)
	case http.StatusConflict:
		return apiFailure("RECORD_CONFLICT", false, retry)
	default:
		if status >= 400 && status < 500 {
			return apiFailure("VALIDATION_FAILED", false, retry)
		}
		return apiFailure("PROVIDER_UNAVAILABLE", mutation, retry)
	}
}

func retryAt(now time.Time, header string) time.Time {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(header), 10, 64); err == nil && seconds >= 0 && seconds <= 7*24*60*60 {
		return now.Add(time.Duration(seconds) * time.Second).UTC()
	}
	if parsed, err := http.ParseTime(header); err == nil && !parsed.Before(now) && !parsed.After(now.Add(7*24*time.Hour)) {
		return parsed.UTC()
	}
	return time.Time{}
}

// providerRevision 规范化完整 API 对象，字段顺序不会制造假变化。
func providerRevision(raw []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return "", fault.New("PROVIDER_INVALID", "提供商记录格式无效")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return "", fault.New("PROVIDER_INVALID", "提供商记录包含尾随数据")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fault.New("PROVIDER_INVALID", "提供商记录无法规范化")
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

func sameScope(expected, actual dns.Scope) error {
	if dns.ValidateScope(actual) != nil || expected != actual {
		return fault.New("SCOPE_INVALID", "DNS 适配器拒绝改变 provider、zone 或凭据版本")
	}
	return nil
}
