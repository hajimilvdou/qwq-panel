// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	xacme "golang.org/x/crypto/acme"
)

// ======================== 固定 CA 与逐请求授权 ========================

func directory(ca certificates.CA) (string, error) {
	switch ca {
	case certificates.LetsEncrypt:
		return "https://acme-v02.api.letsencrypt.org/directory", nil
	case certificates.LetsEncryptStaging:
		return "https://acme-staging-v02.api.letsencrypt.org/directory", nil
	default:
		return "", fault.New("SCOPE_INVALID", "不支持该 ACME CA")
	}
}

func allowedURL(ca certificates.CA, value string) bool {
	endpoint, err := directory(ca)
	if err != nil {
		return false
	}
	base, _ := url.Parse(endpoint)
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host == base.Host && parsed.User == nil && parsed.Fragment == "" && (parsed.Path == "/directory" || strings.HasPrefix(parsed.Path, "/acme/"))
}

type guardedTransport struct {
	base          http.RoundTripper
	authority     *Authority
	caller        certificates.Caller
	certificateID string
	scope         certificates.IssuanceScope
	mu            sync.Mutex
	status        int
	retryAt       time.Time
}

func (g *guardedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	g.mu.Lock()
	g.status, g.retryAt = 0, time.Time{}
	g.mu.Unlock()
	if !allowedURL(g.scope.CA, request.URL.String()) {
		return nil, fault.New("SCOPE_INVALID", "CA 返回了未授权端点")
	}
	if err := g.authority.authorize(request.Context(), g.caller, g.certificateID, g.scope); err != nil {
		return nil, err
	}
	response, err := g.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	_ = response.Body.Close()
	if err != nil || len(data) > 1<<20 {
		return nil, fault.New("CA_UNAVAILABLE", "CA 响应超过上限或未完整读取")
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	g.mu.Lock()
	g.status = response.StatusCode
	g.retryAt = caRetryAt(g.authority.clock.Now(), response.Header.Get("Retry-After"))
	g.mu.Unlock()
	return response, nil
}

func (g *guardedTransport) failure(err error, mutation bool) error {
	var original *fault.Error
	if errors.As(err, &original) {
		return &fault.Error{Code: original.Code, Detail: "ACME 受控原语拒绝或暂不可用", RetryAt: original.RetryAt, Uncertain: original.Uncertain, NotApplied: original.NotApplied}
	}
	g.mu.Lock()
	status, retry := g.status, g.retryAt
	g.mu.Unlock()
	code, notApplied := "CA_UNAVAILABLE", false
	if status == 429 {
		code, notApplied = "RATE_LIMITED", true
	} else if status >= 400 && status < 500 {
		code, notApplied = "CA_REJECTED", true
	}
	return &fault.Error{Code: code, Detail: "ACME 结果未确认或请求已拒绝", RetryAt: retry, Uncertain: mutation && !notApplied, NotApplied: mutation && notApplied}
}

func (a *Authority) acmeClient(caller certificates.Caller, certificateID string, scope certificates.IssuanceScope, key crypto.Signer, accountURI string) (*xacme.Client, *guardedTransport, error) {
	endpoint, err := directory(scope.CA)
	if err != nil {
		return nil, nil, err
	}
	client := http.Client{Timeout: 15 * time.Second}
	if a.client != nil {
		client = *a.client
		if client.Timeout <= 0 || client.Timeout > 30*time.Second {
			client.Timeout = 15 * time.Second
		}
	}
	transport := client.Transport
	if transport == nil {
		standard := http.DefaultTransport.(*http.Transport).Clone()
		standard.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		transport = standard
	}
	if standard, ok := transport.(*http.Transport); ok && standard.TLSClientConfig != nil && standard.TLSClientConfig.InsecureSkipVerify {
		return nil, nil, fault.New("VALIDATION_FAILED", "ACME 必须校验 TLS")
	}
	guard := &guardedTransport{base: transport, authority: a, caller: caller, certificateID: certificateID, scope: scope}
	client.Transport = guard
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if accountURI != "" && !allowedURL(scope.CA, accountURI) {
		return nil, nil, fault.New("STATE_INVALID", "ACME 账户端点不属于受控 CA")
	}
	result := &xacme.Client{Key: key, HTTPClient: &client, DirectoryURL: endpoint, KID: xacme.KeyID(accountURI), UserAgent: "qwq-acme/1"}
	// 库只在 badNonce 的 400 上到达此回调；有限重试明确拒绝的 nonce，
	// 429/5xx 或未知写入立即返回，原 order/CSR 由持久日志对账。
	result.RetryBackoff = func(n int, _ *http.Request, response *http.Response) time.Duration {
		if response.StatusCode == 400 && n <= 3 {
			return time.Millisecond
		}
		return -1
	}
	return result, guard, nil
}

func caRetryAt(now time.Time, value string) time.Time {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && seconds >= 0 && seconds <= 7*24*60*60 {
		return now.Add(time.Duration(seconds) * time.Second).UTC()
	}
	if parsed, err := http.ParseTime(value); err == nil && !parsed.Before(now) && !parsed.After(now.Add(7*24*time.Hour)) {
		return parsed.UTC()
	}
	return time.Time{}
}

func (a *Authority) authorize(ctx context.Context, caller certificates.Caller, certificateID string, scope certificates.IssuanceScope) error {
	access := certificates.Issue
	if caller.PolicyID != "" {
		access = certificates.RenewExisting
	}
	return a.authorizer.Authorize(ctx, certificates.Authorization{Caller: caller, CertificateID: certificateID, Spec: scope.Spec, Issuance: &scope, Access: access})
}
