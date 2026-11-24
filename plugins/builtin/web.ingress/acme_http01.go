// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	DefaultIngressHTTPAddr  = ":80"
	DefaultIngressHTTPSAddr = ":443"
)

// NormalizeIngressListenAddrs 为空配置补齐默认 ":80" / ":443" 监听；显式传入 "off" / "none" / "disabled" 时关闭对应监听。
func NormalizeIngressListenAddrs(rawHTTP, rawHTTPS string) (httpAddr, httpsAddr string) {
	h := strings.TrimSpace(rawHTTP)
	switch strings.ToLower(h) {
	case "off", "none", "disabled":
		httpAddr = ""
	case "":
		httpAddr = DefaultIngressHTTPAddr
	default:
		httpAddr = h
	}

	s := strings.TrimSpace(rawHTTPS)
	switch strings.ToLower(s) {
	case "off", "none", "disabled":
		httpsAddr = ""
	case "":
		httpsAddr = DefaultIngressHTTPSAddr
	default:
		httpsAddr = s
	}
	return httpAddr, httpsAddr
}

// ACMEHTTP01ChallengeStore 挂载在内置反代 HTTP 入口最外层，直接响应 Let's Encrypt 的
// `GET /.well-known/acme-challenge/<token>` 挑战，支持免 DNS Token 自动签发证书。
type ACMEHTTP01ChallengeStore struct {
	mu      sync.RWMutex
	now     func() time.Time
	records map[string]acmeTokenEntry
}

type acmeTokenEntry struct {
	keyAuth   string
	expiresAt time.Time
}

func NewACMEHTTP01ChallengeStore(nowFn func() time.Time) *ACMEHTTP01ChallengeStore {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &ACMEHTTP01ChallengeStore{
		now:     nowFn,
		records: make(map[string]acmeTokenEntry),
	}
}

func (s *ACMEHTTP01ChallengeStore) Present(token, keyAuth string, ttl time.Duration) error {
	token = strings.TrimSpace(token)
	keyAuth = strings.TrimSpace(keyAuth)
	if token == "" || len(token) > 256 || strings.ContainsAny(token, "/\\ \t\r\n") || strings.Contains(token, "..") || keyAuth == "" || len(keyAuth) > 512 {
		return errors.New("非法的 ACME HTTP-01 challenge 参数")
	}
	if ttl <= 0 || ttl > 30*time.Minute {
		ttl = 10 * time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.records {
		if now.After(v.expiresAt) {
			delete(s.records, k)
		}
	}
	if len(s.records) >= 256 {
		return errors.New("ACME HTTP-01 并发 challenge 数量已达上限")
	}
	s.records[token] = acmeTokenEntry{keyAuth: keyAuth, expiresAt: now.Add(ttl)}
	return nil
}

func (s *ACMEHTTP01ChallengeStore) CleanUp(token string) {
	s.mu.Lock()
	delete(s.records, strings.TrimSpace(token))
	s.mu.Unlock()
}

// ServeChallengeIfMatched 在常规站点路由与 HTTPS 重定向之前拦截命中的 ACME HTTP-01 挑战请求。
func (s *ACMEHTTP01ChallengeStore) ServeChallengeIfMatched(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/.well-known/acme-challenge/"
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	if token == "" || strings.Contains(token, "/") {
		return false
	}
	s.mu.RLock()
	ent, ok := s.records[token]
	s.mu.RUnlock()
	if !ok || s.now().After(ent.expiresAt) {
		return false
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(ent.keyAuth))
	}
	return true
}
