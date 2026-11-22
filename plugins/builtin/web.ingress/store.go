// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	maxIngressSites     = 128
	maxIngressSnapshots = 20
)

var (
	domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	headerRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

// SiteRecord 表示一个反向代理虚拟主机配置（BasicAuthHash 仅用于内部与快照，不对外暴露明文口令）。
type SiteRecord struct {
	ID             string            `json:"id"`
	Domain         string            `json:"domain"`
	Enabled        bool              `json:"enabled"`
	UpstreamURL    string            `json:"upstream_url"`
	PathPrefix     string            `json:"path_prefix"`
	WebSocket      bool              `json:"websocket"`
	TLSMode        string            `json:"tls_mode"` // off | managed | custom
	CertID         string            `json:"cert_id,omitempty"`
	ForceHTTPS     bool              `json:"force_https"`
	RateLimitRPS   int               `json:"rate_limit_rps"`
	RateLimitBurst int               `json:"rate_limit_burst"`
	BasicAuthUser  string            `json:"basic_auth_user,omitempty"`
	HasBasicAuth   bool              `json:"has_basic_auth"`
	BasicAuthHash  string            `json:"-"`
	ExtraHeaders   map[string]string `json:"extra_headers,omitempty"`
	Notes          string            `json:"notes,omitempty"`
	Revision       int               `json:"revision"`
	CreatedAt      int64             `json:"created_at"`
	UpdatedAt      int64             `json:"updated_at"`
}

// snapshotSite 保存含密码哈希的完整内部快照，确保回滚不会丢失 BasicAuth 凭据。
type snapshotSite struct {
	SiteRecord
	BasicAuthHash string `json:"basic_auth_hash,omitempty"`
}

// SnapshotRecord 记录一次站点配置变更快照，支持一键回滚。
type SnapshotRecord struct {
	ID        string `json:"id"`
	Revision  int    `json:"revision"`
	Reason    string `json:"reason"`
	SiteCount int    `json:"site_count"`
	CreatedAt int64  `json:"created_at"`
}

type ingressStore struct {
	mu  sync.Mutex
	db  *sql.DB
	now func() time.Time
}

func openIngressStore(dataDir, schemaSQL string, nowFn func() time.Time) (*ingressStore, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir data dir: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(dataDir, "ingress.db")) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=cache_size(-2048)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	return &ingressStore{db: db, now: nowFn}, nil
}

func (s *ingressStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = io.ReadFull(rand.Reader, b)
	return prefix + "_" + hex.EncodeToString(b)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func hasInjectionChars(s string) bool {
	return strings.ContainsAny(s, "\r\n\t\x00;{}\"$`\\")
}

func validateDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	if len(d) == 0 || len(d) > 253 || !domainRe.MatchString(d) {
		return "", errors.New("域名格式非法（仅允许小写字母、数字、连字符和点号，如 app.example.com）")
	}
	return d, nil
}

func validatePathPrefix(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/", nil
	}
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, " \t\r\n\x00;{}\"$`\\?#") {
		return "", errors.New("path_prefix 必须以 / 开头且不得包含空格、.. 或配置注入字符")
	}
	return p, nil
}

func validateUpstreamURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || hasInjectionChars(raw) || strings.ContainsAny(raw, " ") {
		return "", errors.New("upstream_url 非法或包含禁止字符")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("upstream_url 必须是合法的 http:// 或 https:// 地址")
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		// 显式禁止云元数据地址，避免反代配置变成云主机 IMDS 泄露跳板。
		if ip.IsLinkLocalUnicast() || ip == netip.MustParseAddr("169.254.169.254") || ip == netip.MustParseAddr("fd00:ec2::254") {
			return "", errors.New("禁止将云元数据链路本地地址配置为反向代理上游")
		}
	} else if strings.EqualFold(host, "metadata.google.internal") {
		return "", errors.New("禁止将云元数据主机配置为反向代理上游")
	}
	if u.Port() != "" {
		if _, err := net.LookupPort("tcp", u.Port()); err != nil {
			return "", errors.New("upstream_url 端口非法")
		}
	}
	return u.String(), nil
}

func validateHeaders(hdrs map[string]string) (map[string]string, error) {
	if len(hdrs) > 16 {
		return nil, errors.New("自定义响应头最多 16 项")
	}
	out := make(map[string]string, len(hdrs))
	for k, v := range hdrs {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !headerRe.MatchString(k) || len(k) > 64 {
			return nil, fmt.Errorf("非法响应头名 %q", k)
		}
		if len(v) > 256 || hasInjectionChars(v) {
			return nil, fmt.Errorf("响应头 %q 的值包含禁止字符或超长", k)
		}
		out[k] = v
	}
	return out, nil
}

type siteUpsertParams struct {
	ID             string
	Domain         string
	Enabled        bool
	UpstreamURL    string
	PathPrefix     string
	WebSocket      bool
	TLSMode        string
	CertID         string
	ForceHTTPS     bool
	RateLimitRPS   int
	RateLimitBurst int
	BasicAuthUser  string
	BasicAuthPass  string
	ClearBasicAuth bool
	ExtraHeaders   map[string]string
	Notes          string
}

func (s *ingressStore) upsertSite(ctx context.Context, p siteUpsertParams) (SiteRecord, error) {
	domain, err := validateDomain(p.Domain)
	if err != nil {
		return SiteRecord{}, err
	}
	upstream, err := validateUpstreamURL(p.UpstreamURL)
	if err != nil {
		return SiteRecord{}, err
	}
	prefix, err := validatePathPrefix(p.PathPrefix)
	if err != nil {
		return SiteRecord{}, err
	}
	hdrs, err := validateHeaders(p.ExtraHeaders)
	if err != nil {
		return SiteRecord{}, err
	}
	if p.TLSMode == "" {
		p.TLSMode = "managed"
	}
	if p.TLSMode != "off" && p.TLSMode != "managed" && p.TLSMode != "custom" {
		return SiteRecord{}, errors.New("tls_mode 仅支持 off / managed / custom")
	}
	if p.CertID != "" && hasInjectionChars(p.CertID) {
		return SiteRecord{}, errors.New("cert_id 包含非法字符")
	}
	if p.BasicAuthUser != "" && (hasInjectionChars(p.BasicAuthUser) || strings.Contains(p.BasicAuthUser, ":")) {
		return SiteRecord{}, errors.New("basic_auth_user 包含非法字符")
	}
	if p.RateLimitRPS < 0 || p.RateLimitRPS > 10000 || p.RateLimitBurst < 0 || p.RateLimitBurst > 20000 {
		return SiteRecord{}, errors.New("限流参数超出允许范围")
	}
	if p.RateLimitRPS > 0 && p.RateLimitBurst == 0 {
		p.RateLimitBurst = p.RateLimitRPS * 2
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().Unix()
	var existingID, existingUser, existingHash string
	var existingRev int
	if p.ID != "" {
		_ = s.db.QueryRowContext(ctx, `SELECT id, basic_auth_user, basic_auth_hash, revision FROM ingress_sites WHERE id = ?`, p.ID).
			Scan(&existingID, &existingUser, &existingHash, &existingRev)
	} else {
		_ = s.db.QueryRowContext(ctx, `SELECT id, basic_auth_user, basic_auth_hash, revision FROM ingress_sites WHERE domain = ?`, domain).
			Scan(&existingID, &existingUser, &existingHash, &existingRev)
	}

	if existingID == "" {
		var cnt int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ingress_sites`).Scan(&cnt); err == nil && cnt >= maxIngressSites {
			return SiteRecord{}, fmt.Errorf("站点数量已达上限 (%d)", maxIngressSites)
		}
	}

	authUser := strings.TrimSpace(p.BasicAuthUser)
	authHash := existingHash
	if p.ClearBasicAuth {
		authUser = ""
		authHash = ""
	} else if p.BasicAuthPass != "" {
		if authUser == "" {
			authUser = existingUser
		}
		if authUser == "" {
			return SiteRecord{}, errors.New("设置 basic_auth_pass 时必须提供 basic_auth_user")
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(p.BasicAuthPass), bcrypt.DefaultCost)
		if err != nil {
			return SiteRecord{}, err
		}
		authHash = string(hashed)
	} else if authUser == "" {
		authUser = existingUser
	}

	hdrJSON, _ := json.Marshal(hdrs)
	if existingID == "" {
		existingID = newID("ing")
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO ingress_sites
			 (id, domain, enabled, upstream_url, path_prefix, websocket, tls_mode, cert_id, force_https,
			  rate_limit_rps, rate_limit_burst, basic_auth_user, basic_auth_hash, extra_headers_json, notes, revision, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			existingID, domain, boolInt(p.Enabled), upstream, prefix, boolInt(p.WebSocket), p.TLSMode,
			strings.TrimSpace(p.CertID), boolInt(p.ForceHTTPS), p.RateLimitRPS, p.RateLimitBurst,
			authUser, authHash, string(hdrJSON), strings.TrimSpace(p.Notes), now, now)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE ingress_sites SET domain = ?, enabled = ?, upstream_url = ?, path_prefix = ?, websocket = ?,
			 tls_mode = ?, cert_id = ?, force_https = ?, rate_limit_rps = ?, rate_limit_burst = ?,
			 basic_auth_user = ?, basic_auth_hash = ?, extra_headers_json = ?, notes = ?, revision = ?, updated_at = ?
			 WHERE id = ?`,
			domain, boolInt(p.Enabled), upstream, prefix, boolInt(p.WebSocket), p.TLSMode,
			strings.TrimSpace(p.CertID), boolInt(p.ForceHTTPS), p.RateLimitRPS, p.RateLimitBurst,
			authUser, authHash, string(hdrJSON), strings.TrimSpace(p.Notes), existingRev+1, now, existingID)
	}
	if err != nil {
		return SiteRecord{}, err
	}
	_ = s.createSnapshotLocked(ctx, "upsert:"+domain)
	return s.getSiteLocked(ctx, existingID)
}

func (s *ingressStore) deleteSite(ctx context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.ExecContext(ctx, `DELETE FROM ingress_sites WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_ = s.createSnapshotLocked(ctx, "delete:"+id)
	}
	return n > 0, nil
}

func (s *ingressStore) getSiteLocked(ctx context.Context, id string) (SiteRecord, error) {
	var r SiteRecord
	var enabled, ws, forceHTTPS int
	var hdrRaw string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, domain, enabled, upstream_url, path_prefix, websocket, tls_mode, cert_id, force_https,
		        rate_limit_rps, rate_limit_burst, basic_auth_user, basic_auth_hash, extra_headers_json, notes, revision, created_at, updated_at
		 FROM ingress_sites WHERE id = ?`, id).Scan(
		&r.ID, &r.Domain, &enabled, &r.UpstreamURL, &r.PathPrefix, &ws, &r.TLSMode, &r.CertID, &forceHTTPS,
		&r.RateLimitRPS, &r.RateLimitBurst, &r.BasicAuthUser, &r.BasicAuthHash, &hdrRaw, &r.Notes,
		&r.Revision, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	r.Enabled = enabled == 1
	r.WebSocket = ws == 1
	r.ForceHTTPS = forceHTTPS == 1
	r.HasBasicAuth = r.BasicAuthUser != "" && r.BasicAuthHash != ""
	_ = json.Unmarshal([]byte(hdrRaw), &r.ExtraHeaders)
	return r, nil
}

func (s *ingressStore) listSites(ctx context.Context) ([]SiteRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listSitesLocked(ctx)
}

func (s *ingressStore) listSitesLocked(ctx context.Context) ([]SiteRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, domain, enabled, upstream_url, path_prefix, websocket, tls_mode, cert_id, force_https,
		        rate_limit_rps, rate_limit_burst, basic_auth_user, basic_auth_hash, extra_headers_json, notes, revision, created_at, updated_at
		 FROM ingress_sites ORDER BY domain ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SiteRecord, 0)
	for rows.Next() {
		var r SiteRecord
		var enabled, ws, forceHTTPS int
		var hdrRaw string
		if err := rows.Scan(
			&r.ID, &r.Domain, &enabled, &r.UpstreamURL, &r.PathPrefix, &ws, &r.TLSMode, &r.CertID, &forceHTTPS,
			&r.RateLimitRPS, &r.RateLimitBurst, &r.BasicAuthUser, &r.BasicAuthHash, &hdrRaw, &r.Notes,
			&r.Revision, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		r.WebSocket = ws == 1
		r.ForceHTTPS = forceHTTPS == 1
		r.HasBasicAuth = r.BasicAuthUser != "" && r.BasicAuthHash != ""
		_ = json.Unmarshal([]byte(hdrRaw), &r.ExtraHeaders)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *ingressStore) createSnapshotLocked(ctx context.Context, reason string) error {
	sites, err := s.listSitesLocked(ctx)
	if err != nil {
		return err
	}
	snaps := make([]snapshotSite, 0, len(sites))
	for _, st := range sites {
		snaps = append(snaps, snapshotSite{SiteRecord: st, BasicAuthHash: st.BasicAuthHash})
	}
	raw, _ := json.Marshal(snaps)
	var nextRev int
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) + 1 FROM ingress_snapshots`).Scan(&nextRev)
	if nextRev <= 0 {
		nextRev = 1
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO ingress_snapshots (id, revision, reason, sites_json, created_at) VALUES (?, ?, ?, ?, ?)`,
		newID("snp"), nextRev, reason, string(raw), s.now().Unix()); err != nil {
		return err
	}
	_, _ = s.db.ExecContext(ctx,
		`DELETE FROM ingress_snapshots WHERE id NOT IN (SELECT id FROM ingress_snapshots ORDER BY revision DESC LIMIT ?)`,
		maxIngressSnapshots)
	return nil
}

func (s *ingressStore) listSnapshots(ctx context.Context) ([]SnapshotRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, revision, reason, sites_json, created_at FROM ingress_snapshots ORDER BY revision DESC LIMIT ?`,
		maxIngressSnapshots)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SnapshotRecord, 0)
	for rows.Next() {
		var rec SnapshotRecord
		var raw string
		if err := rows.Scan(&rec.ID, &rec.Revision, &rec.Reason, &raw, &rec.CreatedAt); err != nil {
			return nil, err
		}
		var items []snapshotSite
		if json.Unmarshal([]byte(raw), &items) == nil {
			rec.SiteCount = len(items)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *ingressStore) rollbackToSnapshot(ctx context.Context, snapshotID string, targetRev int) (SnapshotRecord, []SiteRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var rec SnapshotRecord
	var raw string
	var err error
	if snapshotID != "" {
		err = s.db.QueryRowContext(ctx,
			`SELECT id, revision, reason, sites_json, created_at FROM ingress_snapshots WHERE id = ?`, snapshotID).
			Scan(&rec.ID, &rec.Revision, &rec.Reason, &raw, &rec.CreatedAt)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT id, revision, reason, sites_json, created_at FROM ingress_snapshots WHERE revision = ?`, targetRev).
			Scan(&rec.ID, &rec.Revision, &rec.Reason, &raw, &rec.CreatedAt)
	}
	if err != nil {
		return rec, nil, errors.New("目标快照不存在")
	}

	var items []snapshotSite
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return rec, nil, err
	}
	rec.SiteCount = len(items)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rec, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM ingress_sites`); err != nil {
		return rec, nil, err
	}
	for _, it := range items {
		hdrJSON, _ := json.Marshal(it.ExtraHeaders)
		if len(hdrJSON) == 0 || string(hdrJSON) == "null" {
			hdrJSON = []byte("{}")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO ingress_sites
			 (id, domain, enabled, upstream_url, path_prefix, websocket, tls_mode, cert_id, force_https,
			  rate_limit_rps, rate_limit_burst, basic_auth_user, basic_auth_hash, extra_headers_json, notes, revision, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			it.ID, it.Domain, boolInt(it.Enabled), it.UpstreamURL, it.PathPrefix, boolInt(it.WebSocket),
			it.TLSMode, it.CertID, boolInt(it.ForceHTTPS), it.RateLimitRPS, it.RateLimitBurst,
			it.BasicAuthUser, it.BasicAuthHash, string(hdrJSON), it.Notes, it.Revision, it.CreatedAt, it.UpdatedAt); err != nil {
			return rec, nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return rec, nil, err
	}
	sites, err := s.listSitesLocked(ctx)
	return rec, sites, err
}
