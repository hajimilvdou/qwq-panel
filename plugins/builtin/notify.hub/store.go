// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxChannelsStored   = 64
	maxRulesStored      = 128
	maxDeliveriesStored = 500
)

// ChannelConfig 保存单个通知渠道的完整明文配置（落盘前使用 AES-256-GCM 加密，永不原样回传前端）。
type ChannelConfig struct {
	// Telegram
	BotToken string `json:"bot_token,omitempty"`
	ChatID   string `json:"chat_id,omitempty"`
	ThreadID string `json:"thread_id,omitempty"`
	APIBase  string `json:"api_base,omitempty"`
	// Webhook / Feishu / DingTalk / WeCom / Discord
	WebhookURL string            `json:"webhook_url,omitempty"`
	Secret     string            `json:"secret,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	// SMTP
	SMTPHost string   `json:"smtp_host,omitempty"`
	SMTPPort int      `json:"smtp_port,omitempty"`
	SMTPUser string   `json:"smtp_user,omitempty"`
	SMTPPass string   `json:"smtp_pass,omitempty"`
	SMTPFrom string   `json:"smtp_from,omitempty"`
	SMTPTo   []string `json:"smtp_to,omitempty"`
	SMTPTLS  bool     `json:"smtp_tls,omitempty"`
}

// ChannelRecord 是面向管理接口/UI 的脱敏渠道视图。
type ChannelRecord struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Enabled    bool           `json:"enabled"`
	Masked     map[string]any `json:"config_masked"`
	LastStatus string         `json:"last_status"`
	LastError  string         `json:"last_error,omitempty"`
	LastSentAt int64          `json:"last_sent_at"`
	CreatedAt  int64          `json:"created_at"`
	UpdatedAt  int64          `json:"updated_at"`
}

type channelWithSecret struct {
	ChannelRecord
	Config ChannelConfig
}

// RuleRecord 描述告警路由、去重冷却与静默时段策略。
type RuleRecord struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Enabled             bool     `json:"enabled"`
	SourcePattern       string   `json:"source_pattern"`
	MinSeverity         string   `json:"min_severity"`
	ChannelIDs          []string `json:"channel_ids"`
	CooldownSec         int      `json:"cooldown_sec"`
	QuietStart          string   `json:"quiet_start,omitempty"`
	QuietEnd            string   `json:"quiet_end,omitempty"`
	QuietTZ             string   `json:"quiet_tz"`
	AllowCriticalBypass bool     `json:"allow_critical_bypass"`
	CreatedAt           int64    `json:"created_at"`
	UpdatedAt           int64    `json:"updated_at"`
}

// DeliveryRecord 记录单次通知投递或静默/降噪拦截审计。
type DeliveryRecord struct {
	ID          string `json:"id"`
	EventID     string `json:"event_id"`
	Source      string `json:"source"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	Status      string `json:"status"`
	Attempts    int    `json:"attempts"`
	HTTPStatus  int    `json:"http_status"`
	ErrorMsg    string `json:"error_msg,omitempty"`
	CreatedAt   int64  `json:"created_at"`
}

type store struct {
	mu        sync.Mutex
	db        *sql.DB
	masterKey []byte
	now       func() time.Time
}

func openStore(dataDir, schemaSQL string, nowFn func() time.Time) (*store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir data dir: %w", err)
	}
	masterKey, err := loadOrCreateKey(filepath.Join(dataDir, "notify.key"))
	if err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(dataDir, "notify.db")) +
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
	return &store{db: db, masterKey: masterKey, now: nowFn}, nil
}

func (s *store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func loadOrCreateKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) == 32 {
		return raw, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("gen key: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("rename key: %w", err)
	}
	return key, nil
}

func (s *store) encryptConfig(cfg ChannelConfig) ([]byte, error) {
	plain, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func (s *store) decryptConfig(blob []byte) (ChannelConfig, error) {
	var cfg ChannelConfig
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return cfg, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return cfg, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return cfg, errors.New("corrupt encrypted config")
	}
	plain, err := gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func maskChannelConfig(kind string, cfg ChannelConfig) map[string]any {
	out := map[string]any{}
	switch kind {
	case "telegram":
		out["chat_id"] = cfg.ChatID
		out["has_token"] = cfg.BotToken != ""
		if cfg.ThreadID != "" {
			out["thread_id"] = cfg.ThreadID
		}
		if cfg.APIBase != "" {
			out["api_base"] = redactURL(cfg.APIBase)
		}
	case "smtp":
		out["smtp_host"] = cfg.SMTPHost
		out["smtp_port"] = cfg.SMTPPort
		out["smtp_from"] = cfg.SMTPFrom
		out["smtp_to_count"] = len(cfg.SMTPTo)
		out["smtp_tls"] = cfg.SMTPTLS
		out["has_password"] = cfg.SMTPPass != ""
	default:
		out["webhook_host"] = redactURL(cfg.WebhookURL)
		out["has_secret"] = cfg.Secret != ""
		if len(cfg.Headers) > 0 {
			out["custom_header_count"] = len(cfg.Headers)
		}
	}
	return out
}

func redactURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/***"
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

func (s *store) upsertChannel(ctx context.Context, id, name, kind string, enabled bool, cfg ChannelConfig) (ChannelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().Unix()
	var existingID string
	var existingEnc []byte
	if id != "" {
		_ = s.db.QueryRowContext(ctx, `SELECT id, config_enc FROM notify_channels WHERE id = ?`, id).Scan(&existingID, &existingEnc)
	} else {
		_ = s.db.QueryRowContext(ctx, `SELECT id, config_enc FROM notify_channels WHERE name = ?`, name).Scan(&existingID, &existingEnc)
	}

	// 编辑既有渠道时若敏感字段留空，则保留原有已加密密钥。
	if len(existingEnc) > 0 {
		if prev, err := s.decryptConfig(existingEnc); err == nil {
			if cfg.BotToken == "" {
				cfg.BotToken = prev.BotToken
			}
			if cfg.WebhookURL == "" {
				cfg.WebhookURL = prev.WebhookURL
			}
			if cfg.Secret == "" {
				cfg.Secret = prev.Secret
			}
			if cfg.SMTPPass == "" {
				cfg.SMTPPass = prev.SMTPPass
			}
		}
	} else {
		var count int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notify_channels`).Scan(&count); err == nil && count >= maxChannelsStored {
			return ChannelRecord{}, fmt.Errorf("channel limit reached (%d)", maxChannelsStored)
		}
	}

	if err := validateChannelConfig(kind, cfg); err != nil {
		return ChannelRecord{}, err
	}
	enc, err := s.encryptConfig(cfg)
	if err != nil {
		return ChannelRecord{}, err
	}
	masked := maskChannelConfig(kind, cfg)
	maskedJSON, _ := json.Marshal(masked)

	if existingID == "" {
		existingID = newID("nch")
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO notify_channels (id, name, kind, enabled, config_enc, config_masked_json, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			existingID, name, kind, boolInt(enabled), enc, string(maskedJSON), now, now)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE notify_channels SET name = ?, kind = ?, enabled = ?, config_enc = ?, config_masked_json = ?, updated_at = ?
			 WHERE id = ?`,
			name, kind, boolInt(enabled), enc, string(maskedJSON), now, existingID)
	}
	if err != nil {
		return ChannelRecord{}, err
	}
	return s.getChannelLocked(ctx, existingID)
}

func (s *store) getChannelLocked(ctx context.Context, id string) (ChannelRecord, error) {
	var rec ChannelRecord
	var enabled int
	var maskedRaw string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, kind, enabled, config_masked_json, last_status, last_error, last_sent_at, created_at, updated_at
		 FROM notify_channels WHERE id = ?`, id).Scan(
		&rec.ID, &rec.Name, &rec.Kind, &enabled, &maskedRaw,
		&rec.LastStatus, &rec.LastError, &rec.LastSentAt, &rec.CreatedAt, &rec.UpdatedAt)
	if err != nil {
		return rec, err
	}
	rec.Enabled = enabled == 1
	_ = json.Unmarshal([]byte(maskedRaw), &rec.Masked)
	if rec.Masked == nil {
		rec.Masked = map[string]any{}
	}
	return rec, nil
}

func (s *store) getChannelWithSecret(ctx context.Context, id string) (channelWithSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out channelWithSecret
	var enabled int
	var enc []byte
	var maskedRaw string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, kind, enabled, config_enc, config_masked_json, last_status, last_error, last_sent_at, created_at, updated_at
		 FROM notify_channels WHERE id = ?`, id).Scan(
		&out.ID, &out.Name, &out.Kind, &enabled, &enc, &maskedRaw,
		&out.LastStatus, &out.LastError, &out.LastSentAt, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	out.Enabled = enabled == 1
	_ = json.Unmarshal([]byte(maskedRaw), &out.Masked)
	cfg, err := s.decryptConfig(enc)
	if err != nil {
		return out, err
	}
	out.Config = cfg
	return out, nil
}

func (s *store) listChannels(ctx context.Context) ([]ChannelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, kind, enabled, config_masked_json, last_status, last_error, last_sent_at, created_at, updated_at
		 FROM notify_channels ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ChannelRecord, 0)
	for rows.Next() {
		var rec ChannelRecord
		var enabled int
		var maskedRaw string
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.Kind, &enabled, &maskedRaw,
			&rec.LastStatus, &rec.LastError, &rec.LastSentAt, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		rec.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(maskedRaw), &rec.Masked)
		if rec.Masked == nil {
			rec.Masked = map[string]any{}
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *store) deleteChannel(ctx context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.ExecContext(ctx, `DELETE FROM notify_channels WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *store) markChannelStatus(ctx context.Context, id, status, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(errMsg) > 240 {
		errMsg = errMsg[:240]
	}
	_, _ = s.db.ExecContext(ctx,
		`UPDATE notify_channels SET last_status = ?, last_error = ?, last_sent_at = ?, updated_at = ? WHERE id = ?`,
		status, errMsg, s.now().Unix(), s.now().Unix(), id)
}

func (s *store) upsertRule(ctx context.Context, rec RuleRecord) (RuleRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	var existingID string
	if rec.ID != "" {
		_ = s.db.QueryRowContext(ctx, `SELECT id FROM notify_rules WHERE id = ?`, rec.ID).Scan(&existingID)
	} else {
		_ = s.db.QueryRowContext(ctx, `SELECT id FROM notify_rules WHERE name = ?`, rec.Name).Scan(&existingID)
	}
	if existingID == "" {
		var count int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notify_rules`).Scan(&count); err == nil && count >= maxRulesStored {
			return RuleRecord{}, fmt.Errorf("rule limit reached (%d)", maxRulesStored)
		}
	}
	if rec.ChannelIDs == nil {
		rec.ChannelIDs = []string{}
	}
	chJSON, _ := json.Marshal(rec.ChannelIDs)
	if rec.QuietTZ == "" {
		rec.QuietTZ = "UTC"
	}
	var err error
	if existingID == "" {
		existingID = newID("nrl")
		rec.ID = existingID
		rec.CreatedAt = now
		rec.UpdatedAt = now
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO notify_rules (id, name, enabled, source_pattern, min_severity, channel_ids_json, cooldown_sec, quiet_start, quiet_end, quiet_tz, allow_critical_bypass, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rec.ID, rec.Name, boolInt(rec.Enabled), rec.SourcePattern, rec.MinSeverity, string(chJSON),
			rec.CooldownSec, rec.QuietStart, rec.QuietEnd, rec.QuietTZ, boolInt(rec.AllowCriticalBypass), now, now)
	} else {
		rec.ID = existingID
		rec.UpdatedAt = now
		_, err = s.db.ExecContext(ctx,
			`UPDATE notify_rules SET name = ?, enabled = ?, source_pattern = ?, min_severity = ?, channel_ids_json = ?,
			 cooldown_sec = ?, quiet_start = ?, quiet_end = ?, quiet_tz = ?, allow_critical_bypass = ?, updated_at = ?
			 WHERE id = ?`,
			rec.Name, boolInt(rec.Enabled), rec.SourcePattern, rec.MinSeverity, string(chJSON),
			rec.CooldownSec, rec.QuietStart, rec.QuietEnd, rec.QuietTZ, boolInt(rec.AllowCriticalBypass), now, existingID)
	}
	if err != nil {
		return RuleRecord{}, err
	}
	return rec, nil
}

func (s *store) listRules(ctx context.Context) ([]RuleRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, enabled, source_pattern, min_severity, channel_ids_json, cooldown_sec,
		        quiet_start, quiet_end, quiet_tz, allow_critical_bypass, created_at, updated_at
		 FROM notify_rules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RuleRecord, 0)
	for rows.Next() {
		var r RuleRecord
		var enabled, bypass int
		var chRaw string
		if err := rows.Scan(&r.ID, &r.Name, &enabled, &r.SourcePattern, &r.MinSeverity, &chRaw,
			&r.CooldownSec, &r.QuietStart, &r.QuietEnd, &r.QuietTZ, &bypass, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		r.AllowCriticalBypass = bypass == 1
		_ = json.Unmarshal([]byte(chRaw), &r.ChannelIDs)
		if r.ChannelIDs == nil {
			r.ChannelIDs = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *store) deleteRule(ctx context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.ExecContext(ctx, `DELETE FROM notify_rules WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *store) recordDelivery(ctx context.Context, d DeliveryRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == "" {
		d.ID = newID("ndl")
	}
	if d.CreatedAt == 0 {
		d.CreatedAt = s.now().Unix()
	}
	if len(d.ErrorMsg) > 300 {
		d.ErrorMsg = d.ErrorMsg[:300]
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO notify_deliveries (id, event_id, source, severity, title, channel_id, channel_name, status, attempts, http_status, error_msg, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.EventID, d.Source, d.Severity, d.Title, d.ChannelID, d.ChannelName,
		d.Status, d.Attempts, d.HTTPStatus, d.ErrorMsg, d.CreatedAt); err != nil {
		return err
	}
	// 有界留存：仅保留最新 500 条投递审计，防止 1C1G 磁盘膨胀。
	_, _ = s.db.ExecContext(ctx,
		`DELETE FROM notify_deliveries WHERE id NOT IN (SELECT id FROM notify_deliveries ORDER BY created_at DESC LIMIT ?)`,
		maxDeliveriesStored)
	return nil
}

func (s *store) listDeliveries(ctx context.Context, limit int) ([]DeliveryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, event_id, source, severity, title, channel_id, channel_name, status, attempts, http_status, error_msg, created_at
		 FROM notify_deliveries ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]DeliveryRecord, 0)
	for rows.Next() {
		var d DeliveryRecord
		if err := rows.Scan(&d.ID, &d.EventID, &d.Source, &d.Severity, &d.Title, &d.ChannelID,
			&d.ChannelName, &d.Status, &d.Attempts, &d.HTTPStatus, &d.ErrorMsg, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *store) stats24h(ctx context.Context) (sent, failed, suppressed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	since := s.now().Add(-24 * time.Hour).Unix()
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM notify_deliveries WHERE created_at >= ? GROUP BY status`, since)
	if err != nil {
		return 0, 0, 0
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var cnt int
		if rows.Scan(&st, &cnt) == nil {
			switch st {
			case "sent":
				sent += cnt
			case "failed":
				failed += cnt
			default:
				suppressed += cnt
			}
		}
	}
	return sent, failed, suppressed
}
