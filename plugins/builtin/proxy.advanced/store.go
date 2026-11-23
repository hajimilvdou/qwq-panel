// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== SQLite 存储层与 0x5100..0x51FF 标记分配器 ========================

//go:embed schema.sql
var schemaSQL string

const (
	trafficMarkMin          = 20736 // 0x5100
	trafficMarkMax          = 20991 // 0x51FF
	maxSubAccessLogsPerUser = 20
	maxPendingSubAccessLogs = 256
	subAccessFlushBatchSize = 64
	subAccessFlushInterval  = 30 * time.Second
	maxListUsersLimit       = 10000
	rollupRetentionDays     = 90
)

type subAccessEntry struct {
	userID     string
	accessedAt int64
	format     string
	uaSummary  string
	statusCode int
}

type planRecord struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	QuotaBytes      int64  `json:"quota_bytes"`
	DownLimitKbps   uint32 `json:"down_limit_kbps"`
	UpLimitKbps     uint32 `json:"up_limit_kbps"`
	MaxConnections  int    `json:"max_connections"`
	MaxIPs          int    `json:"max_ips"`
	BillingResetDay int    `json:"billing_reset_day"`
	ValidityDays    int    `json:"validity_days"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
	Revision        int64  `json:"revision"`
}

type userRecord struct {
	ID                      string `json:"id"`
	DisplayName             string `json:"display_name"`
	PlanID                  string `json:"plan_id"`
	VLESSUUID               string `json:"-"`
	Hy2Password             string `json:"-"`
	SS2022UserKey           string `json:"-"`
	TrafficMark             uint32 `json:"traffic_mark"`
	Status                  string `json:"status"`
	ExpiresAt               int64  `json:"expires_at"`
	SubTokenSHA256          string `json:"-"`
	QuotaBytes              int64  `json:"quota_bytes"`
	DownLimitKbps           uint32 `json:"down_limit_kbps"`
	UpLimitKbps             uint32 `json:"up_limit_kbps"`
	PlanMaxConnections      int    `json:"-"`
	PlanMaxIPs              int    `json:"-"`
	MaxConnectionsOverride  int    `json:"max_connections_override"`
	MaxIPsOverride          int    `json:"max_ips_override"`
	EffectiveMaxConnections int    `json:"effective_max_connections"`
	EffectiveMaxIPs         int    `json:"effective_max_ips"`
	ActiveConnections       int    `json:"active_connections"`
	ActiveIPs               int    `json:"active_ips"`
	ChainID                 string `json:"chain_id"`
	PeriodUpBytes           int64  `json:"period_up_bytes"`
	PeriodDownBytes         int64  `json:"period_down_bytes"`
	TotalUpBytes            int64  `json:"total_up_bytes"`
	TotalDownBytes          int64  `json:"total_down_bytes"`
	CreatedAt               int64  `json:"created_at"`
	UpdatedAt               int64  `json:"updated_at"`
	Revision                int64  `json:"revision"`
}

type usageSample struct {
	UserID  string
	RawUp   int64
	RawDown int64
	HasUp   bool
	HasDown bool
}

type usageRollupPoint struct {
	BucketHourMS int64 `json:"bucket_hour_ms"`
	UpBytes      int64 `json:"up_bytes"`
	DownBytes    int64 `json:"down_bytes"`
}

type overviewStats struct {
	TotalPlans          int
	TotalUsers          int
	ActiveUsers         int
	SuspendedQuotaUsers int
	ExpiredUsers        int
	DisabledUsers       int
	PeriodUpBytes       int64
	PeriodDownBytes     int64
	UsedTrafficMarks    int
}

type proxyStore struct {
	db        *sql.DB // 1 Writer (BEGIN IMMEDIATE + WAL)
	reader    *sql.DB // 4 Readers (query_only=1)
	masterKey []byte
	now       func() time.Time
	closeOnce sync.Once

	subLogMu       sync.Mutex
	pendingSubLogs []subAccessEntry
	subFlushWake   chan struct{}
	subFlushStop   chan struct{}
	subFlushDone   chan struct{}
}

func (s *proxyStore) readDB() *sql.DB {
	if s.reader != nil {
		return s.reader
	}
	return s.db
}

func ensureColumnExists(db *sql.DB, table, col, ddl string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err == nil && name == col {
			return nil
		}
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + ddl)
	return err
}

func openDualSQLiteLocal(dbFilePath string, maxReaders int) (writer *sql.DB, reader *sql.DB, err error) {
	if maxReaders <= 0 {
		maxReaders = 4
	}
	if dbFilePath == ":memory:" {
		wdb, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			return nil, nil, fmt.Errorf("open sqlite memory: %w", err)
		}
		wdb.SetMaxOpenConns(1)
		wdb.SetMaxIdleConns(1)
		for _, p := range []string{
			"PRAGMA foreign_keys=ON;",
			"PRAGMA busy_timeout=5000;",
			"PRAGMA cache_size=-2048;",
			"PRAGMA temp_store=MEMORY;",
		} {
			if _, err := wdb.Exec(p); err != nil {
				_ = wdb.Close()
				return nil, nil, fmt.Errorf("apply pragma %q: %w", p, err)
			}
		}
		return wdb, wdb, nil
	}

	u := url.URL{
		Scheme: "file",
		Path:   filepath.ToSlash(dbFilePath),
	}
	writeQ := url.Values{}
	writeQ.Add("_txlock", "immediate")
	writeQ.Add("_pragma", "journal_mode(WAL)")
	writeQ.Add("_pragma", "synchronous(NORMAL)")
	writeQ.Add("_pragma", "busy_timeout(5000)")
	writeQ.Add("_pragma", "foreign_keys(1)")
	writeQ.Add("_pragma", "journal_size_limit(8388608)")
	writeQ.Add("_pragma", "cache_size(-2048)")
	writeQ.Add("_pragma", "temp_store(MEMORY)")
	u.RawQuery = writeQ.Encode()

	wdb, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite writer: %w", err)
	}
	wdb.SetMaxOpenConns(1)
	wdb.SetMaxIdleConns(1)
	if err := wdb.Ping(); err != nil {
		_ = wdb.Close()
		return nil, nil, fmt.Errorf("ping sqlite writer: %w", err)
	}

	readQ := url.Values{}
	readQ.Add("_pragma", "query_only(1)")
	readQ.Add("_pragma", "busy_timeout(5000)")
	readQ.Add("_pragma", "cache_size(-2048)")
	readQ.Add("_pragma", "temp_store(MEMORY)")
	u.RawQuery = readQ.Encode()

	rdb, err := sql.Open("sqlite", u.String())
	if err != nil {
		_ = wdb.Close()
		return nil, nil, fmt.Errorf("open sqlite reader: %w", err)
	}
	rdb.SetMaxOpenConns(maxReaders)
	rdb.SetMaxIdleConns(min(2, maxReaders))
	if err := rdb.Ping(); err != nil {
		_ = rdb.Close()
		_ = wdb.Close()
		return nil, nil, fmt.Errorf("ping sqlite reader: %w", err)
	}
	return wdb, rdb, nil
}

func openStore(dataDir string, now func() time.Time) (*proxyStore, error) {
	if now == nil {
		now = time.Now
	}
	dbPath := ":memory:"
	if strings.TrimSpace(dataDir) != "" {
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return nil, fmt.Errorf("create proxy data dir: %w", err)
		}
		dbPath = filepath.Join(dataDir, "proxy.db")
	}
	masterKey, err := loadOrCreateMasterKey(dataDir)
	if err != nil {
		return nil, fmt.Errorf("init proxy key: %w", err)
	}
	wdb, rdb, err := openDualSQLiteLocal(dbPath, 4)
	if err != nil {
		return nil, err
	}
	if _, err := wdb.Exec(schemaSQL); err != nil {
		if rdb != nil && rdb != wdb {
			_ = rdb.Close()
		}
		_ = wdb.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	// 幂等升级既有 proxy.db 表结构，保留历史数据零丢失。
	for _, colSpec := range [][3]string{
		{"plans", "max_connections", "max_connections INTEGER NOT NULL DEFAULT 0"},
		{"plans", "max_ips", "max_ips INTEGER NOT NULL DEFAULT 0"},
		{"proxy_users", "max_connections_override", "max_connections_override INTEGER NOT NULL DEFAULT -1"},
		{"proxy_users", "max_ips_override", "max_ips_override INTEGER NOT NULL DEFAULT -1"},
		{"proxy_users", "chain_id", "chain_id TEXT NOT NULL DEFAULT ''"},
		{"tuning_snapshots", "pinned", "pinned INTEGER NOT NULL DEFAULT 0"},
		{"brutal_bindings", "proxy_protocol_v2", "proxy_protocol_v2 INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := ensureColumnExists(wdb, colSpec[0], colSpec[1], colSpec[2]); err != nil {
			if rdb != nil && rdb != wdb {
				_ = rdb.Close()
			}
			_ = wdb.Close()
			return nil, fmt.Errorf("migrate %s.%s: %w", colSpec[0], colSpec[1], err)
		}
	}
	st := &proxyStore{
		db:           wdb,
		reader:       rdb,
		masterKey:    masterKey,
		now:          now,
		subFlushWake: make(chan struct{}, 1),
		subFlushStop: make(chan struct{}),
		subFlushDone: make(chan struct{}),
	}
	go st.subAccessFlushLoop()
	return st, nil
}

func (s *proxyStore) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.subFlushStop != nil {
			close(s.subFlushStop)
			if s.subFlushDone != nil {
				<-s.subFlushDone
			}
		}
		_ = s.FlushSubscriptionAccessLogs(context.Background())
		var errR, errW error
		if s.reader != nil && s.reader != s.db {
			errR = s.reader.Close()
		}
		if s.db != nil {
			_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
			errW = s.db.Close()
		}
		err = errors.Join(errR, errW)
	})
	return err
}

// ======================== 套餐与多用户 CRUD ========================

func (s *proxyStore) ListPlans(ctx context.Context, limit int) ([]planRecord, error) {
	if limit <= 0 || limit > 256 {
		limit = 100
	}
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT id, name, quota_bytes, down_limit_kbps, up_limit_kbps, max_connections, max_ips,
		       billing_reset_day, validity_days, created_at, updated_at, revision
		FROM plans
		ORDER BY id ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]planRecord, 0)
	for rows.Next() {
		var p planRecord
		if err := rows.Scan(&p.ID, &p.Name, &p.QuotaBytes, &p.DownLimitKbps, &p.UpLimitKbps, &p.MaxConnections, &p.MaxIPs,
			&p.BillingResetDay, &p.ValidityDays, &p.CreatedAt, &p.UpdatedAt, &p.Revision); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *proxyStore) UpsertPlan(ctx context.Context, in plansUpsertRequest, expectedRev string) (planRecord, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return planRecord{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	nowMs := s.now().UTC().UnixMilli()
	var existing planRecord
	err = tx.QueryRowContext(ctx, `
		SELECT id, name, quota_bytes, down_limit_kbps, up_limit_kbps, max_connections, max_ips,
		       billing_reset_day, validity_days, created_at, updated_at, revision
		FROM plans WHERE id = ?`, in.ID).Scan(
		&existing.ID, &existing.Name, &existing.QuotaBytes, &existing.DownLimitKbps, &existing.UpLimitKbps,
		&existing.MaxConnections, &existing.MaxIPs,
		&existing.BillingResetDay, &existing.ValidityDays, &existing.CreatedAt, &existing.UpdatedAt, &existing.Revision)

	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return planRecord{}, false, err
	}

	resetDay := 1
	if in.BillingResetDay != nil {
		resetDay = *in.BillingResetDay
	} else if !created {
		resetDay = existing.BillingResetDay
	}
	maxConns := in.MaxConnections
	maxIPs := in.MaxIPs

	var result planRecord
	if created {
		if expectedRev != "" {
			return planRecord{}, false, pluginsdk.PreconditionFailed("plans/"+in.ID, "")
		}
		result = planRecord{
			ID:              in.ID,
			Name:            in.Name,
			QuotaBytes:      in.QuotaBytes,
			DownLimitKbps:   in.DownLimitKbps,
			UpLimitKbps:     in.UpLimitKbps,
			MaxConnections:  maxConns,
			MaxIPs:          maxIPs,
			BillingResetDay: resetDay,
			ValidityDays:    in.ValidityDays,
			CreatedAt:       nowMs,
			UpdatedAt:       nowMs,
			Revision:        1,
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO plans(id, name, quota_bytes, down_limit_kbps, up_limit_kbps, max_connections, max_ips,
			                  billing_reset_day, validity_days, created_at, updated_at, revision)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			result.ID, result.Name, result.QuotaBytes, result.DownLimitKbps, result.UpLimitKbps,
			result.MaxConnections, result.MaxIPs,
			result.BillingResetDay, result.ValidityDays, result.CreatedAt, result.UpdatedAt, result.Revision); err != nil {
			return planRecord{}, false, err
		}
	} else {
		if expectedRev != "" && expectedRev != strconv.FormatInt(existing.Revision, 10) {
			return planRecord{}, false, pluginsdk.PreconditionFailed("plans/"+in.ID, strconv.FormatInt(existing.Revision, 10))
		}
		result = planRecord{
			ID:              in.ID,
			Name:            in.Name,
			QuotaBytes:      in.QuotaBytes,
			DownLimitKbps:   in.DownLimitKbps,
			UpLimitKbps:     in.UpLimitKbps,
			MaxConnections:  maxConns,
			MaxIPs:          maxIPs,
			BillingResetDay: resetDay,
			ValidityDays:    in.ValidityDays,
			CreatedAt:       existing.CreatedAt,
			UpdatedAt:       nowMs,
			Revision:        existing.Revision + 1,
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE plans
			SET name = ?, quota_bytes = ?, down_limit_kbps = ?, up_limit_kbps = ?, max_connections = ?, max_ips = ?,
			    billing_reset_day = ?, validity_days = ?, updated_at = ?, revision = ?
			WHERE id = ?`,
			result.Name, result.QuotaBytes, result.DownLimitKbps, result.UpLimitKbps, result.MaxConnections, result.MaxIPs,
			result.BillingResetDay, result.ValidityDays, result.UpdatedAt, result.Revision, result.ID); err != nil {
			return planRecord{}, false, err
		}
	}

	if err := tx.Commit(); err != nil {
		return planRecord{}, false, err
	}
	return result, created, nil
}

func (s *proxyStore) ListUsers(ctx context.Context, statusFilter, planFilter string, limit int) ([]userRecord, error) {
	if limit <= 0 || limit > maxListUsersLimit {
		limit = maxListUsersLimit
	}
	var args []any
	var conds []string
	if statusFilter != "" {
		conds = append(conds, "u.status = ?")
		args = append(args, statusFilter)
	}
	if planFilter != "" {
		conds = append(conds, "u.plan_id = ?")
		args = append(args, planFilter)
	}
	query := `
		SELECT u.id, u.display_name, u.plan_id, u.vless_uuid, u.hy2_password, u.ss2022_user_key,
		       u.traffic_mark, u.status, u.expires_at, u.sub_token_sha256,
		       p.quota_bytes, p.down_limit_kbps, p.up_limit_kbps,
		       p.max_connections, p.max_ips, u.max_connections_override, u.max_ips_override, u.chain_id,
		       c.period_up_bytes, c.period_down_bytes, c.total_up_bytes, c.total_down_bytes,
		       u.created_at, u.updated_at, u.revision
		FROM proxy_users u
		JOIN plans p ON p.id = u.plan_id
		JOIN usage_counters c ON c.user_id = u.id`
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " ORDER BY u.id ASC LIMIT ?"
	args = append(args, limit)

	rows, err := s.readDB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]userRecord, 0)
	for rows.Next() {
		u, err := scanUserRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *proxyStore) CreateUser(ctx context.Context, in usersCreateRequest, ssMethod string) (userRecord, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return userRecord{}, "", err
	}
	defer func() { _ = tx.Rollback() }()

	var plan planRecord
	err = tx.QueryRowContext(ctx, `
		SELECT id, name, quota_bytes, down_limit_kbps, up_limit_kbps, max_connections, max_ips,
		       billing_reset_day, validity_days, created_at, updated_at, revision
		FROM plans WHERE id = ?`, in.PlanID).Scan(
		&plan.ID, &plan.Name, &plan.QuotaBytes, &plan.DownLimitKbps, &plan.UpLimitKbps, &plan.MaxConnections, &plan.MaxIPs,
		&plan.BillingResetDay, &plan.ValidityDays, &plan.CreatedAt, &plan.UpdatedAt, &plan.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return userRecord{}, "", pluginsdk.Errorf("NOT_FOUND", "指定的套餐 %s 不存在", in.PlanID)
	}
	if err != nil {
		return userRecord{}, "", err
	}

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM proxy_users WHERE id = ?`, in.ID).Scan(&exists); err != nil {
		return userRecord{}, "", err
	}
	if exists > 0 {
		return userRecord{}, "", pluginsdk.Errorf("CONFLICT", "代理用户 %s 已存在", in.ID)
	}

	var mark uint32
	if !in.SkipTrafficMark {
		mark, err = allocateTrafficMarkTx(ctx, tx)
		if err != nil {
			return userRecord{}, "", err
		}
	}

	vlessUUID, err := generateUUIDv4()
	if err != nil {
		return userRecord{}, "", err
	}
	hy2Password, err := generateRandomToken(24)
	if err != nil {
		return userRecord{}, "", err
	}
	ssUserKey, err := generateSS2022Key(ssMethod)
	if err != nil {
		return userRecord{}, "", err
	}
	subToken, err := generateRandomToken(32)
	if err != nil {
		return userRecord{}, "", err
	}
	subHash := hashTokenSHA256(subToken)

	now := s.now().UTC()
	nowMs := now.UnixMilli()
	expiresAt := in.ExpiresAt
	if expiresAt == 0 && plan.ValidityDays > 0 {
		expiresAt = now.Add(time.Duration(plan.ValidityDays) * 24 * time.Hour).UnixMilli()
	}

	periodStart := nowMs
	if plan.BillingResetDay >= 1 && plan.BillingResetDay <= 28 {
		periodStart = billingCycleStart(now, plan.BillingResetDay).UnixMilli()
	}

	maxConnsOverride := -1
	if in.MaxConnectionsOverride != nil {
		maxConnsOverride = *in.MaxConnectionsOverride
	}
	maxIPsOverride := -1
	if in.MaxIPsOverride != nil {
		maxIPsOverride = *in.MaxIPsOverride
	}
	chainID := strings.TrimSpace(in.ChainID)

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO proxy_users(id, display_name, plan_id, vless_uuid, hy2_password, ss2022_user_key,
		                        traffic_mark, status, expires_at, max_connections_override, max_ips_override, chain_id,
		                        sub_token_sha256, created_at, updated_at, revision)
		VALUES(?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, 1)`,
		in.ID, in.DisplayName, in.PlanID, vlessUUID, hy2Password, ssUserKey,
		mark, expiresAt, maxConnsOverride, maxIPsOverride, chainID, subHash, nowMs, nowMs); err != nil {
		return userRecord{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO usage_counters(user_id, period_up_bytes, period_down_bytes, total_up_bytes, total_down_bytes,
		                           last_xray_epoch, last_raw_up, last_raw_down, period_started_at, updated_at)
		VALUES(?, 0, 0, 0, 0, '', 0, 0, ?, ?)`,
		in.ID, periodStart, nowMs); err != nil {
		return userRecord{}, "", err
	}

	if err := tx.Commit(); err != nil {
		return userRecord{}, "", err
	}

	user := userRecord{
		ID:                      in.ID,
		DisplayName:             in.DisplayName,
		PlanID:                  in.PlanID,
		VLESSUUID:               vlessUUID,
		Hy2Password:             hy2Password,
		SS2022UserKey:           ssUserKey,
		TrafficMark:             mark,
		Status:                  "active",
		ExpiresAt:               expiresAt,
		SubTokenSHA256:          subHash,
		QuotaBytes:              plan.QuotaBytes,
		DownLimitKbps:           plan.DownLimitKbps,
		UpLimitKbps:             plan.UpLimitKbps,
		PlanMaxConnections:      plan.MaxConnections,
		PlanMaxIPs:              plan.MaxIPs,
		MaxConnectionsOverride:  maxConnsOverride,
		MaxIPsOverride:          maxIPsOverride,
		EffectiveMaxConnections: resolveEffectiveLimit(plan.MaxConnections, maxConnsOverride),
		EffectiveMaxIPs:         resolveEffectiveLimit(plan.MaxIPs, maxIPsOverride),
		ChainID:                 chainID,
		CreatedAt:               nowMs,
		UpdatedAt:               nowMs,
		Revision:                1,
	}
	return user, subToken, nil
}

func (s *proxyStore) SetUserLimits(ctx context.Context, userID string, maxConnsOverride, maxIPsOverride *int, chainID *string, expectedRev string) (userRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return userRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var rev int64
	var curConn, curIP int
	var curChain string
	err = tx.QueryRowContext(ctx,
		`SELECT revision, max_connections_override, max_ips_override, chain_id FROM proxy_users WHERE id = ?`, userID).
		Scan(&rev, &curConn, &curIP, &curChain)
	if errors.Is(err, sql.ErrNoRows) {
		return userRecord{}, pluginsdk.Errorf("NOT_FOUND", "代理用户 %s 不存在", userID)
	}
	if err != nil {
		return userRecord{}, err
	}
	if expectedRev != "" && expectedRev != strconv.FormatInt(rev, 10) {
		return userRecord{}, pluginsdk.PreconditionFailed("users/"+userID, strconv.FormatInt(rev, 10))
	}
	if maxConnsOverride != nil {
		if *maxConnsOverride < -1 || *maxConnsOverride > 65535 {
			return userRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "max_connections_override 须在 -1..65535 之间")
		}
		curConn = *maxConnsOverride
	}
	if maxIPsOverride != nil {
		if *maxIPsOverride < -1 || *maxIPsOverride > 1024 {
			return userRecord{}, pluginsdk.Errorf("INVALID_ARGUMENT", "max_ips_override 须在 -1..1024 之间")
		}
		curIP = *maxIPsOverride
	}
	if chainID != nil {
		cid := strings.TrimSpace(*chainID)
		if cid != "" {
			var cnt int
			if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM proxy_chains WHERE id = ?`, cid).Scan(&cnt) == nil && cnt == 0 {
				return userRecord{}, pluginsdk.Errorf("NOT_FOUND", "指定的链式代理节点 %s 不存在", cid)
			}
		}
		curChain = cid
	}
	nowMs := s.now().UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `
		UPDATE proxy_users
		SET max_connections_override = ?, max_ips_override = ?, chain_id = ?, updated_at = ?, revision = ?
		WHERE id = ?`,
		curConn, curIP, curChain, nowMs, rev+1, userID); err != nil {
		return userRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return userRecord{}, err
	}
	return s.getUserByID(ctx, userID)
}

func (s *proxyStore) RotateSubscriptionToken(ctx context.Context, userID, expectedRev string) (string, int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var rev int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM proxy_users WHERE id = ?`, userID).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, pluginsdk.Errorf("NOT_FOUND", "代理用户 %s 不存在", userID)
	}
	if err != nil {
		return "", 0, err
	}
	if expectedRev != "" && expectedRev != strconv.FormatInt(rev, 10) {
		return "", 0, pluginsdk.PreconditionFailed("users/"+userID, strconv.FormatInt(rev, 10))
	}

	newToken, err := generateRandomToken(32)
	if err != nil {
		return "", 0, err
	}
	newHash := hashTokenSHA256(newToken)
	nextRev := rev + 1
	nowMs := s.now().UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `
		UPDATE proxy_users SET sub_token_sha256 = ?, updated_at = ?, revision = ? WHERE id = ?`,
		newHash, nowMs, nextRev, userID); err != nil {
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	return newToken, nextRev, nil
}

func (s *proxyStore) SetUserStatus(ctx context.Context, userID, status, expectedRev string) (userRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return userRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var rev int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM proxy_users WHERE id = ?`, userID).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return userRecord{}, pluginsdk.Errorf("NOT_FOUND", "代理用户 %s 不存在", userID)
	}
	if err != nil {
		return userRecord{}, err
	}
	if expectedRev != "" && expectedRev != strconv.FormatInt(rev, 10) {
		return userRecord{}, pluginsdk.PreconditionFailed("users/"+userID, strconv.FormatInt(rev, 10))
	}

	nowMs := s.now().UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `
		UPDATE proxy_users SET status = ?, updated_at = ?, revision = ? WHERE id = ?`,
		status, nowMs, rev+1, userID); err != nil {
		return userRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return userRecord{}, err
	}
	return s.getUserByID(ctx, userID)
}

func (s *proxyStore) getUserByID(ctx context.Context, userID string) (userRecord, error) {
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT u.id, u.display_name, u.plan_id, u.vless_uuid, u.hy2_password, u.ss2022_user_key,
		       u.traffic_mark, u.status, u.expires_at, u.sub_token_sha256,
		       p.quota_bytes, p.down_limit_kbps, p.up_limit_kbps,
		       p.max_connections, p.max_ips, u.max_connections_override, u.max_ips_override, u.chain_id,
		       c.period_up_bytes, c.period_down_bytes, c.total_up_bytes, c.total_down_bytes,
		       u.created_at, u.updated_at, u.revision
		FROM proxy_users u
		JOIN plans p ON p.id = u.plan_id
		JOIN usage_counters c ON c.user_id = u.id
		WHERE u.id = ?
		LIMIT 1`, userID)
	if err != nil {
		return userRecord{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return userRecord{}, err
		}
		return userRecord{}, pluginsdk.Errorf("NOT_FOUND", "代理用户 %s 不存在", userID)
	}
	return scanUserRecord(rows)
}

// FindUserBySubscriptionToken 使用 sub_token_sha256 唯一索引 O(1) 精确查询，并用常量时间比对核验摘要。
func (s *proxyStore) FindUserBySubscriptionToken(ctx context.Context, rawToken string) (userRecord, bool, error) {
	targetHash := hashTokenSHA256(rawToken)
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT u.id, u.display_name, u.plan_id, u.vless_uuid, u.hy2_password, u.ss2022_user_key,
		       u.traffic_mark, u.status, u.expires_at, u.sub_token_sha256,
		       p.quota_bytes, p.down_limit_kbps, p.up_limit_kbps,
		       p.max_connections, p.max_ips, u.max_connections_override, u.max_ips_override, u.chain_id,
		       c.period_up_bytes, c.period_down_bytes, c.total_up_bytes, c.total_down_bytes,
		       u.created_at, u.updated_at, u.revision
		FROM proxy_users u
		JOIN plans p ON p.id = u.plan_id
		JOIN usage_counters c ON c.user_id = u.id
		WHERE u.sub_token_sha256 = ?
		LIMIT 1`, targetHash)
	if err != nil {
		return userRecord{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return userRecord{}, false, rows.Err()
	}
	u, err := scanUserRecord(rows)
	if err != nil {
		return userRecord{}, false, err
	}
	if len(u.SubTokenSHA256) != len(targetHash) || subtle.ConstantTimeCompare([]byte(u.SubTokenSHA256), []byte(targetHash)) != 1 {
		return userRecord{}, false, nil
	}
	return u, true, nil
}

// RecordSubscriptionAccess 将公开订阅访问记录缓冲到内存并按 30 秒周期或批量阈值异步落库，避免公网高频拉订阅造成 SQLite 写放大。
func (s *proxyStore) RecordSubscriptionAccess(_ context.Context, userID, format, uaSummary string, statusCode int) error {
	entry := subAccessEntry{
		userID:     userID,
		accessedAt: s.now().UTC().UnixMilli(),
		format:     format,
		uaSummary:  uaSummary,
		statusCode: statusCode,
	}
	s.subLogMu.Lock()
	if len(s.pendingSubLogs) >= maxPendingSubAccessLogs {
		copy(s.pendingSubLogs, s.pendingSubLogs[1:])
		s.pendingSubLogs[len(s.pendingSubLogs)-1] = entry
	} else {
		s.pendingSubLogs = append(s.pendingSubLogs, entry)
	}
	shouldWake := len(s.pendingSubLogs) >= subAccessFlushBatchSize
	s.subLogMu.Unlock()

	if shouldWake && s.subFlushWake != nil {
		select {
		case s.subFlushWake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *proxyStore) subAccessFlushLoop() {
	defer close(s.subFlushDone)
	ticker := time.NewTicker(subAccessFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.subFlushStop:
			return
		case <-ticker.C:
			_ = s.FlushSubscriptionAccessLogs(context.Background())
		case <-s.subFlushWake:
			_ = s.FlushSubscriptionAccessLogs(context.Background())
		}
	}
}

// FlushSubscriptionAccessLogs 将内存中聚合的订阅访问记录在单个事务中批量写入并按用户裁剪至上限。
func (s *proxyStore) FlushSubscriptionAccessLogs(ctx context.Context) error {
	s.subLogMu.Lock()
	if len(s.pendingSubLogs) == 0 {
		s.subLogMu.Unlock()
		return nil
	}
	batch := s.pendingSubLogs
	s.pendingSubLogs = nil
	s.subLogMu.Unlock()

	if s.db == nil {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	touchedUsers := make(map[string]struct{}, 8)
	for _, entry := range batch {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO subscription_access_logs(user_id, accessed_at, format, ua_summary, status_code)
			VALUES(?, ?, ?, ?, ?)`,
			entry.userID, entry.accessedAt, entry.format, entry.uaSummary, entry.statusCode); err != nil {
			continue
		}
		touchedUsers[entry.userID] = struct{}{}
	}
	for uid := range touchedUsers {
		_, _ = tx.ExecContext(ctx, `
			DELETE FROM subscription_access_logs
			WHERE user_id = ?
			  AND id NOT IN (
				SELECT id FROM subscription_access_logs
				WHERE user_id = ?
				ORDER BY accessed_at DESC, id DESC
				LIMIT ?
			  )`, uid, uid, maxSubAccessLogsPerUser)
	}
	return tx.Commit()
}

func (s *proxyStore) GetUsageHistory(ctx context.Context, userID string, hours int) ([]usageRollupPoint, error) {
	if hours <= 0 {
		hours = 24
	}
	if hours > 2160 {
		hours = 2160
	}
	var exists int
	if err := s.readDB().QueryRowContext(ctx, `SELECT COUNT(1) FROM proxy_users WHERE id = ?`, userID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, pluginsdk.Errorf("NOT_FOUND", "代理用户 %s 不存在", userID)
	}
	cutoff := s.now().UTC().Truncate(time.Hour).Add(-time.Duration(hours) * time.Hour).UnixMilli()
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT bucket_hour_ms, up_bytes, down_bytes
		FROM usage_hourly_rollups
		WHERE user_id = ? AND bucket_hour_ms >= ?
		ORDER BY bucket_hour_ms ASC`, userID, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	points := make([]usageRollupPoint, 0)
	for rows.Next() {
		var pt usageRollupPoint
		if err := rows.Scan(&pt.BucketHourMS, &pt.UpBytes, &pt.DownBytes); err != nil {
			return nil, err
		}
		points = append(points, pt)
	}
	return points, rows.Err()
}

func (s *proxyStore) GetOverviewStats(ctx context.Context) (overviewStats, error) {
	var st overviewStats
	if err := s.readDB().QueryRowContext(ctx, `SELECT COUNT(1) FROM plans`).Scan(&st.TotalPlans); err != nil {
		return st, err
	}
	rows, err := s.readDB().QueryContext(ctx, `
		SELECT u.status, u.traffic_mark, c.period_up_bytes, c.period_down_bytes
		FROM proxy_users u
		JOIN usage_counters c ON c.user_id = u.id`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var mark uint32
		var pUp, pDown int64
		if err := rows.Scan(&status, &mark, &pUp, &pDown); err != nil {
			return st, err
		}
		st.TotalUsers++
		switch status {
		case "active":
			st.ActiveUsers++
		case "suspended_quota":
			st.SuspendedQuotaUsers++
		case "expired":
			st.ExpiredUsers++
		case "disabled":
			st.DisabledUsers++
		}
		if mark >= trafficMarkMin && mark <= trafficMarkMax {
			st.UsedTrafficMarks++
		}
		st.PeriodUpBytes += pUp
		st.PeriodDownBytes += pDown
	}
	return st, rows.Err()
}

// ======================== Reset-Epoch 感知流量累计、配额/到期与月度重置 ========================

// IngestXrayObservation 原子吸收一批 core.observe 用户采样数据：
// 1. 先检查月度账单重置（归零当期用量并恢复 suspended_quota -> active）与到期状态；
// 2. 按 Reset-Epoch 增量累加（同 epoch 且单调增长取差值；重启或 epoch 变更平滑加全量，绝不产生负数）；
// 3. 更新小时聚合桶并裁剪 90 天前历史；
// 4. 超配额自动置 suspended_quota，返回是否需要同步 core.xray 与限速。
func (s *proxyStore) IngestXrayObservation(ctx context.Context, resetEpoch string, samples []usageSample) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	now := s.now().UTC()
	nowMs := now.UnixMilli()
	bucketHourMs := now.Truncate(time.Hour).UnixMilli()
	retentionCutoffMs := now.Add(-time.Duration(rollupRetentionDays) * 24 * time.Hour).UnixMilli()

	type userStateRow struct {
		userID          string
		status          string
		expiresAt       int64
		quotaBytes      int64
		billingResetDay int
		periodUp        int64
		periodDown      int64
		totalUp         int64
		totalDown       int64
		lastEpoch       string
		lastRawUp       int64
		lastRawDown     int64
		periodStartedAt int64
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT u.id, u.status, u.expires_at, p.quota_bytes, p.billing_reset_day,
		       c.period_up_bytes, c.period_down_bytes, c.total_up_bytes, c.total_down_bytes,
		       c.last_xray_epoch, c.last_raw_up, c.last_raw_down, c.period_started_at
		FROM proxy_users u
		JOIN plans p ON p.id = u.plan_id
		JOIN usage_counters c ON c.user_id = u.id`)
	if err != nil {
		return false, err
	}
	states := make(map[string]*userStateRow)
	for rows.Next() {
		st := &userStateRow{}
		if err := rows.Scan(&st.userID, &st.status, &st.expiresAt, &st.quotaBytes, &st.billingResetDay,
			&st.periodUp, &st.periodDown, &st.totalUp, &st.totalDown,
			&st.lastEpoch, &st.lastRawUp, &st.lastRawDown, &st.periodStartedAt); err != nil {
			_ = rows.Close()
			return false, err
		}
		states[st.userID] = st
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	needsCoreSync := false
	statusDirty := make(map[string]string)
	counterDirty := make(map[string]bool)

	// 第 1 步：先处理 resetEpoch 切换（对所有用户统一归零旧 epoch 原始基线，防止空闲用户残留过期 lastRaw）
	// 并结算上一周期末尾 / 当前采样增量，确保跨账期前的尾量归入历史总计而不污染新账期。
	if resetEpoch != "" {
		for _, st := range states {
			if st.lastEpoch != resetEpoch {
				st.lastEpoch = resetEpoch
				st.lastRawUp = 0
				st.lastRawDown = 0
				counterDirty[st.userID] = true
			}
		}
	}

	for _, sample := range samples {
		st, ok := states[sample.UserID]
		if !ok {
			continue
		}
		rawUp := max(sample.RawUp, int64(0))
		rawDown := max(sample.RawDown, int64(0))

		var deltaUp int64
		if sample.HasUp {
			if rawUp >= st.lastRawUp {
				deltaUp = rawUp - st.lastRawUp
			} else {
				deltaUp = rawUp
			}
			st.lastRawUp = rawUp
		}

		var deltaDown int64
		if sample.HasDown {
			if rawDown >= st.lastRawDown {
				deltaDown = rawDown - st.lastRawDown
			} else {
				deltaDown = rawDown
			}
			st.lastRawDown = rawDown
		}

		st.periodUp += deltaUp
		st.periodDown += deltaDown
		st.totalUp += deltaUp
		st.totalDown += deltaDown
		counterDirty[st.userID] = true

		if deltaUp > 0 || deltaDown > 0 {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO usage_hourly_rollups(user_id, bucket_hour_ms, up_bytes, down_bytes)
				VALUES(?, ?, ?, ?)
				ON CONFLICT(user_id, bucket_hour_ms) DO UPDATE SET
					up_bytes = up_bytes + excluded.up_bytes,
					down_bytes = down_bytes + excluded.down_bytes`,
				st.userID, bucketHourMs, deltaUp, deltaDown); err != nil {
				return false, err
			}
		}
	}

	// 第 2 步：执行跨账期清零与恢复 suspended_quota -> active，随后检查到期与新周期超配额熔断。
	for _, st := range states {
		if st.billingResetDay >= 1 && st.billingResetDay <= 28 {
			cycleStartMs := billingCycleStart(now, st.billingResetDay).UnixMilli()
			if st.periodStartedAt < cycleStartMs {
				st.periodUp = 0
				st.periodDown = 0
				st.periodStartedAt = cycleStartMs
				counterDirty[st.userID] = true
				if st.status == "suspended_quota" && (st.expiresAt == 0 || nowMs < st.expiresAt) {
					st.status = "active"
					statusDirty[st.userID] = "active"
					needsCoreSync = true
				}
			}
		}
		if st.expiresAt > 0 && nowMs >= st.expiresAt && st.status != "expired" && st.status != "disabled" {
			st.status = "expired"
			statusDirty[st.userID] = "expired"
			needsCoreSync = true
		}
		if st.quotaBytes > 0 && st.periodUp+st.periodDown >= st.quotaBytes && st.status == "active" {
			st.status = "suspended_quota"
			statusDirty[st.userID] = "suspended_quota"
			needsCoreSync = true
		}
	}

	// 第 3 步：写回计数器与状态变更，并裁剪 90 天前的旧聚合桶。
	for userID := range counterDirty {
		st := states[userID]
		if _, err := tx.ExecContext(ctx, `
			UPDATE usage_counters
			SET period_up_bytes = ?, period_down_bytes = ?,
			    total_up_bytes = ?, total_down_bytes = ?,
			    last_xray_epoch = ?, last_raw_up = ?, last_raw_down = ?,
			    period_started_at = ?, updated_at = ?
			WHERE user_id = ?`,
			st.periodUp, st.periodDown, st.totalUp, st.totalDown,
			st.lastEpoch, st.lastRawUp, st.lastRawDown, st.periodStartedAt, nowMs, userID); err != nil {
			return false, err
		}
	}
	for userID, nextStatus := range statusDirty {
		if _, err := tx.ExecContext(ctx, `
			UPDATE proxy_users SET status = ?, updated_at = ?, revision = revision + 1 WHERE id = ?`,
			nextStatus, nowMs, userID); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM usage_hourly_rollups WHERE bucket_hour_ms < ?`, retentionCutoffMs); err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return needsCoreSync, nil
}

// ======================== 槽位分配、账期计算与安全凭证生成 ========================

func allocateTrafficMarkTx(ctx context.Context, tx *sql.Tx) (uint32, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT traffic_mark FROM proxy_users
		WHERE traffic_mark >= ? AND traffic_mark <= ?
		ORDER BY traffic_mark ASC`, trafficMarkMin, trafficMarkMax)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	used := make(map[uint32]struct{}, trafficMarkMax-trafficMarkMin+1)
	for rows.Next() {
		var m uint32
		if err := rows.Scan(&m); err != nil {
			return 0, err
		}
		used[m] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for candidate := uint32(trafficMarkMin); candidate <= trafficMarkMax; candidate++ {
		if _, taken := used[candidate]; !taken {
			return candidate, nil
		}
	}
	return 0, pluginsdk.Errorf("RESOURCE_EXHAUSTED", "内核限速 traffic_mark 槽位已满（上限 256）")
}

func billingCycleStart(now time.Time, resetDay int) time.Time {
	utc := now.UTC()
	year, month, day := utc.Date()
	if day < resetDay {
		firstOfMonth := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
		prevMonth := firstOfMonth.AddDate(0, -1, 0)
		year, month, _ = prevMonth.Date()
	}
	return time.Date(year, month, resetDay, 0, 0, 0, 0, time.UTC)
}

func scanUserRecord(rows *sql.Rows) (userRecord, error) {
	var u userRecord
	err := rows.Scan(
		&u.ID, &u.DisplayName, &u.PlanID, &u.VLESSUUID, &u.Hy2Password, &u.SS2022UserKey,
		&u.TrafficMark, &u.Status, &u.ExpiresAt, &u.SubTokenSHA256,
		&u.QuotaBytes, &u.DownLimitKbps, &u.UpLimitKbps,
		&u.PlanMaxConnections, &u.PlanMaxIPs, &u.MaxConnectionsOverride, &u.MaxIPsOverride, &u.ChainID,
		&u.PeriodUpBytes, &u.PeriodDownBytes, &u.TotalUpBytes, &u.TotalDownBytes,
		&u.CreatedAt, &u.UpdatedAt, &u.Revision,
	)
	u.EffectiveMaxConnections = resolveEffectiveLimit(u.PlanMaxConnections, u.MaxConnectionsOverride)
	u.EffectiveMaxIPs = resolveEffectiveLimit(u.PlanMaxIPs, u.MaxIPsOverride)
	return u, err
}

func generateUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func generateRandomToken(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func generateSS2022Key(method string) (string, error) {
	size := 16
	if method == "2022-blake3-aes-256-gcm" {
		size = 32
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func hashTokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
