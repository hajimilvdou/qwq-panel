// SPDX-License-Identifier: AGPL-3.0-only

// Package nodespool 实现边缘节点断网自治的本地有界 SQLite Spool 队列（Track 08 P4-4）。
// 队列硬上限默认 32 MiB：断网期间按单调递增 node_seq 持久化操作终态回执、安全审计与监控事件；
// 触及容量上限时优先淘汰低优先级监控采样，死保操作终态回执与安全审计事件不丢失。
package nodespool

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ======================== 常量、优先级与条目定义 ========================

const (
	// DefaultMaxBytes 是边缘节点本地离线缓冲硬上限（32 MiB）。
	DefaultMaxBytes int64 = 32 << 20

	// PriorityCritical 用于操作终态回执与安全审计，容量告警时绝不优先淘汰。
	PriorityCritical = 0
	// PriorityMetrics 用于低优先级监控采样，容量触顶时优先丢弃腾出空间。
	PriorityMetrics = 1
)

// ErrSpoolFull 表示高优先级事件已占满全部容量上限，无法写入。
var ErrSpoolFull = errors.New("nodespool: critical spool budget exhausted")

// Entry 表示写入离线队列的一条节点待回传事件。
type Entry struct {
	Seq       uint64
	EventID   string
	Topic     string
	Priority  int
	Payload   []byte
	SizeBytes int64
	CreatedAt int64
}

// Stats 报告离线缓冲当前占用、条目数与累计淘汰计数。
type Stats struct {
	Count          int64
	BytesUsed      int64
	MaxBytes       int64
	FirstSeq       uint64
	LastSeq        uint64
	DroppedMetrics int64
}

// Spool 持有单写连接 SQLite WAL 队列，保证并发写入安全与崩溃不丢回执。
type Spool struct {
	db       *sql.DB
	maxBytes int64

	mu             sync.Mutex
	droppedMetrics int64
}

const spoolSchema = `
CREATE TABLE IF NOT EXISTS spool_entries (
	seq         INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id    TEXT    NOT NULL UNIQUE,
	topic       TEXT    NOT NULL,
	priority    INTEGER NOT NULL CHECK (priority IN (0, 1)),
	payload     BLOB    NOT NULL,
	size_bytes  INTEGER NOT NULL CHECK (size_bytes >= 0),
	created_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_spool_priority_seq ON spool_entries (priority, seq);
`

// Open 打开或初始化本地离线队列数据库（父目录 0700，文件 0600，WAL 模式）。
func Open(ctx context.Context, path string, maxBytes int64) (*Spool, error) {
	if path == "" {
		return nil, errors.New("nodespool: path is required")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("nodespool: mkdir: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-2048)&_pragma=busy_timeout(5000)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("nodespool: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, spoolSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("nodespool: init schema: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return &Spool{db: db, maxBytes: maxBytes}, nil
}

// Close 关闭底层 SQLite 连接。
func (s *Spool) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Append 追加一条事件并分配单调 node_seq；当总占用将超过 maxBytes 时优先驱逐 PriorityMetrics。
// 若 event_id 已存在则幂等返回既有 seq。
func (s *Spool) Append(ctx context.Context, eventID, topic string, priority int, payload []byte, now time.Time) (uint64, error) {
	if eventID == "" || topic == "" {
		return 0, errors.New("nodespool: event_id and topic are required")
	}
	if priority != PriorityCritical && priority != PriorityMetrics {
		return 0, fmt.Errorf("nodespool: invalid priority %d", priority)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	entryBytes := int64(len(eventID) + len(topic) + len(payload) + 64)
	if entryBytes > s.maxBytes {
		return 0, fmt.Errorf("nodespool: entry size %d exceeds maxBytes %d", entryBytes, s.maxBytes)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("nodespool: begin: %w", err)
	}
	defer tx.Rollback()

	// 幂等去重：同 event_id 直接返回原 seq。
	var existingSeq int64
	if qerr := tx.QueryRowContext(ctx, `SELECT seq FROM spool_entries WHERE event_id = ?`, eventID).Scan(&existingSeq); qerr == nil {
		return uint64(existingSeq), nil
	} else if !errors.Is(qerr, sql.ErrNoRows) {
		return 0, qerr
	}

	var used int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size_bytes), 0) FROM spool_entries`).Scan(&used); err != nil {
		return 0, err
	}

	// 容量不足时按最旧优先淘汰 PriorityMetrics，死保 PriorityCritical。
	if used+entryBytes > s.maxBytes {
		needFree := used + entryBytes - s.maxBytes
		evictedBytes, evictedRows, err := evictMetricsTx(ctx, tx, needFree)
		if err != nil {
			return 0, err
		}
		s.droppedMetrics += evictedRows
		used -= evictedBytes
	}

	if used+entryBytes > s.maxBytes {
		// 若待写入的本身就是低优先级指标，则静默丢弃并计入 droppedMetrics，绝不挤压高优空间。
		if priority == PriorityMetrics {
			s.droppedMetrics++
			if err := tx.Commit(); err != nil {
				return 0, err
			}
			return 0, nil
		}
		return 0, ErrSpoolFull
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO spool_entries (event_id, topic, priority, payload, size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		eventID, topic, priority, payload, entryBytes, now.UTC().UnixMilli(),
	)
	if err != nil {
		return 0, fmt.Errorf("nodespool: insert: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("nodespool: commit: %w", err)
	}
	return uint64(seq), nil
}

func evictMetricsTx(ctx context.Context, tx *sql.Tx, needFree int64) (int64, int64, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT seq, size_bytes FROM spool_entries WHERE priority = ? ORDER BY seq ASC`,
		PriorityMetrics,
	)
	if err != nil {
		return 0, 0, err
	}
	var seqs []int64
	var freed int64
	for rows.Next() {
		var seq, sz int64
		if err := rows.Scan(&seq, &sz); err != nil {
			rows.Close()
			return 0, 0, err
		}
		seqs = append(seqs, seq)
		freed += sz
		if freed >= needFree {
			break
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, err
	}
	rows.Close()

	for _, seq := range seqs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM spool_entries WHERE seq = ?`, seq); err != nil {
			return 0, 0, err
		}
	}
	return freed, int64(len(seqs)), nil
}

// ReadAfter 按 seq 严格递增顺序读取 ackSeq 之后的待续传事件。
func (s *Spool) ReadAfter(ctx context.Context, ackSeq uint64, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, event_id, topic, priority, payload, size_bytes, created_at
		 FROM spool_entries WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
		ackSeq, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("nodespool: read after: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Seq, &e.EventID, &e.Topic, &e.Priority, &e.Payload, &e.SizeBytes, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Ack 在收到 Controller 累计确认后安全清理 seq <= ackSeq 的已送达条目。
func (s *Spool) Ack(ctx context.Context, ackSeq uint64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM spool_entries WHERE seq <= ?`, ackSeq)
	if err != nil {
		return 0, fmt.Errorf("nodespool: ack: %w", err)
	}
	return res.RowsAffected()
}

// Stats 返回当前队列占用与序号边界（供 Agent Hello 握手报告 first_spooled_event_sequence）。
func (s *Spool) Stats(ctx context.Context) (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st := Stats{
		MaxBytes:       s.maxBytes,
		DroppedMetrics: s.droppedMetrics,
	}
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0), COALESCE(MIN(seq), 0), COALESCE(MAX(seq), 0) FROM spool_entries`,
	).Scan(&st.Count, &st.BytesUsed, &st.FirstSeq, &st.LastSeq)
	if err != nil {
		return Stats{}, fmt.Errorf("nodespool: stats: %w", err)
	}
	return st, nil
}
