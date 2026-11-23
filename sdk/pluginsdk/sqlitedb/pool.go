// SPDX-License-Identifier: Apache-2.0

// Package sqlitedb provides a lightweight WAL dual-pool helper (1 writer +
// N query_only readers) for plugins that store state in SQLite.
package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DualPool separates SQLite writes (single connection, BEGIN IMMEDIATE) from
// concurrent read-only queries (query_only(1) pool) under WAL mode, with
// bounded journal and cache sizes suitable for 1C1G hosts.
type DualPool struct {
	Writer *sql.DB
	Reader *sql.DB
}

// OpenDualSQLite opens a WAL-mode SQLite database with one writer connection
// and up to maxReaders read-only connections using driverName (e.g. "sqlite").
func OpenDualSQLite(driverName, dbFilePath string, maxReaders int) (*DualPool, error) {
	if strings.TrimSpace(driverName) == "" {
		driverName = "sqlite"
	}
	if strings.TrimSpace(dbFilePath) == "" {
		return nil, errors.New("sqlitedb: dbFilePath is required")
	}
	if strings.ContainsAny(dbFilePath, "?#") {
		return nil, fmt.Errorf("sqlitedb: dbFilePath %q must not contain '?' or '#'", dbFilePath)
	}
	if maxReaders <= 0 {
		maxReaders = 4
	}
	if err := os.MkdirAll(filepath.Dir(dbFilePath), 0o700); err != nil {
		return nil, fmt.Errorf("sqlitedb: mkdir parent: %w", err)
	}

	basePath := filepath.ToSlash(dbFilePath)

	writeQ := url.Values{}
	writeQ.Add("_txlock", "immediate")
	writeQ.Add("_pragma", "journal_mode(WAL)")
	writeQ.Add("_pragma", "synchronous(NORMAL)")
	writeQ.Add("_pragma", "busy_timeout(5000)")
	writeQ.Add("_pragma", "foreign_keys(1)")
	writeQ.Add("_pragma", "journal_size_limit(8388608)")
	writeQ.Add("_pragma", "cache_size(-2048)")
	writeQ.Add("_pragma", "temp_store(MEMORY)")

	wdb, err := sql.Open(driverName, basePath+"?"+writeQ.Encode())
	if err != nil {
		return nil, fmt.Errorf("open sqlite writer: %w", err)
	}
	wdb.SetMaxOpenConns(1)
	wdb.SetMaxIdleConns(1)
	wdb.SetConnMaxLifetime(0)
	if err := wdb.Ping(); err != nil {
		_ = wdb.Close()
		return nil, fmt.Errorf("ping sqlite writer: %w", err)
	}

	readQ := url.Values{}
	readQ.Add("_pragma", "query_only(1)")
	readQ.Add("_pragma", "busy_timeout(5000)")
	readQ.Add("_pragma", "foreign_keys(1)")
	readQ.Add("_pragma", "cache_size(-2048)")
	readQ.Add("_pragma", "temp_store(MEMORY)")

	rdb, err := sql.Open(driverName, basePath+"?"+readQ.Encode())
	if err != nil {
		_ = wdb.Close()
		return nil, fmt.Errorf("open sqlite reader: %w", err)
	}
	rdb.SetMaxOpenConns(maxReaders)
	rdb.SetMaxIdleConns(min(2, maxReaders))
	rdb.SetConnMaxIdleTime(5 * time.Minute)
	if err := rdb.Ping(); err != nil {
		_ = rdb.Close()
		_ = wdb.Close()
		return nil, fmt.Errorf("ping sqlite reader: %w", err)
	}

	return &DualPool{Writer: wdb, Reader: rdb}, nil
}

// CheckpointPassive runs a non-blocking PASSIVE WAL checkpoint on the writer.
func (p *DualPool) CheckpointPassive(ctx context.Context) error {
	if p == nil || p.Writer == nil {
		return nil
	}
	_, err := p.Writer.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")
	return err
}

// Close closes the reader pool, truncates the WAL journal, and closes the writer.
func (p *DualPool) Close() error {
	if p == nil {
		return nil
	}
	var errR, errW error
	if p.Reader != nil {
		errR = p.Reader.Close()
	}
	if p.Writer != nil {
		_, _ = p.Writer.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		errW = p.Writer.Close()
	}
	return errors.Join(errR, errW)
}
