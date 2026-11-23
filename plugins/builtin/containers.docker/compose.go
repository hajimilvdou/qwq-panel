// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxComposeStacks    = 64
	maxComposeYAMLBytes = 128 * 1024
)

var stackNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)

// ComposeStack 表示受管 Docker Compose 编排栈元数据。
type ComposeStack struct {
	Name        string   `json:"name"`
	WorkDir     string   `json:"work_dir"`
	Status      string   `json:"status"`
	Warnings    []string `json:"warnings,omitempty"`
	LastError   string   `json:"last_error,omitempty"`
	Revision    int      `json:"revision"`
	ComposeYAML string   `json:"compose_yaml,omitempty"`
	CreatedAt   int64    `json:"created_at"`
	UpdatedAt   int64    `json:"updated_at"`
}

func validateStackName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !stackNameRe.MatchString(name) {
		return "", errors.New("栈名称仅允许小写字母、数字、下划线和连字符（1-48 字符）")
	}
	return name, nil
}

// analyzeComposeYAML 使用结构化缩进状态机执行严格 Compose YAML 安全校验。
func analyzeComposeYAML(raw string) ([]string, error) {
	return ValidateComposeYAMLStrict(raw)
}

func detectComposeCmd() (string, []string) {
	if p, err := exec.LookPath("docker"); err == nil {
		return p, []string{"compose"}
	}
	if p, err := exec.LookPath("docker-compose"); err == nil {
		return p, nil
	}
	return "", nil
}

type stackStore struct {
	mu      sync.Mutex
	db      *sql.DB
	dataDir string
	now     func() time.Time
}

func openStackStore(dataDir, schemaSQL string, nowFn func() time.Time) (*stackStore, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "stacks"), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(dataDir, "docker.db")) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=cache_size(-2048)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, err
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	return &stackStore{db: db, dataDir: dataDir, now: nowFn}, nil
}

func (s *stackStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *stackStore) saveStack(ctx context.Context, name, yamlContent, status, lastErr string, warnings []string) (ComposeStack, error) {
	safeName, err := validateStackName(name)
	if err != nil {
		return ComposeStack{}, err
	}
	workDir := filepath.Join(s.dataDir, "stacks", safeName)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return ComposeStack{}, err
	}
	composeFile := filepath.Join(workDir, "compose.yml")
	tmp := composeFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(yamlContent), 0o600); err != nil {
		return ComposeStack{}, err
	}
	if err := os.Rename(tmp, composeFile); err != nil {
		_ = os.Remove(tmp)
		return ComposeStack{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	var existingRev int
	err = s.db.QueryRowContext(ctx, `SELECT revision FROM compose_stacks WHERE name = ?`, safeName).Scan(&existingRev)
	if err != nil {
		var cnt int
		if s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM compose_stacks`).Scan(&cnt) == nil && cnt >= maxComposeStacks {
			return ComposeStack{}, fmt.Errorf("compose 栈数量已达上限 (%d)", maxComposeStacks)
		}
	}
	if warnings == nil {
		warnings = []string{}
	}
	warnJSON, _ := json.Marshal(warnings)
	if existingRev == 0 {
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO compose_stacks (name, compose_yaml, work_dir, status, warnings_json, last_error, revision, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			safeName, yamlContent, workDir, status, string(warnJSON), lastErr, now, now)
		existingRev = 1
	} else {
		existingRev++
		_, err = s.db.ExecContext(ctx,
			`UPDATE compose_stacks SET compose_yaml = ?, work_dir = ?, status = ?, warnings_json = ?, last_error = ?, revision = ?, updated_at = ?
			 WHERE name = ?`,
			yamlContent, workDir, status, string(warnJSON), lastErr, existingRev, now, safeName)
	}
	if err != nil {
		return ComposeStack{}, err
	}
	return ComposeStack{
		Name:      safeName,
		WorkDir:   workDir,
		Status:    status,
		Warnings:  warnings,
		LastError: lastErr,
		Revision:  existingRev,
		UpdatedAt: now,
	}, nil
}

func (s *stackStore) listStacks(ctx context.Context) ([]ComposeStack, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, compose_yaml, work_dir, status, warnings_json, last_error, revision, created_at, updated_at
		 FROM compose_stacks ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ComposeStack, 0)
	for rows.Next() {
		var st ComposeStack
		var warnRaw string
		if err := rows.Scan(&st.Name, &st.ComposeYAML, &st.WorkDir, &st.Status, &warnRaw, &st.LastError, &st.Revision, &st.CreatedAt, &st.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(warnRaw), &st.Warnings)
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *stackStore) deleteStack(ctx context.Context, name string) (bool, string, error) {
	safeName, err := validateStackName(name)
	if err != nil {
		return false, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var workDir string
	_ = s.db.QueryRowContext(ctx, `SELECT work_dir FROM compose_stacks WHERE name = ?`, safeName).Scan(&workDir)
	res, err := s.db.ExecContext(ctx, `DELETE FROM compose_stacks WHERE name = ?`, safeName)
	if err != nil {
		return false, "", err
	}
	n, _ := res.RowsAffected()
	if workDir != "" {
		_ = os.RemoveAll(workDir)
	}
	return n > 0, workDir, nil
}
