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

// analyzeComposeYAML 执行静态安全校验：强阻断 include / 越界 env_file / 根目录挂载 / privileged: true，
// 并对宿主机网络/PID/docker.sock 等中高危项生成审批预警，供审批卡与 AI 清晰呈现风险。
func analyzeComposeYAML(raw string) ([]string, error) {
	if len(raw) == 0 || len(raw) > maxComposeYAMLBytes {
		return nil, fmt.Errorf("compose_yaml 不能为空且不得超过 %d 字节", maxComposeYAMLBytes)
	}
	if strings.ContainsRune(raw, '\x00') {
		return nil, errors.New("compose_yaml 不得包含 NUL 字节")
	}
	hasServices := false
	inEnvFileBlock := false
	envFileIndent := 0
	warnings := make([]string, 0)
	lines := strings.Split(raw, "\n")
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " \t"))
		if strings.HasPrefix(ln, "services:") {
			hasServices = true
		}
		low := strings.ToLower(strings.Join(strings.Fields(trimmed), " "))
		lowUnquoted := strings.NewReplacer(`"`, "", `'`, "").Replace(low)

		// 1. 强阻断 include:（防止跨目录引用宿主机任意 compose / 敏感文件）
		if strings.HasPrefix(lowUnquoted, "include:") {
			return nil, errors.New("出于安全限制，禁止在 compose_yaml 中使用 include: 指令")
		}

		// 2. 强阻断越界 env_file:（禁止绝对路径或含 .. 跳出栈工作目录）
		if inEnvFileBlock {
			if indent <= envFileIndent && !strings.HasPrefix(trimmed, "-") {
				inEnvFileBlock = false
			} else if strings.HasPrefix(trimmed, "-") || strings.HasPrefix(lowUnquoted, "path:") {
				val := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "-"), "path:"))
				val = strings.Trim(val, `"' `)
				if isOutOfBoundsEnvFile(val) {
					return nil, fmt.Errorf("禁止越界 env_file 路径 %q（仅允许当前栈目录内相对路径）", val)
				}
			}
		}
		if strings.HasPrefix(lowUnquoted, "env_file:") {
			rest := strings.TrimSpace(trimmed[len("env_file:"):])
			if rest == "" {
				inEnvFileBlock = true
				envFileIndent = indent
			} else {
				rest = strings.Trim(rest, `[]"' `)
				for _, item := range strings.Split(rest, ",") {
					p := strings.Trim(strings.TrimSpace(item), `"'`)
					if p != "" && isOutOfBoundsEnvFile(p) {
						return nil, fmt.Errorf("禁止越界 env_file 路径 %q（仅允许当前栈目录内相对路径）", p)
					}
				}
			}
		}

		// 3. 强阻断 privileged: true（特权容器等同宿主机 root 逃逸）
		if strings.Contains(lowUnquoted, "privileged: true") || strings.Contains(lowUnquoted, "privileged:true") {
			return nil, errors.New("出于安全限制，禁止部署 privileged: true 特权容器")
		}

		// 4. 强阻断宿主机根目录 / 挂载（含短语法 - /:/... 与长语法 source: /）
		if isRootBindMount(lowUnquoted) {
			return nil, errors.New("出于安全限制，禁止将宿主机根目录 / 挂载至容器内")
		}

		if strings.Contains(lowUnquoted, "network_mode: host") {
			warnings = appendUnique(warnings, "检测到 network_mode: host（容器将共享宿主机网络命名空间）")
		}
		if strings.Contains(lowUnquoted, "pid: host") {
			warnings = appendUnique(warnings, "检测到 pid: host（容器将可见并可干扰宿主机进程空间）")
		}
		if strings.Contains(lowUnquoted, "sys_admin") {
			warnings = appendUnique(warnings, "检测到 CAP_SYS_ADMIN 能力（接近特权容器权限）")
		}
		if strings.Contains(lowUnquoted, "/var/run/docker.sock") {
			warnings = appendUnique(warnings, "检测到挂载 /var/run/docker.sock（等同宿主机容器控制权）")
		}
	}
	if !hasServices {
		return nil, errors.New("compose_yaml 缺少顶层 services: 定义")
	}
	return warnings, nil
}

func isOutOfBoundsEnvFile(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.Contains(p, "..") || strings.Contains(p, `\`) {
		return true
	}
	cleaned := filepath.ToSlash(filepath.Clean(p))
	return strings.HasPrefix(cleaned, "/") || cleaned == ".." || strings.HasPrefix(cleaned, "../")
}

func isRootBindMount(lowUnquoted string) bool {
	if strings.HasPrefix(lowUnquoted, "- /:/") || strings.Contains(lowUnquoted, " - /:/") {
		return true
	}
	if lowUnquoted == "source: /" || strings.HasPrefix(lowUnquoted, "source: / ") {
		return true
	}
	if strings.HasPrefix(lowUnquoted, "- ") {
		spec := strings.TrimSpace(strings.TrimPrefix(lowUnquoted, "- "))
		if idx := strings.IndexByte(spec, ':'); idx > 0 {
			src := strings.TrimSpace(spec[:idx])
			if src == "/" || strings.TrimRight(src, "/") == "" {
				return true
			}
		}
	}
	return false
}

func appendUnique(list []string, v string) []string {
	for _, item := range list {
		if item == v {
			return list
		}
	}
	return append(list, v)
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
		`SELECT name, work_dir, status, warnings_json, last_error, revision, created_at, updated_at
		 FROM compose_stacks ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ComposeStack, 0)
	for rows.Next() {
		var st ComposeStack
		var warnRaw string
		if err := rows.Scan(&st.Name, &st.WorkDir, &st.Status, &warnRaw, &st.LastError, &st.Revision, &st.CreatedAt, &st.UpdatedAt); err != nil {
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
