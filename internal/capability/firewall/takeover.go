// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

const (
	takeoverBackupRelDir = "var/lib/qwq-capability/takeover-backups"
	maxTakeoverBackupRaw = 256 << 10
)

// TakeoverPort is one port/protocol imported from an existing firewall manager.
type TakeoverPort struct {
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
}

// TakeoverRecord is stored atomically on disk before disabling a competing manager.
type TakeoverRecord struct {
	Manager       string            `json:"manager"`
	TakenOverAt   string            `json:"taken_over_at"`
	WasActive     bool              `json:"was_active"`
	WasEnabled    bool              `json:"was_enabled"`
	ImportedPorts []TakeoverPort    `json:"imported_ports,omitempty"`
	BackupFiles   map[string]string `json:"backup_files,omitempty"`
}

// TakeoverStatusEntry summarizes one manageable coexistence service.
type TakeoverStatusEntry struct {
	Manager       string   `json:"manager"`
	Active        bool     `json:"active"`
	TakenOver     bool     `json:"taken_over"`
	BackupExists  bool     `json:"backup_exists"`
	BackupAt      string   `json:"backup_at,omitempty"`
	ImportedPorts []uint16 `json:"imported_ports,omitempty"`
	Detail        string   `json:"detail"`
}

// TakeoverStatusResponse is returned by firewall.takeover_status / takeover / restore_manager.
type TakeoverStatusResponse struct {
	Managers []TakeoverStatusEntry `json:"managers"`
}

func isManageableManager(kind string) bool {
	switch kind {
	case "ufw", "firewalld", "fail2ban":
		return true
	default:
		return false
	}
}

func takeoverBackupDir(rootPath string) string {
	if rootPath == "" {
		rootPath = "/"
	}
	return filepath.Join(rootPath, takeoverBackupRelDir)
}

func readTakeoverRecord(rootPath, manager string) (*TakeoverRecord, bool) {
	if !isManageableManager(manager) {
		return nil, false
	}
	full := filepath.Join(takeoverBackupDir(rootPath), manager+".json")
	raw, err := os.ReadFile(full)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	var rec TakeoverRecord
	if json.Unmarshal(raw, &rec) != nil || rec.Manager != manager {
		return nil, false
	}
	return &rec, true
}

func writeTakeoverRecord(rootPath string, rec TakeoverRecord) error {
	dir := takeoverBackupDir(rootPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return sandbox.WriteFileAtomic(filepath.Join(dir, rec.Manager+".json"), raw, 0o600)
}

func removeTakeoverRecord(rootPath, manager string) error {
	full := filepath.Join(takeoverBackupDir(rootPath), manager+".json")
	err := os.Remove(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Service) guardRootPath() string {
	if sg, ok := s.Guard.(SystemGuard); ok && sg.RootPath != "" {
		return sg.RootPath
	}
	return "/"
}

var (
	ufwRulePortRe      = regexp.MustCompile(`-p\s+(tcp|udp)\s+.*--dport\s+(\d{1,5})\b.*-j\s+ACCEPT`)
	firewalldPortRe    = regexp.MustCompile(`<port\s+protocol="(tcp|udp)"\s+port="(\d{1,5})"\s*/?>`)
	firewalldServiceRe = regexp.MustCompile(`<service\s+name="([a-z0-9-]+)"\s*/?>`)
)

func extractPortsFromUFWRules(content string) []TakeoverPort {
	seen := map[string]struct{}{}
	var out []TakeoverPort
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := ufwRulePortRe.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		p, err := strconv.ParseUint(m[2], 10, 16)
		if err != nil || p == 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", m[1], p)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, TakeoverPort{Proto: m[1], Port: uint16(p)})
	}
	return out
}

func extractPortsFromFirewalldXML(content string) []TakeoverPort {
	seen := map[string]struct{}{}
	var out []TakeoverPort
	add := func(proto string, port uint16) {
		key := fmt.Sprintf("%s:%d", proto, port)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, TakeoverPort{Proto: proto, Port: port})
	}
	for _, m := range firewalldPortRe.FindAllStringSubmatch(content, -1) {
		p, err := strconv.ParseUint(m[2], 10, 16)
		if err == nil && p > 0 {
			add(m[1], uint16(p))
		}
	}
	for _, m := range firewalldServiceRe.FindAllStringSubmatch(content, -1) {
		switch m[1] {
		case "http":
			add("tcp", 80)
		case "https":
			add("tcp", 443)
		case "dns":
			add("tcp", 53)
			add("udp", 53)
		case "smtp":
			add("tcp", 25)
		}
	}
	return out
}

func collectBackupAndPorts(rootPath, manager string) (map[string]string, []TakeoverPort) {
	backups := map[string]string{}
	var ports []TakeoverPort
	totalBytes := 0
	captureFile := func(rel string) string {
		full := filepath.Join(rootPath, rel)
		raw, err := os.ReadFile(full)
		if err != nil || len(raw) == 0 {
			return ""
		}
		if totalBytes+len(raw) <= maxTakeoverBackupRaw {
			backups[rel] = string(raw)
			totalBytes += len(raw)
		}
		return string(raw)
	}
	switch manager {
	case "ufw":
		captureFile("etc/ufw/ufw.conf")
		if c := captureFile("etc/ufw/user.rules"); c != "" {
			ports = append(ports, extractPortsFromUFWRules(c)...)
		}
		if c := captureFile("etc/ufw/user6.rules"); c != "" {
			ports = append(ports, extractPortsFromUFWRules(c)...)
		}
	case "firewalld":
		zoneDir := filepath.Join(rootPath, "etc/firewalld/zones")
		if entries, err := os.ReadDir(zoneDir); err == nil {
			for _, ent := range entries {
				if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".xml") {
					continue
				}
				if c := captureFile(filepath.Join("etc/firewalld/zones", ent.Name())); c != "" {
					ports = append(ports, extractPortsFromFirewalldXML(c)...)
				}
			}
		}
	case "fail2ban":
		captureFile("etc/fail2ban/jail.local")
		jailDir := filepath.Join(rootPath, "etc/fail2ban/jail.d")
		if entries, err := os.ReadDir(jailDir); err == nil {
			for _, ent := range entries {
				if ent.IsDir() || (!strings.HasSuffix(ent.Name(), ".conf") && !strings.HasSuffix(ent.Name(), ".local")) {
					continue
				}
				captureFile(filepath.Join("etc/fail2ban/jail.d", ent.Name()))
			}
		}
	}
	// Deduplicate ports cleanly.
	seen := map[string]struct{}{}
	uniq := make([]TakeoverPort, 0, len(ports))
	for _, tp := range ports {
		k := fmt.Sprintf("%s:%d", tp.Proto, tp.Port)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		uniq = append(uniq, tp)
	}
	sort.Slice(uniq, func(i, j int) bool {
		if uniq[i].Port != uniq[j].Port {
			return uniq[i].Port < uniq[j].Port
		}
		return uniq[i].Proto < uniq[j].Proto
	})
	return backups, uniq
}

func (s *Service) buildTakeoverStatus(ctx context.Context) (TakeoverStatusResponse, error) {
	managers, err := s.Guard.Managers(ctx)
	if err != nil {
		return TakeoverStatusResponse{}, err
	}
	rootPath := s.guardRootPath()
	out := TakeoverStatusResponse{Managers: make([]TakeoverStatusEntry, 0, 3)}
	for _, m := range managers {
		if !isManageableManager(m.Kind) {
			continue
		}
		rec, hasRec := readTakeoverRecord(rootPath, m.Kind)
		ent := TakeoverStatusEntry{
			Manager:      m.Kind,
			Active:       m.Active,
			TakenOver:    hasRec && !m.Active,
			BackupExists: hasRec,
			Detail:       m.Detail,
		}
		if hasRec && rec != nil {
			ent.BackupAt = rec.TakenOverAt
			for _, p := range rec.ImportedPorts {
				ent.ImportedPorts = append(ent.ImportedPorts, p.Port)
			}
		}
		out.Managers = append(out.Managers, ent)
	}
	return out, nil
}

func (s *Service) takeoverStatusOp(ctx context.Context) sandbox.CapabilityResponse {
	st, err := s.buildTakeoverStatus(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "无法读取共存管理器状态")
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return failure("UNAVAILABLE", "无法编码接管状态")
	}
	return sandbox.CapabilityResponse{OK: true, ResultJSON: raw}
}

func (s *Service) takeoverManagerOp(ctx context.Context, params []byte) sandbox.CapabilityResponse {
	var req struct {
		Manager string `json:"manager"`
	}
	if decodeObject(params, &req) != nil || !isManageableManager(req.Manager) {
		return failure("VALIDATION_FAILED", "仅支持接管 ufw、firewalld 或 fail2ban")
	}
	unlock, err := s.State.Lock(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "防火墙资源锁不可用")
	}
	defer unlock()

	unit := req.Manager + ".service"
	activeRes, _ := s.Executor.Execute(ctx, local.Systemctl, []string{"is-active", unit}, nil)
	wasActive := strings.TrimSpace(string(activeRes.Output)) == "active"
	enabledRes, _ := s.Executor.Execute(ctx, local.Systemctl, []string{"is-enabled", unit}, nil)
	wasEnabled := strings.TrimSpace(string(enabledRes.Output)) == "enabled"

	rootPath := s.guardRootPath()
	backups, imported := collectBackupAndPorts(rootPath, req.Manager)

	rec := TakeoverRecord{
		Manager:       req.Manager,
		TakenOverAt:   time.Now().UTC().Format(time.RFC3339),
		WasActive:     wasActive,
		WasEnabled:    wasEnabled,
		ImportedPorts: imported,
		BackupFiles:   backups,
	}
	if err := writeTakeoverRecord(rootPath, rec); err != nil {
		return failure("UNAVAILABLE", "备份原配置文件失败，已中止接管以保护现有配置")
	}

	// For ufw / firewalld, preserve all existing allowed ports plus management/SSH ports in inet qwq BEFORE disabling the old manager.
	if req.Manager == "ufw" || req.Manager == "firewalld" {
		required, rerr := s.Guard.PreservedPorts(ctx)
		if rerr != nil {
			return failure("UNAVAILABLE", "无法核验 SSH 与面板保留端口，已中止接管")
		}
		required, rerr = preservedPorts(required, required)
		if rerr != nil {
			return failure("UNAVAILABLE", "管理端口无效，已中止接管")
		}
		current, serr := s.readSnapshot(ctx)
		if serr != nil {
			return failure("UNAVAILABLE", "读取现有 nftables 状态失败")
		}
		desired, merr := Minimal(required)
		if merr == nil {
			// Append imported ports as accept rules while keeping default policy accept so zero traffic breaks.
			for _, tp := range imported {
				desired.rules = append(desired.rules, buildAcceptPortRuleObject(tp.Proto, tp.Port, "imported-"+req.Manager))
			}
			applyResp := s.apply(ctx, current, desired, required)
			if !applyResp.OK {
				return applyResp
			}
		}
	}

	// Stop & disable the competing manager cleanly.
	if _, err := s.Executor.Execute(ctx, local.Systemctl, []string{"disable", "--now", unit}, nil); err != nil {
		return failure("UNAVAILABLE", "停用原服务失败，配置备份已保留，可稍后重试")
	}

	return s.takeoverStatusOp(ctx)
}

func (s *Service) restoreManagerOp(ctx context.Context, params []byte) sandbox.CapabilityResponse {
	var req struct {
		Manager string `json:"manager"`
	}
	if decodeObject(params, &req) != nil || !isManageableManager(req.Manager) {
		return failure("VALIDATION_FAILED", "仅支持还原 ufw、firewalld 或 fail2ban")
	}
	unlock, err := s.State.Lock(ctx)
	if err != nil {
		return failure("UNAVAILABLE", "防火墙资源锁不可用")
	}
	defer unlock()

	rootPath := s.guardRootPath()
	rec, ok := readTakeoverRecord(rootPath, req.Manager)
	if !ok {
		return failure("NOT_FOUND", "未找到该服务的接管备份记录")
	}

	// If restoring a firewall manager, clear qwq's input chain first so there are zero conflicting rules.
	if req.Manager == "ufw" || req.Manager == "firewalld" {
		current, serr := s.readSnapshot(ctx)
		if serr == nil && current.chainExists {
			delTx := []byte(`{"nftables":[{"delete":{"chain":{"family":"inet","table":"qwq","name":"input"}}}]}`)
			_, _ = s.execute(ctx, []string{"-j", "-f", "-"}, delTx)
		}
		_ = s.State.Commit(nil)
	}

	// Re-enable and start original service cleanly.
	unit := req.Manager + ".service"
	if rec.WasEnabled {
		_, _ = s.Executor.Execute(ctx, local.Systemctl, []string{"enable", unit}, nil)
	}
	if _, err := s.Executor.Execute(ctx, local.Systemctl, []string{"start", unit}, nil); err != nil {
		return failure("UNAVAILABLE", "重新启动原服务失败，请通过终端检查服务状态")
	}
	_ = removeTakeoverRecord(rootPath, req.Manager)

	return s.takeoverStatusOp(ctx)
}

func buildAcceptPortRuleObject(proto string, port uint16, comment string) ruleObject {
	if proto != "udp" {
		proto = "tcp"
	}
	matchRaw, _ := json.Marshal(map[string]any{
		"match": map[string]any{
			"op":    "==",
			"left":  map[string]any{"payload": map[string]any{"protocol": proto, "field": "dport"}},
			"right": port,
		},
	})
	return ruleObject{
		Family:  "inet",
		Table:   "qwq",
		Chain:   "input",
		Comment: comment,
		Expr:    []json.RawMessage{matchRaw, json.RawMessage(`{"accept":null}`)},
	}
}
