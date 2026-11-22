// SPDX-License-Identifier: AGPL-3.0-only

// Package ban 提供基于 journald 增量扫描与 nftables 内核超时集合的防爆破封禁能力。
package ban

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/sandbox"
	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
)

// ======================== 容量、窗口与防自锁约束 ========================

const (
	MaxBanSetEntries = 4096
	MaxSinceSeconds  = 3600
	MinBanTTLSeconds = 60
	MaxBanTTLSeconds = 30 * 86400
	maxBatchEntries  = 512
)

var sshFailPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?([A-Za-z0-9_.-]{1,64}) from ([0-9a-fA-F:.]{3,45})\b`),
	regexp.MustCompile(`Invalid user ([A-Za-z0-9_.-]{1,64}) from ([0-9a-fA-F:.]{3,45})\b`),
	regexp.MustCompile(`Connection closed by authenticating user ([A-Za-z0-9_.-]{1,64}) ([0-9a-fA-F:.]{3,45}) port \d+ \[preauth\]`),
}

// CommandRunner 封装受控命令执行，生产默认直接调用固定路径的 journalctl / nft。
type CommandRunner func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)

// Service 运行在特权 capability helper 中，处理 4 个 ban.* verb。
type Service struct {
	JournalctlPath string
	NftPath        string
	Now            func() time.Time
	RunCmd         CommandRunner
	mu             sync.Mutex
}

// NewService 构造默认封禁能力服务。
func NewService() *Service {
	return &Service{
		JournalctlPath: "/usr/bin/journalctl",
		NftPath:        "/usr/sbin/nft",
		Now:            time.Now,
	}
}

func (s *Service) execCmd(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	if s.RunCmd != nil {
		return s.RunCmd(ctx, name, args, stdin)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.Output()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// ======================== Capability Helper 请求路由 ========================

type scanParams struct {
	Cursor       string `json:"cursor,omitempty"`
	SinceSeconds uint32 `json:"since_seconds,omitempty"`
	Unit         string `json:"unit,omitempty"`
}

type banEntryParam struct {
	IP         string `json:"ip"`
	TTLSeconds uint32 `json:"ttl_seconds"`
}

type applyBansParams struct {
	Entries          []banEntryParam `json:"entries"`
	ExpectedRevision string          `json:"expected_revision,omitempty"`
	ProtectedIPs     []string        `json:"protected_ips,omitempty"`
}

type removeBanParams struct {
	IP               string `json:"ip"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
}

// Run 路由 ban.* 四个受控动词，拒绝非法参数与受保护管理源 IP。
func (s *Service) Run(ctx context.Context, request sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	if sandbox.ValidateCapabilityRequest(request) != nil || len(request.Secret) != 0 {
		return bridge.Failure("VALIDATION_FAILED", "封禁能力请求无效"), nil
	}
	params := request.ParamsJSON
	if len(params) == 0 {
		params = []byte("{}")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch request.Op {
	case "ban.scan":
		var p scanParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return bridge.Failure("VALIDATION_FAILED", "扫描参数无效"), nil
		}
		return s.scanAuthFailures(ctx, p), nil
	case "ban.list":
		return s.listBans(ctx), nil
	case "ban.apply":
		var p applyBansParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return bridge.Failure("VALIDATION_FAILED", "封禁参数无效"), nil
		}
		return s.applyBans(ctx, p), nil
	case "ban.remove":
		var p removeBanParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return bridge.Failure("VALIDATION_FAILED", "解封参数无效"), nil
		}
		return s.removeBan(ctx, p), nil
	default:
		return bridge.Failure("UNIMPLEMENTED", "不支持的封禁能力动词"), nil
	}
}

// ======================== journald 增量流式认证失败扫描 ========================

func allowedUnitArgs(unit string) ([]string, bool) {
	switch unit {
	case "":
		return []string{"-u", "ssh.service", "-u", "sshd.service"}, true
	case "ssh.service", "sshd.service":
		return []string{"-u", unit}, true
	default:
		return nil, false
	}
}

type journalRecord struct {
	Cursor    string `json:"__CURSOR"`
	Timestamp string `json:"__REALTIME_TIMESTAMP"`
	Message   any    `json:"MESSAGE"`
}

func extractJournalMessage(msg any) string {
	switch v := msg.(type) {
	case string:
		return v
	case []any:
		buf := make([]byte, 0, len(v))
		for _, item := range v {
			if f, ok := item.(float64); ok && f >= 0 && f <= 255 {
				buf = append(buf, byte(f))
			}
		}
		return string(buf)
	default:
		return ""
	}
}

func (s *Service) scanAuthFailures(ctx context.Context, p scanParams) sandbox.CapabilityResponse {
	unitArgs, ok := allowedUnitArgs(p.Unit)
	if !ok {
		return bridge.Failure("VALIDATION_FAILED", "日志单元不在白名单内")
	}
	since := p.SinceSeconds
	if since == 0 {
		since = 600
	}
	if since > MaxSinceSeconds {
		since = MaxSinceSeconds
	}
	args := []string{"--no-pager", "-o", "json", "-n", "2000"}
	args = append(args, unitArgs...)
	if p.Cursor != "" {
		if len(p.Cursor) > 512 || strings.ContainsAny(p.Cursor, " \t\r\n\x00'") {
			return bridge.Failure("VALIDATION_FAILED", "journald 游标格式无效")
		}
		args = append(args, "--after-cursor="+p.Cursor)
	} else {
		args = append(args, fmt.Sprintf("--since=-%ds", since))
	}

	jpath := s.JournalctlPath
	if jpath == "" {
		jpath = "/usr/bin/journalctl"
	}
	out, err := s.execCmd(ctx, jpath, args, nil)
	if err != nil && len(out) == 0 {
		return bridge.Failure("UNAVAILABLE", "读取 SSH 认证日志失败")
	}

	type aggKey struct {
		ip   string
		user string
	}
	agg := make(map[aggKey]*banv1.AuthFailure)
	var order []aggKey
	nextCursor := p.Cursor

	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 512*1024)
	for sc.Scan() {
		var rec journalRecord
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		if rec.Cursor != "" {
			nextCursor = rec.Cursor
		}
		msg := extractJournalMessage(rec.Message)
		if msg == "" {
			continue
		}
		var user, rawIP string
		for _, re := range sshFailPatterns {
			if m := re.FindStringSubmatch(msg); len(m) == 3 {
				user, rawIP = m[1], m[2]
				break
			}
		}
		if rawIP == "" {
			continue
		}
		addr, perr := netip.ParseAddr(rawIP)
		if perr != nil {
			continue
		}
		normIP := addr.Unmap().String()
		tsMs := s.now().UnixMilli()
		if rec.Timestamp != "" {
			if usec, terr := strconv.ParseInt(rec.Timestamp, 10, 64); terr == nil && usec > 0 {
				tsMs = usec / 1000
			}
		}
		key := aggKey{ip: normIP, user: user}
		entry, exists := agg[key]
		if !exists {
			entry = &banv1.AuthFailure{Ip: normIP, User: user, OccurredAt: tsMs, Count: 1}
			agg[key] = entry
			order = append(order, key)
		} else {
			entry.Count++
			if tsMs > entry.OccurredAt {
				entry.OccurredAt = tsMs
			}
		}
	}

	failures := make([]*banv1.AuthFailure, 0, len(order))
	for _, k := range order {
		failures = append(failures, agg[k])
	}
	return bridge.Pack(&banv1.ScanAuthFailuresResponse{
		Failures:   failures,
		NextCursor: nextCursor,
	})
}

// ======================== table inet qwq @ban_v4/@ban_v6 内核超时集合 ========================

// ensureBanInfrastructure 幂等声明 table inet qwq 中的 ban_v4/ban_v6 集合及独立 ban 链（priority -1）。
// 与 firewall 管理的 input 链（priority 0）完全隔离，互不踩踏 revision 与规则集。
func (s *Service) ensureBanInfrastructure(ctx context.Context) error {
	script := `add table inet qwq
add set inet qwq ban_v4 { type ipv4_addr; size 4096; flags timeout; }
add set inet qwq ban_v6 { type ipv6_addr; size 4096; flags timeout; }
add chain inet qwq ban { type filter hook input priority -1; policy accept; }
flush chain inet qwq ban
add rule inet qwq ban ct state established,related accept comment "qwq:ban-established"
add rule inet qwq ban iifname "lo" accept comment "qwq:ban-loopback"
add rule inet qwq ban ip saddr @ban_v4 drop comment "qwq:ban-v4"
add rule inet qwq ban ip6 saddr @ban_v6 drop comment "qwq:ban-v6"
`
	nft := s.NftPath
	if nft == "" {
		nft = "/usr/sbin/nft"
	}
	_, err := s.execCmd(ctx, nft, []string{"-f", "-"}, []byte(script))
	return err
}

func (s *Service) readActiveBans(ctx context.Context) ([]*banv1.ActiveBan, string, error) {
	nft := s.NftPath
	if nft == "" {
		nft = "/usr/sbin/nft"
	}
	nowMs := s.now().UnixMilli()
	var all []*banv1.ActiveBan
	for _, setName := range []string{"ban_v4", "ban_v6"} {
		out, err := s.execCmd(ctx, nft, []string{"-j", "list", "set", "inet", "qwq", setName}, nil)
		if err != nil {
			continue
		}
		parsed := parseNftSetJSON(out, nowMs)
		all = append(all, parsed...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].GetIp() < all[j].GetIp() })
	return all, computeBanRevision(all), nil
}

func parseNftSetJSON(raw []byte, nowMs int64) []*banv1.ActiveBan {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []any `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []*banv1.ActiveBan
	for _, obj := range doc.Nftables {
		if obj.Set == nil {
			continue
		}
		for _, item := range obj.Set.Elem {
			switch v := item.(type) {
			case string:
				if addr, err := netip.ParseAddr(v); err == nil {
					out = append(out, &banv1.ActiveBan{Ip: addr.Unmap().String(), ExpiresAt: 0})
				}
			case map[string]any:
				elem, ok := v["elem"].(map[string]any)
				if !ok {
					continue
				}
				valStr, _ := elem["val"].(string)
				addr, err := netip.ParseAddr(valStr)
				if err != nil {
					continue
				}
				var expSec int64
				if e, ok := elem["expires"].(float64); ok && e > 0 {
					expSec = int64(e)
				} else if t, ok := elem["timeout"].(float64); ok && t > 0 {
					expSec = int64(t)
				}
				var expiresAt int64
				if expSec > 0 {
					expiresAt = nowMs + expSec*1000
				}
				out = append(out, &banv1.ActiveBan{Ip: addr.Unmap().String(), ExpiresAt: expiresAt})
			}
		}
	}
	return out
}

func computeBanRevision(bans []*banv1.ActiveBan) string {
	h := sha256.New()
	for _, b := range bans {
		h.Write([]byte(b.GetIp()))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func isAlwaysProtected(addr netip.Addr) bool {
	u := addr.Unmap()
	return u.IsLoopback() || u.IsUnspecified() || u.IsLinkLocalUnicast() || u.IsMulticast()
}

func (s *Service) listBans(ctx context.Context) sandbox.CapabilityResponse {
	bans, rev, err := s.readActiveBans(ctx)
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "读取活跃封禁集合失败")
	}
	return bridge.Pack(&banv1.ListBansResponse{
		Bans:     bans,
		Revision: rev,
	})
}

func (s *Service) applyBans(ctx context.Context, p applyBansParams) sandbox.CapabilityResponse {
	if len(p.Entries) == 0 || len(p.Entries) > maxBatchEntries {
		return bridge.Failure("VALIDATION_FAILED", "封禁条目数量无效")
	}
	protected := make(map[netip.Addr]bool, len(p.ProtectedIPs))
	for _, raw := range p.ProtectedIPs {
		if addr, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			protected[addr.Unmap()] = true
		}
	}

	type cleanEntry struct {
		addr netip.Addr
		ttl  uint32
	}
	cleaned := make([]cleanEntry, 0, len(p.Entries))
	for _, e := range p.Entries {
		addr, err := netip.ParseAddr(strings.TrimSpace(e.IP))
		if err != nil {
			return bridge.Failure("VALIDATION_FAILED", "封禁目标包含非法 IP 地址")
		}
		u := addr.Unmap()
		if isAlwaysProtected(u) || protected[u] {
			return bridge.Failure("PRECONDITION_FAILED", "禁止封禁当前管理源 IP、回环或受保护地址")
		}
		if e.TTLSeconds < MinBanTTLSeconds || e.TTLSeconds > MaxBanTTLSeconds {
			return bridge.Failure("VALIDATION_FAILED", "封禁时长须在 60 秒至 30 天之间")
		}
		cleaned = append(cleaned, cleanEntry{addr: u, ttl: e.TTLSeconds})
	}

	current, curRev, err := s.readActiveBans(ctx)
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "读取现有封禁集合失败")
	}
	if p.ExpectedRevision != "" && p.ExpectedRevision != curRev {
		return bridge.Failure("PRECONDITION_FAILED", "封禁集合版本已变化")
	}
	existing := make(map[string]bool, len(current))
	for _, b := range current {
		existing[b.GetIp()] = true
	}
	netNew := 0
	for _, c := range cleaned {
		if !existing[c.addr.String()] {
			existing[c.addr.String()] = true
			netNew++
		}
	}
	if len(current)+netNew > MaxBanSetEntries {
		return bridge.Failure("RESOURCE_EXHAUSTED", "封禁集合已达 4096 条容量上限")
	}

	if err := s.ensureBanInfrastructure(ctx); err != nil {
		return bridge.Failure("UNAVAILABLE", "初始化 nftables 封禁集合失败")
	}

	var script bytes.Buffer
	for _, c := range cleaned {
		setName := "ban_v6"
		if c.addr.Is4() {
			setName = "ban_v4"
		}
		fmt.Fprintf(&script, "add element inet qwq %s { %s timeout %ds }\n", setName, c.addr.String(), c.ttl)
	}
	nft := s.NftPath
	if nft == "" {
		nft = "/usr/sbin/nft"
	}
	if _, err := s.execCmd(ctx, nft, []string{"-f", "-"}, script.Bytes()); err != nil {
		return bridge.Failure("UNAVAILABLE", "写入 nftables 封禁元素失败")
	}

	after, afterRev, _ := s.readActiveBans(ctx)
	return bridge.Pack(&banv1.ApplyBansResponse{
		Revision:    afterRev,
		ActiveCount: uint32(len(after)),
	})
}

func (s *Service) removeBan(ctx context.Context, p removeBanParams) sandbox.CapabilityResponse {
	addr, err := netip.ParseAddr(strings.TrimSpace(p.IP))
	if err != nil {
		return bridge.Failure("VALIDATION_FAILED", "解封目标不是有效 IP 地址")
	}
	u := addr.Unmap()

	current, curRev, err := s.readActiveBans(ctx)
	if err != nil {
		return bridge.Failure("UNAVAILABLE", "读取现有封禁集合失败")
	}
	if p.ExpectedRevision != "" && p.ExpectedRevision != curRev {
		return bridge.Failure("PRECONDITION_FAILED", "封禁集合版本已变化")
	}
	present := false
	for _, b := range current {
		if b.GetIp() == u.String() {
			present = true
			break
		}
	}
	if !present {
		return bridge.Pack(&banv1.RemoveBanResponse{Revision: curRev})
	}

	setName := "ban_v6"
	if u.Is4() {
		setName = "ban_v4"
	}
	script := fmt.Sprintf("delete element inet qwq %s { %s }\n", setName, u.String())
	nft := s.NftPath
	if nft == "" {
		nft = "/usr/sbin/nft"
	}
	if _, err := s.execCmd(ctx, nft, []string{"-f", "-"}, []byte(script)); err != nil {
		return bridge.Failure("UNAVAILABLE", "删除 nftables 封禁元素失败")
	}

	_, afterRev, _ := s.readActiveBans(ctx)
	return bridge.Pack(&banv1.RemoveBanResponse{Revision: afterRev})
}
