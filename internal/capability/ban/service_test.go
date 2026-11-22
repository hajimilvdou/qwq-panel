// SPDX-License-Identifier: AGPL-3.0-only

package ban

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
)

// ======================== journald 增量扫描与 nft 封禁集合测试 ========================

type banHelperAdapter struct{ svc *Service }

func (a banHelperAdapter) Call(ctx context.Context, req sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	return a.svc.Run(ctx, req)
}

type mockNftState struct {
	mu      sync.Mutex
	v4      map[string]uint32
	v6      map[string]uint32
	journal string
	scripts []string
}

func (m *mockNftState) run(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.HasSuffix(name, "journalctl") {
		return []byte(m.journal), nil
	}
	if len(args) >= 6 && args[0] == "-j" && args[1] == "list" && args[2] == "set" {
		setName := args[5]
		src := m.v4
		if setName == "ban_v6" {
			src = m.v6
		}
		elems := make([]any, 0, len(src))
		for ip, ttl := range src {
			elems = append(elems, map[string]any{
				"elem": map[string]any{"val": ip, "expires": ttl, "timeout": ttl},
			})
		}
		raw, _ := json.Marshal(map[string]any{
			"nftables": []any{map[string]any{"set": map[string]any{"name": setName, "elem": elems}}},
		})
		return raw, nil
	}
	if len(args) == 2 && args[0] == "-f" && args[1] == "-" {
		txt := string(stdin)
		m.scripts = append(m.scripts, txt)
		for _, line := range strings.Split(txt, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "add element inet qwq ban_v4 { ") {
				body := strings.TrimSuffix(strings.TrimPrefix(line, "add element inet qwq ban_v4 { "), " }")
				parts := strings.Fields(body)
				if len(parts) >= 1 {
					m.v4[parts[0]] = 3600
				}
			} else if strings.HasPrefix(line, "add element inet qwq ban_v6 { ") {
				body := strings.TrimSuffix(strings.TrimPrefix(line, "add element inet qwq ban_v6 { "), " }")
				parts := strings.Fields(body)
				if len(parts) >= 1 {
					m.v6[parts[0]] = 3600
				}
			} else if strings.HasPrefix(line, "delete element inet qwq ban_v4 { ") {
				ip := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "delete element inet qwq ban_v4 { "), " }"))
				delete(m.v4, ip)
			} else if strings.HasPrefix(line, "delete element inet qwq ban_v6 { ") {
				ip := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "delete element inet qwq ban_v6 { "), " }"))
				delete(m.v6, ip)
			}
		}
		return nil, nil
	}
	return nil, nil
}

func TestBanScanApplyListRemoveAndProtectedIPGuard(t *testing.T) {
	now := time.Date(2026, 11, 21, 15, 0, 0, 0, time.UTC)
	mock := &mockNftState{
		v4: make(map[string]uint32),
		v6: make(map[string]uint32),
		journal: strings.Join([]string{
			`{"__CURSOR":"cur-1","__REALTIME_TIMESTAMP":"1795265100000000","MESSAGE":"Failed password for invalid user admin from 203.0.113.10 port 44123 ssh2"}`,
			`{"__CURSOR":"cur-2","__REALTIME_TIMESTAMP":"1795265105000000","MESSAGE":"Failed password for invalid user admin from 203.0.113.10 port 44124 ssh2"}`,
			`{"__CURSOR":"cur-3","__REALTIME_TIMESTAMP":"1795265110000000","MESSAGE":"Invalid user root from 2001:db8::99 port 51234"}`,
		}, "\n"),
	}
	svc := NewService()
	svc.Now = func() time.Time { return now }
	svc.RunCmd = mock.run

	adminIP := "198.51.100.77"
	fwd := Forwarder{
		Helper: banHelperAdapter{svc: svc},
		Protected: func(context.Context, hostsvc.CapabilityCall) ([]string, error) {
			return []string{adminIP}, nil
		},
	}

	// 1. ScanAuthFailures 正确聚合并推进 cursor；非法 unit 拒绝。
	badUnit, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "ban", Method: "ScanAuthFailures", PluginID: "security.basic",
		Request: &banv1.ScanAuthFailuresRequest{Unit: "arbitrary.service"},
	})
	if err != nil || badUnit.Error == nil || badUnit.Error.Code != "VALIDATION_FAILED" {
		t.Fatalf("非白名单 unit 应被拒绝：res=%+v err=%v", badUnit, err)
	}

	scanRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "ban", Method: "ScanAuthFailures", PluginID: "security.basic",
		Request: &banv1.ScanAuthFailuresRequest{SinceSeconds: 600, Unit: "sshd.service"},
	})
	if err != nil || scanRes.Error != nil {
		t.Fatalf("ScanAuthFailures 失败：res=%+v err=%v", scanRes, err)
	}
	scanResp := scanRes.Response.(*banv1.ScanAuthFailuresResponse)
	if scanResp.GetNextCursor() != "cur-3" || len(scanResp.GetFailures()) != 2 || scanResp.GetFailures()[0].GetCount() != 2 {
		t.Fatalf("扫描聚合结果不符：%+v", scanResp)
	}

	// 2. 尝试封禁管理员源 IP 或回环地址必须触发 PRECONDITION_FAILED 防自锁。
	for _, blocked := range []string{adminIP, "127.0.0.1", "::1"} {
		selfLock, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
			Service: "ban", Method: "ApplyBans", PluginID: "security.basic",
			Request: &banv1.ApplyBansRequest{
				Entries: []*banv1.BanEntry{{Ip: blocked, TtlSeconds: 600}},
			},
		})
		if err != nil || selfLock.Error == nil || selfLock.Error.Code != "PRECONDITION_FAILED" {
			t.Fatalf("受保护地址 %s 必须拒绝封禁：res=%+v err=%v", blocked, selfLock, err)
		}
	}

	// 3. 合法 IPv4 + IPv6 封禁生效、可 ListBans、支持 CAS 与解封。
	applyRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "ban", Method: "ApplyBans", PluginID: "security.basic",
		Request: &banv1.ApplyBansRequest{
			Entries: []*banv1.BanEntry{
				{Ip: "203.0.113.10", TtlSeconds: 3600},
				{Ip: "2001:db8::99", TtlSeconds: 3600},
			},
		},
	})
	if err != nil || applyRes.Error != nil {
		t.Fatalf("ApplyBans 失败：res=%+v err=%v", applyRes, err)
	}
	applyResp := applyRes.Response.(*banv1.ApplyBansResponse)
	if applyResp.GetActiveCount() != 2 || applyResp.GetRevision() == "" {
		t.Fatalf("ApplyBans 返回不符：%+v", applyResp)
	}

	// 过期 ExpectedRevision 必须返回 PRECONDITION_FAILED。
	staleRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "ban", Method: "RemoveBan", PluginID: "security.basic",
		Request: &banv1.RemoveBanRequest{Ip: "203.0.113.10", ExpectedRevision: "stale-rev"},
	})
	if err != nil || staleRes.Error == nil || staleRes.Error.Code != "PRECONDITION_FAILED" {
		t.Fatalf("过期 revision 应返回 PRECONDITION_FAILED：res=%+v err=%v", staleRes, err)
	}

	// 匹配 revision 解封成功，剩余 1 条。
	remRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "ban", Method: "RemoveBan", PluginID: "security.basic",
		Request: &banv1.RemoveBanRequest{Ip: "203.0.113.10", ExpectedRevision: applyResp.GetRevision()},
	})
	if err != nil || remRes.Error != nil {
		t.Fatalf("RemoveBan 失败：res=%+v err=%v", remRes, err)
	}

	listRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "ban", Method: "ListBans", PluginID: "security.basic",
		Request: &banv1.ListBansRequest{},
	})
	if err != nil || listRes.Error != nil {
		t.Fatalf("ListBans 失败：res=%+v err=%v", listRes, err)
	}
	listResp := listRes.Response.(*banv1.ListBansResponse)
	if len(listResp.GetBans()) != 1 || listResp.GetBans()[0].GetIp() != "2001:db8::99" {
		t.Fatalf("解封后列表不符：%+v", listResp.GetBans())
	}
}
