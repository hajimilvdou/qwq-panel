// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ======================== 内核 UID 门禁必须先于特权副作用 ========================

func TestPrivilegedPeerRejectsForeignUID(t *testing.T) {
	assertPrivilegedPeerDenied(t, func(t *testing.T, h *testHost, req sandbox.HelperRequest) peerWireOutcome {
		clientUID, agentUID := os.Getuid(), os.Getuid()+1
		if os.Geteuid() == 0 {
			// root 是合法例外，必须用独立降权进程真实连接；父测试不切换 UID。
			clientUID, agentUID = 1, 2
		}
		h.server.lookupUID = func(string) (int, error) { return agentUID, nil }
		return peerUnixRequest(t, h.server, req, clientUID)
	})
}

func TestPrivilegedPeerRejectsUnverifiedTransport(t *testing.T) {
	assertPrivilegedPeerDenied(t, peerPipeRequest)
}

func TestPrivilegedPeerRejectsUnresolvedAgentUser(t *testing.T) {
	assertPrivilegedPeerDenied(t, func(t *testing.T, h *testHost, req sandbox.HelperRequest) peerWireOutcome {
		peerUnresolvedAgentUser(t, h)
		if req.Spec != nil {
			// 与合法配置同步，避免字段校验错误抢先掩盖身份解析失败。
			req.Spec.AgentUser = h.cfg.AgentUser
		}
		clientUID := os.Getuid()
		if os.Geteuid() == 0 {
			clientUID = 1
		}
		return peerUnixRequest(t, h.server, req, clientUID)
	})
}

func assertPrivilegedPeerDenied(t *testing.T, exchange func(*testing.T, *testHost, sandbox.HelperRequest) peerWireOutcome) {
	t.Helper()
	for _, op := range []string{sandbox.HelperOpInstall, sandbox.HelperOpRemove} {
		t.Run(op, func(t *testing.T) {
			h := newTestHost(t)
			req := peerMutationRequest(t, h, op)
			before := peerSideEffects(t, h)
			got := exchange(t, h, req)
			if got.Failure != "" {
				t.Errorf("peer 夹具传输失败，不能算身份拒绝：%s", got.Failure)
			} else if !got.Closed && (got.OK || got.Code != string(problem.Unauthenticated)) {
				t.Errorf("未核验的 peer 到达领域处理：ok=%v code=%q", got.OK, got.Code)
			}
			after := peerSideEffects(t, h)
			if before.commands != after.commands {
				t.Errorf("拒绝请求执行了特权命令：before=%d after=%d", before.commands, after.commands)
			}
			var changed []string
			for path, state := range after.paths {
				if old, ok := before.paths[path]; !ok || old != state {
					changed = append(changed, path)
				}
			}
			for path := range before.paths {
				if _, ok := after.paths[path]; !ok {
					changed = append(changed, path)
				}
			}
			if len(changed) != 0 {
				sort.Strings(changed)
				// 只报告夹具路径，不输出凭据正文或其摘要。
				t.Errorf("拒绝请求改变了 unit/token/version 等路径：%v", changed)
			}
		})
	}
}

// ======================== root 与配置的 agent 均保留正常 one-shot 协议 ========================

func TestPrivilegedPeerAcceptsAuthorizedOneShot(t *testing.T) {
	for _, test := range []struct {
		identity        string
		root            bool
		unresolvedAgent bool
	}{
		{identity: "agent"},
		{identity: "root", root: true},
		{identity: "root_unresolved_agent", root: true, unresolvedAgent: true},
	} {
		t.Run(test.identity, func(t *testing.T) {
			if test.root && os.Getuid() != 0 {
				t.Skip("非 root 构建不创建提权连接进程")
			}
			h := newTestHost(t)
			if test.unresolvedAgent {
				peerUnresolvedAgentUser(t, h)
			}
			req := peerMutationRequest(t, h, sandbox.HelperOpInstall)
			clientUID, agentUID := os.Getuid(), os.Getuid()
			if os.Geteuid() == 0 {
				agentUID = 1
				if !test.root {
					clientUID = agentUID
				}
			}
			if !test.unresolvedAgent {
				h.server.lookupUID = func(string) (int, error) { return agentUID, nil }
			}
			got := peerUnixRequest(t, h.server, req, clientUID)
			if got.Failure != "" || got.Closed || !got.OK {
				t.Fatalf("合法 %s 连接未完成 one-shot：failure=%q closed=%v ok=%v code=%q",
					test.identity, got.Failure, got.Closed, got.OK, got.Code)
			}
			for _, path := range []string{
				filepath.Join(h.cfg.UnitDir, "qwq-plugin@alpha.service"),
				filepath.Join(h.cfg.CredDir, "alpha.token"),
			} {
				if _, err := os.Stat(path); err != nil {
					t.Errorf("合法连接未写入原安装产物：%s: %v", path, err)
				}
			}
			if !h.runner.has("systemctl", "daemon-reload") {
				t.Error("合法连接没有到达原安装执行链")
			}
		})
	}
}

// ======================== 未解析配置用户：真实 NSS 失败，领域字段保持合法 ========================

func peerUnresolvedAgentUser(t *testing.T, h *testHost) {
	t.Helper()
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("生成缺失用户夹具名称失败：%v", err)
	}
	missing := "qwq_peer_missing_" + hex.EncodeToString(suffix[:])
	if !userPattern.MatchString(missing) {
		t.Fatal("缺失用户夹具名称不符合生产配置格式")
	}
	// Go 文件查询与 CGO/NSS 可返回不同失败类型；门禁必须对真实解析失败一律拒绝。
	if _, err := lookupUID(missing); err == nil {
		t.Fatal("随机配置用户被系统解析，不能用于身份解析失败回归")
	}
	h.cfg.AgentUser = missing
	h.server.cfg.AgentUser = missing
	h.server.installer.AgentUser = missing
	h.server.lookupUID = lookupUID
}

// peerMutationRequest 复用已通过的安装/删除领域夹具；请求自报用户名不能授权连接。
func peerMutationRequest(t *testing.T, h *testHost, op string) sandbox.HelperRequest {
	t.Helper()
	versionDir := h.addVersion(t, "alpha", "1.2.3")
	spec := specFor("alpha", versionDir)
	spec.AgentUser = h.cfg.AgentUser
	req := installRequest(spec, token())
	if op == sandbox.HelperOpInstall {
		return req
	}
	if setup := h.server.handle(t.Context(), req); !setup.OK {
		t.Fatalf("受信安装夹具准备失败：code=%q", setup.Code)
	}
	return sandbox.HelperRequest{
		Op: sandbox.HelperOpRemove, ID: "alpha", Version: "1.2.3", Paths: []string{versionDir},
	}
}

// ======================== 受信临时路径：同时核对内容、权限、属主和命令数量 ========================

type peerPathState struct {
	mode   fs.FileMode
	uid    uint32
	gid    uint32
	digest [sha256.Size]byte
}

type peerEffects struct {
	paths    map[string]peerPathState
	commands int
}

func peerSideEffects(t *testing.T, h *testHost) peerEffects {
	t.Helper()
	result := peerEffects{paths: make(map[string]peerPathState)}
	for _, root := range []string{
		h.cfg.UnitDir, h.cfg.TmpfilesDir, h.cfg.RuntimeBase,
		h.cfg.CredDir, h.cfg.PluginsRoot, h.cfg.StagingRoot,
	} {
		if _, err := os.Lstat(root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			t.Fatalf("检查夹具根失败：%v", err)
		}
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			state := peerPathState{mode: info.Mode()}
			state.uid, state.gid, err = peerFileOwner(info)
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				state.digest = sha256.Sum256(data)
				clear(data)
			}
			result.paths[path] = state
			return nil
		}); err != nil {
			t.Fatalf("读取副作用夹具快照失败：%v", err)
		}
	}
	h.runner.mu.Lock()
	result.commands = len(h.runner.calls)
	h.runner.mu.Unlock()
	return result
}
