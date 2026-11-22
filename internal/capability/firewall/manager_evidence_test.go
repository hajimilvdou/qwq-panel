// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/capability/local"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ======================== 预装但未启用的 UFW 不得永久阻断自有防火墙 ========================

func TestInactiveDisabledUFWIsNotUncertain(t *testing.T) {
	guard, _, _ := managerEvidenceFixture(t, "ENABLED=no\n", "inactive")
	managers, err := guard.Managers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if managers[0].Kind != "ufw" || managers[0].Active || managers[0].Uncertain {
		t.Fatalf("明确停用且没有原生规则的 UFW 仍被当成共存冲突：active=%v uncertain=%v", managers[0].Active, managers[0].Uncertain)
	}
}

func TestInactiveDisabledUFWAllowsManagedFirewallApply(t *testing.T) {
	s, native, state, ports := firewallFixture()
	guard, executor, _ := managerEvidenceFixture(t, "# Ubuntu default\nENABLED=no\n", "inactive")
	executor.native = native
	s.Guard = managerEvidenceGuard{fakeGuard: ports, system: guard}
	before := getFirewall(t, s)
	result := applyFirewall(t, s, before.Revision)
	if !result.OK || native.writes != 1 || native.checks != 1 || state.raw == nil {
		t.Fatalf("明确停用的预装 UFW 阻断了通过原生预检的策略：ok=%v code=%q checks=%d writes=%d", result.OK, result.Code, native.checks, native.writes)
	}
}

func TestUFWConflictingEvidenceBlocksManagedFirewallApply(t *testing.T) {
	for _, test := range []struct {
		name, cfg, unitState string
		chain, table         bool
		unsafe, otherManager bool
		malformedTables      bool
		code                 string
	}{
		{name: "active unit", cfg: "ENABLED=no\n", unitState: "active", code: "CONFLICT"},
		{name: "enabled config", cfg: "ENABLED=yes\n", unitState: "inactive", code: "CONFLICT"},
		{name: "comment only", cfg: "# ENABLED=no\n", unitState: "inactive", code: "CONFLICT"},
		{name: "conflicting assignments", cfg: "ENABLED=no\nENABLED=yes\n", unitState: "inactive", code: "CONFLICT"},
		{name: "unknown unit", cfg: "ENABLED=no\n", unitState: "unknown", code: "CONFLICT"},
		{name: "failed unit", cfg: "ENABLED=no\n", unitState: "failed", code: "CONFLICT"},
		{name: "transitioning unit", cfg: "ENABLED=no\n", unitState: "deactivating", code: "CONFLICT"},
		{name: "native chain remains", cfg: "ENABLED=no\n", unitState: "inactive", chain: true, code: "CONFLICT"},
		{name: "native table remains", cfg: "ENABLED=no\n", unitState: "inactive", table: true, code: "CONFLICT"},
		{name: "untrusted file", cfg: "ENABLED=no\n", unitState: "inactive", unsafe: true, code: "UNAVAILABLE"},
		{name: "oversized config", cfg: "ENABLED=no\n" + strings.Repeat("# old entry\n", 7000), unitState: "inactive", code: "CONFLICT"},
		{name: "malformed native tables", cfg: "ENABLED=no\n", unitState: "inactive", malformedTables: true, code: "UNAVAILABLE"},
		{name: "other manager still protected", cfg: "ENABLED=no\n", unitState: "inactive", otherManager: true, code: "CONFLICT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, native, state, ports := firewallFixture()
			guard, executor, path := managerEvidenceFixture(t, test.cfg, test.unitState)
			executor.native, executor.ufwChain, executor.ufwTable = native, test.chain, test.table
			if test.unsafe {
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if test.otherManager {
				if err := os.MkdirAll(filepath.Join(guard.RootPath, "etc", "firewalld"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if test.malformedTables {
				executor.tableOutput = []byte(`{"nftables":[{"table":{"family":"inet"}}]}`)
			}
			s.Guard = managerEvidenceGuard{fakeGuard: ports, system: guard}
			before := getFirewall(t, s)
			result := applyFirewall(t, s, before.Revision)
			if result.OK || result.Code != test.code || native.writes != 0 || native.checks != 0 || state.raw != nil {
				t.Errorf("缺少安全停用事实仍进入原生写入：ok=%v code=%q checks=%d writes=%d", result.OK, result.Code, native.checks, native.writes)
			}
		})
	}
}

// ======================== 复用已有原生规则和端口夹具；只替换可信系统状态输入 ========================

type managerEvidenceExecutor struct {
	native      *nftFake
	state       string
	ufwChain    bool
	ufwTable    bool
	tableOutput []byte
}

func (e *managerEvidenceExecutor) Execute(ctx context.Context, tool local.Tool, args []string, input []byte) (local.Result, error) {
	if err := ctx.Err(); err != nil {
		return local.Result{}, err
	}
	if tool == local.Systemctl {
		return local.Result{ExitCode: 3, Output: []byte(e.state + "\nunknown\nunknown\nunknown\nunknown\n")}, nil
	}
	if tool == local.Nft && len(args) == 3 && args[0] == "-j" && args[1] == "list" {
		if args[2] == "tables" && e.tableOutput != nil {
			return local.Result{Output: append([]byte(nil), e.tableOutput...)}, nil
		}
		if args[2] == "chains" && e.ufwChain {
			return local.Result{Output: []byte(`{"nftables":[{"chain":{"family":"ip","table":"filter","name":"ufw-before-input"}}]}`)}, nil
		}
		if args[2] == "tables" && e.ufwTable {
			return local.Result{Output: []byte(`{"nftables":[{"table":{"family":"inet","name":"ufw"}}]}`)}, nil
		}
	}
	return e.native.Execute(ctx, tool, args, input)
}

type managerEvidenceGuard struct {
	*fakeGuard
	system SystemGuard
}

func (g managerEvidenceGuard) Managers(ctx context.Context) ([]Manager, error) {
	return g.system.Managers(ctx)
}

func managerEvidenceFixture(t *testing.T, cfg, state string) (SystemGuard, *managerEvidenceExecutor, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "etc", "ufw", "ufw.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	executor := &managerEvidenceExecutor{state: state, native: new(nftFake)}
	guard := SystemGuard{Executor: executor, RootPath: root, Trust: sandbox.TrustPolicy{UID: os.Getuid(), StopAt: root}}
	return guard, executor, path
}
