// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestBuiltinAgentSystemToolsPermissionsAndExecution(t *testing.T) {
	e := newAgentEnv(t)
	e.runner.Controller = e.c
	e.runner.Authz = e.c.Authorizer()
	operator := e.createUser("agent-op-tools", identity.RoleOperator)

	workDir := t.TempDir()
	sampleFile := filepath.Join(workDir, "nginx.conf")
	if err := os.WriteFile(sampleFile, []byte("server {\n  listen 80;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Admin in read_only can list/read/search, but cannot write/edit/exec.
	listRes := e.run(e.call(e.admin.ID, operations.PermissionReadOnly, "host.fs.list",
		mustJSON(t, map[string]any{"path": workDir}), 701))
	if listRes.Status != agentsession.ToolSucceeded || !strings.Contains(string(listRes.Result), "nginx.conf") {
		t.Fatalf("host.fs.list = %+v", listRes)
	}
	readRes := e.run(e.call(e.admin.ID, operations.PermissionReadOnly, "host.fs.read",
		mustJSON(t, map[string]any{"path": sampleFile}), 702))
	if readRes.Status != agentsession.ToolSucceeded || !strings.Contains(string(readRes.Result), "listen 80;") {
		t.Fatalf("host.fs.read = %+v", readRes)
	}
	searchRes := e.run(e.call(e.admin.ID, operations.PermissionReadOnly, "host.fs.search",
		mustJSON(t, map[string]any{"path": workDir, "pattern": "listen 80"}), 703))
	if searchRes.Status != agentsession.ToolSucceeded || !strings.Contains(string(searchRes.Result), "nginx.conf") {
		t.Fatalf("host.fs.search = %+v", searchRes)
	}
	deniedExec := e.run(e.call(e.admin.ID, operations.PermissionReadOnly, "host.shell.exec",
		`{"command":"echo hi"}`, 704))
	if deniedExec.Status != agentsession.ToolFailed || deniedExec.Error == nil || deniedExec.Error.Code != problem.PermissionDenied {
		t.Fatalf("read_only shell = %+v, want PERMISSION_DENIED", deniedExec)
	}

	// 2. Admin in safe mode without inline approval is blocked; with inline approval executes.
	safeNoApr := e.run(e.call(e.admin.ID, operations.PermissionSafe, "host.shell.exec",
		`{"command":"echo approved-run"}`, 705))
	if safeNoApr.Status != agentsession.ToolFailed || safeNoApr.Error == nil || safeNoApr.Error.Code != problem.PermissionDenied {
		t.Fatalf("safe unapproved shell = %+v, want PERMISSION_DENIED", safeNoApr)
	}
	ctxApproved := agentsession.WithInlineApproved(operations.WithPermissionMode(t.Context(), operations.PermissionSafe))
	safeApr, err := e.runner.RunTool(ctxApproved, e.call(e.admin.ID, operations.PermissionSafe, "host.shell.exec",
		`{"command":"echo approved-run"}`, 706))
	if err != nil || safeApr.Status != agentsession.ToolSucceeded || !strings.Contains(string(safeApr.Result), "approved-run") {
		t.Fatalf("safe approved shell = (%+v, %v)", safeApr, err)
	}

	// 3. Admin in full mode can write, edit, and run non-destructive shell directly,
	// while dangerous commands still require approval.
	writtenFile := filepath.Join(workDir, "out.txt")
	writeRes := e.run(e.call(e.admin.ID, operations.PermissionFull, "host.fs.write",
		mustJSON(t, map[string]any{"path": writtenFile, "content": "hello world\n"}), 707))
	if writeRes.Status != agentsession.ToolSucceeded {
		t.Fatalf("full fs.write = %+v", writeRes)
	}
	editRes := e.run(e.call(e.admin.ID, operations.PermissionFull, "host.fs.edit",
		mustJSON(t, map[string]any{"path": writtenFile, "old_text": "world", "new_text": "qwq"}), 708))
	if editRes.Status != agentsession.ToolSucceeded {
		t.Fatalf("full fs.edit = %+v", editRes)
	}
	raw, _ := os.ReadFile(writtenFile)
	if string(raw) != "hello qwq\n" {
		t.Fatalf("edited content = %q, want %q", string(raw), "hello qwq\n")
	}
	dangerFull := e.run(e.call(e.admin.ID, operations.PermissionFull, "host.shell.exec",
		`{"command":"rm -rf /"}`, 709))
	if dangerFull.Status != agentsession.ToolFailed || dangerFull.Error == nil || dangerFull.Error.Code != problem.PermissionDenied {
		t.Fatalf("dangerous full shell = %+v, want PERMISSION_DENIED", dangerFull)
	}

	// 4. Protected panel master.key cannot be read via host.fs.read.
	masterKey := filepath.Join(e.c.Config().DataDir, "master.key")
	protRes := e.run(e.call(e.admin.ID, operations.PermissionFull, "host.fs.read",
		mustJSON(t, map[string]any{"path": masterKey}), 710))
	if protRes.Status != agentsession.ToolFailed || protRes.Error == nil || protRes.Error.Code != problem.PermissionDenied {
		t.Fatalf("master.key read = %+v, want PERMISSION_DENIED", protRes)
	}

	// 5. Operator cannot call host.fs.read or host.shell.exec, but CAN use host.exchange.* tools.
	opFS := e.run(e.call(operator.ID, operations.PermissionSafe, "host.fs.read",
		mustJSON(t, map[string]any{"path": sampleFile}), 711))
	if opFS.Status != agentsession.ToolFailed || opFS.Error == nil || opFS.Error.Code != problem.PermissionDenied {
		t.Fatalf("operator fs.read = %+v, want PERMISSION_DENIED", opFS)
	}
	opMkdir := e.run(e.call(operator.ID, operations.PermissionSafe, "host.exchange.mkdir",
		`{"path":"op-audit"}`, 712))
	if opMkdir.Status != agentsession.ToolSucceeded {
		t.Fatalf("operator exchange.mkdir = %+v", opMkdir)
	}
	opWrite := e.run(e.call(operator.ID, operations.PermissionSafe, "host.exchange.write",
		`{"path":"op-audit/report.md","content":"# ok"}`, 713))
	if opWrite.Status != agentsession.ToolSucceeded {
		t.Fatalf("operator exchange.write = %+v", opWrite)
	}
	opRead := e.run(e.call(operator.ID, operations.PermissionSafe, "host.exchange.read",
		`{"path":"op-audit/report.md"}`, 714))
	if opRead.Status != agentsession.ToolSucceeded || !strings.Contains(string(opRead.Result), "# ok") {
		t.Fatalf("operator exchange.read = %+v", opRead)
	}

	// 6. Admin host.approvals.list sees host-wide pending approvals consistently with host.operations.list.
	pending := e.pending(operations.PermissionSafe, 715)
	aprList := e.run(e.call(e.admin.ID, operations.PermissionReadOnly, "host.approvals.list", `{}`, 716))
	if aprList.Status != agentsession.ToolSucceeded || !strings.Contains(string(aprList.Result), pending.ApprovalID) {
		t.Fatalf("admin host.approvals.list missing pending approval %s: %+v", pending.ApprovalID, aprList)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
