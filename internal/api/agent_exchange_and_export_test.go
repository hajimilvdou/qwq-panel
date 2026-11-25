// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

func TestAgentSessionExportAndOptional2FADestructiveApproval(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)

	// Optional 2FA: destructive user deletion succeeds without enrolling TOTP.
	e.createApprovedUser(a, "tempuser", "viewer")
	u := e.userByUsername(a, "tempuser")
	delReq := a.sign(http.MethodDelete, "/api/v1/users/"+mustString(t, u, "user_id")+"?expected_revision="+mustString(t, u, "revision"), "")
	delReq.Header.Set("Idempotency-Key", idempotencyKey(901))
	var accepted struct {
		ApprovalID string `json:"approval_id"`
	}
	e.do(delReq).expect(t, http.StatusAccepted).decode(t, &accepted)
	appRev := mustString(t, e.approval(a, accepted.ApprovalID), "revision")
	e.decide(a, accepted.ApprovalID, "approve", appRev, idempotencyKey(902)).expect(t, http.StatusOK)

	// Create an agent session and export as Markdown & JSON.
	var created struct {
		SessionID string `json:"session_id"`
	}
	e.do(a.sign(http.MethodPost, "/api/v1/agent-sessions", `{"title":"服务器审查会话","core":"native","permission_mode":"safe"}`)).
		expect(t, http.StatusCreated).decode(t, &created)

	mdResp := e.do(a.sign(http.MethodGet, "/api/v1/agent-sessions/"+created.SessionID+"/export?format=markdown", "")).expect(t, http.StatusOK)
	if !strings.Contains(mdResp.header.Get("Content-Disposition"), "attachment;") {
		t.Fatalf("markdown Content-Disposition = %q", mdResp.header.Get("Content-Disposition"))
	}
	if !strings.Contains(string(mdResp.body), "# 服务器审查会话") {
		t.Fatalf("markdown export missing title: %s", mdResp.body)
	}

	jsonResp := e.do(a.sign(http.MethodGet, "/api/v1/agent-sessions/"+created.SessionID+"/export?format=json", "")).expect(t, http.StatusOK)
	var exported struct {
		Session  map[string]any   `json:"session"`
		Messages []map[string]any `json:"messages"`
	}
	jsonResp.decode(t, &exported)
	if mustString(t, exported.Session, "session_id") != created.SessionID {
		t.Fatalf("exported session_id = %v", exported.Session["session_id"])
	}
}

func TestAgentExchangeFolderEndpoints(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	viewer := e.signIn("ex-viewer", identity.RoleViewer)
	operator := e.signIn("ex-op", identity.RoleOperator)

	// Viewer can read entries but cannot mutate the exchange folder.
	e.do(viewer.sign(http.MethodGet, "/api/v1/agent-exchange/entries", "")).
		expect(t, http.StatusOK)
	e.do(viewer.sign(http.MethodPost, "/api/v1/agent-exchange/mkdir", `{"path":"blocked"}`)).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// Operator creates a task subfolder.
	e.do(operator.sign(http.MethodPost, "/api/v1/agent-exchange/mkdir", `{"path":"审查任务A"}`)).
		expect(t, http.StatusCreated)

	// Multipart upload two files into the subfolder.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("dir", "审查任务A")
	p1, _ := mw.CreateFormFile("files", "raw.conf")
	_, _ = io.WriteString(p1, "listen 443 ssl;\n")
	p2, _ := mw.CreateFormFile("files", "notes.txt")
	_, _ = io.WriteString(p2, "请结合服务器情况审查\n")
	_ = mw.Close()

	upReq := operator.sign(http.MethodPost, "/api/v1/agent-exchange/upload", body.String())
	upReq.Header.Set("Content-Type", mw.FormDataContentType())
	var upRes struct {
		Total int `json:"total"`
	}
	e.do(upReq).expect(t, http.StatusCreated).decode(t, &upRes)
	if upRes.Total != 2 {
		t.Fatalf("uploaded total = %d, want 2", upRes.Total)
	}

	// List subfolder entries.
	var listRes struct {
		TotalFiles int `json:"total_files"`
	}
	e.do(a.sign(http.MethodGet, "/api/v1/agent-exchange/entries?path="+url.QueryEscape("审查任务A"), "")).
		expect(t, http.StatusOK).decode(t, &listRes)
	if listRes.TotalFiles != 2 {
		t.Fatalf("list total_files = %d, want 2", listRes.TotalFiles)
	}

	// Preview uploaded file.
	var prevRes struct {
		IsText  bool   `json:"is_text"`
		Content string `json:"content"`
	}
	e.do(a.sign(http.MethodGet, "/api/v1/agent-exchange/preview?path="+url.QueryEscape("审查任务A/raw.conf"), "")).
		expect(t, http.StatusOK).decode(t, &prevRes)
	if !prevRes.IsText || !strings.Contains(prevRes.Content, "listen 443") {
		t.Fatalf("preview = %+v", prevRes)
	}

	// Write deliverable via PUT, rename, download single file, download folder zip.
	putBody, _ := json.Marshal(map[string]string{"path": "审查任务A/report.md", "content": "# 审查报告\n通过"})
	e.do(a.sign(http.MethodPut, "/api/v1/agent-exchange/file", string(putBody))).expect(t, http.StatusOK)

	renBody, _ := json.Marshal(map[string]string{"from": "审查任务A/report.md", "to": "审查任务A/final-report.md"})
	e.do(a.sign(http.MethodPost, "/api/v1/agent-exchange/rename", string(renBody))).expect(t, http.StatusOK)

	dlFile := e.do(a.sign(http.MethodGet, "/api/v1/agent-exchange/download?path="+url.QueryEscape("审查任务A/final-report.md"), "")).expect(t, http.StatusOK)
	if !strings.Contains(string(dlFile.body), "审查报告") {
		t.Fatalf("downloaded file body = %q", string(dlFile.body))
	}

	dlZip := e.do(a.sign(http.MethodGet, "/api/v1/agent-exchange/download?path="+url.QueryEscape("审查任务A"), "")).expect(t, http.StatusOK)
	zr, err := zip.NewReader(bytes.NewReader(dlZip.body), int64(len(dlZip.body)))
	if err != nil || len(zr.File) != 3 {
		t.Fatalf("zip entries = %d, err = %v", len(zr.File), err)
	}

	// Delete subfolder.
	e.do(a.sign(http.MethodDelete, "/api/v1/agent-exchange/entry?path="+url.QueryEscape("审查任务A"), "")).expect(t, http.StatusNoContent)
}
