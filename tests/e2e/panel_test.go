// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

// =============================================================================
//  经 HTTPS API 驱动已安装的面板（ENG-02）
// -----------------------------------------------------------------------------
//  TestPluginEndToEnd      安装 → 更新 → 失败的更新 → 回滚 → 重启 controller
//                          → 卸载，逐步核对产品落盘的文件、socket 与属主。
//  TestControllerEndToEnd  setup-token → setup → 上传/安装/调用 → 更新 → 回滚
//                          → 重启 controller → 模拟重启主机，每步之后都调用插件。
// =============================================================================

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const panelOrigin = "https://127.0.0.1:8443"

// panel is a signed-in administrator session.
type panel struct {
	t      *testing.T
	hc     *http.Client
	cookie *http.Cookie
	csrf   string
	keys   int
	plugin string
	caps   []map[string]string
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Minute,
		// The listener is self-signed; requireSetupFingerprint pins it instead.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // pinned below
	}
}

// waitPanelReady waits until /readyz answers 200.
func waitPanelReady(t *testing.T) {
	t.Helper()
	hc := newHTTPClient()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := hc.Get(panelOrigin + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("the panel did not become ready; journal:\n%s", journalTail(controllerU))
}

var setupLinkRe = regexp.MustCompile(`/setup#token=(\S+)`)
var fingerprintRe = regexp.MustCompile(`SHA256:([0-9A-F:]+)`)

// setupPanel runs `qwq setup-token` like an operator, completes the setup over
// HTTP and returns the administrator session. A second setup-token exits 3.
func setupPanel(t *testing.T) *panel {
	t.Helper()
	out := run(t, qwqCLI, "setup-token")
	m := setupLinkRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("setup-token printed no link:\n%s", out)
	}
	p := &panel{t: t, hc: newHTTPClient(), plugin: pluginID, caps: acceptedCaps()}

	var status struct {
		Initialized    bool   `json:"initialized"`
		TLSFingerprint string `json:"tls_fingerprint"`
	}
	p.decode(p.request(http.MethodGet, "/api/v1/setup", nil, "", false), http.StatusOK, &status)
	if status.Initialized {
		t.Fatal("a fresh install reports initialized")
	}
	if fp := fingerprintRe.FindStringSubmatch(out); fp == nil || fp[1] != status.TLSFingerprint {
		t.Fatalf("setup-token fingerprint %v does not match the listener's %q", fp, status.TLSFingerprint)
	}

	password := os.Getenv("QWQ_E2E_PASSWORD")
	if password == "" {
		password = "E2e-correct-horse-battery"
	}
	body, _ := json.Marshal(map[string]string{"setup_token": m[1], "username": "admin", "password": password})
	resp := p.request(http.MethodPost, "/api/v1/setup", bytes.NewReader(body), "application/json", false)
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "qwq_session") {
			p.cookie = c
		}
	}
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	p.decode(resp, http.StatusCreated, &session)
	if p.cookie == nil || session.CSRFToken == "" {
		t.Fatal("setup did not sign the administrator in")
	}
	p.csrf = session.CSRFToken

	if err := exec.Command(qwqCLI, "setup-token").Run(); exitCode(err) != 3 {
		t.Fatalf("setup-token after setup = %v, want exit 3", err)
	}
	requireDataOwnedByQwq(t)
	return p
}

// requireDataOwnedByQwq: the root CLI must not leave root-owned database files.
func requireDataOwnedByQwq(t *testing.T) {
	t.Helper()
	files, _ := filepath.Glob("/var/lib/qwq/qwq.db*")
	for _, f := range files {
		if got := run(t, "stat", "-c", "%U", f); got != qwqUser {
			t.Fatalf("%s is owned by %s, want %s", f, got, qwqUser)
		}
	}
}

func (p *panel) request(method, path string, body io.Reader, contentType string, idempotent bool) *http.Response {
	p.t.Helper()
	req, err := http.NewRequest(method, panelOrigin+path, body)
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Origin", panelOrigin)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if p.cookie != nil {
		req.AddCookie(p.cookie)
		req.Header.Set("X-CSRF-Token", p.csrf)
	}
	if idempotent {
		p.keys++
		req.Header.Set("Idempotency-Key", fmt.Sprintf("e2e-%d-%04d", time.Now().UnixNano(), p.keys))
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		p.t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// decode checks the status and decodes the JSON body into v (may be nil).
func (p *panel) decode(resp *http.Response, want int, v any) {
	p.t.Helper()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		p.t.Fatalf("%s %s = %d, want %d: %s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, raw)
	}
	if v != nil {
		if err := json.Unmarshal(raw, v); err != nil {
			p.t.Fatalf("decode %s: %v: %s", resp.Request.URL.Path, err, raw)
		}
	}
}

func (p *panel) postJSON(path string, v any, want int, out any) {
	p.t.Helper()
	body, _ := json.Marshal(v)
	p.decode(p.request(http.MethodPost, path, bytes.NewReader(body), "application/json", true), want, out)
}

// upload stages a package and returns its upload id.
func (p *panel) upload(pkgPath string) string {
	p.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("package", filepath.Base(pkgPath))
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := fw.Write(readFile(p.t, pkgPath)); err != nil {
		p.t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		p.t.Fatal(err)
	}
	var up struct {
		UploadID string `json:"upload_id"`
	}
	p.decode(p.request(http.MethodPost, "/api/v1/plugin-packages", &buf, mw.FormDataContentType(), false), http.StatusCreated, &up)
	return up.UploadID
}

func acceptedCaps(names ...string) []map[string]string {
	if len(names) == 0 {
		names = pluginCaps
	}
	var caps []map[string]string
	for _, c := range names {
		caps = append(caps, map[string]string{"name": c, "scope": "self"})
	}
	return caps
}

func (p *panel) install(pkgPath string) {
	p.t.Helper()
	p.postJSON("/api/v1/plugins", map[string]any{"upload_id": p.upload(pkgPath), "accepted_capabilities": p.caps},
		http.StatusCreated, nil)
}

func (p *panel) update(pkgPath string) {
	p.t.Helper()
	p.postJSON("/api/v1/plugins/"+p.plugin+"/update",
		map[string]any{"upload_id": p.upload(pkgPath), "accepted_capabilities": p.caps}, http.StatusOK, nil)
}

// updateFails asserts an update is refused and returns the status.
func (p *panel) updateFails(pkgPath string) int {
	p.t.Helper()
	body, _ := json.Marshal(map[string]any{"upload_id": p.upload(pkgPath), "accepted_capabilities": p.caps})
	resp := p.request(http.MethodPost, "/api/v1/plugins/"+p.plugin+"/update", bytes.NewReader(body), "application/json", true)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 400 {
		p.t.Fatalf("an update whose Initialize fails was accepted: %d %s", resp.StatusCode, raw)
	}
	p.t.Logf("failing update refused: %d %s", resp.StatusCode, raw)
	return resp.StatusCode
}

func (p *panel) rollback() {
	p.t.Helper()
	p.decode(p.request(http.MethodPost, "/api/v1/plugins/"+p.plugin+"/rollback", nil, "", true), http.StatusOK, nil)
}

func (p *panel) uninstall() {
	p.t.Helper()
	// 卸载沿用公共 API 的并发前置条件；读取实际当前版本后提交同一 revision。
	var current struct {
		Revision string `json:"revision"`
	}
	path := "/api/v1/plugins/" + p.plugin
	p.decode(p.request(http.MethodGet, path+"?fields=/revision", nil, "", false), http.StatusOK, &current)
	if current.Revision == "" {
		p.t.Fatal("卸载前缺少宿主返回的插件 revision")
	}
	resp := p.request(http.MethodDelete, path+"?expected_revision="+url.QueryEscape(current.Revision), nil, "", true)
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		p.t.Fatalf("uninstall = %d: %s", resp.StatusCode, raw)
	}
	if resp.StatusCode == http.StatusNoContent {
		_ = resp.Body.Close()
		return
	}
	var operation operationResult
	p.decode(resp, resp.StatusCode, &operation)
	p.approveFixtureJob(&operation)
	p.waitOperation(&operation)
}

type operationResult struct {
	OperationID string         `json:"operation_id"`
	ApprovalID  string         `json:"approval_id"`
	Status      string         `json:"status"`
	Result      map[string]any `json:"result"`
	Error       any            `json:"error"`
}

// invoke runs a plugin operation and waits for its result.
func (p *panel) invoke(op string, payload any) map[string]any {
	p.t.Helper()
	body, _ := json.Marshal(map[string]any{"payload": payload})
	resp := p.request(http.MethodPost, "/api/v1/nodes/local/plugins/"+p.plugin+"/instances/default/operations/"+op, bytes.NewReader(body), "application/json", true)
	var opv operationResult
	want := resp.StatusCode
	if want != http.StatusOK && want != http.StatusAccepted {
		want = http.StatusOK // decode reports the unexpected status
	}
	p.decode(resp, want, &opv)
	return p.waitOperation(&opv)
}

// waitOperation 对测试夹具的 job 使用同一有界轮询，不绕过生产执行器。
func (p *panel) waitOperation(opv *operationResult) map[string]any {
	p.t.Helper()
	deadline := time.Now().Add(time.Minute)
	for opv.Status != "SUCCEEDED" {
		switch opv.Status {
		case "FAILED", "CANCELED", "REJECTED", "EXPIRED":
			p.t.Fatalf("operation ended %s: %v", opv.Status, opv.Error)
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("operation still %s after a minute", opv.Status)
		}
		time.Sleep(200 * time.Millisecond)
		p.decode(p.request(http.MethodGet, "/api/v1/operations/"+opv.OperationID, nil, "", false), http.StatusOK, opv)
	}
	return opv.Result
}

// approveFixtureJob 仅用于已通过干净主机检查的安装夹具，核对 operation 后审批。
func (p *panel) approveFixtureJob(operation *operationResult, mfaCodes ...string) {
	p.t.Helper()
	if len(mfaCodes) > 1 {
		p.t.Fatal("fixture approval accepts at most one second factor")
	}
	mfaCode := ""
	if len(mfaCodes) == 1 {
		mfaCode = mfaCodes[0]
	}
	if operation.Status != "AWAITING_APPROVAL" {
		return
	}
	var approval struct {
		OperationID string `json:"operation_id"`
		Revision    string `json:"revision"`
		RequiresMFA bool   `json:"requires_mfa"`
		Status      string `json:"status"`
	}
	p.decode(p.request(http.MethodGet, "/api/v1/approvals/"+operation.ApprovalID, nil, "", false), http.StatusOK, &approval)
	if approval.OperationID != operation.OperationID || approval.Revision == "" || approval.RequiresMFA != (mfaCode != "") {
		p.t.Fatal("unexpected approval for the disposable fixture")
	}
	decision := map[string]string{
		"decision": "approve", "expected_revision": approval.Revision,
	}
	if mfaCode != "" {
		decision["mfa_code"] = mfaCode
	}
	p.postJSON("/api/v1/approvals/"+operation.ApprovalID+"/decision", decision, http.StatusOK, &approval)
	if approval.OperationID != operation.OperationID || approval.Status != "APPROVED" {
		p.t.Fatal("fixture approval did not record the expected decision")
	}
	// 审批接口返回 Approval；随后读取 Operation，避免混用两种资源状态。
	p.decode(p.request(http.MethodGet, "/api/v1/operations/"+operation.OperationID, nil, "", false), http.StatusOK, operation)
}

// kvRoundTrip writes through the host channel (PutState) and checks the
// revision advanced past prev, which proves the state was read back and
// persisted (GetState).
func (p *panel) kvRoundTrip(value, prev string) string {
	p.t.Helper()
	res := p.invoke("noop.set", map[string]string{"value": value})
	rev, _ := res["revision"].(string)
	if res["value"] != value || rev == "" || rev == prev {
		p.t.Fatalf("noop.set(%q) = %v (previous revision %q)", value, res, prev)
	}
	if echo := p.invoke("noop.echo", map[string]string{"message": value}); echo["message"] != value {
		p.t.Fatalf("noop.echo = %v", echo)
	}
	return rev
}

func journalTail(unit string) string {
	out, _ := exec.Command("journalctl", "-u", unit, "-n", "40", "--no-pager").CombinedOutput()
	return string(out)
}

// --- tests ------------------------------------------------------------------

func TestPluginEndToEnd(t *testing.T) {
	requireEnv(t, "QWQ_E2E_PKG_V1", "QWQ_E2E_PKG_V2", "QWQ_E2E_PKG_BAD")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	prepareHost(t)
	p := setupPanel(t)

	t.Log("=== step 1: install", versionV1)
	p.install(os.Getenv("QWQ_E2E_PKG_V1"))
	pid1 := requireRunningPlugin(t, ctx, versionV1)
	requireVersionTree(t, versionV1)
	requireVerifyEntrypoint(t, versionV1)
	requireCredential(t)
	requirePluginSocket(t)
	requireHostChannel(t)
	requirePluginHealth(t, versionV1)
	rev := p.kvRoundTrip("one", "")

	t.Log("=== step 2: update", versionV2)
	p.update(os.Getenv("QWQ_E2E_PKG_V2"))
	pid2 := requireRunningPlugin(t, ctx, versionV2)
	if pid2 == pid1 {
		t.Fatalf("the MainPID did not change across the update (%d)", pid1)
	}
	requireVersionTree(t, versionV1) // retained for rollback
	requireVersionTree(t, versionV2)
	rev = p.kvRoundTrip("two", rev)

	t.Log("=== step 3: an update whose Initialize fails keeps", versionV2)
	p.updateFails(os.Getenv("QWQ_E2E_PKG_BAD"))
	requireRunningPlugin(t, ctx, versionV2)
	requirePluginHealth(t, versionV2)
	rev = p.kvRoundTrip("three", rev)

	t.Log("=== step 4: rollback", versionV1)
	p.rollback()
	pid4 := requireRunningPlugin(t, ctx, versionV1)
	if pid4 == pid2 {
		t.Fatalf("the MainPID did not change across the rollback (%d)", pid2)
	}
	rev = p.kvRoundTrip("four", rev)

	t.Log("=== step 5: restart the controller")
	run(t, "systemctl", "restart", controllerU)
	waitPanelReady(t)
	if pid := requireRunningPlugin(t, ctx, versionV1); pid != pid4 {
		t.Fatalf("a controller restart restarted the plugin (MainPID %d → %d)", pid4, pid)
	}
	requireRuntimeSockets(t)
	p.kvRoundTrip("five", rev)

	t.Log("=== step 6: uninstall")
	p.uninstall()
	requirePluginRemoved(t)
}

func TestControllerEndToEnd(t *testing.T) {
	requireEnv(t, "QWQ_E2E_PKG_V1", "QWQ_E2E_PKG_V2")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	prepareHost(t)
	p := setupPanel(t)

	p.install(os.Getenv("QWQ_E2E_PKG_V1"))
	rev := p.kvRoundTrip("install", "")
	p.update(os.Getenv("QWQ_E2E_PKG_V2"))
	rev = p.kvRoundTrip("update", rev)
	p.rollback()
	rev = p.kvRoundTrip("rollback", rev)

	run(t, "systemctl", "restart", controllerU)
	waitPanelReady(t)
	requireRuntimeSockets(t)
	rev = p.kvRoundTrip("restart", rev)

	// Reboot simulation: everything stops, the tmpfs /run is empty, tmpfiles
	// rebuilds the skeleton and the enabled units start in boot order.
	t.Log("=== reboot simulation")
	_ = exec.Command("systemctl", "stop", controllerU, pluginService, pluginSocketU, helperSocketU, helperService).Run()
	if err := os.RemoveAll(runtimeBase); err != nil {
		t.Fatalf("clear %s: %v", runtimeBase, err)
	}
	snippets, _ := filepath.Glob(filepath.Join(tmpfilesDir, "qwq-plugin-*.conf"))
	run(t, "systemd-tmpfiles", append([]string{"--create", "/usr/lib/tmpfiles.d/qwq.conf"}, snippets...)...)
	run(t, "systemctl", "start", helperSocketU, pluginSocketU)
	run(t, "systemctl", "start", controllerU)
	waitPanelReady(t)
	p.kvRoundTrip("reboot", rev)
	requireRunningPlugin(t, ctx, versionV1)
	requireHostChannel(t)
}
