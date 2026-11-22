// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// fakePluginManager is an api.PluginManager that records the calls the HTTP
// layer makes. The real updater behavior is covered by its own package tests
// and by the cmd/qwq adapter tests.
type fakePluginManager struct {
	mu sync.Mutex

	plugins        []api.Plugin
	byID           map[string]api.Plugin
	configs        map[string]api.PluginConfig
	schemas        map[string]json.RawMessage
	missing        map[string]bool
	installReq     *api.InstallPackageRequest
	updateReq      *api.UpdatePackageRequest
	rollbackID     string
	rollbackRev    int64
	restartID      string
	restartReason  string
	uninstallID    string
	uninstallPurge bool
	dependents     []string
	enabledID      string
	enabledValue   bool
	logID          string
	logCursor      string
	logStream      string
	logLimit       int
	logPage        api.PluginLogPage
	logErr         error
	configReq      *api.ApplyPluginConfigRequest
	validateReq    *api.ApplyPluginConfigRequest
	validateConfig func(context.Context, api.ApplyPluginConfigRequest) error

	installResult  api.PluginVersion
	updateResult   api.PluginUpdate
	rollbackResult api.PluginUpdate
	applyResult    api.PluginConfig

	inspectResult api.PackageInspection
	inspectErr    error
	inspectCalls  int
	inspectPath   string

	listErr, getErr, installErr, updateErr, rollbackErr, getConfigErr, applyConfigErr, schemaErr error

	// onInstall, when set, runs with the context the manager received.
	onInstall func(context.Context)
	// onApply 在故障回归中模拟后端已提交再返回错误。
	onApply func(context.Context, api.ApplyPluginConfigRequest) error
}

func newFakePluginManager() *fakePluginManager {
	return &fakePluginManager{
		byID:    make(map[string]api.Plugin),
		configs: make(map[string]api.PluginConfig),
		schemas: make(map[string]json.RawMessage),
		missing: make(map[string]bool),
	}
}

func (f *fakePluginManager) List(context.Context) ([]api.Plugin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]api.Plugin(nil), f.plugins...), nil
}

func (f *fakePluginManager) Get(_ context.Context, pluginID string) (api.Plugin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return api.Plugin{}, f.getErr
	}
	p, ok := f.byID[pluginID]
	if !ok {
		return api.Plugin{}, problem.New(problem.NotFound, "The plugin is not installed.")
	}
	return p, nil
}

func (f *fakePluginManager) Install(ctx context.Context, req api.InstallPackageRequest) (api.PluginVersion, error) {
	if f.onInstall != nil {
		f.onInstall(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := req
	f.installReq = &cp
	if f.installErr != nil {
		return api.PluginVersion{}, f.installErr
	}
	return f.installResult, nil
}

func (f *fakePluginManager) Update(_ context.Context, req api.UpdatePackageRequest) (api.PluginUpdate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := req
	f.updateReq = &cp
	if f.updateErr != nil {
		return api.PluginUpdate{}, f.updateErr
	}
	return f.updateResult, nil
}

func (f *fakePluginManager) Rollback(_ context.Context, pluginID string, expected int64) (api.PluginUpdate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollbackID, f.rollbackRev = pluginID, expected
	if f.rollbackErr != nil {
		return api.PluginUpdate{}, f.rollbackErr
	}
	return f.rollbackResult, nil
}

func (f *fakePluginManager) Uninstall(_ context.Context, pluginID string, purgeData bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uninstallID, f.uninstallPurge = pluginID, purgeData
	return nil
}

func (f *fakePluginManager) Logs(_ context.Context, pluginID, cursor, stream string, limit int) (api.PluginLogPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logID, f.logCursor, f.logStream, f.logLimit = pluginID, cursor, stream, limit
	if f.logErr != nil {
		return api.PluginLogPage{}, f.logErr
	}
	return f.logPage, nil
}

func (f *fakePluginManager) SetEnabled(_ context.Context, pluginID string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabledID, f.enabledValue = pluginID, enabled
	return nil
}

func (f *fakePluginManager) Dependents(context.Context, string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dependents...), nil
}

func (f *fakePluginManager) Restart(_ context.Context, pluginID, reason string) (api.Plugin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restartID, f.restartReason = pluginID, reason
	p, ok := f.byID[pluginID]
	if !ok {
		return api.Plugin{}, problem.New(problem.NotFound, "The plugin is not installed.")
	}
	return p, nil
}

func (f *fakePluginManager) InspectPackage(_ context.Context, req api.InspectPackageRequest) (api.PackageInspection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inspectCalls++
	f.inspectPath = req.PackagePath
	if f.inspectErr != nil {
		return api.PackageInspection{}, f.inspectErr
	}
	return f.inspectResult, nil
}

func (f *fakePluginManager) GetConfig(_ context.Context, pluginID string) (api.PluginConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getConfigErr != nil {
		return api.PluginConfig{}, f.getConfigErr
	}
	if f.missing[pluginID] {
		return api.PluginConfig{}, problem.New(problem.NotFound, "The plugin is not installed.")
	}
	cfg, ok := f.configs[pluginID]
	if !ok {
		return api.PluginConfig{PluginID: pluginID, Config: json.RawMessage("{}")}, nil
	}
	return cfg, nil
}

func (f *fakePluginManager) ApplyConfig(ctx context.Context, req api.ApplyPluginConfigRequest) (api.PluginConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := req
	f.configReq = &cp
	if f.onApply != nil {
		if err := f.onApply(ctx, req); err != nil {
			return api.PluginConfig{}, err
		}
	}
	if f.applyConfigErr != nil {
		return api.PluginConfig{}, f.applyConfigErr
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := f.applyResult
	if cfg.PluginID == "" {
		cfg = api.PluginConfig{
			PluginID: req.PluginID, Revision: 1, Config: req.Config,
			Active: true, CreatedAt: now, AppliedAt: now,
		}
	}
	f.configs[req.PluginID] = cfg
	return cfg, nil
}

func (f *fakePluginManager) ValidateConfig(ctx context.Context, req api.ApplyPluginConfigRequest) error {
	f.mu.Lock()
	f.validateReq = &req
	validate := f.validateConfig
	f.mu.Unlock()
	if validate != nil {
		return validate(ctx, req)
	}
	return ctx.Err()
}

func (f *fakePluginManager) ConfigSchema(_ context.Context, pluginID string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.schemaErr != nil {
		return nil, f.schemaErr
	}
	if f.missing[pluginID] {
		return nil, problem.New(problem.NotFound, "The plugin is not installed.")
	}
	if schema, ok := f.schemas[pluginID]; ok {
		return schema, nil
	}
	return json.RawMessage(`{"type":"object"}`), nil
}

// ======================== 真实 HTTP 主体，提取秘密前的配置守卫 ========================

func TestPluginConfigAuthorizationRejectsBeforeSecretExtraction(t *testing.T) {
	mgr := newFakePluginManager()
	mgr.schemas["com.example.monitor"] = json.RawMessage(`{"properties":{"password":{"x-secret":true}}}`)
	e := newPluginTestEnv(t, mgr)
	who := e.setupAdmin(adminUser)
	mgr.validateConfig = func(_ context.Context, req api.ApplyPluginConfigRequest) error {
		if !req.Actor.IsHumanSession() || req.Actor.ID != who.userID || req.PluginID != "com.example.monitor" ||
			!bytes.Contains(req.Config, []byte("rejected-preview-value")) {
			t.Fatal("配置守卫没有收到当前真实主体和原候选")
		}
		return problem.New(problem.PermissionDenied, "配置消费范围拒绝。")
	}
	var before, after int
	if err := e.c.DB().Reader().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM secrets").Scan(&before); err != nil {
		t.Fatal(err)
	}
	request := withIdempotency(who.sign(http.MethodPut, "/api/v1/plugins/com.example.monitor/config", `{"config":{"password":"rejected-preview-value"},"expected_revision":"0"}`), idempotencyKey(81))
	response := e.do(request)
	response.expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	if bytes.Contains(response.body, []byte("rejected-preview-value")) || mgr.configReq != nil {
		t.Fatal("守卫拒绝仍写入配置或泄漏原始输入")
	}
	if err := e.c.DB().Reader().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM secrets").Scan(&after); err != nil || before != after {
		t.Fatal("守卫拒绝前已创建秘密")
	}
}

// pluginTestEnv is one host with a fake manager and a real upload store.
type pluginTestEnv struct {
	*env
	uploads *api.PluginUploads
	dir     string
	clock   *clock.Fake
	mgr     *fakePluginManager
}

func newPluginTestEnv(t *testing.T, mgr *fakePluginManager) *pluginTestEnv {
	t.Helper()
	if mgr == nil {
		mgr = newFakePluginManager()
	}
	clk := clock.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	dir := t.TempDir()
	uploads, err := api.NewPluginUploads(dir, api.DefaultPluginUploadTTL, clk)
	if err != nil {
		t.Fatalf("NewPluginUploads: %v", err)
	}
	e := newEnvWith(t, func(d *api.Deps) {
		d.Plugins = mgr
		d.PluginUploads = uploads
		// The API shares the fake clock with the upload store: the inspection
		// cache and the upload expiry must move together.
		d.Clock = clk
	})
	return &pluginTestEnv{env: e, uploads: uploads, dir: dir, clock: clk, mgr: mgr}
}

func multipartBody(t *testing.T, field, filename string, payload []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write package part: %v", err)
	}
	if err := mw.WriteField("ignored", "yes"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return bytes.NewReader(buf.Bytes()), mw.FormDataContentType()
}

func uploadRequest(t *testing.T, a auth, field, filename string, payload []byte) *http.Request {
	t.Helper()
	body, contentType := multipartBody(t, field, filename, payload)
	req := a.sign(http.MethodPost, "/api/v1/plugin-packages", "")
	req.Body = io.NopCloser(body)
	if seeker, ok := body.(io.Seeker); ok {
		if size, err := seeker.Seek(0, io.SeekEnd); err == nil {
			req.ContentLength = size
			_, _ = seeker.Seek(0, io.SeekStart)
		}
	}
	req.Header.Set("Content-Type", contentType)
	return req
}

type uploadResponse struct {
	UploadID  string `json:"upload_id"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	ExpiresAt string `json:"expires_at"`
}

// upload stages payload and returns the decoded response and the private file.
func (e *pluginTestEnv) upload(t *testing.T, a auth, payload []byte) (uploadResponse, string) {
	t.Helper()
	resp := e.do(uploadRequest(t, a, "package", "../../evil name.zip", payload)).expect(t, http.StatusCreated)
	var out uploadResponse
	resp.decode(t, &out)
	if !strings.HasPrefix(out.UploadID, "upl_") {
		t.Fatalf("upload_id = %q", out.UploadID)
	}
	files, err := filepath.Glob(filepath.Join(e.dir, "upload-*.pkg"))
	if err != nil || len(files) != 1 {
		t.Fatalf("staged files = %v (%v)", files, err)
	}
	return out, files[0]
}

func installBody(uploadID string, caps []string, revision string) string {
	type cap struct {
		Name  string `json:"name"`
		Scope string `json:"scope,omitempty"`
	}
	out := struct {
		UploadID    string `json:"upload_id"`
		Caps        []cap  `json:"accepted_capabilities"`
		ExpectedRev string `json:"expected_revision,omitempty"`
	}{UploadID: uploadID, Caps: []cap{}, ExpectedRev: revision}
	for _, name := range caps {
		out.Caps = append(out.Caps, cap{Name: name, Scope: "test"})
	}
	raw, _ := json.Marshal(out)
	return string(raw)
}

func withIdempotency(req *http.Request, key string) *http.Request {
	req.Header.Set("Idempotency-Key", key)
	return req
}

// serviceTokenWithRole creates a service account with the given role.
func (e *pluginTestEnv) serviceTokenWithRole(t *testing.T, a auth, role authz.Role) string {
	t.Helper()
	by := actor.Actor{Kind: actor.Human, ID: a.userID, SessionID: "test-session"}
	var created authz.CreatedServiceAccount
	err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		tx.SetOrigin(storage.Origin{Actor: by})
		var cerr error
		created, cerr = e.c.Authorizer().CreateServiceAccount(t.Context(), tx, authz.CreateServiceAccountInput{
			Actor: by, Name: "plugin-test-" + string(role), Role: role,
		})
		return cerr
	})
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	return created.Token
}

func TestPluginPackageUploadAndInstall(t *testing.T) {
	mgr := newFakePluginManager()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	mgr.installResult = api.PluginVersion{
		PluginID: "com.example.monitor", Version: "1.2.3",
		Digest: "sha256:" + strings.Repeat("a", 64),
		Status: "ACTIVE", InstallStatus: "INSTALLED", Active: true,
		InstalledAt: now, ActivatedAt: now, Revision: 11,
	}
	e := newPluginTestEnv(t, mgr)
	a := e.setupAdmin(adminUser)

	payload := []byte("signed-package-bytes")
	upload, path := e.upload(t, a, payload)
	if upload.Size != int64(len(payload)) || upload.ExpiresAt == "" {
		t.Fatalf("upload = %+v", upload)
	}
	sum := sha256.Sum256(payload)
	if upload.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %q", upload.SHA256)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("staged file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("staged file mode = %v, want 0600", info.Mode().Perm())
	}
	if filepath.Base(path) == "evil name.zip" {
		t.Fatal("the multipart filename became the staging path")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("staged bytes = %q (%v)", stored, err)
	}

	body := installBody(upload.UploadID, []string{"net.connect"}, "4")
	req := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", body), idempotencyKey(20))
	resp := e.do(req).expect(t, http.StatusCreated)
	if loc := resp.header.Get("Location"); loc != "/api/v1/plugins/com.example.monitor" {
		t.Fatalf("Location = %q", loc)
	}
	var version map[string]any
	resp.decode(t, &version)
	if mustString(t, version, "plugin_id") != "com.example.monitor" ||
		mustString(t, version, "version") != "1.2.3" ||
		version["status"] != "ACTIVE" || version["active"] != true {
		t.Fatalf("version = %v", version)
	}
	if mgr.installReq == nil {
		t.Fatal("the manager did not receive an install request")
	}
	if mgr.installReq.PackagePath != path ||
		len(mgr.installReq.AcceptedCapabilities) != 1 ||
		mgr.installReq.AcceptedCapabilities[0] != "net.connect:test" ||
		mgr.installReq.ExpectedRevision != 4 {
		t.Fatalf("install request = %+v", *mgr.installReq)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the staged package survived a successful install: %v", err)
	}

	// The same key and body replay the stored answer even though the upload is
	// gone; a different body with the same key is a key reuse.
	replay := e.do(withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", body), idempotencyKey(20))).
		expect(t, http.StatusCreated)
	if replay.header.Get("Idempotency-Replayed") != "true" {
		t.Fatal("the replay is not marked")
	}
	reuse := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", installBody(upload.UploadID, []string{"net.connect"}, "5")), idempotencyKey(20))
	e.do(reuse).expectProblem(t, http.StatusUnprocessableEntity, problem.IdempotencyKeyReused)

	// A consumed upload cannot be used again under a fresh key.
	again := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", body), idempotencyKey(21))
	e.do(again).expectProblem(t, http.StatusNotFound, problem.NotFound)
}

func TestPluginInstallValidation(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)

	cases := []struct {
		name string
		body string
		code string
	}{
		{"missing upload", `{"accepted_capabilities":[]}`, "REQUIRED"},
		{"path traversal", `{"upload_id":"../../etc/passwd","accepted_capabilities":[]}`, "INVALID"},
		{"unknown field", `{"upload_id":"upl_00000000000000000000000000000000","accepted_capabilities":[],"version":"9.9.9"}`, "UNKNOWN_FIELD"},
		{"missing capabilities", `{"upload_id":"upl_00000000000000000000000000000000"}`, "REQUIRED"},
		{"bad revision", `{"upload_id":"upl_00000000000000000000000000000000","accepted_capabilities":[],"expected_revision":"nope"}`, "INVALID"},
	}
	for i, tc := range cases {
		req := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", tc.body), idempotencyKey(30+i))
		p := e.do(req).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
		if len(p.Violations) == 0 || p.Violations[0].Code != tc.code {
			t.Fatalf("%s: violations = %+v", tc.name, p.Violations)
		}
	}

	// A well-formed but unknown id is NOT_FOUND, never a filesystem probe.
	body := installBody("upl_00000000000000000000000000000000", nil, "")
	req := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", body), idempotencyKey(40))
	e.do(req).expectProblem(t, http.StatusNotFound, problem.NotFound)
}

func TestPluginInstallFailureKeepsUpload(t *testing.T) {
	mgr := newFakePluginManager()
	mgr.installResult = api.PluginVersion{PluginID: "com.example.monitor", Version: "1.0.0", Status: "ACTIVE"}
	e := newPluginTestEnv(t, mgr)
	a := e.setupAdmin(adminUser)

	upload, path := e.upload(t, a, []byte("retry-me"))
	mgr.installErr = problem.Validation(problem.Violation{
		Pointer: "/plugin_id", Code: "MANIFEST_MISMATCH",
		Message: "The package belongs to another plugin.",
	})
	failed := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins",
		installBody(upload.UploadID, nil, "")), idempotencyKey(80))
	e.do(failed).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a failed install removed the staged package: %v", err)
	}
	mgr.installErr = nil
	retry := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins",
		installBody(upload.UploadID, nil, "")), idempotencyKey(81))
	e.do(retry).expect(t, http.StatusCreated)
}

func TestPluginUpdateRollbackAndConfig(t *testing.T) {
	mgr := newFakePluginManager()
	mgr.updateResult = api.PluginUpdate{
		SagaID: "sag_update", PluginID: "com.example.monitor",
		FromVersion: "1.0.0", ToVersion: "1.1.0", Strategy: "restart",
		State: "COMMITTED", Restarted: true,
		Version: api.PluginVersion{PluginID: "com.example.monitor", Version: "1.1.0", Status: "ACTIVE", InstallStatus: "INSTALLED", Active: true, Revision: 12},
	}
	mgr.rollbackResult = api.PluginUpdate{
		SagaID: "sag_rollback", PluginID: "com.example.monitor",
		FromVersion: "1.1.0", ToVersion: "1.0.0", Strategy: "restart",
		State: "COMMITTED", Restarted: true,
		Version: api.PluginVersion{PluginID: "com.example.monitor", Version: "1.0.0", Status: "ACTIVE", InstallStatus: "INSTALLED", Active: true, Revision: 13},
	}
	mgr.schemas["com.example.monitor"] = json.RawMessage(`{
		"type":"object",
		"properties":{"password":{"type":"string","writeOnly":true},"url":{"type":"string"}}
	}`)
	e := newPluginTestEnv(t, mgr)
	a := e.setupAdmin(adminUser)

	upload, path := e.upload(t, a, []byte("update-package"))
	req := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins/com.example.monitor/update",
		installBody(upload.UploadID, []string{"net.connect"}, "12")), idempotencyKey(50))
	var updated map[string]any
	e.do(req).expect(t, http.StatusOK).decode(t, &updated)
	if mustString(t, updated, "saga_id") != "sag_update" || updated["restarted"] != true {
		t.Fatalf("update = %v", updated)
	}
	if mgr.updateReq == nil || mgr.updateReq.PluginID != "com.example.monitor" ||
		mgr.updateReq.PackagePath != path || mgr.updateReq.ExpectedRevision != 12 {
		t.Fatalf("update request = %+v", mgr.updateReq)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the staged package survived a successful update")
	}

	rollback := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins/com.example.monitor/rollback",
		`{"expected_revision":"13"}`), idempotencyKey(51))
	var rolled map[string]any
	e.do(rollback).expect(t, http.StatusOK).decode(t, &rolled)
	if mustString(t, rolled, "saga_id") != "sag_rollback" {
		t.Fatalf("rollback = %v", rolled)
	}
	if mgr.rollbackID != "com.example.monitor" || mgr.rollbackRev != 13 {
		t.Fatalf("rollback call = %q/%d", mgr.rollbackID, mgr.rollbackRev)
	}

	// The rollback body is optional.
	noBody := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins/com.example.monitor/rollback", ""), idempotencyKey(54))
	e.do(noBody).expect(t, http.StatusOK)

	// A sensitive value is replaced by a secret reference before the updater
	// sees it, and the response redacts it.
	put := withIdempotency(a.sign(http.MethodPut, "/api/v1/plugins/com.example.monitor/config",
		`{"config":{"password":"hunter2","url":"https://example.com"},"expected_revision":"0"}`), idempotencyKey(52))
	var applied map[string]any
	e.do(put).expect(t, http.StatusOK).decode(t, &applied)
	if mgr.configReq == nil {
		t.Fatal("the manager did not receive a config request")
	}
	if mgr.configReq.PluginID != "com.example.monitor" || mgr.configReq.ExpectedRevision != 0 {
		t.Fatalf("config request = %+v", mgr.configReq)
	}
	if bytes.Contains(mgr.configReq.Config, []byte("hunter2")) {
		t.Fatalf("plaintext secret reached the updater: %s", mgr.configReq.Config)
	}
	if !bytes.Contains(mgr.configReq.Config, []byte(`"$secret":"sec_`)) {
		t.Fatalf("stored config has no secret reference: %s", mgr.configReq.Config)
	}
	cfg, ok := applied["config"].(map[string]any)
	if !ok || cfg["password"] != "[REDACTED]" || cfg["url"] != "https://example.com" {
		t.Fatalf("applied config = %v", applied["config"])
	}

	get := e.do(a.sign(http.MethodGet, "/api/v1/plugins/com.example.monitor/config", "")).expect(t, http.StatusOK)
	var got map[string]any
	get.decode(t, &got)
	gotCfg, _ := got["config"].(map[string]any)
	if gotCfg["password"] != "[REDACTED]" || gotCfg["url"] != "https://example.com" {
		t.Fatalf("get config = %v", got)
	}
	if mustString(t, got, "revision") != "1" || got["active"] != true {
		t.Fatalf("config revision = %v", got)
	}

	// Conflict and not-found errors keep their documented codes.
	mgr.rollbackErr = problem.Conflict("13")
	conflict := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins/com.example.monitor/rollback", `{}`), idempotencyKey(53))
	p := e.do(conflict).expectProblem(t, http.StatusConflict, problem.RevisionConflict)
	if p.CurrentRevision != "13" {
		t.Fatalf("current_revision = %q", p.CurrentRevision)
	}
	mgr.getConfigErr = problem.New(problem.NotFound, "The plugin is not installed.")
	e.do(a.sign(http.MethodGet, "/api/v1/plugins/missing/config", "")).expectProblem(t, http.StatusNotFound, problem.NotFound)
}

func TestPluginListAndDetail(t *testing.T) {
	mgr := newFakePluginManager()
	mgr.plugins = []api.Plugin{
		{
			PluginID: "alpha", Name: "Alpha", Summary: "first", Publisher: "acme",
			Placement: "node", ActiveVersion: "2.0.0", ActiveStatus: "ACTIVE",
			InstallStatus: "INSTALLED", ConfigRevision: 3, Revision: 20,
			CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Versions: []api.PluginVersion{
				{PluginID: "alpha", Version: "2.0.0", Status: "ACTIVE", InstallStatus: "INSTALLED", Active: true, Revision: 20},
				{PluginID: "alpha", Version: "1.0.0", Status: "STOPPED", InstallStatus: "INSTALLED", Revision: 10},
			},
		},
		{
			PluginID: "beta", Name: "Beta", Summary: "second", Publisher: "acme",
			Placement: "controller", ConfigRevision: 0, Revision: 5,
			CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Versions: []api.PluginVersion{
				{PluginID: "beta", Version: "0.1.0", Status: "REJECTED", InstallStatus: "STAGED", Revision: 5, RejectedReason: "crash loop"},
			},
		},
	}
	mgr.byID["alpha"] = mgr.plugins[0]
	mgr.byID["beta"] = mgr.plugins[1]
	e := newPluginTestEnv(t, mgr)
	a := e.setupAdmin(adminUser)

	page := e.do(a.sign(http.MethodGet, "/api/v1/plugins", "")).expect(t, http.StatusOK)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	page.decode(t, &list)
	if len(list.Items) != 2 || mustString(t, list.Items[0], "plugin_id") != "alpha" {
		t.Fatalf("plugins = %v", list.Items)
	}
	if versions, _ := list.Items[0]["versions"].([]any); len(versions) != 2 {
		t.Fatalf("versions = %v", list.Items[0]["versions"])
	}
	if mustString(t, list.Items[0], "config_revision") != "3" {
		t.Fatalf("config_revision = %v", list.Items[0]["config_revision"])
	}

	projected := e.do(a.sign(http.MethodGet, "/api/v1/plugins?fields=/plugin_id", "")).expect(t, http.StatusOK)
	var fieldsPage struct {
		Items []map[string]any `json:"items"`
	}
	projected.decode(t, &fieldsPage)
	if len(fieldsPage.Items) != 2 || fieldsPage.Items[0]["plugin_id"] != "alpha" {
		t.Fatalf("projected plugins = %v", fieldsPage.Items)
	}
	if _, ok := fieldsPage.Items[0]["name"]; ok {
		t.Fatalf("the projection kept name: %v", fieldsPage.Items[0])
	}

	paged := e.do(a.sign(http.MethodGet, "/api/v1/plugins?limit=1", "")).expect(t, http.StatusOK)
	var firstPage struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	paged.decode(t, &firstPage)
	if len(firstPage.Items) != 1 || firstPage.NextCursor != "alpha" {
		t.Fatalf("first page = %v (cursor %q)", firstPage.Items, firstPage.NextCursor)
	}
	second := e.do(a.sign(http.MethodGet, "/api/v1/plugins?limit=1&cursor=alpha", "")).expect(t, http.StatusOK)
	var secondPage struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	second.decode(t, &secondPage)
	if len(secondPage.Items) != 1 || secondPage.Items[0]["plugin_id"] != "beta" || secondPage.NextCursor != "" {
		t.Fatalf("second page = %v (cursor %q)", secondPage.Items, secondPage.NextCursor)
	}

	detail := e.do(a.sign(http.MethodGet, "/api/v1/plugins/alpha", "")).expect(t, http.StatusOK)
	var got map[string]any
	detail.decode(t, &got)
	if mustString(t, got, "name") != "Alpha" || mustString(t, got, "active_version") != "2.0.0" {
		t.Fatalf("plugin = %v", got)
	}
	e.do(a.sign(http.MethodGet, "/api/v1/plugins/missing", "")).expectProblem(t, http.StatusNotFound, problem.NotFound)
}

func TestPluginRoutesWithoutUpdater(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)

	e.do(a.sign(http.MethodGet, "/api/v1/plugins", "")).expect(t, http.StatusOK)
	e.do(uploadRequest(t, a, "package", "a.zip", []byte("x"))).
		expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
	install := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", `{"upload_id":"upl_00000000000000000000000000000000","accepted_capabilities":[]}`), idempotencyKey(60))
	e.do(install).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
	update := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins/x/update", `{}`), idempotencyKey(61))
	e.do(update).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
	rollback := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins/x/rollback", ""), idempotencyKey(62))
	e.do(rollback).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
	e.do(a.sign(http.MethodGet, "/api/v1/plugins/x/config", "")).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
	put := withIdempotency(a.sign(http.MethodPut, "/api/v1/plugins/x/config", `{"config":{}}`), idempotencyKey(63))
	e.do(put).expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
}

func TestPluginRoutesAuthCSRFAndLimits(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)

	// No credentials.
	body, contentType := multipartBody(t, "package", "a.zip", []byte("x"))
	anon := newRequest(http.MethodPost, "/api/v1/plugin-packages", "")
	anon.Body = io.NopCloser(body)
	anon.Header.Set("Content-Type", contentType)
	anon.Header.Set("Origin", testOrigin)
	e.do(anon).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)

	// A viewer service account may read but not upload.
	viewer := e.serviceTokenWithRole(t, a, authz.RoleViewer)
	read := bearer(http.MethodGet, "/api/v1/plugins", "", viewer)
	e.do(read).expect(t, http.StatusOK)
	body, contentType = multipartBody(t, "package", "a.zip", []byte("x"))
	write := bearer(http.MethodPost, "/api/v1/plugin-packages", "", viewer)
	write.Body = io.NopCloser(body)
	write.Header.Set("Content-Type", contentType)
	e.do(write).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// Session mutations need the CSRF header.
	noCSRF := uploadRequest(t, a, "package", "a.zip", []byte("x"))
	noCSRF.Header.Del("X-CSRF-Token")
	e.do(noCSRF).expectProblem(t, http.StatusForbidden, problem.CSRFFailed)

	// Wrong media type.
	wrongType := a.sign(http.MethodPost, "/api/v1/plugin-packages", `{}`)
	e.do(wrongType).expectProblem(t, http.StatusUnsupportedMediaType, problem.UnsupportedMediaType)

	// A body over the route limit is rejected before it is read.
	huge := a.sign(http.MethodPost, "/api/v1/plugin-packages", "")
	huge.Body = io.NopCloser(strings.NewReader("x"))
	huge.ContentLength = gateway.MaxPackageBytes + 1
	huge.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	tooLarge := e.do(huge).expectProblem(t, http.StatusRequestEntityTooLarge, problem.PayloadTooLarge)
	if tooLarge.Limit == nil || tooLarge.Limit.Name != "max_package_bytes" || tooLarge.Limit.Max != gateway.MaxPackageBytes {
		t.Fatalf("limit = %+v", tooLarge.Limit)
	}

	// Missing package part and malformed multipart.
	missing := uploadRequest(t, a, "other", "a.zip", []byte("x"))
	e.do(missing).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	bad := a.sign(http.MethodPost, "/api/v1/plugin-packages", "")
	bad.Body = io.NopCloser(strings.NewReader("not a multipart body"))
	bad.ContentLength = 17
	bad.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")
	e.do(bad).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// An empty package part is rejected.
	empty := uploadRequest(t, a, "package", "a.zip", nil)
	e.do(empty).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
}

func TestPluginUploadExpiryAndDuplicateParts(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)
	upload, path := e.upload(t, a, []byte("expires"))

	e.clock.Advance(api.DefaultPluginUploadTTL + time.Minute)
	body := installBody(upload.UploadID, nil, "")
	req := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", body), idempotencyKey(70))
	e.do(req).expectProblem(t, http.StatusNotFound, problem.NotFound)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an expired package file survived: %v", err)
	}
	if e.uploads.Count() != 0 {
		t.Fatalf("pending uploads = %d", e.uploads.Count())
	}

	// Two `package` parts are ambiguous and refused.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, name := range []string{"first.zip", "second.zip"} {
		part, err := mw.CreateFormFile("package", name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write([]byte("x"))
	}
	_ = mw.Close()
	dup := a.sign(http.MethodPost, "/api/v1/plugin-packages", "")
	dup.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	dup.ContentLength = int64(buf.Len())
	dup.Header.Set("Content-Type", mw.FormDataContentType())
	e.do(dup).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
}

// TestUploadSlowClientBeyondReadTimeout: a slow uplink must be bounded by the
// package read timeout, not by the server's whole-request ReadTimeout.
func TestUploadSlowClientBeyondReadTimeout(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)
	ts := httptest.NewUnstartedServer(e.c.Handler())
	ts.Config.ReadTimeout = 200 * time.Millisecond
	ts.Start()
	defer ts.Close()

	body, contentType := multipartBody(t, "package", "a.zip", bytes.Repeat([]byte("x"), 20<<10))
	pr, pw := io.Pipe()
	go func() {
		chunk := make([]byte, 1<<10)
		for {
			n, err := body.Read(chunk)
			if n > 0 {
				if _, werr := pw.Write(chunk[:n]); werr != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err != nil {
				_ = pw.Close()
				return
			}
		}
	}()
	signed := a.sign(http.MethodPost, "/api/v1/plugin-packages", "")
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/plugin-packages", pr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header = signed.Header.Clone()
	req.Host = signed.Host
	req.Header.Set("Content-Type", contentType)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body %s", resp.StatusCode, raw)
	}
}

// TestInstallIgnoresClientCancellation: a client that disconnects mid-install
// must not cancel the plugin lifecycle the manager is running.
func TestInstallIgnoresClientCancellation(t *testing.T) {
	mgr := newFakePluginManager()
	e := newPluginTestEnv(t, mgr)
	a := e.setupAdmin(adminUser)
	upload, _ := e.upload(t, a, []byte("signed-package-bytes"))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var seen error
	mgr.onInstall = func(c context.Context) {
		cancel() // the client goes away while the install runs
		seen = c.Err()
	}
	req := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins", installBody(upload.UploadID, nil, "")), idempotencyKey(90))
	e.do(req.WithContext(ctx))
	if seen != nil {
		t.Fatalf("manager context error = %v, want nil", seen)
	}
}

func TestPluginUpdatePublisherChangeIsHumanOnly(t *testing.T) {
	mgr := newFakePluginManager()
	mgr.updateResult = api.PluginUpdate{
		SagaID: "sag_update", PluginID: "com.example.monitor", State: "COMMITTED",
		Version: api.PluginVersion{PluginID: "com.example.monitor", Version: "1.1.0", Status: "ACTIVE", InstallStatus: "INSTALLED", Active: true, Revision: 12},
	}
	e := newPluginTestEnv(t, mgr)
	a := e.setupAdmin(adminUser)
	upload, _ := e.upload(t, a, []byte("update-package"))
	body := strings.TrimSuffix(installBody(upload.UploadID, []string{"net.connect"}, "12"), "}") + `,"accept_publisher_change":true}`

	bot := bearer(http.MethodPost, "/api/v1/plugins/com.example.monitor/update", body, e.serviceToken(a))
	withIdempotency(bot, idempotencyKey(60))
	if got := e.do(bot); got.status != http.StatusForbidden {
		t.Fatalf("service account: status = %d (body %s)", got.status, got.body)
	}
	human := withIdempotency(a.sign(http.MethodPost, "/api/v1/plugins/com.example.monitor/update", body), idempotencyKey(61))
	e.do(human).expect(t, http.StatusOK)
	if mgr.updateReq == nil || !mgr.updateReq.AcceptPublisherChange {
		t.Fatalf("update request = %+v", mgr.updateReq)
	}
}
