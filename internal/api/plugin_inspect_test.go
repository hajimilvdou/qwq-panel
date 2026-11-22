// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// inspectionDoc is the decoded PluginPackageInspection of one GET.
type inspectionDoc struct {
	UploadID  string `json:"upload_id"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	ExpiresAt string `json:"expires_at"`
	Signature struct {
		Valid       bool   `json:"valid"`
		KeyID       string `json:"key_id"`
		Trusted     bool   `json:"trusted"`
		PublisherID string `json:"publisher_id"`
	} `json:"signature"`
	Manifest *struct {
		ID           string `json:"id"`
		Version      string `json:"version"`
		Name         string `json:"name"`
		Summary      string `json:"summary"`
		Placement    string `json:"placement"`
		Target       string `json:"target"`
		ABI          string `json:"abi"`
		Capabilities []struct {
			Name      string `json:"name"`
			Scope     string `json:"scope"`
			Reason    string `json:"reason"`
			Sensitive bool   `json:"sensitive"`
		} `json:"capabilities"`
		ConnectSources []string `json:"connect_sources"`
		Resources      struct {
			MemoryMaxMB int64 `json:"memory_max_mb"`
		} `json:"resources"`
		Operations []struct {
			Name         string `json:"name"`
			Summary      string `json:"summary"`
			Effect       string `json:"effect"`
			Risk         string `json:"risk"`
			Approval     string `json:"approval"`
			Reachability bool   `json:"reachability"`
		} `json:"operations"`
		UIRoutes int `json:"ui_routes"`
		Widgets  int `json:"widgets"`
	} `json:"manifest"`
	Compatibility struct {
		OK       bool `json:"ok"`
		Problems []struct {
			Pointer string `json:"pointer"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"problems"`
	} `json:"compatibility"`
	Memory struct {
		RequiredMB  int64 `json:"required_mb"`
		AvailableMB int64 `json:"available_mb"`
		OK          bool  `json:"ok"`
	} `json:"memory"`
	Disk struct {
		RequiredMB  int64 `json:"required_mb"`
		AvailableMB int64 `json:"available_mb"`
		OK          bool  `json:"ok"`
	} `json:"disk"`
	Installed *struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	} `json:"installed"`
}

// TestPluginPackageInspection: the uploader inspects a staged package; the
// response merges the upload metadata with the host's verdict, the private
// staging file is what the manager was asked about, and a repeated lookup is
// served from the cache without inspecting again (GAPS gap 4).
func TestPluginPackageInspection(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)
	upload, path := e.upload(t, a, []byte("inspect-me"))
	e.mgr.inspectResult = api.PackageInspection{
		PluginID: "acme.demo", Version: "1.0.0",
		Manifest: &api.PackageManifest{
			ID: "acme.demo", Version: "1.0.0", Name: "Demo", Summary: "demo summary",
			PublisherID: "acme", Placement: "controller", Target: "linux/amd64", ABI: "1.0",
			Capabilities: []api.PluginCapability{
				{Name: "net.connect", Scope: "outbound", Reason: "calls the API", Sensitive: false},
			},
			ConnectSources: []string{"https://api.acme.example"},
			Resources:      &api.PluginResources{MemoryMaxMB: 48, CPUQuotaPercent: 100, PIDsMax: 32, FDsMax: 256, DiskMaxMB: 10},
			Operations: []api.PackageOperation{
				{Name: "status", Summary: "reads status", Effect: "read", Risk: "low", Approval: "auto"},
				{Name: "firewall.apply", Summary: "applies rules", Effect: "write", Risk: "high", Approval: "ai_confirm", Reachability: true},
			},
			UIRoutes: 2, Widgets: 1,
		},
		SignatureValid: true, SignatureTrusted: true, SignatureKeyID: "ed25519:" + strings.Repeat("a", 64),
		Problems: []api.PackageProblem{
			{Pointer: "/schema_version", Code: "SCHEMA_VERSION_TOO_OLD", Message: "too old"},
		},
		UnpackedBytes: 3<<20 + 512<<10, // 3.5 MiB: required_mb must round up
		Memory:        api.InspectionCapacity{RequiredBytes: 48 << 20, AvailableBytes: 4 << 30, OK: true},
		Disk:          api.InspectionCapacity{RequiredBytes: 3<<20 + 512<<10, AvailableBytes: 10 << 30, OK: true},
		Installed:     &api.InstalledPluginVersion{Version: "0.9.0", Revision: 42},
	}

	resp := e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "")).expect(t, http.StatusOK)
	var doc inspectionDoc
	resp.decode(t, &doc)

	if doc.UploadID != upload.UploadID || doc.Size != upload.Size || doc.SHA256 != upload.SHA256 || doc.ExpiresAt != upload.ExpiresAt {
		t.Fatalf("upload metadata = %+v (want %+v)", doc, upload)
	}
	if !doc.Signature.Valid || !doc.Signature.Trusted || doc.Signature.KeyID == "" {
		t.Fatalf("signature = %+v", doc.Signature)
	}
	if doc.Signature.PublisherID != "acme" {
		t.Fatalf("publisher = %q", doc.Signature.PublisherID)
	}
	m := doc.Manifest
	if m == nil || m.ID != "acme.demo" || m.Version != "1.0.0" || m.Name != "Demo" || m.Summary != "demo summary" {
		t.Fatalf("manifest = %+v", m)
	}
	if m.Placement != "controller" || m.Target != "linux/amd64" || m.ABI != "1.0" {
		t.Fatalf("manifest target = %+v", m)
	}
	if len(m.Capabilities) != 1 || m.Capabilities[0].Name != "net.connect" || m.Capabilities[0].Scope != "outbound" {
		t.Fatalf("capabilities = %+v", m.Capabilities)
	}
	if len(m.ConnectSources) != 1 || m.ConnectSources[0] != "https://api.acme.example" {
		t.Fatalf("connect_sources = %+v", m.ConnectSources)
	}
	if m.Resources.MemoryMaxMB != 48 {
		t.Fatalf("resources = %+v", m.Resources)
	}
	if len(m.Operations) != 2 || m.Operations[1].Name != "firewall.apply" ||
		m.Operations[1].Risk != "high" || m.Operations[1].Approval != "ai_confirm" || !m.Operations[1].Reachability {
		t.Fatalf("operations = %+v", m.Operations)
	}
	if m.UIRoutes != 2 || m.Widgets != 1 {
		t.Fatalf("ui counts = %d/%d", m.UIRoutes, m.Widgets)
	}
	if doc.Compatibility.OK || len(doc.Compatibility.Problems) != 1 ||
		doc.Compatibility.Problems[0].Code != "SCHEMA_VERSION_TOO_OLD" {
		t.Fatalf("compatibility = %+v", doc.Compatibility)
	}
	if doc.Memory.RequiredMB != 48 || doc.Memory.AvailableMB != 4096 || !doc.Memory.OK {
		t.Fatalf("memory = %+v", doc.Memory)
	}
	if doc.Disk.RequiredMB != 4 || doc.Disk.AvailableMB != 10240 || !doc.Disk.OK {
		t.Fatalf("disk = %+v", doc.Disk)
	}
	if doc.Installed == nil || doc.Installed.Version != "0.9.0" || doc.Installed.Revision != "42" {
		t.Fatalf("installed = %+v", doc.Installed)
	}

	// The manager was handed the private staging file, never the id.
	if e.mgr.inspectPath != path {
		t.Fatalf("inspect path = %q, want the staged file", e.mgr.inspectPath)
	}
	// A repeated lookup is served from the cache: no second inspection.
	again := e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "")).expect(t, http.StatusOK)
	if string(again.body) != string(resp.body) {
		t.Fatalf("cached body differs:\n%s\n%s", resp.body, again.body)
	}
	if e.mgr.inspectCalls != 1 {
		t.Fatalf("inspect calls = %d, want 1", e.mgr.inspectCalls)
	}
}

// TestPluginPackageInspectionOnlyUploader: only the principal that uploaded
// the package may inspect it. Another principal with the same permission gets
// the same 404 as for an unknown id, and no inspection runs.
func TestPluginPackageInspectionOnlyUploader(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)
	upload, _ := e.upload(t, a, []byte("mine"))

	operator := e.serviceTokenWithRole(t, a, authz.RoleOperator)
	e.do(bearer(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "", operator)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	if e.mgr.inspectCalls != 0 {
		t.Fatalf("an inspection ran for another principal: %d", e.mgr.inspectCalls)
	}

	// A viewer lacks host.plugins:install and is refused before ownership.
	viewer := e.serviceTokenWithRole(t, a, authz.RoleViewer)
	e.do(bearer(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "", viewer)).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// The uploader still can.
	e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "")).expect(t, http.StatusOK)
}

// TestPluginPackageInspectionUnknownAndExpired: unknown, malformed and
// expired upload ids are the same 404.
func TestPluginPackageInspectionUnknownAndExpired(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)
	for _, id := range []string{"upl_" + strings.Repeat("0", 32), "not-an-id"} {
		e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+id, "")).
			expectProblem(t, http.StatusNotFound, problem.NotFound)
	}
	upload, _ := e.upload(t, a, []byte("short-lived"))
	e.clock.Advance(api.DefaultPluginUploadTTL + time.Minute)
	e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
	if e.mgr.inspectCalls != 0 {
		t.Fatalf("expired upload was inspected: %d", e.mgr.inspectCalls)
	}
}

// TestPluginPackageInspectionSignatureRefusalAndRetry: a refused signature is
// a 200 with valid=false, and a failed inspection is not cached: the next
// lookup recomputes.
func TestPluginPackageInspectionSignatureRefusalAndRetry(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)
	upload, _ := e.upload(t, a, []byte("unsigned"))

	e.mgr.inspectErr = problem.New(problem.Internal, "the package could not be read")
	e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "")).
		expectProblem(t, http.StatusInternalServerError, problem.Internal)

	e.mgr.inspectErr = nil
	e.mgr.inspectResult = api.PackageInspection{
		SignatureValid: false, SignatureTrusted: false,
		Manifest: &api.PackageManifest{ID: "acme.demo", Version: "1.0.0", Name: "Demo", Summary: "unsigned"},
	}
	resp := e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "")).expect(t, http.StatusOK)
	var doc inspectionDoc
	resp.decode(t, &doc)
	if doc.Signature.Valid || doc.Signature.Trusted {
		t.Fatalf("signature = %+v, want refused", doc.Signature)
	}
	if doc.Manifest == nil || doc.Manifest.ID != "acme.demo" {
		t.Fatalf("manifest = %+v", doc.Manifest)
	}
	if !doc.Compatibility.OK {
		t.Fatalf("compatibility = %+v", doc.Compatibility)
	}
	if e.mgr.inspectCalls != 2 {
		t.Fatalf("inspect calls = %d, want 2 (failure must not be cached)", e.mgr.inspectCalls)
	}
	// Now cached.
	e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "")).expect(t, http.StatusOK)
	if e.mgr.inspectCalls != 2 {
		t.Fatalf("inspect calls = %d, want 2 after a successful cache fill", e.mgr.inspectCalls)
	}
}

// TestPluginPackageInspectionEmptyCollections 保证必需数组输出 []，符合 OpenAPI。
func TestPluginPackageInspectionEmptyCollections(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	a := e.setupAdmin(adminUser)
	upload, _ := e.upload(t, a, []byte("minimal"))
	e.mgr.inspectResult = api.PackageInspection{
		Manifest: &api.PackageManifest{ID: "acme.demo", Version: "1.0.0", Name: "Demo", Summary: "demo"},
	}
	resp := e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/"+upload.UploadID, "")).expect(t, http.StatusOK)
	var doc struct {
		Manifest struct {
			Capabilities json.RawMessage `json:"capabilities"`
			Operations   json.RawMessage `json:"operations"`
		} `json:"manifest"`
		Compatibility struct {
			Problems json.RawMessage `json:"problems"`
		} `json:"compatibility"`
	}
	resp.decode(t, &doc)
	for name, raw := range map[string]json.RawMessage{
		"capabilities": doc.Manifest.Capabilities,
		"operations":   doc.Manifest.Operations,
		"problems":     doc.Compatibility.Problems,
	} {
		if string(raw) != "[]" {
			t.Errorf("%s = %s, want []", name, raw)
		}
	}
}

// TestPluginPackageInspectionWithoutUpdater: a host without an updater
// answers 503 like the other plugin routes.
func TestPluginPackageInspectionWithoutUpdater(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	e.do(a.sign(http.MethodGet, "/api/v1/plugin-packages/upl_"+strings.Repeat("0", 32), "")).
		expectProblem(t, http.StatusServiceUnavailable, problem.PluginUnavailable)
}

// TestPluginPackageInspectionUnauthenticated: no credentials, no inspection.
func TestPluginPackageInspectionUnauthenticated(t *testing.T) {
	e := newPluginTestEnv(t, nil)
	req := newRequest(http.MethodGet, "/api/v1/plugin-packages/upl_"+strings.Repeat("0", 32), "")
	e.do(req).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
}
