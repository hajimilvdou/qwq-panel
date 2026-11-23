// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/trust"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustGenTrustKeyPEM(t *testing.T) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemBytes, err := pkgfile.MarshalPublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}
	return manifest.KeyID(pub), string(pemBytes)
}

func TestPluginTrustKeysCRUDAndMFA(t *testing.T) {
	sysDir := filepath.Join(t.TempDir(), "official-trust")
	custDir := filepath.Join(t.TempDir(), "custom-trust")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatalf("mkdir sysDir: %v", err)
	}
	offID, offPEM := mustGenTrustKeyPEM(t)
	if err := os.WriteFile(filepath.Join(sysDir, "official.pem"), []byte(offPEM), 0o644); err != nil {
		t.Fatalf("write official pem: %v", err)
	}
	trustStore := trust.NewCompositeTrustStore(sysDir, custDir, clock.System{})

	e := newEnvWith(t, func(d *api.Deps) {
		d.PluginTrust = trustStore
	})
	admin := e.setupAdmin(adminUser)

	// 1. List shows the official key.
	var listResp struct {
		Items []struct {
			KeyID        string `json:"key_id"`
			Label        string `json:"label"`
			Source       string `json:"source"`
			PublicKeyPEM string `json:"public_key_pem"`
		} `json:"items"`
	}
	e.do(admin.sign(http.MethodGet, "/api/v1/plugin-trust-keys", "")).
		expect(t, http.StatusOK).
		decode(t, &listResp)
	if len(listResp.Items) != 1 || listResp.Items[0].KeyID != offID || listResp.Items[0].Source != trust.SourceOfficial {
		t.Fatalf("unexpected initial trust keys: %+v", listResp.Items)
	}

	// 2. Add custom developer key.
	devID, devPEM := mustGenTrustKeyPEM(t)
	addBody, _ := json.Marshal(map[string]string{
		"label":          "Community Dev",
		"public_key_pem": devPEM,
	})
	var added struct {
		KeyID  string `json:"key_id"`
		Label  string `json:"label"`
		Source string `json:"source"`
	}
	e.do(admin.sign(http.MethodPost, "/api/v1/plugin-trust-keys", string(addBody))).
		expect(t, http.StatusCreated).
		decode(t, &added)
	if added.KeyID != devID || added.Label != "Community Dev" || added.Source != trust.SourceCustom {
		t.Fatalf("unexpected added key: %+v", added)
	}

	// Duplicate add returns 409 STATE_CONFLICT.
	e.do(admin.sign(http.MethodPost, "/api/v1/plugin-trust-keys", string(addBody))).
		expectProblem(t, http.StatusConflict, problem.StateConflict)

	// Invalid PEM returns 400 VALIDATION_FAILED.
	badBody, _ := json.Marshal(map[string]string{
		"label":          "Broken",
		"public_key_pem": "not-a-pem",
	})
	e.do(admin.sign(http.MethodPost, "/api/v1/plugin-trust-keys", string(badBody))).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// 3. Official key cannot be deleted.
	e.do(admin.sign(http.MethodDelete, "/api/v1/plugin-trust-keys/"+url.PathEscape(offID), "")).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// 4. Custom key can be deleted, and second delete is 404 NOT_FOUND.
	e.do(admin.sign(http.MethodDelete, "/api/v1/plugin-trust-keys/"+url.PathEscape(devID), "")).
		expect(t, http.StatusNoContent)
	e.do(admin.sign(http.MethodDelete, "/api/v1/plugin-trust-keys/"+url.PathEscape(devID), "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)

	// 5. MFA enforcement when user enables TOTP on existing non-MFA session.
	_, recoveryCodes := e.enableTOTP(admin.userID)
	dev2ID, dev2PEM := mustGenTrustKeyPEM(t)
	add2Body, _ := json.Marshal(map[string]string{
		"label":          "MFA Protected Key",
		"public_key_pem": dev2PEM,
	})
	e.do(admin.sign(http.MethodPost, "/api/v1/plugin-trust-keys", string(add2Body))).
		expectProblem(t, http.StatusForbidden, problem.MFARequired)

	reqWithMFA := admin.sign(http.MethodPost, "/api/v1/plugin-trust-keys", string(add2Body))
	reqWithMFA.Header.Set("X-QWQ-MFA-Code", recoveryCodes[0])
	e.do(reqWithMFA).expect(t, http.StatusCreated)

	delWithMFA := admin.sign(http.MethodDelete, "/api/v1/plugin-trust-keys/"+url.PathEscape(dev2ID), "")
	delWithMFA.Header.Set("X-QWQ-MFA-Code", recoveryCodes[1])
	e.do(delWithMFA).expect(t, http.StatusNoContent)
}

func TestPluginPackageFetchSSRFAndSuccess(t *testing.T) {
	payload := []byte("fake-signed-qwqpkg-payload-bytes")
	sum := sha256.Sum256(payload)
	wantSHA := hex.EncodeToString(sum[:])

	uploads, err := api.NewPluginUploads(filepath.Join(t.TempDir(), "uploads"), 15*time.Minute, clock.System{})
	if err != nil {
		t.Fatalf("NewPluginUploads: %v", err)
	}
	pm := newFakePluginManager()

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://releases.example.com/demo-0.1.0.qwqpkg":
			return &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: int64(len(payload)),
				Header:        make(http.Header),
				Body:          io.NopCloser(bytes.NewReader(payload)),
			}, nil
		case "https://releases.example.com/redirect-private":
			h := make(http.Header)
			h.Set("Location", "https://127.0.0.1/secret.qwqpkg")
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     h,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		case "https://releases.example.com/redirect-http":
			h := make(http.Header)
			h.Set("Location", "http://releases.example.com/demo.qwqpkg")
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     h,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}
	})

	e := newEnvWith(t, func(d *api.Deps) {
		d.Plugins = pm
		d.PluginUploads = uploads
		d.PackageFetchTransport = transport
	})
	admin := e.setupAdmin(adminUser)

	// 1. SSRF and scheme rejections.
	blockedURLs := []string{
		"http://releases.example.com/demo.qwqpkg",
		"https://127.0.0.1/demo.qwqpkg",
		"https://[::1]/demo.qwqpkg",
		"https://localhost/demo.qwqpkg",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.1/demo.qwqpkg",
		"https://172.16.5.4/demo.qwqpkg",
		"https://192.168.1.10/demo.qwqpkg",
		"https://100.64.0.1/demo.qwqpkg",
		"https://[64:ff9b::127.0.0.1%25eth0]/demo.qwqpkg",
		"https://[64:ff9b:1::1]/demo.qwqpkg",
		"https://[2002:7f00:0001::]/demo.qwqpkg",
		"https://[2001::1]/demo.qwqpkg",
		"https://user:pass@releases.example.com/demo.qwqpkg",
		"https://releases.example.com/redirect-private",
		"https://releases.example.com/redirect-http",
	}
	for _, u := range blockedURLs {
		body, _ := json.Marshal(map[string]string{"url": u})
		e.do(admin.sign(http.MethodPost, "/api/v1/plugin-packages/fetch", string(body))).
			expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	}

	// 2. Mismatched expected_sha256 fails and does not leave a staged upload.
	badSHABody, _ := json.Marshal(map[string]string{
		"url":             "https://releases.example.com/demo-0.1.0.qwqpkg",
		"expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	})
	e.do(admin.sign(http.MethodPost, "/api/v1/plugin-packages/fetch", string(badSHABody))).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if uploads.Count() != 0 {
		t.Fatalf("expected 0 staged uploads after sha mismatch, got %d", uploads.Count())
	}

	// 3. Valid HTTPS fetch with matching expected_sha256 stages the package.
	okBody, _ := json.Marshal(map[string]string{
		"url":             "https://releases.example.com/demo-0.1.0.qwqpkg",
		"expected_sha256": "sha256:" + wantSHA,
	})
	var staged struct {
		UploadID  string `json:"upload_id"`
		Size      int64  `json:"size"`
		SHA256    string `json:"sha256"`
		ExpiresAt string `json:"expires_at"`
	}
	e.do(admin.sign(http.MethodPost, "/api/v1/plugin-packages/fetch", string(okBody))).
		expect(t, http.StatusCreated).
		decode(t, &staged)
	if staged.UploadID == "" || staged.Size != int64(len(payload)) || staged.SHA256 != wantSHA {
		t.Fatalf("unexpected staged response: %+v", staged)
	}
	if _, ok := uploads.Resolve(staged.UploadID); !ok {
		t.Fatalf("staged upload_id %s not found in PluginUploads", staged.UploadID)
	}
}
