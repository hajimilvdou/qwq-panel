// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/trust"
	"github.com/qwq-panel/qwq/internal/storage"
)

const (
	mfaCodeHeader      = "X-QWQ-MFA-Code"
	maxFetchURLLength  = 2048
	maxFetchRedirects  = 5
	fetchDownloadLimit = gateway.MaxPackageBytes // 64 MiB
	fetchTimeout       = 5 * time.Minute
)

var sha256HexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// --- DTOs -------------------------------------------------------------------

type pluginTrustKeyDTO struct {
	KeyID        string `json:"key_id"`
	Label        string `json:"label"`
	Source       string `json:"source"`
	PublicKeyPEM string `json:"public_key_pem"`
	AddedBy      string `json:"added_by,omitempty"`
	AddedAt      string `json:"added_at,omitempty"`
}

type pluginTrustKeyListDTO struct {
	Items []pluginTrustKeyDTO `json:"items"`
}

type pluginTrustKeyCreateRequest struct {
	Label        string `json:"label"`
	PublicKeyPEM string `json:"public_key_pem"`
}

type pluginPackageFetchRequest struct {
	URL            string `json:"url"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

func newPluginTrustKeyDTO(k trust.TrustKeyInfo) pluginTrustKeyDTO {
	return pluginTrustKeyDTO{
		KeyID:        k.KeyID,
		Label:        k.Label,
		Source:       k.Source,
		PublicKeyPEM: k.PublicKeyPEM,
		AddedBy:      k.AddedBy,
		AddedAt:      ts(k.AddedAt),
	}
}

// --- Trust key handlers -----------------------------------------------------

// listPluginTrustKeys answers GET /api/v1/plugin-trust-keys.
func (a *api) listPluginTrustKeys(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:read", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	items := []pluginTrustKeyDTO{}
	if a.d.PluginTrust != nil {
		keys, err := a.d.PluginTrust.List()
		if err != nil {
			a.fail(w, r, problem.Wrap(err))
			return
		}
		items = make([]pluginTrustKeyDTO, 0, len(keys))
		for _, k := range keys {
			items = append(items, newPluginTrustKeyDTO(k))
		}
	}
	a.writeResource(w, r, http.StatusOK, pluginTrustKeyListDTO{Items: items}, nil)
}

// addPluginTrustKey answers POST /api/v1/plugin-trust-keys.
func (a *api) addPluginTrustKey(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:install", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.PluginTrust == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	// Decode and pre-validate request syntax before MFA so malformed input
	// never consumes a single-use recovery code.
	var req pluginTrustKeyCreateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := trust.ValidateAddInput(req.Label, req.PublicKeyPEM); err != nil {
		a.fail(w, r, mapTrustStoreError(err))
		return
	}
	if err := a.requireTrustKeyMFA(r, act, "Adding a trusted publisher key requires a second factor."); err != nil {
		a.fail(w, r, err)
		return
	}
	added, err := a.d.PluginTrust.Add(req.Label, req.PublicKeyPEM, act.ID)
	if err != nil {
		a.fail(w, r, mapTrustStoreError(err))
		return
	}
	// Newly trusted keys must immediately affect staged package re-inspections.
	a.inspections.clear()
	a.auditTrustKeyChange(r, act, "plugin.trust_key.add", added.KeyID, map[string]any{
		"key_id": added.KeyID,
		"label":  added.Label,
		"source": added.Source,
	})
	a.writeResource(w, r, http.StatusCreated, newPluginTrustKeyDTO(added), nil)
}

// deletePluginTrustKey answers DELETE /api/v1/plugin-trust-keys/{key_id}.
func (a *api) deletePluginTrustKey(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:install", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.PluginTrust == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	// Validate key_id format and reject immutable official keys before MFA so
	// invalid requests never burn a single-use recovery code.
	keyID := r.PathValue("key_id")
	if err := trust.ValidateKeyID(keyID); err != nil {
		a.fail(w, r, mapTrustStoreError(err))
		return
	}
	if src, ok := a.d.PluginTrust.KeySource(keyID); ok && src == trust.SourceOfficial {
		a.fail(w, r, mapTrustStoreError(trust.ErrOfficialKey))
		return
	}
	if err := a.requireTrustKeyMFA(r, act, "Removing a trusted publisher key requires a second factor."); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.d.PluginTrust.Remove(keyID); err != nil {
		a.fail(w, r, mapTrustStoreError(err))
		return
	}
	a.inspections.clear()
	a.auditTrustKeyChange(r, act, "plugin.trust_key.remove", keyID, map[string]any{
		"key_id": keyID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) requireTrustKeyMFA(r *http.Request, act actor.Actor, detail string) error {
	if a.d.Identity == nil {
		return nil
	}
	u, err := a.d.Identity.User(r.Context(), act.ID)
	if err != nil {
		return err
	}
	if !u.MFAEnabled || act.MFA {
		return nil
	}
	code := strings.TrimSpace(r.Header.Get(mfaCodeHeader))
	if code == "" {
		return problem.New(problem.MFARequired, "%s", detail)
	}
	return a.d.Identity.VerifySecondFactor(r.Context(), act.ID, code, gateway.ClientIP(r.Context()))
}

func mapTrustStoreError(err error) error {
	switch {
	case errors.Is(err, trust.ErrInvalidLabel):
		return problem.Validation(problem.Violation{
			Pointer: "/label",
			Code:    "INVALID",
			Message: "Label must be 1 to 120 printable characters.",
		})
	case errors.Is(err, trust.ErrInvalidKey):
		return problem.Validation(problem.Violation{
			Pointer: "/public_key_pem",
			Code:    "INVALID",
			Message: "public_key_pem must be a valid Ed25519 PKIX PUBLIC KEY PEM block.",
		})
	case errors.Is(err, trust.ErrInvalidKeyID):
		return problem.Validation(problem.Violation{
			In:      "path",
			Pointer: "/key_id",
			Code:    "INVALID",
			Message: `key_id must match "ed25519:" followed by 64 lower-case hex digits.`,
		})
	case errors.Is(err, trust.ErrDuplicateKey):
		return problem.New(problem.StateConflict, "This publisher public key is already trusted.")
	case errors.Is(err, trust.ErrTooManyKeys):
		return problem.New(problem.StateConflict, "The maximum number of custom trusted publisher keys has been reached.")
	case errors.Is(err, trust.ErrOfficialKey):
		return problem.New(problem.PermissionDenied, "Official system publisher keys cannot be removed.")
	case errors.Is(err, trust.ErrKeyNotFound):
		return problem.New(problem.NotFound, "The trusted publisher key was not found.")
	default:
		return problem.Wrap(err)
	}
}

func (a *api) auditTrustKeyChange(r *http.Request, act actor.Actor, action, keyID string, details map[string]any) {
	rawDetails, _ := json.Marshal(details)
	rec := operations.AuditRecord{
		Actor:     act,
		Action:    action,
		Subject:   "plugin-trust-keys/" + keyID,
		Outcome:   operations.AuditSuccess,
		Details:   rawDetails,
		NodeID:    a.d.NodeID,
		TraceID:   gateway.TraceID(r.Context()),
		RequestID: requestID(r),
	}
	if err := a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, rec)
	}); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: audit plugin trust key change", "action", action, "error", err)
	}
}

// --- Remote HTTPS .qwqpkg fetch handler -------------------------------------

// fetchPluginPackage answers POST /api/v1/plugin-packages/fetch. It validates a
// strict HTTPS URL with SSRF-blocking dialer + redirect guard, enforces the
// 64 MiB and 60s download budgets, optionally checks expected_sha256, and
// stages the downloaded bytes through the exact same PluginUploads path as
// multipart uploads.
func (a *api) fetchPluginPackage(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.authorize(r.Context(), act, "host.plugins:install", ""); err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.Plugins == nil || a.d.PluginUploads == nil {
		a.fail(w, r, pluginUnavailable())
		return
	}
	var req pluginPackageFetchRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	targetURL, err := validateRemotePackageURL(req.URL)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	expectedSHA, err := normalizeOptionalSHA256(req.ExpectedSHA256)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), fetchTimeout)
	defer cancel()

	client := a.packageFetchClient()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "INVALID", Message: "The remote package URL could not be prepared.",
		}))
		return
	}
	httpReq.Header.Set("User-Agent", "qwq-panel/plugin-fetch")
	httpReq.Header.Set("Accept", "application/octet-stream, */*;q=0.1")

	resp, err := client.Do(httpReq)
	if err != nil {
		a.auditPackageFetch(r, act, targetURL.Host, operations.AuditFailure, map[string]any{
			"url":   targetURL.String(),
			"error": err.Error(),
		})
		a.fail(w, r, mapFetchError(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.auditPackageFetch(r, act, targetURL.Host, operations.AuditFailure, map[string]any{
			"url":         targetURL.String(),
			"http_status": resp.StatusCode,
		})
		if resp.StatusCode >= 500 {
			a.fail(w, r, problem.New(problem.Unavailable,
				"Remote host returned HTTP %d while downloading the plugin package.", resp.StatusCode))
			return
		}
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/url",
			Code:    "REMOTE_HTTP_ERROR",
			Message: fmt.Sprintf("Remote server returned HTTP %d.", resp.StatusCode),
		}))
		return
	}
	if resp.ContentLength > fetchDownloadLimit {
		a.fail(w, r, packageTooLarge(fetchDownloadLimit))
		return
	}

	upload, err := a.d.PluginUploads.Stage(ctx, resp.Body, principalScope(act), expectedSHA)
	if err != nil {
		a.auditPackageFetch(r, act, targetURL.Host, operations.AuditFailure, map[string]any{
			"url":   targetURL.String(),
			"error": err.Error(),
		})
		a.fail(w, r, err)
		return
	}
	a.auditPackageFetch(r, act, targetURL.Host, operations.AuditSuccess, map[string]any{
		"url":       targetURL.String(),
		"upload_id": upload.ID,
		"sha256":    upload.SHA256,
		"size":      upload.Size,
	})
	a.writeResource(w, r, http.StatusCreated, newPluginPackageUploadDTO(upload), nil)
}

func (a *api) auditPackageFetch(r *http.Request, act actor.Actor, host, outcome string, details map[string]any) {
	if a.d.DB == nil {
		return
	}
	rawDetails, _ := json.Marshal(details)
	rec := operations.AuditRecord{
		Actor:     act,
		Action:    "plugin.package.fetch",
		Subject:   "plugin-packages/" + host,
		Outcome:   outcome,
		Details:   rawDetails,
		NodeID:    a.d.NodeID,
		TraceID:   gateway.TraceID(r.Context()),
		RequestID: requestID(r),
	}
	if err := a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, rec)
	}); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: audit plugin package fetch", "host", host, "error", err)
	}
}

func (a *api) packageFetchClient() *http.Client {
	tr := a.d.PackageFetchTransport
	if tr == nil {
		tr = defaultSafeFetchTransport()
	}
	return &http.Client{
		Transport: tr,
		Timeout:   fetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxFetchRedirects {
				return &fetchPolicyError{code: "TOO_MANY_REDIRECTS", msg: "Remote package URL exceeded maximum redirect hops."}
			}
			if _, err := validateRemotePackageURL(req.URL.String()); err != nil {
				return &fetchPolicyError{code: "REDIRECT_BLOCKED", msg: "Redirect target must be a public HTTPS URL without credentials."}
			}
			return nil
		},
	}
}

type fetchPolicyError struct {
	code string
	msg  string
}

func (e *fetchPolicyError) Error() string { return e.msg }

func validateRemotePackageURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "REQUIRED", Message: "A remote HTTPS package URL is required.",
		})
	}
	if len(trimmed) > maxFetchURLLength {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "TOO_LONG", Message: fmt.Sprintf("URL must be at most %d characters.", maxFetchURLLength),
		})
	}
	u, err := url.Parse(trimmed)
	if err != nil || !u.IsAbs() {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "INVALID", Message: "URL must be a valid absolute HTTPS URL.",
		})
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "HTTPS_REQUIRED", Message: "Only https:// URLs are allowed for remote plugin package fetch.",
		})
	}
	if u.User != nil {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "CREDENTIALS_FORBIDDEN", Message: "URL must not contain embedded user credentials.",
		})
	}
	if u.Fragment != "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "INVALID", Message: "URL must not contain a fragment.",
		})
	}
	host := u.Hostname()
	if host == "" {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "INVALID", Message: "URL must include a hostname.",
		})
	}
	if strings.Contains(host, "%") {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "SSRF_BLOCKED", Message: "Zoned IP literals are not allowed.",
		})
	}
	lowerHost := strings.ToLower(strings.TrimSuffix(host, "."))
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/url", Code: "SSRF_BLOCKED", Message: "Loopback and local hostnames are not allowed.",
		})
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if isBlockedFetchAddr(addr) {
			return nil, problem.Validation(problem.Violation{
				Pointer: "/url", Code: "SSRF_BLOCKED", Message: "Private, loopback, link-local, and reserved IP addresses are not allowed.",
			})
		}
	}
	return u, nil
}

func normalizeOptionalSHA256(raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", nil
	}
	trimmed = strings.TrimPrefix(trimmed, "sha256:")
	if !sha256HexPattern.MatchString(trimmed) {
		return "", problem.Validation(problem.Violation{
			Pointer: "/expected_sha256",
			Code:    "INVALID",
			Message: "expected_sha256 must be 64 lower-case hex digits (optional sha256: prefix).",
		})
	}
	return trimmed, nil
}

func mapFetchError(err error) error {
	var pe *fetchPolicyError
	if errors.As(err, &pe) {
		return problem.Validation(problem.Violation{
			Pointer: "/url",
			Code:    pe.code,
			Message: pe.msg,
		})
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return problem.New(problem.Timeout, "Downloading the remote plugin package timed out.")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return problem.New(problem.Timeout, "Downloading the remote plugin package timed out.")
	}
	return problem.New(problem.Unavailable, "The remote plugin package could not be downloaded.")
}

// isBlockedFetchAddr reports whether addr is non-public (loopback, RFC1918,
// RFC4193, link-local, CGNAT, multicast, unspecified, zoned, or reserved),
// while unwrapping public NAT64 addresses (64:ff9b::/96 and 64:ff9b:1::/48)
// and recursively blocking private/loopback/metadata IPv4 suffixes.
func isBlockedFetchAddr(addr netip.Addr) bool {
	return trust.IsBlockedRemoteFetchAddr(addr)
}

var (
	safeFetchTransportOnce sync.Once
	safeFetchTransportInst *http.Transport
)

func defaultSafeFetchTransport() *http.Transport {
	safeFetchTransportOnce.Do(func() {
		safeFetchTransportInst = newSafeFetchTransport()
	})
	return safeFetchTransportInst
}

func newSafeFetchTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil, // Never allow ambient HTTP_PROXY to bypass SSRF dial checks.
		DialContext:           safeFetchDialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

// safeFetchDialContext resolves the target hostname, validates that every
// returned IP is public, and dials the verified IP directly to prevent DNS
// rebinding between resolution and connect.
func safeFetchDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &fetchPolicyError{code: "INVALID", msg: "Invalid remote host:port."}
	}
	var addrs []netip.Addr
	if literal, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{literal}
	} else {
		ips, rerr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if rerr != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %w", host, rerr)
		}
		addrs = make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip.IP)
			if !ok {
				return nil, &fetchPolicyError{code: "SSRF_BLOCKED", msg: "Remote hostname resolved to an invalid IP address."}
			}
			addrs = append(addrs, a)
		}
	}
	for _, a := range addrs {
		if isBlockedFetchAddr(a) {
			return nil, &fetchPolicyError{
				code: "SSRF_BLOCKED",
				msg:  "Remote hostname resolved to a blocked private, loopback, link-local, or reserved IP address.",
			}
		}
	}
	const perIPDialTimeout = 8 * time.Second
	dialer := &net.Dialer{Timeout: perIPDialTimeout, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, a := range addrs {
		ipCtx, ipCancel := context.WithTimeout(ctx, perIPDialTimeout)
		conn, derr := dialer.DialContext(ipCtx, network, net.JoinHostPort(a.Unmap().String(), port))
		ipCancel()
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}
