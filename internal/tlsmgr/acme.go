// SPDX-License-Identifier: AGPL-3.0-only

package tlsmgr

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/qwq-panel/qwq/internal/platform/config"
)

// setupACME wires autocert for the configured domains. It performs no network
// call: the first handshake or HTTP-01 challenge is what contacts the directory,
// which keeps offline starts and tests quiet.
//
// The cache holds the account key and the issued certificates; autocert renews
// them on demand about 30 days before expiry, so a running host keeps its
// certificate as long as it receives handshakes.
func (m *Manager) setupACME(t config.TLS) error {
	dir := filepath.Join(m.dataDir, "acme")
	if err := ensurePrivateDir(dir, m.log); err != nil {
		return err
	}
	domains := make([]string, 0, len(t.Domains))
	allowed := make(map[string]bool, len(t.Domains))
	for _, d := range t.Domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" {
			continue
		}
		domains = append(domains, d)
		allowed[d] = true
	}
	if len(domains) == 0 {
		return errors.New("tlsmgr: acme mode requires at least one domain")
	}
	cache := autocert.DirCache(dir)
	manager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  t.Email,
		Cache:  cache,
		// Only names from the bootstrap config may be requested. Without this an
		// attacker could point a DNS record at the host and make it obtain
		// certificates for arbitrary names, and with HTTP-01 the challenge would
		// even be served on port 80.
		HostPolicy: func(_ context.Context, host string) error {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if !allowed[host] {
				return fmt.Errorf("tlsmgr: host %q is not configured for ACME", host)
			}
			return nil
		},
	}
	manager.Client = &acme.Client{
		HTTPClient:   &http.Client{Timeout: 30 * time.Second},
		DirectoryURL: t.DirectoryURL,
	}
	m.dir = dir
	m.acme = manager
	m.acmeDomains = domains
	m.acmeCache = cache
	m.log.Info("tls: ACME enabled", "domains", strings.Join(domains, ","), "cache", dir)
	return nil
}

// acmeStatus reports the cached certificate that expires soonest. Until a
// certificate is issued the listener cannot complete a handshake, so readiness
// is false with a detail that says so.
func (m *Manager) acmeStatus(ctx context.Context, st Status) Status {
	var soonest *x509.Certificate
	soonestFP := ""
	for _, domain := range m.acmeDomains {
		leaf, fp, err := m.cachedLeaf(ctx, domain)
		if err != nil {
			m.log.DebugContext(ctx, "tls: no cached ACME certificate", "domain", domain, "error", err)
			continue
		}
		if soonest == nil || leaf.NotAfter.Before(soonest.NotAfter) {
			soonest, soonestFP = leaf, fp
		}
	}
	if soonest == nil {
		st.Detail = "No ACME certificate has been issued yet."
		return st
	}
	return describeCert(st, soonest, m.clock.Now(), soonestFP)
}

// cachedLeaf reads one cached certificate (autocert stores the PEM certificate
// and key under the domain name).
func (m *Manager) cachedLeaf(ctx context.Context, domain string) (*x509.Certificate, string, error) {
	pemBytes, err := m.acmeCache.Get(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", err
		}
		return leaf, fingerprint(block.Bytes), nil
	}
	return nil, "", errors.New("no certificate in the cached entry")
}

// HTTPHandler wraps the plain-text handler for ACME HTTP-01 challenges, which
// need port 80 to be reachable from the internet. On the current test host ports
// 80 and 443 belong to another service, so HTTP-01 is documented as unusable
// there. In other modes the fallback is returned unchanged.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	if fallback == nil {
		fallback = http.NotFoundHandler()
	}
	if m.acme == nil {
		return fallback
	}
	return m.acme.HTTPHandler(fallback)
}
