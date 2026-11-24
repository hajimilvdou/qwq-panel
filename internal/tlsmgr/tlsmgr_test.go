// SPDX-License-Identifier: AGPL-3.0-only

package tlsmgr

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// testTime is the fake clock start for every test.
var testTime = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// fixedAddrs stands in for the host interfaces, so certificates in tests do not
// depend on the machine running them.
func fixedAddrs() ([]net.Addr, error) {
	return []net.Addr{
		&net.IPNet{IP: net.ParseIP("10.1.2.3"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("169.254.10.20"), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
	}, nil
}

// newSelfSigned returns a manager over a fresh data directory.
func newSelfSigned(t *testing.T, dir string, listen string, origins []string, c clock.Clock) *Manager {
	t.Helper()
	m, err := New(Options{
		TLS:           config.TLS{Mode: config.TLSSelfSigned},
		Listen:        listen,
		PublicOrigins: origins,
		DataDir:       dir,
		Clock:         c,
		LocalAddrs:    fixedAddrs,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func hasDNS(leaf *x509.Certificate, name string) bool {
	return slices.ContainsFunc(leaf.DNSNames, func(n string) bool { return strings.EqualFold(n, name) })
}

func hasIP(leaf *x509.Certificate, want string) bool {
	for _, ip := range leaf.IPAddresses {
		if ip.String() == want {
			return true
		}
	}
	return false
}

var fingerprintRE = regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`)

func TestSelfSignedCertificate(t *testing.T) {
	dir := t.TempDir()
	m := newSelfSigned(t, dir, "127.0.0.1:8443",
		[]string{"https://Panel.Example.com:8443", "https://203.0.113.7"}, clock.NewFake(testTime))

	c := m.current.Load()
	if c == nil {
		t.Fatal("no certificate was generated")
	}
	leaf := c.leaf
	if !fingerprintRE.MatchString(m.Fingerprint()) {
		t.Fatalf("fingerprint %q is not colon-separated upper-case SHA-256", m.Fingerprint())
	}
	if m.Fingerprint() != c.fp {
		t.Fatalf("Fingerprint() = %q, cached %q", m.Fingerprint(), c.fp)
	}
	if !leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("self-signed leaf must be able to act as its own root: IsCA=%v keyUsage=%v", leaf.IsCA, leaf.KeyUsage)
	}
	if got := leaf.NotAfter.Sub(testTime); got != selfSignedValidity {
		t.Fatalf("validity %v, want %v", got, selfSignedValidity)
	}
	if span := leaf.NotAfter.Sub(leaf.NotBefore); span > 398*24*time.Hour {
		t.Fatalf("validity spans %v, more than browsers accept", span)
	}
	if leaf.Subject.CommonName == "" {
		t.Fatal("certificate has no common name")
	}

	// The listener host, loopback and the public origins are covered; names that
	// are configured as IPs become IP SANs.
	for _, name := range []string{"localhost", "panel.example.com"} {
		if !hasDNS(leaf, name) {
			t.Fatalf("certificate does not cover %q: %v", name, leaf.DNSNames)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "203.0.113.7"} {
		if !hasIP(leaf, ip) {
			t.Fatalf("certificate does not cover %q: %v", ip, leaf.IPAddresses)
		}
	}
	// The listener binds one address, so interfaces are not enumerated.
	if hasIP(leaf, "10.1.2.3") {
		t.Fatalf("certificate covers an unrelated interface address: %v", leaf.IPAddresses)
	}

	// Files and permissions.
	tlsDir := filepath.Join(dir, "tls")
	if info, err := os.Stat(tlsDir); err != nil || info.Mode().Perm() != privateDirMode {
		t.Fatalf("tls directory: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(tlsDir, selfSignedKeyFile)); err != nil || info.Mode().Perm() != keyFileMode {
		t.Fatalf("key file: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(tlsDir, selfSignedCertFile)); err != nil || info.Mode().Perm() != certFileMode {
		t.Fatalf("certificate file: info=%v err=%v", info, err)
	}
}

func TestSelfSignedEnumeratesLocalAddresses(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8443", "[::]:8443"} {
		t.Run(listen, func(t *testing.T) {
			m := newSelfSigned(t, t.TempDir(), listen, nil, clock.NewFake(testTime))
			leaf := m.current.Load().leaf
			if !hasIP(leaf, "10.1.2.3") {
				t.Fatalf("certificate misses the host's unicast address: %v", leaf.IPAddresses)
			}
			if !hasIP(leaf, "127.0.0.1") || !hasDNS(leaf, "localhost") {
				t.Fatalf("certificate misses loopback: %v %v", leaf.IPAddresses, leaf.DNSNames)
			}
			// Link-local addresses rotate with DHCP and are not usable by name.
			if hasIP(leaf, "169.254.10.20") || hasIP(leaf, "fe80::1") {
				t.Fatalf("certificate includes link-local addresses: %v", leaf.IPAddresses)
			}
		})
	}
}

func TestSelfSignedFingerprintIsStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	fake := clock.NewFake(testTime)
	first := newSelfSigned(t, dir, "127.0.0.1:8443", []string{"https://panel.example.com"}, fake)
	keyPath := filepath.Join(dir, "tls", selfSignedKeyFile)
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	// A restart with the same configuration must reuse the stored pair: the
	// installer printed the fingerprint and the operator may have pinned it.
	second := newSelfSigned(t, dir, "127.0.0.1:8443", []string{"https://panel.example.com"}, fake)
	if second.Fingerprint() != first.Fingerprint() {
		t.Fatalf("fingerprint changed across restart: %s -> %s", first.Fingerprint(), second.Fingerprint())
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("the key file was rewritten on restart")
	}
}

func TestSelfSignedRenewsBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	fake := clock.NewFake(testTime)
	first := newSelfSigned(t, dir, "127.0.0.1:8443", nil, fake)
	oldNotAfter := first.current.Load().leaf.NotAfter

	// 27 days left is below the 30-day renewal threshold.
	fake.Advance(selfSignedValidity - renewBefore + time.Hour)
	second := newSelfSigned(t, dir, "127.0.0.1:8443", nil, fake)
	if second.Fingerprint() == first.Fingerprint() {
		t.Fatal("an almost expired certificate was reused")
	}
	if got, want := second.current.Load().leaf.NotAfter, fake.Now().Add(selfSignedValidity); !got.Equal(want) {
		t.Fatalf("renewed certificate expires at %v, want %v", got, want)
	}
	if !second.current.Load().leaf.NotAfter.After(oldNotAfter) {
		t.Fatal("renewed certificate expires no later than the old one")
	}
}

func TestSelfSignedReplacesCertificateWhenNamesChange(t *testing.T) {
	dir := t.TempDir()
	fake := clock.NewFake(testTime)
	first := newSelfSigned(t, dir, "127.0.0.1:8443", []string{"https://a.example.com"}, fake)
	second := newSelfSigned(t, dir, "127.0.0.1:8443",
		[]string{"https://a.example.com", "https://b.example.com"}, fake)
	if second.Fingerprint() == first.Fingerprint() {
		t.Fatal("a certificate that misses a configured name was kept")
	}
	if !hasDNS(second.current.Load().leaf, "b.example.com") {
		t.Fatalf("new certificate does not cover b.example.com: %v", second.current.Load().leaf.DNSNames)
	}
}

func TestSelfSignedRestartKeepsFreshCertificate(t *testing.T) {
	// A restart shortly before expiry but with more than renewBefore left must
	// keep the fingerprint: that is what "stable across restarts" means for a
	// host that reboots often.
	dir := t.TempDir()
	fake := clock.NewFake(testTime)
	first := newSelfSigned(t, dir, "127.0.0.1:8443", nil, fake)
	fake.Advance(100 * 24 * time.Hour)
	second := newSelfSigned(t, dir, "127.0.0.1:8443", nil, fake)
	if second.Fingerprint() != first.Fingerprint() {
		t.Fatal("a certificate with 297 days left was replaced")
	}
}

func TestTLSConfigDefaults(t *testing.T) {
	m := newSelfSigned(t, t.TempDir(), "127.0.0.1:8443", nil, clock.NewFake(testTime))
	cfg := m.TLSConfig()
	if cfg == nil {
		t.Fatal("self-signed mode returned a nil TLS config")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
	want := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	if !slices.Equal(cfg.CipherSuites, want) {
		t.Fatalf("CipherSuites = %v, want the AEAD-only list %v", cfg.CipherSuites, want)
	}
	if !slices.Equal(cfg.CurvePreferences, []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}) {
		t.Fatalf("CurvePreferences = %v", cfg.CurvePreferences)
	}
	if !slices.Contains(cfg.NextProtos, "h2") || !slices.Contains(cfg.NextProtos, "http/1.1") {
		t.Fatalf("NextProtos = %v, want HTTP/2 and HTTP/1.1", cfg.NextProtos)
	}
	if slices.Contains(cfg.NextProtos, "acme-tls/1") {
		t.Fatal("self-signed mode advertises the ACME ALPN protocol")
	}
	if cfg.GetCertificate == nil || cfg.InsecureSkipVerify || cfg.Renegotiation != tls.RenegotiateNever {
		t.Fatalf("unexpected TLS config: %+v", cfg)
	}
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if fingerprint(got.Certificate[0]) != m.Fingerprint() {
		t.Fatal("GetCertificate returned a different certificate")
	}
}

func TestSetListenRefreshesSelfSignedSANs(t *testing.T) {
	fake := clock.NewFake(testTime)
	dir := t.TempDir()
	pubIP := net.ParseIP("203.0.113.10")
	m, err := New(Options{
		TLS:     config.TLS{Mode: config.TLSSelfSigned},
		Listen:  "127.0.0.1:8443",
		DataDir: dir,
		Clock:   fake,
		LocalAddrs: func() ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
				&net.IPNet{IP: pubIP, Mask: net.CIDRMask(24, 32)},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	origFP := m.Fingerprint()
	if c := m.current.Load(); c == nil || slices.ContainsFunc(c.leaf.IPAddresses, func(ip net.IP) bool { return ip.Equal(pubIP) }) {
		t.Fatalf("loopback-only cert should not yet include public IP %v", pubIP)
	}
	if err := m.SetListen("0.0.0.0:45001"); err != nil {
		t.Fatalf("SetListen(0.0.0.0:45001): %v", err)
	}
	pubFP := m.Fingerprint()
	if pubFP == origFP {
		t.Fatal("SetListen to 0.0.0.0 should regenerate cert to include public NIC IP SAN")
	}
	if c := m.current.Load(); c == nil || !slices.ContainsFunc(c.leaf.IPAddresses, func(ip net.IP) bool { return ip.Equal(pubIP) }) {
		t.Fatalf("public cert missing NIC IP SAN %v", pubIP)
	}
	// Repeating SetListen with already-covered SAN keeps the same fingerprint.
	if err := m.SetListen("0.0.0.0:45002"); err != nil {
		t.Fatalf("SetListen(0.0.0.0:45002): %v", err)
	}
	if m.Fingerprint() != pubFP {
		t.Fatal("SetListen rotated cert unnecessarily when SANs were already covered")
	}
}

func TestStatusSelfSigned(t *testing.T) {
	ctx := context.Background()
	fake := clock.NewFake(testTime)
	m := newSelfSigned(t, t.TempDir(), "127.0.0.1:8443", nil, fake)

	st := m.Status(ctx)
	if !st.Ready || st.Warn || st.Detail != "" {
		t.Fatalf("fresh status = %+v", st)
	}
	if !st.NotAfter.Equal(testTime.Add(selfSignedValidity)) || st.ExpiresIn != selfSignedValidity {
		t.Fatalf("status expiry = %v (%v)", st.NotAfter, st.ExpiresIn)
	}
	if st.Fingerprint != m.Fingerprint() {
		t.Fatalf("status fingerprint %q, want %q", st.Fingerprint, m.Fingerprint())
	}
	if err := m.Ready(ctx); err != nil {
		t.Fatalf("Ready: %v", err)
	}

	// Below 14 days readiness stays true but warns.
	fake.Advance(selfSignedValidity - 12*24*time.Hour)
	st = m.Status(ctx)
	if !st.Ready || !st.Warn {
		t.Fatalf("status with 12 days left = %+v", st)
	}
	if !strings.Contains(st.Detail, "expires in 12 days") {
		t.Fatalf("status detail = %q", st.Detail)
	}
	if err := m.Ready(ctx); err != nil {
		t.Fatalf("Ready with 12 days left: %v", err)
	}

	// Expired: /readyz must fail with UNAVAILABLE.
	fake.Advance(13 * 24 * time.Hour)
	st = m.Status(ctx)
	if st.Ready {
		t.Fatalf("expired certificate reported ready: %+v", st)
	}
	err := m.Ready(ctx)
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Ready on an expired certificate = %v", err)
	}
	if !strings.Contains(problem.From(err).Detail, "expired") {
		t.Fatalf("readiness detail = %q", problem.From(err).Detail)
	}
}

func TestProxyMode(t *testing.T) {
	ctx := context.Background()
	m, err := New(Options{
		TLS:     config.TLS{Mode: config.TLSProxy},
		Listen:  "127.0.0.1:8443",
		DataDir: t.TempDir(),
		Clock:   clock.NewFake(testTime),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.Mode() != config.TLSProxy {
		t.Fatalf("Mode = %q", m.Mode())
	}
	if cfg := m.TLSConfig(); cfg != nil {
		t.Fatalf("proxy mode returned a TLS config: %+v", cfg)
	}
	if fp := m.Fingerprint(); fp != "" {
		t.Fatalf("proxy mode fingerprint = %q", fp)
	}
	st := m.Status(ctx)
	if !st.Ready || st.Fingerprint != "" || !st.NotAfter.IsZero() {
		t.Fatalf("proxy status = %+v", st)
	}
	if !strings.Contains(st.Detail, "reverse proxy") {
		t.Fatalf("proxy detail = %q", st.Detail)
	}

	called := false
	h := m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || rec.Code != http.StatusNoContent {
		t.Fatalf("proxy HTTPHandler did not pass the request through: called=%v code=%d", called, rec.Code)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	if _, err := New(Options{TLS: config.TLS{Mode: "bogus"}, DataDir: t.TempDir()}); err == nil {
		t.Fatal("New accepted an unknown TLS mode")
	}
	if _, err := New(Options{TLS: config.TLS{Mode: config.TLSSelfSigned}}); err == nil {
		t.Fatal("New accepted an empty data directory")
	}
	if _, err := New(Options{TLS: config.TLS{Mode: config.TLSACME}, DataDir: t.TempDir()}); err == nil {
		t.Fatal("New accepted acme mode without domains")
	}
	if _, err := New(Options{
		TLS:     config.TLS{Mode: config.TLSSelfSigned},
		Listen:  "not-a-host-port",
		DataDir: t.TempDir(),
	}); err == nil {
		t.Fatal("New accepted a listen address without a port")
	}
}

func TestACMEConfiguration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	m, err := New(Options{
		TLS: config.TLS{
			Mode:         config.TLSACME,
			Domains:      []string{"Panel.Example.com", "www.example.com."},
			Email:        "ops@example.com",
			DirectoryURL: "https://acme-staging.example.com/directory",
		},
		Listen:  "0.0.0.0:443",
		DataDir: dir,
		Clock:   clock.NewFake(testTime),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !slices.Equal(m.acmeDomains, []string{"panel.example.com", "www.example.com"}) {
		t.Fatalf("domains = %v", m.acmeDomains)
	}

	info, err := os.Stat(filepath.Join(dir, "acme"))
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if got := info.Mode().Perm(); got != privateDirMode {
		t.Fatalf("ACME cache mode %04o, want 0700", got)
	}

	// Only configured domains may be requested, folded and without a trailing
	// dot, exactly as ACME SNI arrives.
	policy := m.acme.HostPolicy
	if policy == nil {
		t.Fatal("no host policy was installed")
	}
	for _, host := range []string{"panel.example.com", "PANEL.EXAMPLE.COM", "www.example.com."} {
		if err := policy(ctx, host); err != nil {
			t.Fatalf("host policy rejected the configured host %q: %v", host, err)
		}
	}
	for _, host := range []string{"evil.example.com", "", "example.com", "panel.example.com.evil.test"} {
		if err := policy(ctx, host); err == nil {
			t.Fatalf("host policy accepted %q", host)
		}
	}

	if m.acme.Email != "ops@example.com" {
		t.Fatalf("email = %q", m.acme.Email)
	}
	if m.acme.Client == nil || m.acme.Client.DirectoryURL != "https://acme-staging.example.com/directory" {
		t.Fatalf("directory URL not applied: %+v", m.acme.Client)
	}

	cfg := m.TLSConfig()
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatal("acme mode returned an unusable TLS config")
	}
	if !slices.Contains(cfg.NextProtos, "acme-tls/1") {
		t.Fatalf("NextProtos = %v, want the TLS-ALPN-01 protocol", cfg.NextProtos)
	}
	if !slices.Contains(cfg.NextProtos, "h2") {
		t.Fatalf("NextProtos = %v, want HTTP/2", cfg.NextProtos)
	}

	// HTTP-01: challenge paths may be answered, everything else goes to the
	// application handler.
	called := false
	h := m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	if !called || rec.Code != http.StatusTeapot {
		t.Fatalf("non-challenge request did not reach the application: called=%v code=%d", called, rec.Code)
	}

	// No certificate has been issued, and nothing in this test contacted the
	// directory: readiness says so instead of pretending.
	st := m.Status(ctx)
	if st.Ready {
		t.Fatalf("acme status before issuance = %+v", st)
	}
	if !strings.Contains(st.Detail, "issued yet") {
		t.Fatalf("acme detail = %q", st.Detail)
	}
	if !problem.HasCode(m.Ready(ctx), problem.Unavailable) {
		t.Fatalf("Ready before issuance = %v", m.Ready(ctx))
	}
}
