// SPDX-License-Identifier: AGPL-3.0-only

// Package tlsmgr obtains, renews and serves the certificate of the management
// listener (P1-T9; ARCH §4.1.1, ADR-0005 Q6).
//
// The mode comes from config.HTTP.TLS.Mode:
//
//   - self_signed: an ECDSA P-256 certificate generated on first start and kept
//     in dataDir/tls, covering the listener address, localhost, the loopback
//     addresses and the hosts of http.public_origins. It is replaced when less
//     than 30 days remain or when the configured names are no longer covered,
//     and its SHA-256 fingerprint stays the same across restarts, so the
//     installer can print it for the operator to compare with the browser.
//   - acme: certificates from an ACME directory (Let's Encrypt, or a staging URL)
//     through x/crypto/acme/autocert, cached in dataDir/acme. TLS-ALPN-01 is
//     answered by GetCertificate and HTTP-01 by HTTPHandler; only the configured
//     domains are allowed. Nothing contacts the network until the first
//     handshake or challenge. No listener mounts HTTPHandler yet, so TLS-ALPN-01
//     is the only challenge answered and config.Validate requires the listener
//     on config.ACMEPort.
//   - proxy: TLS is terminated by a reverse proxy. TLSConfig returns nil and the
//     gateway trusts only http.trusted_proxies.
//
// TLSConfig returns a configuration with TLS 1.2 as the floor, AEAD-only cipher
// suites, X25519 first and HTTP/2 in ALPN. Certificates are read from an atomic
// pointer, so Reload and renewals never interrupt established connections.
package tlsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const (
	// selfSignedValidity stays just under the 398 days browsers accept.
	selfSignedValidity = 397 * 24 * time.Hour
	// renewBefore is when a self-signed certificate is replaced.
	renewBefore = 30 * 24 * time.Hour
	// warnBefore is when readiness reports a certificate that expires soon.
	warnBefore = 14 * 24 * time.Hour
	// defaultCheckEvery is how often Maintain re-checks the certificate.
	defaultCheckEvery = 6 * time.Hour
	// clockSkew backdates NotBefore for clients whose clock is slow.
	clockSkew = time.Hour
)

// Options configure New.
type Options struct {
	// TLS is config.HTTP.TLS: mode, domains, email and directory URL.
	TLS config.TLS
	// Listen is the management listener host:port; the self-signed certificate
	// covers its host.
	Listen string
	// PublicOrigins is config.HTTP.PublicOrigins; their hosts join the SANs.
	PublicOrigins []string
	// DataDir holds tls/ and acme/; normally config.DataDir.
	DataDir string
	// Clock is the time source for validity and renewal decisions.
	Clock clock.Clock
	// Logger receives certificate events. Fingerprints and host names only.
	Logger *slog.Logger
	// CheckEvery overrides defaultCheckEvery; short values are for tests.
	CheckEvery time.Duration
	// LocalAddrs overrides the interface enumeration used when the listener
	// binds 0.0.0.0 or ::; tests inject it to get a stable certificate.
	LocalAddrs func() ([]net.Addr, error)
}

// Manager owns the listener's certificate and its rotation.
type Manager struct {
	mode    string
	dataDir string
	// dir is dataDir/tls for self_signed and dataDir/acme for acme.
	dir     string
	listen  string
	origins []string
	sans    sanSet
	clock   clock.Clock
	log     *slog.Logger
	addrs   func() ([]net.Addr, error)
	check   time.Duration

	// mu serializes generation, renewal and Reload; current publishes the
	// certificate to concurrent handshakes.
	mu      sync.Mutex
	current atomic.Pointer[cert]

	acme        *autocert.Manager
	acmeDomains []string
	acmeCache   autocert.Cache
}

// cert is a loaded certificate with its cached fingerprint.
type cert struct {
	pair *tls.Certificate
	leaf *x509.Certificate
	fp   string
}

// New prepares the certificate for the configured mode. In self_signed mode it
// loads the stored certificate or generates one, so the listener has a
// certificate before it accepts its first connection; acme mode performs no
// network call.
func New(o Options) (*Manager, error) {
	if o.DataDir == "" {
		return nil, errors.New("tlsmgr: a data directory is required")
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.CheckEvery <= 0 {
		o.CheckEvery = defaultCheckEvery
	}
	if o.LocalAddrs == nil {
		o.LocalAddrs = net.InterfaceAddrs
	}
	m := &Manager{
		mode:    o.TLS.Mode,
		dataDir: o.DataDir,
		listen:  o.Listen,
		origins: append([]string(nil), o.PublicOrigins...),
		clock:   o.Clock,
		log:     o.Logger,
		addrs:   o.LocalAddrs,
		check:   o.CheckEvery,
	}
	switch o.TLS.Mode {
	case config.TLSSelfSigned:
		sans, err := requiredSANs(o.Listen, o.PublicOrigins, o.LocalAddrs)
		if err != nil {
			return nil, err
		}
		m.sans = sans
		m.dir = filepath.Join(o.DataDir, "tls")
		if err := m.ensureSelfSigned(); err != nil {
			return nil, err
		}
	case config.TLSACME:
		if err := m.setupACME(o.TLS); err != nil {
			return nil, err
		}
	case config.TLSProxy:
	default:
		return nil, fmt.Errorf("tlsmgr: unknown TLS mode %q", o.TLS.Mode)
	}
	return m, nil
}

// Mode returns config.HTTP.TLS.Mode the manager was built for.
func (m *Manager) Mode() string { return m.mode }

// TLSConfig returns the listener configuration, or nil in proxy mode where the
// reverse proxy terminates TLS.
func (m *Manager) TLSConfig() *tls.Config {
	if m.mode == config.TLSProxy {
		return nil
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// AEAD only, all with ephemeral key exchange: no CBC, RC4, 3DES or
		// static RSA. AES-GCM is preferred where AES is accelerated (x86 with
		// AES-NI), ChaCha20 covers ARM hosts without it. TLS 1.3 suites are
		// built in and not configurable.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		NextProtos:       m.nextProtos(),
		GetCertificate:   m.GetCertificate,
		// The panel is a TLS server only; client-initiated renegotiation is a
		// known DoS vector and never needed here.
		Renegotiation: tls.RenegotiateNever,
	}
}

// nextProtos lists ALPN protocols: HTTP/2 first, then HTTP/1.1, and the ACME
// TLS-ALPN-01 protocol when the manager answers challenges.
func (m *Manager) nextProtos() []string {
	if m.acme != nil {
		return []string{"h2", "http/1.1", acme.ALPNProto}
	}
	return []string{"h2", "http/1.1"}
}

// GetCertificate serves the current certificate. In acme mode it hands the
// handshake to autocert, which also answers TLS-ALPN-01 challenges.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.acme != nil {
		return m.acme.GetCertificate(hello)
	}
	c := m.current.Load()
	if c == nil {
		return nil, errors.New("tlsmgr: no certificate is loaded")
	}
	return c.pair, nil
}

// Fingerprint returns the SHA-256 of the served certificate as colon-separated
// upper-case hex, the form the installer prints and browsers display. It is
// empty in proxy mode and in acme mode before a certificate is cached; for
// acme, Status reports the fingerprint of the cached certificate.
func (m *Manager) Fingerprint() string {
	c := m.current.Load()
	if c == nil {
		return ""
	}
	return c.fp
}

// SetListen updates the listener host:port for self-signed certificate SAN
// coverage (for example when the operator hot-switches from 127.0.0.1 to
// 0.0.0.0 or ::, or on startup after reading SQLite panel_access_settings).
// Existing certificates that already cover the required SANs and remain fresh
// are kept unchanged so their fingerprint stays stable. It is a no-op outside
// self_signed mode.
func (m *Manager) SetListen(listen string) error {
	if m == nil || m.mode != config.TLSSelfSigned {
		return nil
	}
	nextSANs, err := requiredSANs(listen, m.origins, m.addrs)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listen = listen
	m.sans = nextSANs
	return m.ensureSelfSignedLocked()
}

// Reload re-reads the self-signed certificate from disk and swaps it in without
// interrupting established connections. Operators use it after replacing the
// files by hand; renewals do the same thing internally. It is a no-op in acme
// and proxy mode.
func (m *Manager) Reload() error {
	if m.mode != config.TLSSelfSigned {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := loadSelfSigned(m.dir, m.log)
	if err != nil {
		return err
	}
	m.current.Store(c)
	m.log.Info("tls: certificate reloaded from disk", "fingerprint", c.fp,
		"not_after", c.leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// Maintain checks the certificate every CheckEvery until ctx ends and renews it
// when needed. Run it in one goroutine for the life of the process; in acme mode
// it only reports an expiry warning, because autocert renews on handshake.
func (m *Manager) Maintain(ctx context.Context) {
	timer := m.clock.After(m.check)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer:
		}
		if m.mode == config.TLSSelfSigned {
			if err := m.ensureSelfSigned(); err != nil {
				m.log.ErrorContext(ctx, "tls: self-signed certificate check failed", "error", err)
			}
		} else if m.mode == config.TLSACME && m.acme != nil {
			for _, domain := range m.acmeDomains {
				leaf, _, err := m.cachedLeaf(ctx, domain)
				if err != nil {
					continue
				}
				if leaf.NotAfter.Sub(m.clock.Now()) < 30*24*time.Hour {
					go func(dom string) {
						if _, rErr := m.acme.GetCertificate(&tls.ClientHelloInfo{ServerName: dom}); rErr != nil {
							m.log.WarnContext(ctx, "tls: proactive ACME pre-renewal failed", "domain", dom, "error", rErr)
						}
					}(domain)
				}
			}
		}
		if st := m.Status(ctx); st.Warn {
			m.log.WarnContext(ctx, "tls: certificate expires soon", "mode", st.Mode,
				"not_after", st.NotAfter.Format(time.RFC3339), "expires_in_days", int(st.ExpiresIn.Hours()/24))
		}
		timer = m.clock.After(m.check)
	}
}

// Status describes the certificate for /readyz and host health (ARCH §12).
type Status struct {
	Mode        string
	Ready       bool
	Warn        bool
	NotAfter    time.Time
	ExpiresIn   time.Duration
	Fingerprint string
	Detail      string
}

// Err returns nil when the listener can serve TLS, otherwise UNAVAILABLE with a
// short detail for the problem document.
func (s Status) Err() error {
	if s.Ready {
		return nil
	}
	return &problem.Error{Code: problem.Unavailable, Detail: s.Detail}
}

// Status reports whether the listener has a usable certificate. In acme mode it
// reads the certificate cache, so it is cheap but not free; call it from the
// readiness probe rather than from every request.
func (m *Manager) Status(ctx context.Context) Status {
	st := Status{Mode: m.mode}
	switch m.mode {
	case config.TLSProxy:
		st.Ready = true
		st.Detail = "TLS is terminated by a reverse proxy."
		return st
	case config.TLSSelfSigned:
		c := m.current.Load()
		if c == nil {
			st.Detail = "No TLS certificate is loaded."
			return st
		}
		return describeCert(st, c.leaf, m.clock.Now(), c.fp)
	case config.TLSACME:
		return m.acmeStatus(ctx, st)
	}
	st.Detail = "The TLS mode is not configured."
	return st
}

// Ready is the readiness predicate the gateway's /readyz uses.
func (m *Manager) Ready(ctx context.Context) error { return m.Status(ctx).Err() }

// describeCert fills a status from one certificate.
func describeCert(st Status, leaf *x509.Certificate, now time.Time, fp string) Status {
	st.NotAfter = leaf.NotAfter.UTC()
	st.Fingerprint = fp
	st.ExpiresIn = leaf.NotAfter.Sub(now)
	switch {
	case !now.Before(leaf.NotAfter):
		st.Detail = "The TLS certificate expired at " + st.NotAfter.Format(time.RFC3339) + "."
		return st
	case leaf.NotBefore.After(now.Add(clockSkew)):
		st.Detail = "The TLS certificate is not valid yet."
		return st
	}
	st.Ready = true
	if st.ExpiresIn < warnBefore {
		st.Warn = true
		st.Detail = fmt.Sprintf("The TLS certificate expires in %d days.", int(st.ExpiresIn.Hours()/24))
	}
	return st
}
