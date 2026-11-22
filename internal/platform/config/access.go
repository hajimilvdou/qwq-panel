// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Disguise modes served when a caller hits the panel port without a valid
// secret entry path (and without a valid entry-gate cookie).
const (
	// DisguiseDrop aborts/resets the TCP/HTTP2 connection with zero HTTP bytes
	// and zero headers — indistinguishable in browser & DevTools F12 from a
	// closed/unserved port.
	DisguiseDrop = "drop"
	// DisguiseNginx404 returns a stock Nginx 404 page with zero qwq headers.
	DisguiseNginx404 = "nginx_404"
	// DisguiseNginx403 returns a stock Nginx 403 page with zero qwq headers.
	DisguiseNginx403 = "nginx_403"
	// DisguiseBlank404 returns an empty-body 404 with zero qwq headers.
	DisguiseBlank404 = "blank_404"
	// DisguiseCustomHTML returns the operator-configured HTML with zero qwq headers.
	DisguiseCustomHTML = "custom_html"
)

// MaxDisguiseHTMLBytes bounds custom disguise HTML payload size (64 KiB).
const MaxDisguiseHTMLBytes = 64 << 10

var entryPathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{3,47}$`)

var reservedEntryPaths = map[string]bool{
	"api":       true,
	"assets":    true,
	"plugin-ui": true,
	"p":         true,
	"healthz":   true,
	"readyz":    true,
	"setup":     true,
	"login":     true,
	"enroll":    true,
	"settings":  true,
	"apps":      true,
	"activity":  true,
	"agent":     true,
	"plugins":   true,
	"favicon":   true,
	"robots":    true,
}

// NormalizeEntryPath trims whitespace and leading/trailing slashes.
func NormalizeEntryPath(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "/")
	return s
}

// ValidateEntryPath validates an optional secret entry path ("" disables it).
func ValidateEntryPath(raw string) (string, error) {
	p := NormalizeEntryPath(raw)
	if p == "" {
		return "", nil
	}
	if strings.Contains(p, "/") {
		return "", errors.New("must be a single path segment without '/'")
	}
	if !entryPathPattern.MatchString(p) {
		return "", errors.New("must be 4-48 characters of [A-Za-z0-9_-] starting with a letter or digit")
	}
	if reservedEntryPaths[strings.ToLower(p)] {
		return "", fmt.Errorf("%q is a reserved panel route prefix", p)
	}
	return p, nil
}

// NormalizeDisguise maps empty to DisguiseDrop and validates the mode.
func NormalizeDisguise(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	if d == "" {
		return DisguiseDrop, nil
	}
	switch d {
	case DisguiseDrop, DisguiseNginx404, DisguiseNginx403, DisguiseBlank404, DisguiseCustomHTML:
		return d, nil
	default:
		return "", fmt.Errorf("unknown disguise mode %q (want drop, nginx_404, nginx_403, blank_404 or custom_html)", raw)
	}
}

// NormalizePanelDomain accepts either a bare domain ("panel.example.com") or an
// http(s) URL ("https://panel.example.com") and returns the lowercase DNS name.
// Empty string clears the panel domain.
func NormalizePanelDomain(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", errors.New("must be a valid domain name or https://domain URL")
		}
		if u.Path != "" && u.Path != "/" {
			return "", errors.New("must not contain a URL path")
		}
		s = u.Hostname()
	} else if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if !validDomain(s) {
		return "", fmt.Errorf("%q is not a valid DNS domain name", raw)
	}
	return s, nil
}

// GenerateRandomEntryPath returns a cryptographically random 10-character
// lowercase alphanumeric secret entry path (e.g. "k8m4x2p9qv").
func GenerateRandomEntryPath() (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	const length = 10
	out := make([]byte, length)
	maxIdx := big.NewInt(int64(len(alphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, maxIdx)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

// AutoDisableEnabled reports whether reverse-proxy domain auto-disable is on
// (defaults to true when omitted).
func (h HTTP) AutoDisableEnabled() bool {
	return h.AutoDisableOnDomain == nil || *h.AutoDisableOnDomain
}

// DomainAutoBypassReason reports why the secret entry path & disguise are
// automatically disabled for reverse-proxy / domain access ("" when NOT bypassed).
func (h HTTP) DomainAutoBypassReason() string {
	if !h.AutoDisableEnabled() {
		return ""
	}
	if h.TLS.Mode == TLSProxy {
		return "tls_proxy"
	}
	if strings.TrimSpace(h.PanelDomain) != "" {
		return "panel_domain"
	}
	for _, o := range h.PublicOrigins {
		if u, err := url.Parse(o); err == nil {
			host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
			if host != "" && host != "localhost" {
				if _, ipErr := netip.ParseAddr(host); ipErr != nil {
					return "public_origin"
				}
			}
		}
	}
	return ""
}

// EffectiveEntryPath returns the normalized secret entry path when active, or
// "" when disabled or automatically bypassed by a reverse-proxy domain.
func (h HTTP) EffectiveEntryPath() string {
	if h.DomainAutoBypassReason() != "" {
		return ""
	}
	return NormalizeEntryPath(h.EntryPath)
}

// ListenPort parses the numeric TCP port from h.Listen.
func (h HTTP) ListenPort() (int, error) {
	_, portStr, err := net.SplitHostPort(h.Listen)
	if err != nil {
		return 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", portStr)
	}
	return p, nil
}

// WithListenPort returns a copy of Listen with the same host and a new port.
func WithListenPort(listen string, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %d", port)
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
