// SPDX-License-Identifier: AGPL-3.0-only

// Package config loads the host's bootstrap configuration.
//
// The file (/etc/qwq/qwq.json by default) holds only what is needed before the
// database opens: role, directories, listener, TLS mode and logging. Everything
// else is a setting in the database, changed through operations like any other
// resource (ADR-0004 D1). Decoding is strict: unknown fields, duplicate
// documents and invalid values are errors, so a typo never silently falls back
// to a default.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultPath is where installers write the file.
const DefaultPath = "/etc/qwq/qwq.json"

// maxFileSize bounds the bootstrap file; it is small by design.
const maxFileSize = 1 << 20

// Roles (ARCH §3.1). The first release supports standalone only (ADR-0005 Q8).
const (
	RoleStandalone = "standalone"
	RoleController = "controller"
	RoleAgent      = "agent"
)

// TLS modes (ADR-0005 Q6).
const (
	TLSSelfSigned = "self_signed"
	TLSACME       = "acme"
	TLSProxy      = "proxy" // TLS terminates at a reverse proxy; listen on loopback only
)

// ACMEPort is the only port the listener may use in mode "acme". The listener
// answers TLS-ALPN-01 only, and the certificate authority always validates that
// challenge on port 443 of the domain (RFC 8737 §3); on any other port no
// certificate is ever issued and /readyz never turns ready.
const ACMEPort = 443

// CoexistenceDoc is the guide for hosts whose ports 80/443 already belong to a
// web server (BaoTa and similar panels). Errors and doctor fixes point at it.
const CoexistenceDoc = "docs/operations/coexistence-baota.md"

// Config is the bootstrap configuration.
type Config struct {
	Role    string `json:"role"`
	DataDir string `json:"data_dir"`
	RunDir  string `json:"run_dir"`
	HTTP    HTTP   `json:"http"`
	Log     Log    `json:"log"`
	Agent   Agent  `json:"agent"`
	// Retention bounds how long the host keeps records (OPS-05). It is bootstrap
	// configuration because the sweeper starts with the database, before any
	// setting could be read from it.
	Retention Retention `json:"retention"`
}

// Retention is how long a record is kept after it is no longer current. Values
// are a day count with a "d" suffix (90d) or a Go duration (2160h).
type Retention struct {
	// Operations is how long a finished operation keeps its row, attempts and
	// approvals.
	Operations string `json:"operations"`
	// Audit is how long an audit row is kept.
	Audit string `json:"audit"`
	// Sessions is how long a session row is kept after it expired or was revoked.
	Sessions string `json:"sessions"`
}

// RetentionWindows are the parsed retention durations.
type RetentionWindows struct {
	Operations time.Duration
	Audit      time.Duration
	Sessions   time.Duration
}

// Windows parses the three retention values. Validate rejects a value this
// cannot parse, so a configuration that passed it always yields windows.
func (r Retention) Windows() (RetentionWindows, error) {
	var w RetentionWindows
	for _, f := range []struct {
		name  string
		value string
		dst   *time.Duration
	}{
		{"operations", r.Operations, &w.Operations},
		{"audit", r.Audit, &w.Audit},
		{"sessions", r.Sessions, &w.Sessions},
	} {
		d, err := parseRetention(f.value)
		if err != nil {
			return RetentionWindows{}, fmt.Errorf("retention.%s: %w", f.name, err)
		}
		*f.dst = d
	}
	return w, nil
}

// parseRetention reads a day count ("90d") or a Go duration ("2160h"). Zero and
// negative windows are refused: they would delete records the moment they are
// written.
func parseRetention(v string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 {
			return 0, fmt.Errorf("%q is not a positive day count", v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration", v)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q must be positive", v)
	}
	return d, nil
}

// Agent configures the native agent sessions.
type Agent struct {
	// ModelEgressAllow opens private destinations for the sessions' model
	// endpoints, for a local model such as Ollama. Each entry is a CIDR or
	// host:port, where host is an IP address or localhost. Only the
	// administrator can set it; a session owner cannot widen it.
	ModelEgressAllow []string `json:"model_egress_allow,omitempty"`
}

// ParseEgressAllow splits ModelEgressAllow entries into CIDRs and single
// destinations. localhost stands for both loopback addresses.
func ParseEgressAllow(entries []string) ([]netip.Prefix, []netip.AddrPort, error) {
	var (
		prefixes []netip.Prefix
		addrs    []netip.AddrPort
	)
	for _, entry := range entries {
		if p, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		host, portText, err := net.SplitHostPort(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("%q is neither a CIDR nor host:port", entry)
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, nil, fmt.Errorf("%q has an invalid port", entry)
		}
		if host == "localhost" {
			addrs = append(addrs,
				netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port)),
				netip.AddrPortFrom(netip.IPv6Loopback(), uint16(port)))
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, nil, fmt.Errorf("%q: host must be an IP address or localhost", entry)
		}
		addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
	}
	return prefixes, addrs, nil
}

// HTTP configures the management listener.
type HTTP struct {
	// Listen is host:port. The default binds loopback only: first-time setup
	// happens over an SSH tunnel or the one-time setup link (ARCH §4.1.1).
	Listen string `json:"listen"`
	TLS    TLS    `json:"tls"`
	// PublicOrigins are the https origins users reach the panel at, used for
	// Origin/Host checks and links. Empty = derived from the listener or the
	// ACME domains.
	PublicOrigins []string `json:"public_origins,omitempty"`
	// TrustedProxies are the addresses or CIDRs whose X-Forwarded-For is trusted.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
}

// Loopback reports whether the listener binds a loopback address only: the
// panel is then reached through an SSH tunnel or a reverse proxy on the same
// host, and no firewall port has to be opened for it.
func (h HTTP) Loopback() bool {
	host, _, err := net.SplitHostPort(h.Listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// TLS selects how the listener gets its certificate.
type TLS struct {
	Mode string `json:"mode"`
	// ACME only; the mode also requires http.listen on port ACMEPort.
	Domains      []string `json:"domains,omitempty"`
	Email        string   `json:"email,omitempty"`
	DirectoryURL string   `json:"directory_url,omitempty"` // default: Let's Encrypt production
}

// Log configures the host logger.
type Log struct {
	Level  string `json:"level"`  // debug | info | warn | error
	Format string `json:"format"` // json | text
}

// Default returns the configuration used for fields the file omits.
func Default() Config {
	return Config{
		Role:    RoleStandalone,
		DataDir: "/var/lib/qwq",
		RunDir:  "/run/qwq",
		HTTP: HTTP{
			Listen: "127.0.0.1:8443",
			TLS:    TLS{Mode: TLSSelfSigned},
		},
		Log: Log{Level: "info", Format: "json"},
		Retention: Retention{
			Operations: "90d",
			Audit:      "365d",
			Sessions:   "30d",
		},
	}
}

// Load reads, decodes and validates the file at path. A missing file is an
// error; callers that allow running with defaults check os.ErrNotExist.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > maxFileSize {
		return Config{}, fmt.Errorf("%s: larger than %d bytes", path, maxFileSize)
	}
	c, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse decodes data over the defaults and validates the result.
func Parse(data []byte) (Config, error) {
	c := Default()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return Config{}, errors.New("decode: unexpected data after the JSON object")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks every field and returns all problems at once.
func (c Config) Validate() error {
	var errs []error
	bad := func(field, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...)))
	}

	switch c.Role {
	case RoleStandalone:
	case RoleController, RoleAgent:
		bad("role", "%q is not available in this release; use %q", c.Role, RoleStandalone)
	default:
		bad("role", "unknown role %q", c.Role)
	}
	checkDir := func(field, dir string) {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
			bad(field, "must be a clean absolute path other than /")
		}
	}
	checkDir("data_dir", c.DataDir)
	checkDir("run_dir", c.RunDir)

	host, port, err := net.SplitHostPort(c.HTTP.Listen)
	var listenPort int // stays 0 when the port is invalid, so it is reported once
	if err != nil {
		bad("http.listen", "must be host:port")
	} else {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			bad("http.listen", "invalid port %q", port)
		} else {
			listenPort = p
		}
		if host == "" {
			bad("http.listen", "host is required; use 0.0.0.0 or :: to listen on all interfaces")
		} else if _, err := netip.ParseAddr(host); err != nil && host != "localhost" {
			bad("http.listen", "host must be an IP address or localhost")
		}
	}

	for i, p := range c.HTTP.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				bad(fmt.Sprintf("http.trusted_proxies[%d]", i), "not an IP address or CIDR")
			}
		}
	}
	for i, o := range c.HTTP.PublicOrigins {
		if err := checkOrigin(o); err != nil {
			bad(fmt.Sprintf("http.public_origins[%d]", i), "%v", err)
		}
	}

	t := c.HTTP.TLS
	switch t.Mode {
	case TLSSelfSigned:
		if len(t.Domains) > 0 || t.Email != "" || t.DirectoryURL != "" {
			bad("http.tls", "domains, email and directory_url apply to mode %q only", TLSACME)
		}
	case TLSACME:
		// Refuse to start rather than serve a listener that can never get its
		// certificate. Next to a web server that owns 443 the working modes are
		// "proxy" behind it or "self_signed" on a free port.
		if listenPort != 0 && listenPort != ACMEPort {
			bad("http.listen", "mode %q requires port %d, got %d: the certificate authority validates the domain on port %d only; "+
				"when another web server (BaoTa, nginx) owns that port, use mode %q behind it or mode %q on this port, see %s",
				TLSACME, ACMEPort, listenPort, ACMEPort, TLSProxy, TLSSelfSigned, CoexistenceDoc)
		}
		if len(t.Domains) == 0 {
			bad("http.tls.domains", "required for mode %q", TLSACME)
		}
		for i, d := range t.Domains {
			if !validDomain(d) {
				bad(fmt.Sprintf("http.tls.domains[%d]", i), "not a DNS name (IP-only hosts use mode %q)", TLSSelfSigned)
			}
		}
		if t.Email != "" && !strings.Contains(t.Email, "@") {
			bad("http.tls.email", "not an email address")
		}
		if t.DirectoryURL != "" {
			if u, err := url.Parse(t.DirectoryURL); err != nil || u.Scheme != "https" || u.Host == "" {
				bad("http.tls.directory_url", "must be an https URL")
			}
		}
	case TLSProxy:
		if err == nil && !c.HTTP.Loopback() {
			bad("http.listen", "mode %q requires a loopback address; the proxy terminates TLS", TLSProxy)
		}
		if len(c.HTTP.TrustedProxies) == 0 {
			bad("http.trusted_proxies", "required for mode %q", TLSProxy)
		}
		if len(t.Domains) > 0 || t.Email != "" || t.DirectoryURL != "" {
			bad("http.tls", "domains, email and directory_url apply to mode %q only", TLSACME)
		}
	default:
		bad("http.tls.mode", "must be %q, %q or %q", TLSSelfSigned, TLSACME, TLSProxy)
	}

	if _, _, err := ParseEgressAllow(c.Agent.ModelEgressAllow); err != nil {
		bad("agent.model_egress_allow", "%v", err)
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		bad("log.level", "must be debug, info, warn or error")
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		bad("log.format", "must be json or text")
	}

	if _, err := c.Retention.Windows(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func checkOrigin(o string) error {
	u, err := url.Parse(o)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an https origin such as https://panel.example.com:8443")
	}
	return nil
}

// validDomain accepts LDH names with at least two labels; it rejects IP literals.
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || strings.HasSuffix(d, ".") {
		return false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
