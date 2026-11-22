// SPDX-License-Identifier: AGPL-3.0-only

package tlsmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

// Files and modes of the self-signed certificate in dataDir/tls.
const (
	selfSignedCertFile = "self_signed.crt"
	selfSignedKeyFile  = "self_signed.key"
	privateDirMode     = 0o700
	certFileMode       = 0o644
	keyFileMode        = 0o600
)

// sanSet is the set of names a self-signed certificate must cover.
type sanSet struct {
	dns []string
	ips []netip.Addr
}

// addName records a DNS name; a value that parses as an IP address becomes an
// IP SAN instead, because a browser matches them differently.
func (s *sanSet) addName(name string) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		s.addIP(addr)
		return
	}
	if !slices.Contains(s.dns, name) {
		s.dns = append(s.dns, name)
	}
}

// addIP records an IP address.
func (s *sanSet) addIP(addr netip.Addr) {
	addr = addr.Unmap()
	if !addr.IsValid() || slices.Contains(s.ips, addr) {
		return
	}
	s.ips = append(s.ips, addr)
}

// sortedDNS returns the DNS names in a stable order.
func (s sanSet) sortedDNS() []string {
	out := slices.Clone(s.dns)
	sort.Strings(out)
	return out
}

// sortedIPs returns the addresses in a stable order.
func (s sanSet) sortedIPs() []netip.Addr {
	out := slices.Clone(s.ips)
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// ipList converts the addresses for x509.Certificate.
func (s sanSet) ipList() []net.IP {
	ips := s.sortedIPs()
	out := make([]net.IP, 0, len(ips))
	for _, addr := range ips {
		out = append(out, net.IP(addr.AsSlice()))
	}
	return out
}

// String lists the names for a log line.
func (s sanSet) String() string {
	names := s.sortedDNS()
	ips := s.sortedIPs()
	parts := make([]string, 0, len(names)+len(ips))
	parts = append(parts, names...)
	for _, addr := range ips {
		parts = append(parts, addr.String())
	}
	return strings.Join(parts, ",")
}

// covers reports whether leaf carries every name in the set. A certificate that
// is missing a configured host is replaced even when it is still valid.
func (s sanSet) covers(leaf *x509.Certificate) bool {
	have := make(map[string]bool, len(leaf.DNSNames)+len(leaf.IPAddresses))
	for _, name := range leaf.DNSNames {
		have[strings.ToLower(strings.TrimSuffix(name, "."))] = true
	}
	for _, ip := range leaf.IPAddresses {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			have[addr.Unmap().String()] = true
		}
	}
	for _, name := range s.dns {
		if !have[strings.ToLower(name)] {
			return false
		}
	}
	for _, addr := range s.ips {
		if !have[addr.String()] {
			return false
		}
	}
	return true
}

// requiredSANs collects the names a self-signed certificate must cover: the
// listener host (all local addresses when it binds 0.0.0.0 or ::), localhost,
// both loopback addresses and every public origin host.
func requiredSANs(listen string, origins []string, localAddrs func() ([]net.Addr, error)) (sanSet, error) {
	var s sanSet
	s.addName("localhost")
	s.addIP(netip.MustParseAddr("127.0.0.1"))
	s.addIP(netip.MustParseAddr("::1"))

	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return sanSet{}, fmt.Errorf("tlsmgr: listen address %q: %w", listen, err)
	}
	switch {
	case host == "":
		return sanSet{}, fmt.Errorf("tlsmgr: listen address %q has no host", listen)
	case host == "localhost":
		// Already covered.
	default:
		addr, err := netip.ParseAddr(host)
		switch {
		case err != nil:
			s.addName(host)
		case addr.IsUnspecified():
			addrs, err := localAddrs()
			if err != nil {
				return sanSet{}, fmt.Errorf("tlsmgr: enumerate local addresses: %w", err)
			}
			addLocalIPs(&s, addrs)
		default:
			s.addIP(addr)
		}
	}

	for i, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil {
			return sanSet{}, fmt.Errorf("tlsmgr: public origin %d is not a URL", i)
		}
		if u.Hostname() == "" {
			return sanSet{}, fmt.Errorf("tlsmgr: public origin %d has no host", i)
		}
		s.addName(u.Hostname())
	}
	sort.Strings(s.dns)
	return s, nil
}

// addLocalIPs adds the host's usable unicast addresses. Loopback is already in
// the set; unspecified, multicast and link-local addresses are skipped because
// browsers cannot reach them by name and DHCP or MAC changes would rotate the
// certificate, and its fingerprint, for nothing.
func addLocalIPs(s *sanSet, addrs []net.Addr) {
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			continue
		}
		s.addIP(addr)
	}
}

// generateSelfSigned returns the PEM encoded certificate and key. The leaf is
// self-signed, a CA (so a client can pin it as its own root) and valid for
// selfSignedValidity.
func generateSelfSigned(now time.Time, sans sanSet) (certPEM, keyPEM []byte, err error) {
	return generateSelfSignedValidity(now, sans, selfSignedValidity)
}

// generateSelfSignedValidity 共享相同密钥、SAN 与用途模板，只由宿主指定有效期。
func generateSelfSignedValidity(now time.Time, sans sanSet, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsmgr: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("tlsmgr: generate serial number: %w", err)
	}
	commonName := "qwq"
	if names := sans.sortedDNS(); len(names) > 0 {
		commonName = names[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"qwq"}},
		NotBefore:             now.Add(-clockSkew).UTC(),
		NotAfter:              now.Add(validity).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              sans.sortedDNS(),
		IPAddresses:           sans.ipList(),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsmgr: create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsmgr: marshal key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ensureSelfSigned loads the stored certificate, keeping it when it is fresh and
// covers the configured names, and generating a new one otherwise.
func (m *Manager) ensureSelfSigned() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := loadSelfSigned(m.dir, m.log)
	if err == nil {
		switch {
		case !m.sans.covers(c.leaf):
			m.log.Info("tls: certificate does not cover the configured names; replacing it",
				"fingerprint", c.fp, "names", m.sans.String())
		case !m.fresh(c.leaf):
			m.log.Info("tls: self-signed certificate expires soon; renewing",
				"fingerprint", c.fp, "not_after", c.leaf.NotAfter.UTC().Format(time.RFC3339))
		default:
			m.current.Store(c)
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		m.log.Warn("tls: stored certificate is unusable; generating a new one", "error", err)
	}
	return m.generate()
}

// fresh reports whether the certificate has more than renewBefore left.
func (m *Manager) fresh(leaf *x509.Certificate) bool {
	return m.clock.Now().Add(renewBefore).Before(leaf.NotAfter)
}

// generate writes a new certificate and key and publishes them. The caller holds
// m.mu.
func (m *Manager) generate() error {
	certPEM, keyPEM, err := generateSelfSigned(m.clock.Now(), m.sans)
	if err != nil {
		return err
	}
	if err := saveSelfSigned(m.dir, certPEM, keyPEM, m.log); err != nil {
		return err
	}
	// Read back what landed on disk: this validates the pair and makes the
	// published certificate the same bytes the next start will load.
	c, err := loadSelfSigned(m.dir, m.log)
	if err != nil {
		return err
	}
	m.current.Store(c)
	m.log.Info("tls: self-signed certificate generated", "fingerprint", c.fp,
		"names", m.sans.String(), "not_after", c.leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// loadSelfSigned reads and validates the stored certificate pair. The key file
// is tightened to 0600 when it was wider; a mismatch between key and certificate
// is an error, which makes the caller generate a new pair.
func loadSelfSigned(dir string, log *slog.Logger) (*cert, error) {
	certPath := filepath.Join(dir, selfSignedCertFile)
	keyPath := filepath.Join(dir, selfSignedKeyFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("tlsmgr: read certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("tlsmgr: read key: %w", err)
	}
	tightenFile(keyPath, keyFileMode, log)
	return parsePair(certPEM, keyPEM)
}

// saveSelfSigned stores the pair under dir, key first: a crash between the two
// renames leaves a mismatched pair, which loadSelfSigned rejects and the next
// start replaces.
func saveSelfSigned(dir string, certPEM, keyPEM []byte, log *slog.Logger) error {
	if err := ensurePrivateDir(dir, log); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, selfSignedKeyFile), keyPEM, keyFileMode); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, selfSignedCertFile), certPEM, certFileMode)
}

// SelfSignedFingerprint reads only the self-signed certificate under
// dataDir/tls (never the key) and returns its fingerprint, for offline tools
// that print it next to the setup link.
func SelfSignedFingerprint(dataDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, "tls", selfSignedCertFile))
	if err != nil {
		return "", fmt.Errorf("tlsmgr: read certificate: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("tlsmgr: certificate file holds no PEM certificate")
	}
	return fingerprint(block.Bytes), nil
}

// fingerprint returns the SHA-256 of a DER certificate as colon-separated
// upper-case hex, as printed by openssl and shown by browsers.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, len(sum)*3-1)
	for i, b := range sum {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

// ensurePrivateDir creates dir with mode 0700 and tightens an existing directory
// that is wider, logging the change when a logger is given.
func ensurePrivateDir(dir string, log *slog.Logger) error {
	if err := os.MkdirAll(dir, privateDirMode); err != nil {
		return fmt.Errorf("tlsmgr: create %s: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("tlsmgr: stat %s: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, privateDirMode); err != nil {
			return fmt.Errorf("tlsmgr: tighten %s: %w", dir, err)
		}
		if log != nil {
			log.Warn("tls: tightened a directory that group or others could access",
				"dir", dir, "old_mode", fmt.Sprintf("%04o", perm))
		}
	}
	return nil
}

// tightenFile removes group and other permissions from path.
func tightenFile(path string, perm os.FileMode, log *slog.Logger) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if old := info.Mode().Perm(); old&0o077 != 0 {
		if err := os.Chmod(path, perm); err == nil && log != nil {
			log.Warn("tls: tightened a key file that group or others could access",
				"path", path, "old_mode", fmt.Sprintf("%04o", old))
		}
	}
}

// writeFileAtomic replaces path via a temporary file in the same directory,
// fsync, rename and directory fsync, so a crash cannot leave a partial
// certificate or key.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("tlsmgr: create temporary file: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	fail := func(err error) error {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		return fail(fmt.Errorf("tlsmgr: set mode on %s: %w", tmp, err))
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("tlsmgr: write %s: %w", tmp, err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("tlsmgr: sync %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("tlsmgr: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("tlsmgr: replace %s: %w", path, err)
	}
	return fsyncDir(dir)
}

// fsyncDir makes a rename durable. Windows cannot fsync a directory handle, so
// the call is skipped there; the host itself only runs on Linux.
func fsyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("tlsmgr: open directory for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("tlsmgr: sync directory: %w", err)
	}
	return nil
}
