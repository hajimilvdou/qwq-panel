// SPDX-License-Identifier: AGPL-3.0-only

// Package panelaccess manages the panel's live listening port, secret entry
// path ("密道"), F12-proof stealth disguise, and automatic bypass when a
// reverse-proxy domain is configured.
package panelaccess

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// GateCookieName is the neutral HttpOnly cookie name granted only after a
// browser enters through the valid secret entry path.
const GateCookieName = "_g"

// DefaultCapabilityPanelPortFile is the runtime file read by qwq-capability's
// SystemGuard.ManagementPorts() to preserve the live panel port in firewall/sshd guards.
const DefaultCapabilityPanelPortFile = "/var/lib/qwq-capability/panel-port.json"

// Snapshot is an immutable point-in-time view of the panel's live access config.
type Snapshot struct {
	ListenHost          string
	Port                int
	TLSMode             string
	PublicOrigins       []string
	EntryPath           string
	Disguise            string
	DisguiseHTML        string
	PanelDomain         string
	AutoDisableOnDomain bool
	GateSecret          string
	Revision            int64
	UpdatedAt           time.Time
}

// ListenAddr returns host:port for the active listener.
func (s Snapshot) ListenAddr() string {
	return net.JoinHostPort(s.ListenHost, strconv.Itoa(s.Port))
}

// DomainAutoBypassReason reports why the secret entry path & disguise are
// automatically bypassed ("" when active).
func (s Snapshot) DomainAutoBypassReason() string {
	auto := s.AutoDisableOnDomain
	h := config.HTTP{
		Listen:              s.ListenAddr(),
		TLS:                 config.TLS{Mode: s.TLSMode},
		PublicOrigins:       s.PublicOrigins,
		EntryPath:           s.EntryPath,
		PanelDomain:         s.PanelDomain,
		AutoDisableOnDomain: &auto,
	}
	return h.DomainAutoBypassReason()
}

// EffectiveEntryPath returns the active secret entry path, or "" when disabled
// or automatically bypassed by a reverse-proxy domain.
func (s Snapshot) EffectiveEntryPath() string {
	if s.DomainAutoBypassReason() != "" {
		return ""
	}
	return config.NormalizeEntryPath(s.EntryPath)
}

// EntryGateActive reports whether requests without the secret entry path are
// gated and disguised.
func (s Snapshot) EntryGateActive() bool {
	return s.EffectiveEntryPath() != ""
}

// EffectiveDisguise returns the normalized disguise mode.
func (s Snapshot) EffectiveDisguise() string {
	d, err := config.NormalizeDisguise(s.Disguise)
	if err != nil {
		return config.DisguiseDrop
	}
	return d
}

// GateToken computes the expected HMAC-SHA256 cookie token for the current
// effective secret entry path. Rotating EntryPath immediately invalidates old cookies.
func (s Snapshot) GateToken() string {
	return s.GateTokenForPath(s.EffectiveEntryPath())
}

// GateTokenForPath computes the expected HMAC-SHA256 cookie token for rawEntry
// even when DomainAutoBypassReason is non-empty (so emergency bare-IP access via
// https://IP:Port/<rawEntry> still works cleanly).
func (s Snapshot) GateTokenForPath(rawEntry string) string {
	ep := config.NormalizeEntryPath(rawEntry)
	if ep == "" || s.GateSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(s.GateSecret))
	mac.Write([]byte("entry:"))
	mac.Write([]byte(ep))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidGateCookie verifies cookieVal in constant time against the effective entry path.
func (s Snapshot) ValidGateCookie(cookieVal string) bool {
	return s.ValidGateCookieForPath(s.EffectiveEntryPath(), cookieVal)
}

// ValidGateCookieForPath verifies cookieVal in constant time against rawEntry.
func (s Snapshot) ValidGateCookieForPath(rawEntry, cookieVal string) bool {
	want := s.GateTokenForPath(rawEntry)
	if want == "" || cookieVal == "" {
		return false
	}
	return hmac.Equal([]byte(want), []byte(cookieVal))
}

// SetGateCookie writes the HttpOnly gate cookie when the effective secret entry path is active.
func (s Snapshot) SetGateCookie(w http.ResponseWriter, secure bool) {
	s.SetGateCookieForPath(w, s.EffectiveEntryPath(), secure)
}

// SetGateCookieForPath writes the HttpOnly gate cookie for rawEntry.
func (s Snapshot) SetGateCookieForPath(w http.ResponseWriter, rawEntry string, secure bool) {
	tok := s.GateTokenForPath(rawEntry)
	if tok == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     GateCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 3600,
	})
}

// ClearGateCookie expires the HttpOnly gate cookie on logout.
func ClearGateCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     GateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	})
}

// NormalizeListenHost validates and canonicalizes a panel listener bind host.
// Supports 127.0.0.1, 0.0.0.0, ::1, ::, localhost, or any specific host unicast IP.
func NormalizeListenHost(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	if strings.EqualFold(h, "localhost") {
		return "127.0.0.1", nil
	}
	switch h {
	case "127.0.0.1", "0.0.0.0", "::1", "::":
		return h, nil
	default:
		ip, err := netip.ParseAddr(h)
		if err != nil || !ip.IsValid() || ip.IsMulticast() || ip.IsUnspecified() {
			return "", fmt.Errorf("不支持的监听地址 %q（支持 127.0.0.1、0.0.0.0、::1、:: 或具体网卡单播 IP）", raw)
		}
		return ip.String(), nil
	}
}

func isLoopbackListenHost(h string) bool {
	if h == "127.0.0.1" || h == "::1" || strings.EqualFold(h, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil && ip.Unmap().IsLoopback()
}

// UpdateInput carries the desired live access configuration from PUT /api/v1/system/access.
type UpdateInput struct {
	ListenHost              *string
	Port                    *int
	EntryPath               *string
	GenerateRandomEntryPath bool
	Disguise                *string
	DisguiseHTML            *string
	PanelDomain             *string
	AutoDisableOnDomain     *bool
	ExpectedRevision        *int64
	// AuditTx optionally runs inside the same SQLite write transaction after updating panel_access_settings.
	AuditTx func(ctx context.Context, tx *storage.Tx, next Snapshot, portChanged bool) error
}

// BindHandle represents a two-phase TCP listener pre-bind returned by PrepareBindFunc.
// Commit activates serving on the new port after SQLite persistence succeeds;
// Abort closes the pre-bound listener if persistence fails so no split-brain occurs.
type BindHandle interface {
	Commit()
	Abort()
}

// PrepareBindFunc pre-binds newListenAddr before persisting the port change.
type PrepareBindFunc func(newListenAddr string) (BindHandle, error)

// RebindFunc is called by Manager.Update when the operator changes the TCP
// listening port and PrepareBind is not configured. Returning a non-nil error
// aborts the update before saving.
type RebindFunc func(newListenAddr string) error

// Manager owns the live panel access Snapshot backed by SQLite.
type Manager struct {
	db           *storage.DB
	clock        clock.Clock
	mu           sync.Mutex
	snap         atomic.Pointer[Snapshot]
	prepareBind  PrepareBindFunc
	rebind       RebindFunc
	onAllow      func(domain string)
	onPortChange func(port int)
}

// Options configure a Manager.
type Options struct {
	DB           *storage.DB
	Clock        clock.Clock
	Bootstrap    config.HTTP
	PrepareBind  PrepareBindFunc
	Rebind       RebindFunc
	OnAllowHost  func(domain string)
	OnPortChange func(port int)
}

// NewManager loads or seeds panel_access_settings from DB and cfg.HTTP.
// When DB is nil (unit tests), an in-memory manager is returned.
func NewManager(ctx context.Context, opts Options) (*Manager, error) {
	clk := opts.Clock
	if clk == nil {
		clk = clock.System{}
	}
	host, port, err := splitListen(opts.Bootstrap.Listen)
	if err != nil {
		return nil, fmt.Errorf("panelaccess: bootstrap listen %q: %w", opts.Bootstrap.Listen, err)
	}
	disguise, err := config.NormalizeDisguise(opts.Bootstrap.Disguise)
	if err != nil {
		return nil, fmt.Errorf("panelaccess: bootstrap disguise: %w", err)
	}
	entryPath, err := config.ValidateEntryPath(opts.Bootstrap.EntryPath)
	if err != nil {
		return nil, fmt.Errorf("panelaccess: bootstrap entry_path: %w", err)
	}
	panelDomain, err := config.NormalizePanelDomain(opts.Bootstrap.PanelDomain)
	if err != nil {
		return nil, fmt.Errorf("panelaccess: bootstrap panel_domain: %w", err)
	}

	m := &Manager{
		db:           opts.DB,
		clock:        clk,
		prepareBind:  opts.PrepareBind,
		rebind:       opts.Rebind,
		onAllow:      opts.OnAllowHost,
		onPortChange: opts.OnPortChange,
	}

	seed := Snapshot{
		ListenHost:          host,
		Port:                port,
		TLSMode:             opts.Bootstrap.TLS.Mode,
		PublicOrigins:       append([]string(nil), opts.Bootstrap.PublicOrigins...),
		EntryPath:           entryPath,
		Disguise:            disguise,
		DisguiseHTML:        opts.Bootstrap.DisguiseHTML,
		PanelDomain:         panelDomain,
		AutoDisableOnDomain: opts.Bootstrap.AutoDisableEnabled(),
		Revision:            1,
		UpdatedAt:           clk.Now().UTC(),
	}

	if opts.DB == nil {
		sec, err := randomHex(32)
		if err != nil {
			return nil, err
		}
		seed.GateSecret = sec
		m.snap.Store(&seed)
		if seed.Port > 0 && m.onPortChange != nil {
			m.onPortChange(seed.Port)
		}
		return m, nil
	}

	loaded, err := loadOrSeed(ctx, opts.DB, seed)
	if err != nil {
		return nil, err
	}
	m.snap.Store(&loaded)
	if loaded.PanelDomain != "" && m.onAllow != nil {
		m.onAllow(loaded.PanelDomain)
	}
	if loaded.Port > 0 && m.onPortChange != nil {
		m.onPortChange(loaded.Port)
	}
	return m, nil
}

// ReadEffectiveFromDB reads the effective listen addr & entry path from SQLite
// (falling back to bootstrap HTTP config when no DB row exists yet). Used by
// CLI helpers (`qwq setup-token`, `qwq plugin bootstrap`, `qwq doctor`).
func ReadEffectiveFromDB(ctx context.Context, db *storage.DB, bootstrap config.HTTP) (listenAddr, effectiveEntryPath, rawEntryPath, panelDomain, bypassReason string) {
	listenAddr = bootstrap.Listen
	rawEntryPath = config.NormalizeEntryPath(bootstrap.EntryPath)
	panelDomain = strings.TrimSpace(bootstrap.PanelDomain)
	effectiveEntryPath = bootstrap.EffectiveEntryPath()
	bypassReason = bootstrap.DomainAutoBypassReason()
	if db == nil {
		return
	}
	host, bootPort, err := splitListen(bootstrap.Listen)
	if err != nil {
		return
	}
	var (
		dbHost      string
		port        int
		ep          string
		dom         string
		autoDisable int
	)
	qerr := db.View(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT listen_host, listen_port, entry_path, panel_domain, auto_disable_on_domain FROM panel_access_settings WHERE id = 1`,
		).Scan(&dbHost, &port, &ep, &dom, &autoDisable)
	})
	if qerr != nil {
		return
	}
	if h := strings.TrimSpace(dbHost); h != "" {
		host = h
	}
	if port <= 0 {
		port = bootPort
	}
	listenAddr = net.JoinHostPort(host, strconv.Itoa(port))
	rawEntryPath = config.NormalizeEntryPath(ep)
	panelDomain = strings.TrimSpace(dom)
	auto := autoDisable != 0
	s := Snapshot{
		ListenHost:          host,
		Port:                port,
		TLSMode:             bootstrap.TLS.Mode,
		PublicOrigins:       bootstrap.PublicOrigins,
		EntryPath:           rawEntryPath,
		PanelDomain:         panelDomain,
		AutoDisableOnDomain: auto,
	}
	bypassReason = s.DomainAutoBypassReason()
	effectiveEntryPath = s.EffectiveEntryPath()
	return
}

// SetPrepareBind installs the two-phase port pre-bind callback after the HTTP server is wired.
func (m *Manager) SetPrepareBind(fn PrepareBindFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prepareBind = fn
}

// SetRebind installs the live port rebind callback after the HTTP server is wired.
func (m *Manager) SetRebind(fn RebindFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rebind = fn
}

// Snapshot returns the current immutable settings snapshot.
func (m *Manager) Snapshot() Snapshot {
	if p := m.snap.Load(); p != nil {
		return *p
	}
	return Snapshot{Disguise: config.DisguiseDrop, AutoDisableOnDomain: true}
}

// ValidateUpdate validates UpdateInput and expected_revision against the live
// snapshot without mutating state, rebinding sockets, or consuming MFA codes.
func (m *Manager) ValidateUpdate(in UpdateInput) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.validateNext(m.Snapshot(), in, false)
	return err
}

func (m *Manager) validateNext(cur Snapshot, in UpdateInput, generateRandom bool) (Snapshot, error) {
	if in.ExpectedRevision != nil && *in.ExpectedRevision != cur.Revision {
		return cur, problem.New(problem.RevisionConflict,
			"Access settings revision mismatch: expected %d, current %d.", *in.ExpectedRevision, cur.Revision)
	}

	next := cur
	if in.ListenHost != nil {
		nh, err := NormalizeListenHost(*in.ListenHost)
		if err != nil {
			return cur, problem.New(problem.ValidationFailed, "listen_host: %s", err.Error())
		}
		if cur.TLSMode == config.TLSProxy && !isLoopbackListenHost(nh) {
			return cur, problem.New(problem.ValidationFailed,
				"listen_host: 反代模式（tls.mode=proxy）未启用 HTTPS，仅允许监听本机回环地址（127.0.0.1 或 ::1）")
		}
		next.ListenHost = nh
	}
	if in.Port != nil {
		if *in.Port < 1 || *in.Port > 65535 {
			return cur, problem.New(problem.ValidationFailed, "port must be between 1 and 65535")
		}
		if cur.TLSMode == config.TLSACME && *in.Port != config.ACMEPort {
			return cur, problem.New(problem.ValidationFailed,
				"ACME TLS mode requires port %d", config.ACMEPort)
		}
		next.Port = *in.Port
	}

	if in.GenerateRandomEntryPath {
		if generateRandom {
			rnd, err := config.GenerateRandomEntryPath()
			if err != nil {
				return cur, problem.Wrap(err)
			}
			next.EntryPath = rnd
		}
	} else if in.EntryPath != nil {
		p, err := config.ValidateEntryPath(*in.EntryPath)
		if err != nil {
			return cur, problem.New(problem.ValidationFailed, "entry_path: %s", err.Error())
		}
		next.EntryPath = p
	}

	if in.Disguise != nil {
		d, err := config.NormalizeDisguise(*in.Disguise)
		if err != nil {
			return cur, problem.New(problem.ValidationFailed, "disguise: %s", err.Error())
		}
		next.Disguise = d
	}

	if in.DisguiseHTML != nil {
		if len(*in.DisguiseHTML) > config.MaxDisguiseHTMLBytes {
			return cur, problem.New(problem.ValidationFailed,
				"disguise_html exceeds %d bytes", config.MaxDisguiseHTMLBytes)
		}
		next.DisguiseHTML = *in.DisguiseHTML
	}

	if in.PanelDomain != nil {
		dom, err := config.NormalizePanelDomain(*in.PanelDomain)
		if err != nil {
			return cur, problem.New(problem.ValidationFailed, "panel_domain: %s", err.Error())
		}
		next.PanelDomain = dom
	}

	if in.AutoDisableOnDomain != nil {
		next.AutoDisableOnDomain = *in.AutoDisableOnDomain
	}

	return next, nil
}

// Update validates, optionally hot-rebinds the port, persists to SQLite, and
// atomically publishes the new live settings.
func (m *Manager) Update(ctx context.Context, in UpdateInput) (Snapshot, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := m.Snapshot()
	next, err := m.validateNext(cur, in, true)
	if err != nil {
		return cur, false, err
	}

	addrChanged := next.Port != cur.Port || next.ListenHost != cur.ListenHost
	var stagedBind BindHandle
	if addrChanged {
		if m.prepareBind != nil {
			h, err := m.prepareBind(next.ListenAddr())
			if err != nil {
				return cur, false, problem.New(problem.StateConflict,
					"Could not bind new listen address %s: %v", next.ListenAddr(), err)
			}
			stagedBind = h
		} else if m.rebind != nil {
			if err := m.rebind(next.ListenAddr()); err != nil {
				return cur, false, problem.New(problem.StateConflict,
					"Could not bind new listen address %s: %v", next.ListenAddr(), err)
			}
		}
	}

	next.Revision = cur.Revision + 1
	next.UpdatedAt = m.clock.Now().UTC()

	if m.db != nil {
		err := m.db.Update(ctx, func(tx *storage.Tx) error {
			autoInt := 0
			if next.AutoDisableOnDomain {
				autoInt = 1
			}
			_, uerr := tx.ExecContext(ctx, `
				UPDATE panel_access_settings
				SET listen_host = ?, listen_port = ?, entry_path = ?, disguise = ?, disguise_html = ?,
				    panel_domain = ?, auto_disable_on_domain = ?, revision = ?, updated_at = ?
				WHERE id = 1`,
				next.ListenHost, next.Port, next.EntryPath, next.Disguise, next.DisguiseHTML,
				next.PanelDomain, autoInt, next.Revision, storage.FormatTime(next.UpdatedAt),
			)
			if uerr != nil {
				return uerr
			}
			if in.AuditTx != nil {
				return in.AuditTx(ctx, tx, next, addrChanged)
			}
			return nil
		})
		if err != nil {
			if stagedBind != nil {
				stagedBind.Abort()
			}
			return cur, false, problem.Wrap(err)
		}
	}

	m.snap.Store(&next)
	if stagedBind != nil {
		stagedBind.Commit()
	}
	if m.onAllow != nil {
		m.onAllow(next.PanelDomain)
	}
	if addrChanged && m.onPortChange != nil {
		m.onPortChange(next.Port)
	}
	return next, addrChanged, nil
}

// WriteCapabilityPanelPort atomically writes {"port": <n>} to targetPath so
// qwq-capability's SystemGuard.ManagementPorts() preserves the live panel port.
func WriteCapabilityPanelPort(targetPath string, port int) error {
	if targetPath == "" || port < 1 || port > 65535 {
		return fmt.Errorf("panelaccess: invalid capability panel port target")
	}
	raw, err := json.Marshal(struct {
		Port int `json:"port"`
	}{Port: port})
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(filepath.Clean(targetPath))
	tmp, err := os.CreateTemp(dir, ".panel-port-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(raw); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func loadOrSeed(ctx context.Context, db *storage.DB, seed Snapshot) (Snapshot, error) {
	var out Snapshot
	var found bool
	err := db.View(ctx, func(tx *sql.Tx) error {
		var (
			dbHost      string
			port        int
			ep          string
			disguise    string
			html        string
			dom         string
			autoDisable int
			secret      string
			rev         int64
			updatedAt   string
		)
		rerr := tx.QueryRowContext(ctx, `
			SELECT listen_host, listen_port, entry_path, disguise, disguise_html, panel_domain,
			       auto_disable_on_domain, gate_secret, revision, updated_at
			FROM panel_access_settings WHERE id = 1`,
		).Scan(&dbHost, &port, &ep, &disguise, &html, &dom, &autoDisable, &secret, &rev, &updatedAt)
		if errors.Is(rerr, sql.ErrNoRows) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		found = true
		out = seed
		if h := strings.TrimSpace(dbHost); h != "" {
			out.ListenHost = h
		}
		if port > 0 {
			out.Port = port
		}
		out.EntryPath = config.NormalizeEntryPath(ep)
		if d, derr := config.NormalizeDisguise(disguise); derr == nil {
			out.Disguise = d
		}
		out.DisguiseHTML = html
		out.PanelDomain = dom
		out.AutoDisableOnDomain = autoDisable != 0
		out.GateSecret = secret
		out.Revision = rev
		if ts, terr := time.Parse(time.RFC3339Nano, updatedAt); terr == nil {
			out.UpdatedAt = ts
		}
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	if found && out.GateSecret != "" {
		return out, nil
	}
	sec, err := randomHex(32)
	if err != nil {
		return Snapshot{}, err
	}
	if !found {
		seed.GateSecret = sec
		var persisted Snapshot
		err = db.Update(ctx, func(tx *storage.Tx) error {
			autoInt := 0
			if seed.AutoDisableOnDomain {
				autoInt = 1
			}
			if _, ierr := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO panel_access_settings
				(id, listen_host, listen_port, entry_path, disguise, disguise_html, panel_domain,
				 auto_disable_on_domain, gate_secret, revision, updated_at)
				VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				seed.ListenHost, seed.Port, seed.EntryPath, seed.Disguise, seed.DisguiseHTML, seed.PanelDomain,
				autoInt, seed.GateSecret, seed.Revision, storage.FormatTime(seed.UpdatedAt),
			); ierr != nil {
				return ierr
			}
			var (
				dbHost      string
				port        int
				ep          string
				disguise    string
				html        string
				dom         string
				autoDisable int
				secret      string
				rev         int64
				updatedAt   string
			)
			if serr := tx.QueryRowContext(ctx, `
				SELECT listen_host, listen_port, entry_path, disguise, disguise_html, panel_domain,
				       auto_disable_on_domain, gate_secret, revision, updated_at
				FROM panel_access_settings WHERE id = 1`,
			).Scan(&dbHost, &port, &ep, &disguise, &html, &dom, &autoDisable, &secret, &rev, &updatedAt); serr != nil {
				return serr
			}
			persisted = seed
			if h := strings.TrimSpace(dbHost); h != "" {
				persisted.ListenHost = h
			}
			if port > 0 {
				persisted.Port = port
			}
			persisted.EntryPath = config.NormalizeEntryPath(ep)
			if d, derr := config.NormalizeDisguise(disguise); derr == nil {
				persisted.Disguise = d
			}
			persisted.DisguiseHTML = html
			persisted.PanelDomain = dom
			persisted.AutoDisableOnDomain = autoDisable != 0
			persisted.GateSecret = secret
			persisted.Revision = rev
			if ts, terr := time.Parse(time.RFC3339Nano, updatedAt); terr == nil {
				persisted.UpdatedAt = ts
			}
			return nil
		})
		if err != nil {
			return Snapshot{}, err
		}
		return persisted, nil
	}
	out.GateSecret = sec
	if err := db.Update(ctx, func(tx *storage.Tx) error {
		_, uerr := tx.ExecContext(ctx, `UPDATE panel_access_settings SET gate_secret = ? WHERE id = 1`, sec)
		return uerr
	}); err != nil {
		return Snapshot{}, err
	}
	return out, nil
}

func splitListen(listen string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	return host, p, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
