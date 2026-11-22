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
	"errors"
	"fmt"
	"net"
	"net/http"
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
// secret entry path. Rotating EntryPath immediately invalidates old cookies.
func (s Snapshot) GateToken() string {
	ep := s.EffectiveEntryPath()
	if ep == "" || s.GateSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(s.GateSecret))
	mac.Write([]byte("entry:"))
	mac.Write([]byte(ep))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidGateCookie verifies cookieVal in constant time.
func (s Snapshot) ValidGateCookie(cookieVal string) bool {
	want := s.GateToken()
	if want == "" || cookieVal == "" {
		return false
	}
	return hmac.Equal([]byte(want), []byte(cookieVal))
}

// SetGateCookie writes the HttpOnly gate cookie when the secret entry path is active.
func (s Snapshot) SetGateCookie(w http.ResponseWriter, secure bool) {
	tok := s.GateToken()
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

// UpdateInput carries the desired live access configuration from PUT /api/v1/system/access.
type UpdateInput struct {
	Port                    *int
	EntryPath               *string
	GenerateRandomEntryPath bool
	Disguise                *string
	DisguiseHTML            *string
	PanelDomain             *string
	AutoDisableOnDomain     *bool
	ExpectedRevision        *int64
}

// RebindFunc is called by Manager.Update when the operator changes the TCP
// listening port. Returning a non-nil error aborts the update before saving.
type RebindFunc func(newListenAddr string) error

// Manager owns the live panel access Snapshot backed by SQLite.
type Manager struct {
	db      *storage.DB
	clock   clock.Clock
	mu      sync.Mutex
	snap    atomic.Pointer[Snapshot]
	rebind  RebindFunc
	onAllow func(domain string)
}

// Options configure a Manager.
type Options struct {
	DB          *storage.DB
	Clock       clock.Clock
	Bootstrap   config.HTTP
	Rebind      RebindFunc
	OnAllowHost func(domain string)
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
		db:      opts.DB,
		clock:   clk,
		rebind:  opts.Rebind,
		onAllow: opts.OnAllowHost,
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
		port        int
		ep          string
		dom         string
		autoDisable int
	)
	qerr := db.View(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT listen_port, entry_path, panel_domain, auto_disable_on_domain FROM panel_access_settings WHERE id = 1`,
		).Scan(&port, &ep, &dom, &autoDisable)
	})
	if qerr != nil {
		return
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

// Update validates, optionally hot-rebinds the port, persists to SQLite, and
// atomically publishes the new live settings.
func (m *Manager) Update(ctx context.Context, in UpdateInput) (Snapshot, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := m.Snapshot()
	if in.ExpectedRevision != nil && *in.ExpectedRevision != cur.Revision {
		return cur, false, problem.New(problem.RevisionConflict,
			"Access settings revision mismatch: expected %d, current %d.", *in.ExpectedRevision, cur.Revision)
	}

	next := cur
	if in.Port != nil {
		if *in.Port < 1 || *in.Port > 65535 {
			return cur, false, problem.New(problem.ValidationFailed, "port must be between 1 and 65535")
		}
		if cur.TLSMode == config.TLSACME && *in.Port != config.ACMEPort {
			return cur, false, problem.New(problem.ValidationFailed,
				"ACME TLS mode requires port %d", config.ACMEPort)
		}
		next.Port = *in.Port
	}

	if in.GenerateRandomEntryPath {
		rnd, err := config.GenerateRandomEntryPath()
		if err != nil {
			return cur, false, problem.Wrap(err)
		}
		next.EntryPath = rnd
	} else if in.EntryPath != nil {
		p, err := config.ValidateEntryPath(*in.EntryPath)
		if err != nil {
			return cur, false, problem.New(problem.ValidationFailed, "entry_path: %s", err.Error())
		}
		next.EntryPath = p
	}

	if in.Disguise != nil {
		d, err := config.NormalizeDisguise(*in.Disguise)
		if err != nil {
			return cur, false, problem.New(problem.ValidationFailed, "disguise: %s", err.Error())
		}
		next.Disguise = d
	}

	if in.DisguiseHTML != nil {
		if len(*in.DisguiseHTML) > config.MaxDisguiseHTMLBytes {
			return cur, false, problem.New(problem.ValidationFailed,
				"disguise_html exceeds %d bytes", config.MaxDisguiseHTMLBytes)
		}
		next.DisguiseHTML = *in.DisguiseHTML
	}

	if in.PanelDomain != nil {
		dom, err := config.NormalizePanelDomain(*in.PanelDomain)
		if err != nil {
			return cur, false, problem.New(problem.ValidationFailed, "panel_domain: %s", err.Error())
		}
		next.PanelDomain = dom
	}

	if in.AutoDisableOnDomain != nil {
		next.AutoDisableOnDomain = *in.AutoDisableOnDomain
	}

	portChanged := next.Port != cur.Port
	if portChanged && m.rebind != nil {
		if err := m.rebind(next.ListenAddr()); err != nil {
			return cur, false, problem.New(problem.StateConflict,
				"Could not bind new port %d: %v", next.Port, err)
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
				SET listen_port = ?, entry_path = ?, disguise = ?, disguise_html = ?,
				    panel_domain = ?, auto_disable_on_domain = ?, revision = ?, updated_at = ?
				WHERE id = 1`,
				next.Port, next.EntryPath, next.Disguise, next.DisguiseHTML,
				next.PanelDomain, autoInt, next.Revision, storage.FormatTime(next.UpdatedAt),
			)
			return uerr
		})
		if err != nil {
			return cur, false, problem.Wrap(err)
		}
	}

	m.snap.Store(&next)
	if next.PanelDomain != "" && m.onAllow != nil {
		m.onAllow(next.PanelDomain)
	}
	return next, portChanged, nil
}

func loadOrSeed(ctx context.Context, db *storage.DB, seed Snapshot) (Snapshot, error) {
	var out Snapshot
	var found bool
	err := db.View(ctx, func(tx *sql.Tx) error {
		var (
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
			SELECT listen_port, entry_path, disguise, disguise_html, panel_domain,
			       auto_disable_on_domain, gate_secret, revision, updated_at
			FROM panel_access_settings WHERE id = 1`,
		).Scan(&port, &ep, &disguise, &html, &dom, &autoDisable, &secret, &rev, &updatedAt)
		if errors.Is(rerr, sql.ErrNoRows) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		found = true
		out = seed
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
		err = db.Update(ctx, func(tx *storage.Tx) error {
			autoInt := 0
			if seed.AutoDisableOnDomain {
				autoInt = 1
			}
			_, ierr := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO panel_access_settings
				(id, listen_port, entry_path, disguise, disguise_html, panel_domain,
				 auto_disable_on_domain, gate_secret, revision, updated_at)
				VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				seed.Port, seed.EntryPath, seed.Disguise, seed.DisguiseHTML, seed.PanelDomain,
				autoInt, seed.GateSecret, seed.Revision, storage.FormatTime(seed.UpdatedAt),
			)
			return ierr
		})
		if err != nil {
			return Snapshot{}, err
		}
		return seed, nil
	}
	out.GateSecret = sec
	_ = db.Update(ctx, func(tx *storage.Tx) error {
		_, uerr := tx.ExecContext(ctx, `UPDATE panel_access_settings SET gate_secret = ? WHERE id = 1`, sec)
		return uerr
	})
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
