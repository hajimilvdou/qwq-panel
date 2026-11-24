// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"net/http"
	"time"
)

// SessionCookieName is the session cookie of the public API. It matches
// identity.SessionCookieName and the sessionCookie security scheme: the
// __Secure- prefix stops a network attacker from planting it over plain HTTP,
// and Path=/api/ keeps it away from public plugin routes under /p/
// (ARCH §4.1.1).
const SessionCookieName = "__Secure-qwq_session"

// sessionCookiePath is the cookie path required by the contract.
const sessionCookiePath = "/api/"

// SetSessionCookie writes the session cookie. ttl is the remaining lifetime;
// a non-positive ttl writes a session cookie (no Max-Age).
//
// The Secure attribute is always set except when Config.InsecureCookies is on,
// which exists for tests on plain HTTP. Browsers reject a __Secure- cookie
// without Secure, which is exactly the protection the prefix promises.
func (g *Gateway) SetSessionCookie(w http.ResponseWriter, value string, ttl time.Duration) {
	c := &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     sessionCookiePath,
		HttpOnly: true,
		Secure:   !g.cfg.InsecureCookies,
		SameSite: http.SameSiteLaxMode,
	}
	if ttl > 0 {
		c.MaxAge = int(ttl / time.Second)
		c.Expires = g.clock.Now().Add(ttl)
	}
	http.SetCookie(w, c)
}

// GateCookieName matches panelaccess.GateCookieName so explicit logout clears
// the stealth entry-gate cookie alongside the session cookie.
const GateCookieName = "_g"

// ClearSessionCookie expires both the session cookie and the stealth entry-gate
// cookie on explicit user logout.
func (g *Gateway) ClearSessionCookie(w http.ResponseWriter) {
	g.ClearSessionCookieWithGateSecure(w, !g.cfg.InsecureCookies)
}

// ClearSessionCookieWithGateSecure expires both the session cookie and the
// stealth entry-gate cookie, using gateSecure for the _g cookie so plain-HTTP
// tls_mode="proxy" sessions clear _g cleanly as well.
func (g *Gateway) ClearSessionCookieWithGateSecure(w http.ResponseWriter, gateSecure bool) {
	g.clearSessionCookieOnly(w)
	http.SetCookie(w, &http.Cookie{
		Name:     GateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   gateSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
	})
}

// clearSessionCookieOnly expires only the session cookie (used on 401 for stale
// sessions so the browser can stay on /login without losing the entry gate).
func (g *Gateway) clearSessionCookieOnly(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     sessionCookiePath,
		HttpOnly: true,
		Secure:   !g.cfg.InsecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
	})
}
