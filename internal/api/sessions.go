// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/panelaccess"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// loginRequest is the LoginRequest schema.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// mfaVerifyRequest is the MfaVerifyRequest schema.
type mfaVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Method      string `json:"method"`
	Code        string `json:"code"`
}

// createSession logs a user in with a password. A user with TOTP enabled gets an
// MfaChallenge (200) instead of a session (201).
func (a *api) createSession(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.d.Identity.Login(r.Context(), identity.LoginInput{
		Username:  req.Username,
		Password:  req.Password,
		ClientIP:  gateway.ClientIP(r.Context()),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if res.MFA != nil {
		a.writeResource(w, r, http.StatusOK, newMFAChallengeDTO(*res.MFA), nil)
		return
	}
	a.g.SetSessionCookie(w, res.Token, a.sessionTTL(res.Session))
	a.writeResource(w, r, http.StatusCreated, newSessionDTO(res.Session), nil)
}

// verifySessionMFA completes a login (or elevates the session the cookie names)
// with a TOTP or recovery code.
func (a *api) verifySessionMFA(w http.ResponseWriter, r *http.Request) {
	var req mfaVerifyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.d.Identity.VerifyMFA(r.Context(), identity.VerifyMFAInput{
		ChallengeID:  req.ChallengeID,
		Method:       req.Method,
		Code:         req.Code,
		ClientIP:     gateway.ClientIP(r.Context()),
		UserAgent:    r.UserAgent(),
		SessionToken: sessionToken(r),
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !res.Authenticated() {
		a.fail(w, r, problem.New(problem.Unauthenticated, "Authentication required."))
		return
	}
	a.g.SetSessionCookie(w, res.Token, a.sessionTTL(res.Session))
	a.writeResource(w, r, http.StatusCreated, newSessionDTO(res.Session), nil)
}

// currentSession returns the session the cookie names, including the CSRF token
// the Shell keeps in memory.
func (a *api) currentSession(w http.ResponseWriter, r *http.Request) {
	sess, err := a.currentSessionRow(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newSessionDTO(sess), fields)
}

// deleteSession logs out: the session is revoked and the cookie cleared.
// Repeating it is harmless.
func (a *api) deleteSession(w http.ResponseWriter, r *http.Request) {
	token := sessionToken(r)
	if token == "" {
		a.fail(w, r, problem.New(problem.Unauthenticated, "The request has no credentials."))
		return
	}
	if err := a.d.Identity.Logout(r.Context(), token); err != nil {
		a.fail(w, r, err)
		return
	}
	tlsMode := a.d.Config.HTTP.TLS.Mode
	if a.d.Access != nil {
		if snap := a.d.Access.Snapshot(); snap.TLSMode != "" {
			tlsMode = snap.TLSMode
		}
	}
	gateSecure := panelaccess.ShouldUseSecureGateCookie(tlsMode, r, a.trustedProxies)
	a.g.ClearSessionCookieWithGateSecure(w, gateSecure)
	w.WriteHeader(http.StatusNoContent)
}

// currentSessionRow resolves the cookie to its session. The gateway already
// authenticated the request; this second lookup exists because the principal
// carries only the actor, while the Session schema needs the CSRF token and the
// two deadlines.
func (a *api) currentSessionRow(r *http.Request) (identity.Session, error) {
	token := sessionToken(r)
	if token == "" {
		return identity.Session{}, problem.New(problem.Unauthenticated, "The request has no credentials.")
	}
	_, sess, err := a.d.Identity.AuthenticateSession(r.Context(), token)
	if err != nil {
		return identity.Session{}, err
	}
	return sess, nil
}
