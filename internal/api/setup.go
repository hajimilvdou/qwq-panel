// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/identity"
)

// setupRequest is the SetupRequest schema.
type setupRequest struct {
	SetupToken  string `json:"setup_token"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// getSetup reports whether the installation is initialized and, on a
// self-signed listener, the SHA-256 fingerprint the installer prints.
func (a *api) getSetup(w http.ResponseWriter, r *http.Request) {
	initialized, err := a.d.Identity.SetupInitialized(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	status := setupStatus{Initialized: initialized}
	if a.d.TLS != nil {
		status.TLSFingerprint = a.d.TLS.Fingerprint()
	}
	a.writeResource(w, r, http.StatusOK, status, nil)
}

// postSetup creates the first administrator with the one-time installation
// token and, on success, signs them in exactly like a login does.
func (a *api) postSetup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.d.Identity.CompleteSetup(r.Context(), identity.CompleteSetupInput{
		SetupToken:  req.SetupToken,
		Username:    req.Username,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		ClientIP:    gateway.ClientIP(r.Context()),
		UserAgent:   r.UserAgent(),
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.g.SetSessionCookie(w, res.Token, a.sessionTTL(res.Session))
	a.writeResource(w, r, http.StatusCreated, newSessionDTO(res.Session), nil)
}
