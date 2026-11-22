// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Check is one readiness probe: a named function that reports whether a
// subsystem can serve requests (database open, TLS certificate valid, local
// agent connected).
type Check struct {
	// Name identifies the check in logs and in the UNAVAILABLE detail.
	Name string
	// Check returns nil when the subsystem is ready.
	Check func(ctx context.Context) error
}

func (c Check) valid() error {
	if c.Name == "" {
		return errors.New("a name is required")
	}
	if len(c.Name) > 64 {
		return errors.New("the name is longer than 64 characters")
	}
	if c.Check == nil {
		return errors.New("a check function is required")
	}
	return nil
}

// HealthStatus is the HealthStatus schema of /healthz and /readyz.
type HealthStatus struct {
	Status string `json:"status"`
}

// checkTimeout bounds one readiness probe so /readyz always answers promptly.
const checkTimeout = 2 * time.Second

// health answers /healthz: the process is alive.
func (g *Gateway) health(w http.ResponseWriter, r *http.Request) {
	_ = WriteJSON(w, http.StatusOK, HealthStatus{Status: "ok"})
}

// ready answers /readyz: every registered check passed, otherwise 503
// UNAVAILABLE. The failure detail names the check but never carries its error
// (that goes to the log).
func (g *Gateway) ready(w http.ResponseWriter, r *http.Request) {
	for _, c := range g.checksSnapshot() {
		ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
		err := c.Check(ctx)
		cancel()
		if err == nil {
			continue
		}
		g.log.WarnContext(r.Context(), "readiness check failed",
			slog.String("check", c.Name), slog.Any("error", err))
		g.writeProblem(w, r, problem.New(problem.Unavailable, "Not ready: %s has not completed.", c.Name))
		return
	}
	_ = WriteJSON(w, http.StatusOK, HealthStatus{Status: "ok"})
}
