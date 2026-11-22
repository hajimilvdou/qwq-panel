// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// responseWriter records the status code for the access log and tells the panic
// handler whether a status line is already on the wire.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *responseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status, w.wroteHeader = code, true
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush and SetWriteDeadline through
// the wrapper; the SSE endpoint needs both.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// underlying follows Unwrap to the writer the server handed to ServeHTTP.
func underlying(w http.ResponseWriter) http.ResponseWriter {
	for i := 0; i < 8; i++ {
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		next := u.Unwrap()
		if next == nil || next == w {
			return w
		}
		w = next
	}
	return w
}

// WriteJSON writes v as an application/json response. Handlers use it so every
// success response carries the same content type and cache directive.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// EncodeJSON writes v without a trailing newline; the SSE endpoint uses it for
// one-line `data:` payloads.
func EncodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// writeProblem renders err as RFC 9457 Problem Details and logs the server-side
// cause with the request ID. Client-visible detail never contains the cause.
func (g *Gateway) writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	p := problem.Write(w, err, RequestID(r.Context()), r.URL.Path)
	switch {
	case p.Status >= http.StatusInternalServerError:
		g.log.ErrorContext(r.Context(), "request failed",
			slog.String("code", string(p.Code)), slog.Int("status", p.Status), slog.Any("error", err))
	case g.log.Enabled(r.Context(), slog.LevelDebug):
		g.log.DebugContext(r.Context(), "request rejected",
			slog.String("code", string(p.Code)), slog.Int("status", p.Status),
			slog.String("path", r.URL.Path))
	}
}

// payloadTooLarge builds PAYLOAD_TOO_LARGE with the limit that was hit.
func payloadTooLarge(name string, max int64) *problem.Error {
	e := problem.New(problem.PayloadTooLarge, "The request exceeds %s (%d).", name, max)
	e.Limit = &problem.Limit{Name: name, Max: max}
	return e
}

// rateLimited builds RATE_LIMITED for a limiter that refused a request; the
// retry delay becomes Retry-After in whole seconds (1 s to 1 day).
func rateLimited(retry time.Duration) *problem.Error {
	seconds := int(retry/time.Second) + 1
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 86400 {
		seconds = 86400
	}
	e := problem.New(problem.RateLimited, "Too many requests; retry in %d seconds.", seconds)
	e.RetryAfterSec = seconds
	return e
}

// fieldViolation builds a FieldViolation.
func fieldViolation(in, pointer, code, message string) problem.Violation {
	return problem.Violation{In: in, Pointer: pointer, Code: code, Message: message}
}

// badRequest builds VALIDATION_FAILED with one violation.
func badRequest(in, pointer, code, message string) *problem.Error {
	return problem.Validation(fieldViolation(in, pointer, code, message))
}

// csrfFailed is the CSRF_FAILED error for cross-site or foreign-origin
// requests.
func csrfFailed(detail string) *problem.Error {
	return problem.New(problem.CSRFFailed, "%s", detail)
}

// isProblemInternal reports whether err became an INTERNAL problem, which means
// the cause belongs in the log.
func isProblemInternal(err error) bool {
	var e *problem.Error
	return errors.As(err, &e) && e.Code == problem.Internal
}
