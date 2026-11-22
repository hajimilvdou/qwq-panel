// SPDX-License-Identifier: AGPL-3.0-only

// Package logging builds the host's structured logger on log/slog.
//
// Records carry the fields of ARCH §13: timestamp, level, service, node_id,
// plugin_id, operation_id, trace_id. Correlation fields travel in the context
// (With) and are added by the handler, so call sites stay short. Values under
// sensitive keys and values of type Secret are redacted, and long strings are
// truncated, so a careless log line cannot leak a token or flood the disk.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"
)

// Standard field names (ARCH §13).
const (
	KeyService     = "service"
	KeyNodeID      = "node_id"
	KeyPluginID    = "plugin_id"
	KeyOperationID = "operation_id"
	KeyTraceID     = "trace_id"
	KeyRequestID   = "request_id"
)

// MaxValueLen is the longest string value written to a log record, in bytes.
const MaxValueLen = 4096

const redacted = "[REDACTED]"

// Options configure New.
type Options struct {
	Service string
	Level   slog.Leveler
	// Format is "json" (default) or "text".
	Format string
}

// New returns a logger writing to w.
func New(w io.Writer, opts Options) *slog.Logger {
	ho := &slog.HandlerOptions{Level: opts.Level, ReplaceAttr: replaceAttr}
	var h slog.Handler
	if opts.Format == "text" {
		h = slog.NewTextHandler(w, ho)
	} else {
		h = slog.NewJSONHandler(w, ho)
	}
	l := slog.New(contextHandler{h})
	if opts.Service != "" {
		l = l.With(KeyService, opts.Service)
	}
	return l
}

// ParseLevel accepts debug, info, warn and error.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q", s)
}

// Secret wraps a value that must never appear in logs.
type Secret string

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// String keeps fmt from printing the value.
func (Secret) String() string { return redacted }

type ctxKey struct{}

// With returns a context whose log records carry the given attributes. Later
// values for the same key replace earlier ones.
func With(ctx context.Context, attrs ...slog.Attr) context.Context {
	prev, _ := ctx.Value(ctxKey{}).([]slog.Attr)
	merged := make([]slog.Attr, 0, len(prev)+len(attrs))
	for _, a := range prev {
		if !hasKey(attrs, a.Key) {
			merged = append(merged, a)
		}
	}
	merged = append(merged, attrs...)
	return context.WithValue(ctx, ctxKey{}, merged)
}

func hasKey(attrs []slog.Attr, k string) bool {
	for _, a := range attrs {
		if a.Key == k {
			return true
		}
	}
	return false
}

// contextHandler adds the attributes stored by With to every record.
type contextHandler struct{ slog.Handler }

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if attrs, ok := ctx.Value(ctxKey{}).([]slog.Attr); ok && len(attrs) > 0 {
		r = r.Clone()
		r.AddAttrs(attrs...)
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.String("timestamp", a.Value.Time().UTC().Format(time.RFC3339Nano))
	}
	if sensitive(a.Key) {
		return slog.String(a.Key, redacted)
	}
	if a.Value.Kind() == slog.KindString {
		if s := a.Value.String(); len(s) > MaxValueLen {
			return slog.String(a.Key, truncate(s))
		}
	}
	return a
}

// sensitiveKeys are matched against the whole key or, for the last four, its
// last "_"/"." separated segment (session_token, db.password).
var sensitiveKeys = map[string]bool{
	"authorization": true, "proxy_authorization": true, "cookie": true, "set_cookie": true,
	"api_key": true, "private_key": true, "client_secret": true, "csr": true,
	"otp": true, "totp_code": true, "recovery_code": true, "passwd": true,
	"password": true, "secret": true, "token": true, "credential": true,
}

var sensitiveSuffixes = map[string]bool{"password": true, "secret": true, "token": true, "credential": true}

// IsSensitiveKey reports whether a log attribute with this key is redacted;
// offline tools (qwq support-bundle) use it to filter collected logs.
func IsSensitiveKey(key string) bool { return sensitive(key) }

func sensitive(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if sensitiveKeys[k] {
		return true
	}
	if i := strings.LastIndexAny(k, "_."); i >= 0 {
		return sensitiveSuffixes[k[i+1:]]
	}
	return false
}

func truncate(s string) string {
	cut := MaxValueLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%s…[truncated %d bytes]", s[:cut], len(s)-cut)
}
