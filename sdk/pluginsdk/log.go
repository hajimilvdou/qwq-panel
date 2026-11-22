// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"log/slog"
	"os"
	"strings"
)

// EnvLogLevel selects the plugin's log level: debug, info, warn or error. The
// default is info.
const EnvLogLevel = "QWQ_PLUGIN_LOG_LEVEL"

// defaultLogger writes structured JSON to stderr. stdout belongs to the
// transport handshake (go-plugin reads it), so the SDK never logs there.
func defaultLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(os.Getenv(EnvLogLevel))}))
}

func logLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
