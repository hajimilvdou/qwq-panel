// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"fmt"
	"log/slog"
	"runtime/debug"
)

// panicError reports that plugin code panicked. It is deliberately not a domain
// [Error]: errorDetail and publicRouteStatus map it to their generic INTERNAL
// answers, so neither the panic value nor the stack reaches the host.
type panicError struct{ value any }

func (e *panicError) Error() string { return fmt.Sprintf("plugin code panicked: %v", e.value) }

// safely runs plugin code and turns a panic into a *panicError. The stack is
// only written to the plugin's own log. With Options.CrashOnPanic the panic
// propagates and ends the process.
func safely[T any](in *instance, what string, fn func() (T, error)) (out T, err error) {
	if in.crashOnPanic {
		return fn()
	}
	defer func() {
		if r := recover(); r != nil {
			in.log.Error("plugin code panicked", slog.String("call", what),
				slog.Any("panic", r), slog.String("stack", string(debug.Stack())))
			var zero T
			out, err = zero, &panicError{value: r}
		}
	}()
	return fn()
}

// safelyRun is [safely] for plugin code that only returns an error.
func safelyRun(in *instance, what string, fn func() error) error {
	_, err := safely(in, what, func() (struct{}, error) { return struct{}{}, fn() })
	return err
}
