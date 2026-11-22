// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"encoding/json"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Errors that only exist inside the package.
var (
	// errSpoolClosed is returned to a publisher when the server stopped.
	errSpoolClosed = errors.New("hostsvc: event spool is closed")
	// errInvalidValue is a defensive check of a StateStore value.
	errInvalidValue = errors.New("hostsvc: state value is not valid JSON")
	// errStateCorrupt marks a built-in state file that cannot be parsed.
	errStateCorrupt = errors.New("hostsvc: state file is corrupt")
)

// jsonValid reports whether b is a JSON document. Values and payloads of this
// ABI are JSON by contract; invalid bytes are rejected before they reach the
// host.
func jsonValid(b []byte) bool { return len(b) > 0 && json.Valid(b) }

// dependencyError maps an error from a host dependency to a client-visible
// status. A dependency may return a gRPC status to choose the code and
// message; plain errors use the exported sentinels, and anything else becomes
// INTERNAL with a generic message so host internals never leak to a plugin.
func statusFromError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	var limit *LimitError
	if errors.As(err, &limit) {
		return status.Error(codes.ResourceExhausted, limit.Error())
	}
	switch {
	case errors.Is(err, ErrSecretDenied):
		return status.Error(codes.PermissionDenied, "the secret is not available to this instance")
	case errors.Is(err, ErrOperationNotDispatched):
		return status.Error(codes.FailedPrecondition, "the operation is not dispatched to this instance")
	case errors.Is(err, ErrRateLimited):
		return status.Error(codes.ResourceExhausted, "the call is rate limited")
	case errors.Is(err, errSpoolClosed):
		return status.Error(codes.Unavailable, "the host service is shutting down")
	case errors.Is(err, errAuditUnavailable):
		return status.Error(codes.Unavailable, "audit is not available")
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return st.Err()
	}
	return status.Error(codes.Internal, "the host failed to complete the call")
}

// dependencyError logs the cause and maps it to a client-visible status. The
// log line carries the operation and the error; the plugin sees only the mapped
// status, whose message is fixed for the internal case.
func (s *Server) dependencyError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if status.Code(statusFromError(err)) != codes.Internal {
		s.log.Warn("host call failed", "operation", operation, "error", err)
	} else {
		s.log.Error("host call failed", "operation", operation, "error", err)
	}
	return statusFromError(err)
}

// sinkError is dependencyError for a host infrastructure sink (journal, audit
// store, config source). An unrecognized sink error becomes UNAVAILABLE instead
// of INTERNAL: the plugin should retry a transient storage failure, and the
// concrete cause stays in the Agent log.
func (s *Server) sinkError(operation string, err error) error {
	if err == nil {
		return nil
	}
	mapped := statusFromError(err)
	if status.Code(mapped) == codes.Internal {
		s.log.Error("host dependency failed", "operation", operation, "error", err)
		return status.Error(codes.Unavailable, "a host dependency is unavailable")
	}
	s.log.Warn("host dependency failed", "operation", operation, "error", err)
	return mapped
}

// unavailable returns a fixed UNAVAILABLE status for a dependency that is not
// wired.
func unavailable(what string) error {
	return status.Error(codes.Unavailable, what+" is not available")
}
