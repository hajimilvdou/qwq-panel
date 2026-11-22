// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Error is a domain failure reported as ErrorDetail with a stable code while
// the gRPC status stays OK (platform.proto, "Errors"). Return it from an
// operation or config handler; the SDK converts it with [errorDetail].
//
// An Error never carries secrets or stack traces: Message is untrusted text for
// users and DetailsJSON is shown to clients as-is.
type Error struct {
	// Code is stable and machine readable, e.g. PRECONDITION_FAILED.
	Code string
	// Message is localized user-facing text.
	Message string
	// Retryable tells the host whether the same attempt may be repeated.
	Retryable bool
	// DetailsJSON is optional machine-readable detail.
	DetailsJSON []byte
	// Violations are field-level causes, e.g. for VALIDATION_FAILED.
	Violations []FieldViolation

	cause error
}

// Error implements error.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Code == "" {
		return e.Message
	}
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Unwrap exposes the transport error a mapped host failure came from, if any.
func (e *Error) Unwrap() error { return e.cause }

// Errorf builds a domain error with a stable code and a formatted message.
// Prefer [Validation] and [PreconditionFailed] for those two common codes.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Validation reports field-level validation failures with the stable code
// VALIDATION_FAILED. Set Message on the result to localize the summary text.
func Validation(violations ...FieldViolation) *Error {
	return &Error{Code: "VALIDATION_FAILED", Message: "invalid request", Violations: violations}
}

// PreconditionFailed reports a stale [Precondition] with the stable code
// PRECONDITION_FAILED. revision is the revision observed while rejecting the
// call; it may be empty when the plugin cannot read it cheaply.
func PreconditionFailed(subject, revision string) *Error {
	details, _ := json.Marshal(map[string]string{"subject": subject, "revision": revision})
	return &Error{
		Code:        "PRECONDITION_FAILED",
		Message:     "the resource has changed since it was planned",
		DetailsJSON: details,
	}
}

// CodeOf returns the stable domain code of err: the Error code when err is the
// SDK's Error, the gRPC code name for a raw status, or "" otherwise.
func CodeOf(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if s, ok := status.FromError(err); ok {
		return s.Code().String()
	}
	return ""
}

// IsConflict reports whether err is a failed KV compare-and-swap
// (revision conflict). The host reports it as gRPC ABORTED, which the SDK maps
// to the stable code REVISION_CONFLICT.
func IsConflict(err error) bool { return CodeOf(err) == "REVISION_CONFLICT" }

// statusCodes maps gRPC statuses to the stable ErrorDetail codes plugins see.
// The ABI does not define this mapping (Host Service responses have no
// ErrorDetail field), so the SDK owns it; see REPORT.md.
var statusCodes = map[codes.Code]struct {
	code      string
	retryable bool
}{
	codes.PermissionDenied:   {"PERMISSION_DENIED", false},
	codes.Unauthenticated:    {"UNAUTHENTICATED", false},
	codes.NotFound:           {"NOT_FOUND", false},
	codes.InvalidArgument:    {"INVALID_ARGUMENT", false},
	codes.FailedPrecondition: {"FAILED_PRECONDITION", false},
	codes.Aborted:            {"REVISION_CONFLICT", false},
	codes.Unavailable:        {"UNAVAILABLE", true},
	codes.DeadlineExceeded:   {"DEADLINE_EXCEEDED", true},
	codes.Canceled:           {"CANCELED", false},
	codes.Unimplemented:      {"UNIMPLEMENTED", false},
	// Not retryable: repeating the same call hits the same quota or message limit.
	codes.ResourceExhausted: {"RESOURCE_EXHAUSTED", false},
	codes.Internal:          {"INTERNAL", false},
}

// errorFromStatus turns a Host Service failure into a domain Error with a
// stable code, keeping the original error for [errors.Unwrap]. It returns nil
// when err is nil, so callers can return it directly.
func errorFromStatus(err error) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	st := status.Convert(err)
	if m, ok := statusCodes[st.Code()]; ok {
		return &Error{Code: m.code, Message: st.Message(), Retryable: m.retryable, cause: err}
	}
	return &Error{Code: "INTERNAL", Message: st.Message(), cause: err}
}

// errorDetail converts a handler error to the ABI's domain ErrorDetail. Errors
// that are not [*Error] (and not context cancellation) become INTERNAL with a
// generic message; the caller logs the original.
func errorDetail(err error, locale string) *platformv1.ErrorDetail {
	var domain *Error
	if errors.As(err, &domain) {
		d := &platformv1.ErrorDetail{
			Code:        domain.Code,
			Message:     domain.Message,
			Retryable:   domain.Retryable,
			DetailsJson: append([]byte(nil), domain.DetailsJSON...),
		}
		for _, v := range domain.Violations {
			d.Violations = append(d.Violations, &platformv1.FieldViolation{Pointer: v.Pointer, Code: v.Code, Message: v.Message})
		}
		return d
	}
	if errors.Is(err, context.Canceled) {
		return &platformv1.ErrorDetail{Code: "CANCELED", Message: Localize(locale, "调用已取消", "the call was canceled")}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &platformv1.ErrorDetail{
			Code: "DEADLINE_EXCEEDED", Message: Localize(locale, "调用超时", "the call timed out"), Retryable: true,
		}
	}
	return &platformv1.ErrorDetail{Code: "INTERNAL", Message: Localize(locale, "插件内部错误", "the plugin failed unexpectedly")}
}

// violationsToProto converts SDK violations to the ABI message.
func violationsToProto(vs []FieldViolation) []*platformv1.FieldViolation {
	if len(vs) == 0 {
		return nil
	}
	out := make([]*platformv1.FieldViolation, len(vs))
	for i, v := range vs {
		out[i] = &platformv1.FieldViolation{Pointer: v.Pointer, Code: v.Code, Message: v.Message}
	}
	return out
}
