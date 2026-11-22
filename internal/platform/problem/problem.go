// SPDX-License-Identifier: AGPL-3.0-only

// Package problem defines the host's error codes and renders them as RFC 9457
// Problem Details (application/problem+json), as specified by the Problem and
// ProblemCode schemas in api/public/v1/openapi.yaml.
//
// Host code returns *Error values; the gateway converts any error with
// From and writes it with Write. Errors that are not *Error become INTERNAL
// and their text is never sent to the client: it belongs in the log under the
// request ID.
package problem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"unicode/utf8"
)

// Code is a machine-readable error code (ProblemCode in the OpenAPI document).
type Code string

// Codes. Keep in sync with ProblemCode in api/public/v1/openapi.yaml; the
// test reads the document and compares.
const (
	ValidationFailed      Code = "VALIDATION_FAILED"
	Unauthenticated       Code = "UNAUTHENTICATED"
	MFARequired           Code = "MFA_REQUIRED"
	CSRFFailed            Code = "CSRF_FAILED"
	PermissionDenied      Code = "PERMISSION_DENIED"
	ApprovalRequired      Code = "APPROVAL_REQUIRED"
	NotFound              Code = "NOT_FOUND"
	MethodNotAllowed      Code = "METHOD_NOT_ALLOWED"
	RevisionConflict      Code = "REVISION_CONFLICT"
	PreconditionFailed    Code = "PRECONDITION_FAILED"
	PlanExpired           Code = "PLAN_EXPIRED"
	StateConflict         Code = "STATE_CONFLICT"
	IdempotencyInProgress Code = "IDEMPOTENCY_IN_PROGRESS"
	PayloadTooLarge       Code = "PAYLOAD_TOO_LARGE"
	UnsupportedMediaType  Code = "UNSUPPORTED_MEDIA_TYPE"
	IdempotencyKeyReused  Code = "IDEMPOTENCY_KEY_REUSED"
	PluginError           Code = "PLUGIN_ERROR"
	RateLimited           Code = "RATE_LIMITED"
	Internal              Code = "INTERNAL"
	Unavailable           Code = "UNAVAILABLE"
	InsufficientStorage   Code = "INSUFFICIENT_STORAGE"
	NodeOffline           Code = "NODE_OFFLINE"
	PluginUnavailable     Code = "PLUGIN_UNAVAILABLE"
	Timeout               Code = "TIMEOUT"
)

type codeInfo struct {
	status    int
	retryable bool
	title     string
}

var codes = map[Code]codeInfo{
	ValidationFailed:      {http.StatusBadRequest, false, "Validation failed"},
	Unauthenticated:       {http.StatusUnauthorized, false, "Authentication required"},
	MFARequired:           {http.StatusForbidden, false, "Second factor required"},
	CSRFFailed:            {http.StatusForbidden, false, "CSRF check failed"},
	PermissionDenied:      {http.StatusForbidden, false, "Permission denied"},
	ApprovalRequired:      {http.StatusForbidden, false, "Approval required"},
	NotFound:              {http.StatusNotFound, false, "Not found"},
	MethodNotAllowed:      {http.StatusMethodNotAllowed, false, "Method not allowed"},
	RevisionConflict:      {http.StatusConflict, false, "Revision conflict"},
	PreconditionFailed:    {http.StatusConflict, false, "Precondition failed"},
	PlanExpired:           {http.StatusConflict, false, "Plan expired"},
	StateConflict:         {http.StatusConflict, false, "State conflict"},
	IdempotencyInProgress: {http.StatusConflict, true, "Request with this idempotency key in progress"},
	PayloadTooLarge:       {http.StatusRequestEntityTooLarge, false, "Payload too large"},
	UnsupportedMediaType:  {http.StatusUnsupportedMediaType, false, "Unsupported media type"},
	IdempotencyKeyReused:  {http.StatusUnprocessableEntity, false, "Idempotency key reused"},
	PluginError:           {http.StatusUnprocessableEntity, false, "Plugin error"},
	RateLimited:           {http.StatusTooManyRequests, true, "Rate limited"},
	Internal:              {http.StatusInternalServerError, true, "Internal error"},
	Unavailable:           {http.StatusServiceUnavailable, true, "Service unavailable"},
	InsufficientStorage:   {http.StatusInsufficientStorage, true, "Insufficient storage"},
	NodeOffline:           {http.StatusServiceUnavailable, true, "Node offline"},
	PluginUnavailable:     {http.StatusServiceUnavailable, true, "Plugin unavailable"},
	Timeout:               {http.StatusGatewayTimeout, true, "Timeout"},
}

// Status returns the HTTP status of the code, 500 for unknown codes.
func (c Code) Status() int {
	if i, ok := codes[c]; ok {
		return i.status
	}
	return http.StatusInternalServerError
}

// Known reports whether c is one of the codes above.
func (c Code) Known() bool { _, ok := codes[c]; return ok }

// Limits from the Problem schema.
const (
	MaxViolations    = 100
	maxDetail        = 2000
	maxMessage       = 500
	maxPluginCode    = 64
	maxRetryAfterSec = 86400
)

// Violation is one field-level problem (FieldViolation).
type Violation struct {
	In      string `json:"in,omitempty"` // body (default), query, header, path
	Pointer string `json:"pointer"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// FailedPrecondition is a precondition that no longer held at execution time.
// An empty CurrentRevision means the resource no longer exists.
type FailedPrecondition struct {
	Subject          string
	ExpectedRevision string
	CurrentRevision  string
}

// Limit names the limit that was hit (PAYLOAD_TOO_LARGE, RATE_LIMITED).
type Limit struct {
	Name string `json:"name"`
	Max  int64  `json:"max"`
}

// Error is a host error with a stable code.
type Error struct {
	Code                Code
	Detail              string // English, for humans; untrusted for PLUGIN_ERROR
	Violations          []Violation
	CurrentRevision     string
	FailedPreconditions []FailedPrecondition
	OperationID         string
	NodeID              string
	EffectiveRisk       string
	Limit               *Limit
	PluginCode          string
	RetryAfterSec       int
	// Dependents names the plugins that still require the resource a
	// STATE_CONFLICT refuses to remove (GAPS gap 7).
	Dependents []string
	// Retryable overrides the code's default (used for PLUGIN_ERROR, whose
	// retryability is reported by the plugin).
	Retryable *bool
	// Cause is logged, never sent to clients.
	Cause error
}

// maxDependents bounds the dependents list of a conflict; a plugin cannot have
// more dependents than the host has plugins, but the response stays bounded.
const maxDependents = 64

// clipDependents copies at most maxDependents identifiers.
func clipDependents(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxDependents {
		in = in[:maxDependents]
	}
	return append([]string(nil), in...)
}

// New returns an error with a formatted detail.
func New(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Validation returns VALIDATION_FAILED with the given violations.
func Validation(vs ...Violation) *Error {
	return &Error{Code: ValidationFailed, Detail: "The request has invalid fields.", Violations: vs}
}

// Conflict returns REVISION_CONFLICT carrying the current revision.
func Conflict(current string) *Error {
	return &Error{Code: RevisionConflict, Detail: "The resource was modified; reload and retry with the current revision.", CurrentRevision: current}
}

// Wrap returns INTERNAL with a cause that is logged but never shown.
func Wrap(cause error) *Error {
	return &Error{Code: Internal, Detail: "An unexpected error occurred.", Cause: cause}
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Detail, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

func (e *Error) Unwrap() error { return e.Cause }

// Is matches errors with the same code, so errors.Is(err, problem.New(NotFound, ""))
// and the sentinel helpers below work.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && t.Detail == "" && t.Cause == nil
}

// Sentinel matches any *Error with code c in errors.Is.
func Sentinel(c Code) error { return &Error{Code: c} }

// HasCode reports whether err is or wraps an *Error with code c.
func HasCode(err error, c Code) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == c
}

// From converts any error to *Error. Context errors map to TIMEOUT; anything
// else unrecognized becomes INTERNAL with the original error as the cause.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: Timeout, Detail: "The operation did not finish before its deadline.", Cause: err}
	}
	return Wrap(err)
}

// FromPlugin maps a plugin ErrorDetail (ADR-0007) to a host error. Codes that
// match a host code the plugin may report keep it; all others become
// PLUGIN_ERROR with the plugin's code in plugin_code.
func FromPlugin(code, message string, retryable bool, violations []Violation) *Error {
	switch Code(code) {
	case ValidationFailed, PreconditionFailed, RevisionConflict:
		return &Error{Code: Code(code), Detail: message, Violations: violations}
	}
	r := retryable
	return &Error{Code: PluginError, Detail: message, PluginCode: code, Violations: violations, Retryable: &r}
}

// Problem is the wire form (the Problem schema).
type Problem struct {
	Type                string               `json:"type"`
	Title               string               `json:"title"`
	Status              int                  `json:"status"`
	Detail              string               `json:"detail,omitempty"`
	Instance            string               `json:"instance,omitempty"`
	Code                Code                 `json:"code"`
	Retryable           bool                 `json:"retryable"`
	RetryAfter          int                  `json:"retry_after,omitempty"`
	RequestID           string               `json:"request_id"`
	Violations          []Violation          `json:"violations,omitempty"`
	ViolationsTruncated bool                 `json:"violations_truncated,omitempty"`
	CurrentRevision     string               `json:"current_revision,omitempty"`
	FailedPreconditions []failedPrecondition `json:"failed_preconditions,omitempty"`
	OperationID         string               `json:"operation_id,omitempty"`
	NodeID              string               `json:"node_id,omitempty"`
	EffectiveRisk       string               `json:"effective_risk,omitempty"`
	Limit               *Limit               `json:"limit,omitempty"`
	PluginCode          string               `json:"plugin_code,omitempty"`
	Dependents          []string             `json:"dependents,omitempty"`
}

type failedPrecondition struct {
	Subject          string  `json:"subject"`
	ExpectedRevision string  `json:"expected_revision"`
	CurrentRevision  *string `json:"current_revision"` // null when the resource no longer exists
}

// Problem renders e for a response. Unknown codes are rendered as INTERNAL so
// a typo cannot leak an undocumented code.
func (e *Error) Problem(requestID, instance string) Problem {
	code := e.Code
	info, ok := codes[code]
	detail := e.Detail
	if !ok {
		code, info, detail = Internal, codes[Internal], "An unexpected error occurred."
	}
	p := Problem{
		Type:            "urn:qwq:problem:" + string(code),
		Title:           info.title,
		Status:          info.status,
		Detail:          clip(detail, maxDetail),
		Instance:        instance,
		Code:            code,
		Retryable:       info.retryable,
		RequestID:       requestID,
		CurrentRevision: e.CurrentRevision,
		OperationID:     e.OperationID,
		NodeID:          e.NodeID,
		EffectiveRisk:   e.EffectiveRisk,
		Limit:           e.Limit,
		PluginCode:      clip(e.PluginCode, maxPluginCode),
		Dependents:      clipDependents(e.Dependents),
	}
	if e.Retryable != nil {
		p.Retryable = *e.Retryable
	}
	if e.RetryAfterSec > 0 {
		p.RetryAfter = min(e.RetryAfterSec, maxRetryAfterSec)
	}
	vs := e.Violations
	if len(vs) > MaxViolations {
		vs, p.ViolationsTruncated = vs[:MaxViolations], true
	}
	for _, v := range vs {
		v.Message = clip(v.Message, maxMessage)
		if v.In == "body" {
			v.In = ""
		}
		p.Violations = append(p.Violations, v)
	}
	for i, f := range e.FailedPreconditions {
		if i == MaxViolations {
			break
		}
		fp := failedPrecondition{Subject: f.Subject, ExpectedRevision: f.ExpectedRevision}
		if f.CurrentRevision != "" {
			cur := f.CurrentRevision
			fp.CurrentRevision = &cur
		}
		p.FailedPreconditions = append(p.FailedPreconditions, fp)
	}
	return p
}

// Write sends err as application/problem+json and returns the rendered
// problem so the caller can log it with the cause.
func Write(w http.ResponseWriter, err error, requestID, instance string) Problem {
	e := From(err)
	p := e.Problem(requestID, instance)
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if requestID != "" {
		h.Set("X-Request-Id", requestID)
	}
	if p.RetryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(p.RetryAfter))
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
	return p
}

// clip shortens s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
