// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// StateStore is the durable key/value state of one plugin instance. The
// built-in implementation (a JSON file below Config.StateDir) is used when
// Config.State is nil; tests and hosts with their own storage can supply one
// instead.
//
// Keys are already validated by the server ([A-Za-z0-9._/-], at most
// Limits.MaxKeyBytes); values are valid JSON no larger than
// Limits.MaxValueBytes. The store owns total-size accounting because only it
// knows the other values: it must return a *LimitError when the instance total
// would exceed Limits.MaxTotalBytes.
//
// A failed guard returns a *StateConflictError (errors.Is err
// ErrStateConflict), which the server renders as gRPC ABORTED so the SDK maps
// it to REVISION_CONFLICT.
type StateStore interface {
	// Get returns the entry and whether it exists. A missing key is not an
	// error.
	Get(ctx context.Context, key string) (StateEntry, bool, error)
	// Put stores valueJSON and returns its new revision. An empty
	// ExpectedRevision means "the key must not exist" (the same guard as
	// MustNotExist); an unset StateGuard means an unconditional write.
	Put(ctx context.Context, key string, valueJSON []byte, guard StateGuard) (revision string, err error)
	// Delete removes key. An empty expectedRevision is an unconditional
	// delete of a possibly absent key; a non-empty one is a compare-and-swap
	// that fails when the key is absent or has another revision.
	Delete(ctx context.Context, key, expectedRevision string) error
	// List returns keys in byte order, starting after pageToken. pageSize is
	// already clamped to Limits.MaxPageSize. An empty NextPageToken means the
	// last page.
	List(ctx context.Context, prefix, pageToken string, pageSize int, includeValues bool) (StatePage, error)
}

// StateGuard is the optimistic concurrency guard of a write. MustNotExist wins
// when both fields are set. The zero value is an unconditional write.
type StateGuard struct {
	MustNotExist     bool
	ExpectedRevision string
}

// StateEntry is one stored value.
type StateEntry struct {
	Key      string
	Revision string
	// Value is only set by Get and by a List that asked for values.
	Value []byte
}

// StatePage is one page of List.
type StatePage struct {
	Entries       []StateEntry
	NextPageToken string
}

// ErrStateConflict matches every failed compare-and-swap of a StateStore.
var ErrStateConflict = errors.New("hostsvc: state revision conflict")

// StateConflictError is a failed StateStore guard. Current is empty when the
// key does not exist.
type StateConflictError struct {
	Key     string
	Current string
}

// Error implements error.
func (e *StateConflictError) Error() string {
	return fmt.Sprintf("hostsvc: state key %q changed (current revision %q)", e.Key, e.Current)
}

// Is matches ErrStateConflict.
func (e *StateConflictError) Is(target error) bool { return target == ErrStateConflict }

// LimitError reports that a bounded resource is exhausted: a message or value
// size, the event spool, an audit quota, a subscription count or a rate limit.
// The server maps it to gRPC RESOURCE_EXHAUSTED.
type LimitError struct {
	Name string
	Max  int64
}

// Error implements error.
func (e *LimitError) Error() string {
	return fmt.Sprintf("hostsvc: %s limit exceeded (max %d)", e.Name, e.Max)
}

// EventDraft is a plugin-controlled event handed to the EventSink. EventID,
// sequence, time, actor and delivery class are assigned by the host.
type EventDraft struct {
	// Type is dotted, e.g. "security.alert". Types starting with "resource."
	// or "operation." are reserved for the host and rejected by the server.
	Type          string
	SchemaVersion string
	// Subject is a relative subject; the sink prefixes it with the instance
	// namespace before it reaches the journal.
	Subject     string
	PayloadJSON []byte
	// OperationID and TraceID are copied from HostCallContext for log and
	// audit correlation. They never authorize anything.
	OperationID string
	TraceID     string
}

// EventRef identifies the journal entry the sink created for a draft.
type EventRef struct {
	EventID  string
	Sequence uint64
}

// ResourceChange is a change to a plugin-owned resource (ADR-0004 D3). Subject
// is relative; the sink turns it into a resource.changed event with the full
// subject, actor and operation.
type ResourceChange struct {
	Subject         string
	Revision        string
	ChangedPointers []string
	Deleted         bool
}

// ChangeSet is one ReportChanges call. OperationID and TraceID come from
// HostCallContext and are correlation data only.
type ChangeSet struct {
	OperationID string
	TraceID     string
	Changes     []ResourceChange
}

// EventSink is the host side of the event service. Publish must be safe for
// concurrent use with ack and report calls of the same instance; the server
// serializes Publish through its spool and calls the other methods from their
// handlers.
//
// Publish returns the journal identity of the accepted event. An error means
// the event was not accepted; the server reports UNAVAILABLE (or the mapped
// domain status) to the plugin.
type EventSink interface {
	Publish(ctx context.Context, draft EventDraft) (EventRef, error)
	ReportChanges(ctx context.Context, set ChangeSet) error
	// Ack is cumulative: every reliable event of subscription up to and
	// including sequence is acknowledged.
	Ack(ctx context.Context, subscription string, sequence uint64) error
}

// ConfigSource provides the currently applied config snapshot of the instance.
// The JSON must be valid; rev is the applied revision and is opaque.
type ConfigSource interface {
	Current(ctx context.Context) (rev string, configJSON []byte, err error)
}

// SecretRevealer decrypts one secret reference for a dispatched operation. It
// must verify real dispatch, current permission, the declared capability and
// original sensitive argument membership for operation scope. grantedScopes is
// selected by the host from signed grants; request purpose is only audit text.
// Implementations must not put secret material into their error messages.
//
// Errors may be plain errors, in which case the server maps the exported
// sentinels below, or a gRPC status, whose code and message pass through.
type SecretRevealer interface {
	Reveal(ctx context.Context, ref, operationID string, grantedScopes []string) ([]byte, error)
}

// Secret reveal sentinels a SecretRevealer may wrap to select a status code.
var (
	// ErrSecretDenied maps to PERMISSION_DENIED (missing capability, secret
	// not assigned to this instance).
	ErrSecretDenied = errors.New("hostsvc: secret access denied")
	// ErrOperationNotDispatched maps to FAILED_PRECONDITION (unknown
	// operation, another instance's operation, or an operation that already
	// finished).
	ErrOperationNotDispatched = errors.New("hostsvc: operation is not dispatched to this instance")
	// ErrRateLimited maps to RESOURCE_EXHAUSTED.
	ErrRateLimited = errors.New("hostsvc: rate limited")
)

// AuditOutcome is the plugin-visible outcome of an audited action. The values
// match the names of the proto enum.
type AuditOutcome string

// Audit outcomes.
const (
	AuditUnspecified AuditOutcome = ""
	AuditSuccess     AuditOutcome = "SUCCESS"
	AuditFailure     AuditOutcome = "FAILURE"
	AuditDenied      AuditOutcome = "DENIED"
)

// AuditRecord is one plugin-written audit entry. The host fills actor, source,
// time and plugin identity; PluginID, InstanceID, OccurredAt and Source are
// set by the server, so a plugin cannot impersonate another component.
type AuditRecord struct {
	Action      string
	Subject     string
	Outcome     AuditOutcome
	DetailsJSON []byte
	// PluginID, InstanceID, OperationID, TraceID and OccurredAt are filled by
	// the server from Config, HostCallContext and Clock.
	PluginID    string
	InstanceID  string
	OperationID string
	TraceID     string
	// Source is "plugin" for records that came from the ABI.
	Source     string
	OccurredAt time.Time
}

// AuditSink persists audit records. It must not return an error for a record it
// stored; the server logs and maps errors (quota errors stay
// RESOURCE_EXHAUSTED).
type AuditSink interface {
	Write(ctx context.Context, record AuditRecord) error
}

// OperationState is the lifecycle state of a host operation (ADR-0004 D7). The
// values match the proto enum names.
type OperationState string

// Operation states.
const (
	OperationUnspecified OperationState = ""
	OperationPending     OperationState = "PENDING"
	OperationAwaiting    OperationState = "AWAITING_APPROVAL"
	OperationApproved    OperationState = "APPROVED"
	OperationRejected    OperationState = "REJECTED"
	OperationExpired     OperationState = "EXPIRED"
	OperationRunning     OperationState = "RUNNING"
	OperationSucceeded   OperationState = "SUCCEEDED"
	OperationFailed      OperationState = "FAILED"
	OperationCanceled    OperationState = "CANCELED"
)

// DomainError is a domain failure of an InvokePlugin call that reached the
// handler. It becomes the ErrorDetail of the response while the gRPC status
// stays OK (platform.proto, "Errors").
type DomainError struct {
	Code        string
	Message     string
	Retryable   bool
	DetailsJSON []byte
}

// Progress is the latest progress of a job operation.
type Progress struct {
	// Percent is 0-100; 0 means unknown.
	Percent   int
	Step      string
	StepIndex int
	StepCount int
	Message   string
}

// InvokeCall is one host-mediated plugin-to-plugin call. CallerPluginID and
// CallerInstanceID are host-known facts from Config, not values a plugin sent;
// ParentOperationID and TraceID are correlation data from HostCallContext and
// must be validated by the Invoker before they are trusted.
type InvokeCall struct {
	CallerPluginID    string
	CallerInstanceID  string
	ParentOperationID string
	TraceID           string

	TargetPluginID   string
	TargetInstanceID string
	TargetNodeID     string
	Operation        string
	APIVersion       string
	PayloadJSON      []byte
	IdempotencyKey   string
}

// InvokeResult is the outcome of an InvokePlugin call. Exactly one of
// PayloadJSON / Error / OperationID is meaningful; the server copies the
// fields into the response as they are.
type InvokeResult struct {
	PayloadJSON []byte
	Error       *DomainError
	OperationID string
	State       OperationState
}

// WaitCall asks the Invoker to wait for an operation this instance created.
// Timeout is already capped by Limits.WaitTimeout and by the gRPC deadline; 0
// returns the current state without waiting.
type WaitCall struct {
	CallerPluginID   string
	CallerInstanceID string
	OperationID      string
	Timeout          time.Duration
}

// OperationSnapshot is the state of one operation at the time of a WaitCall.
type OperationSnapshot struct {
	State      OperationState
	ResultJSON []byte
	Error      *DomainError
	Progress   *Progress
}

// CancelCall asks the Invoker to cancel an operation this instance created.
type CancelCall struct {
	CallerPluginID   string
	CallerInstanceID string
	OperationID      string
}

// Invoker is the host side of plugin-to-plugin calls. It owns capability
// checks, schema validation, routing and the operation state machine; the
// server only validates the message shape. The Caller* fields are the
// authoritative caller identity.
type Invoker interface {
	InvokePlugin(ctx context.Context, call InvokeCall) (InvokeResult, error)
	WaitOperation(ctx context.Context, call WaitCall) (OperationSnapshot, error)
	CancelOperation(ctx context.Context, call CancelCall) (OperationState, error)
}

// PeerVerifier decides whether the process that connected to the host socket is
// the plugin instance this listener serves. It is called on the accepted
// connection, before any RPC is handled, with the kernel-provided SO_PEERCRED
// values; a non-nil error closes the connection.
//
// The production implementation reads /proc/<pid>/cgroup, compares the unit
// with the one systemd reports for the instance and checks the uid; see
// REPORT.md. The server never falls back to a self-reported identity when the
// verifier fails.
type PeerVerifier interface {
	Verify(pid, uid int) error
}

// PeerInfo is the kernel-verified identity of the process at the other end of
// the host socket. It is the only trusted caller identity of a Host service
// call; HostCallContext fields are not.
type PeerInfo struct {
	PID int
	UID int
	GID int
	// PIDFD reports that SO_PEERPIDFD was available while the peer was
	// verified, so the kernel guarantees the pid was not reused during the
	// check (Linux >= 6.5).
	PIDFD bool
}

type peerKey struct{}

// PeerFromContext returns the peer identity the connection interceptor
// installed. Handlers use it for logging and for host-side policy; it is
// always present for an RPC that reached a handler.
func PeerFromContext(ctx context.Context) (PeerInfo, bool) {
	info, ok := ctx.Value(peerKey{}).(PeerInfo)
	return info, ok
}

// withPeer stores info in ctx.
func withPeer(ctx context.Context, info PeerInfo) context.Context {
	return context.WithValue(ctx, peerKey{}, info)
}

// operationStateProto maps a domain state to the ABI enum. Unknown states map
// to OPERATION_STATE_UNSPECIFIED, which tells a plugin not to classify them.
func operationStateProto(state OperationState) platformv1.OperationState {
	switch state {
	case OperationPending:
		return platformv1.OperationState_OPERATION_STATE_PENDING
	case OperationAwaiting:
		return platformv1.OperationState_OPERATION_STATE_AWAITING_APPROVAL
	case OperationApproved:
		return platformv1.OperationState_OPERATION_STATE_APPROVED
	case OperationRejected:
		return platformv1.OperationState_OPERATION_STATE_REJECTED
	case OperationExpired:
		return platformv1.OperationState_OPERATION_STATE_EXPIRED
	case OperationRunning:
		return platformv1.OperationState_OPERATION_STATE_RUNNING
	case OperationSucceeded:
		return platformv1.OperationState_OPERATION_STATE_SUCCEEDED
	case OperationFailed:
		return platformv1.OperationState_OPERATION_STATE_FAILED
	case OperationCanceled:
		return platformv1.OperationState_OPERATION_STATE_CANCELED
	default:
		return platformv1.OperationState_OPERATION_STATE_UNSPECIFIED
	}
}

// domainErrorProto renders a DomainError as the ABI ErrorDetail.
func domainErrorProto(e *DomainError) *platformv1.ErrorDetail {
	if e == nil {
		return nil
	}
	return &platformv1.ErrorDetail{
		Code:        clipString(e.Code, 64),
		Message:     clipString(e.Message, 500),
		Retryable:   e.Retryable,
		DetailsJson: append([]byte(nil), e.DetailsJSON...),
	}
}

// progressProto renders a domain progress report as the ABI message.
func progressProto(p *Progress) *platformv1.JobProgress {
	if p == nil {
		return nil
	}
	percent := max(0, min(p.Percent, 100))
	return &platformv1.JobProgress{
		Percent:   uint32(percent),
		Message:   clipString(p.Message, 500),
		Step:      clipString(p.Step, 64),
		StepIndex: uint32(max(0, p.StepIndex)),
		StepCount: uint32(max(0, p.StepCount)),
	}
}

// auditOutcomeFromProto validates a plugin-supplied enum value. Unknown numeric
// values are rejected: appending an outcome in a later ABI minor must not be
// silently written as UNSPECIFIED.
func auditOutcomeFromProto(outcome platformv1.AuditOutcome) (AuditOutcome, bool) {
	switch outcome {
	case platformv1.AuditOutcome_AUDIT_OUTCOME_UNSPECIFIED:
		return AuditUnspecified, true
	case platformv1.AuditOutcome_AUDIT_OUTCOME_SUCCESS:
		return AuditSuccess, true
	case platformv1.AuditOutcome_AUDIT_OUTCOME_FAILURE:
		return AuditFailure, true
	case platformv1.AuditOutcome_AUDIT_OUTCOME_DENIED:
		return AuditDenied, true
	default:
		return "", false
	}
}
