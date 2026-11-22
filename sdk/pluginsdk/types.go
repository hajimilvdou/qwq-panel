// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"encoding/json"
	"strings"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// LifecycleState is the lifecycle of one instance (platform.proto,
// LifecycleState).
type LifecycleState int

const (
	// StateInitialized: Initialize succeeded, the instance accepts nothing yet.
	StateInitialized LifecycleState = iota + 1
	// StateReady: Start succeeded; requests are served, no background work.
	StateReady
	// StateActive: Activate succeeded; background work may run.
	StateActive
	// StateDraining: Stop started; new requests are refused, in-flight ones drain.
	StateDraining
	// StateStopped: Stop finished; the instance only answers CheckHealth,
	// ReleaseInstance and GetDescriptor.
	StateStopped
	// StateFailed: a lifecycle hook or instance construction failed.
	StateFailed
)

// String returns the name used in logs and errors.
func (s LifecycleState) String() string {
	switch s {
	case StateInitialized:
		return "INITIALIZED"
	case StateReady:
		return "READY"
	case StateActive:
		return "ACTIVE"
	case StateDraining:
		return "DRAINING"
	case StateStopped:
		return "STOPPED"
	case StateFailed:
		return "FAILED"
	}
	return "UNSPECIFIED"
}

// proto converts s to the ABI enum.
func (s LifecycleState) proto() platformv1.LifecycleState {
	switch s {
	case StateInitialized:
		return platformv1.LifecycleState_LIFECYCLE_STATE_INITIALIZED
	case StateReady:
		return platformv1.LifecycleState_LIFECYCLE_STATE_READY
	case StateActive:
		return platformv1.LifecycleState_LIFECYCLE_STATE_ACTIVE
	case StateDraining:
		return platformv1.LifecycleState_LIFECYCLE_STATE_DRAINING
	case StateStopped:
		return platformv1.LifecycleState_LIFECYCLE_STATE_STOPPED
	case StateFailed:
		return platformv1.LifecycleState_LIFECYCLE_STATE_FAILED
	}
	return platformv1.LifecycleState_LIFECYCLE_STATE_UNSPECIFIED
}

// InstanceInfo is what the host told the plugin about one instance in
// Initialize, plus the SDK's per-instance handles.
//
// The struct is passed to [Plugin.NewInstance] and must be handed unchanged to
// [NewInstanceBase]. Its exported fields are a snapshot from Initialize:
// Config is the configuration at Initialize time, and [InstanceBase.Config]
// returns the currently applied snapshot after a hot apply.
type InstanceInfo struct {
	// ID is RequestContext.instance_id, unique within the plugin process.
	ID string
	// DataDir is the instance's private writable directory. Empty if the host
	// did not provide one.
	DataDir string
	// Config is the raw config JSON snapshot passed to Initialize.
	Config []byte
	// ConfigRevision is the revision of Config; empty for a brand-new instance.
	ConfigRevision string
	// StateSchemaVersion is the persisted state schema version; empty for a new
	// instance (platform.proto, InitializeRequest).
	StateSchemaVersion string
	// HostABIMinor is the ABI minor implemented by the host.
	HostABIMinor uint32

	core *instance
}

// Plugin is implemented by every plugin. NewInstance is called once per
// instance, in Initialize, and must return an object embedding
// *InstanceBase with all operations registered. It must not start background
// work: that belongs to [Activator.Activate].
//
// NewInstance may return an error to reject the instance; the host then fails
// the initialization and does not call the other lifecycle RPCs.
type Plugin interface {
	NewInstance(ctx context.Context, info InstanceInfo) (Instance, error)
}

// Instance is the opaque author object returned by [Plugin.NewInstance].
// Implementations must embed *InstanceBase; the sealed interface makes that a
// compile-time requirement.
type Instance interface {
	base() *InstanceBase
}

// Starter is an optional instance hook: the instance is ready to serve
// requests after Start returns. Requests arrive only after Start.
type Starter interface {
	Start(ctx context.Context) error
}

// Activator is an optional instance hook that starts background work. It is
// called only after the instance became ACTIVE, and ctx is the background
// context: it is canceled by Deactivate, Stop and ReleaseInstance. Long-lived
// work must watch ctx and must be started with [InstanceBase.Go] so the SDK can
// wait for it during Deactivate.
type Activator interface {
	Activate(ctx context.Context) error
}

// Deactivator is an optional instance hook called after the background
// context is canceled. Implement it to wait for work that [InstanceBase.Go]
// cannot track; ctx carries the caller's grace period.
type Deactivator interface {
	Deactivate(ctx context.Context) error
}

// Stopper is an optional instance hook for final teardown after the instance
// stopped accepting requests. ctx carries the caller's grace period.
type Stopper interface {
	Stop(ctx context.Context) error
}

// Releaser is an optional instance hook that frees the instance's resources.
// The SDK has already canceled the background context and waited for tracked
// goroutines. Host-side cleanup never depends on this hook (ARCH §5.7).
type Releaser interface {
	Release(ctx context.Context) error
}

// Config is one configuration snapshot handed to [ConfigValidator] and
// [ConfigApplier].
type Config struct {
	// JSON is the raw candidate snapshot.
	JSON []byte
	// Revision is the revision the snapshot would be stored as.
	Revision string
	// CurrentRevision is the revision currently applied, empty for none.
	CurrentRevision string
}

// ConfigValidation is the result of [ConfigValidator.ValidateConfig].
// Violations block the revision; warnings are shown but do not.
type ConfigValidation struct {
	Violations []FieldViolation
	Warnings   []FieldViolation
}

// ConfigValidator is an optional instance hook. It runs before a config
// revision is committed and must not have side effects.
type ConfigValidator interface {
	ValidateConfig(ctx context.Context, cfg Config) (ConfigValidation, error)
}

// ConfigApplier is an optional instance hook. It makes the candidate snapshot
// the applied configuration; the SDK records the revision only after it
// returns nil. The host never calls it concurrently for one instance.
type ConfigApplier interface {
	ApplyConfig(ctx context.Context, cfg Config) error
}

// Health is a plugin's domain readiness report for one instance.
type Health struct {
	// Message is a short, localized, untrusted explanation.
	Message string
	// Details is optional JSON merged into CheckHealthResponse.details_json
	// under the "plugin" key.
	Details json.RawMessage
}

// HealthReporter is an optional instance hook used by CheckHealth. Returning a
// status is not part of the interface: the SDK maps the lifecycle state to
// SERVING/NOT_SERVING, and a plugin that is not serving reports through
// Message or by failing its lifecycle hooks.
type HealthReporter interface {
	Health(ctx context.Context) Health
}

// HTTPHeader is one public route header. Names are lower-case on the wire
// (platform.proto, HttpHeader).
type HTTPHeader struct {
	Name  string
	Value string
}

// PublicRouteRequest is a public route call. The host owns TLS, rate limits and
// the route table and has already stripped Cookie, Authorization and
// Proxy-Authorization (ADR-0002, ADR-0007). Bodies are at most 4 MiB.
type PublicRouteRequest struct {
	Route    string
	Method   string
	Path     string
	RawQuery string
	Headers  []HTTPHeader
	Body     []byte
	Call     Call
}

// PublicRouteResponse is the route handler's response. A zero Status means 200.
// The host adds its security headers and strips hop-by-hop headers.
type PublicRouteResponse struct {
	Status  uint32
	Headers []HTTPHeader
	Body    []byte
}

// PublicRouteHandler is an optional instance interface. A plugin without it
// answers UNIMPLEMENTED for ServePublicRoute; the host never calls a route the
// plugin did not declare with the public.route capability.
type PublicRouteHandler interface {
	ServePublicRoute(ctx context.Context, req PublicRouteRequest) (PublicRouteResponse, error)
}

// Call is the host-supplied metadata of one call. Actor, node and trace fields
// are for logging and user-facing text only; they never authorize anything
// (platform.proto header, review C2).
type Call struct {
	RequestID   string
	OperationID string
	TraceID     string
	InstanceID  string
	NodeID      string
	Locale      string
	Actor       *platformv1.Actor
	// Attempt is the execution attempt of OperationID, starting at 1.
	Attempt uint32
	// Preconditions are the host-supplied optimistic guards of this operation
	// (updated by Execute of a plan, ADR-0004 D7).
	Preconditions []Precondition
}

// Precondition returns the first precondition for subject and whether one was
// present. Revision empty means "must not exist".
func (c Call) Precondition(subject string) (Precondition, bool) {
	for _, p := range c.Preconditions {
		if p.Subject == subject {
			return p, true
		}
	}
	return Precondition{}, false
}

// Localize picks zh when the locale starts with "zh", otherwise en. Codes stay
// language independent; only user-facing text is localized.
func Localize(locale, zh, en string) string {
	if strings.HasPrefix(strings.ToLower(locale), "zh") {
		return zh
	}
	return en
}

// FieldViolation is a field-level validation result (platform.proto,
// FieldViolation); it is also used for warnings.
type FieldViolation struct {
	// Pointer is an RFC 6901 JSON Pointer, e.g. "/inbounds/0/port".
	Pointer string
	// Code is stable and machine readable, e.g. "PORT_IN_USE".
	Code string
	// Message is localized and untrusted.
	Message string
}

// ResourceChange reports a change to a plugin-owned resource (ADR-0004 D3,
// ADR-0007). Subject is relative to the instance namespace and is validated by
// the SDK before it is sent.
type ResourceChange struct {
	Subject string
	// Revision is the revision after the change; empty when deleted.
	Revision string
	// ChangedPointers are RFC 6901 pointers within the resource; empty means
	// the whole resource changed.
	ChangedPointers []string
	Deleted         bool
}

// Precondition is an optimistic concurrency guard on a plugin-owned resource
// (ADR-0004 D2, D7). Revision empty means "must not exist".
type Precondition struct {
	Subject  string
	Revision string
}

// PlannedChangeKind says what a planned change does.
type PlannedChangeKind int

const (
	// ChangeUnspecified is invalid in a plan.
	ChangeUnspecified PlannedChangeKind = iota
	// ChangeCreate creates the subject.
	ChangeCreate
	// ChangeUpdate updates the subject.
	ChangeUpdate
	// ChangeDelete deletes the subject.
	ChangeDelete
)

// PlannedChange is one entry of a side-effect-free preview (platform.proto,
// PlannedChange).
type PlannedChange struct {
	Kind       PlannedChangeKind
	Subject    string
	Pointer    string
	Before     []byte
	After      []byte
	Reversible bool
	// Description is one line for the confirmation card, localized and
	// untrusted, at most 200 characters.
	Description string
}

// Plan is the result of a plan handler. It must not have side effects; the SDK
// refuses Host state writes while a plan is being computed.
type Plan struct {
	Changes       []PlannedChange
	Preconditions []Precondition
	Warnings      []FieldViolation
}

// Request is one operation call handed to a raw handler. Typed handlers
// registered with the HandleX helpers receive the decoded payload instead and
// can obtain Call with [CallFromContext].
type Request struct {
	Operation     string
	APIVersion    string
	Attempt       uint32
	Payload       []byte
	Preconditions []Precondition

	call Call
	host *Host
}

// Call returns the host-supplied metadata of this call.
func (r Request) Call() Call { return r.call }

// OperationID is the operation this call acts for, for HostCallContext.
func (r Request) OperationID() string { return r.call.OperationID }

// Locale is RequestContext.locale, for user-facing text.
func (r Request) Locale() string { return r.call.Locale }

// Actor is who caused the call. It is for logging only, never authorization.
func (r Request) Actor() *platformv1.Actor { return r.call.Actor }

// InstanceID is the target instance.
func (r Request) InstanceID() string { return r.call.InstanceID }

// Host returns the instance's Host client.
func (r Request) Host() *Host { return r.host }

// Decode unmarshals the JSON payload into v. An empty payload decodes as the
// zero value, so operations without a request body work.
func (r Request) Decode(v any) error {
	return decodePayload(r.Payload, r.call.Locale, v)
}

// Precondition returns the first host-supplied precondition for subject and
// whether one was present. Revision empty means "must not exist".
func (r Request) Precondition(subject string) (Precondition, bool) {
	return r.call.Precondition(subject)
}

// Response is the result of a raw invoke handler.
type Response struct {
	// Payload is the response JSON; nil means no payload.
	Payload []byte
	// Changes are plugin-owned resources changed by this call.
	Changes []ResourceChange
}

// Result is the terminal result of a raw job handler. Changes reported earlier
// with [Progress] were already sent; Changes here are sent with the terminal
// message.
type Result struct {
	// Payload is the result JSON; nil means no result.
	Payload []byte
	// Changes are reported with the terminal message.
	Changes []ResourceChange
}

// ProgressUpdate is one RunJob progress message. Zero values are omitted
// fields, except Percent, which is the percentage completed (0-100).
type ProgressUpdate struct {
	Percent   uint32
	Message   string
	Step      string
	StepIndex uint32
	StepCount uint32
	Changes   []ResourceChange
}

// Progress reports progress of one job attempt. It returns an error when the
// stream is gone or the job already finished; a handler should then stop.
// Messages are serialized by the SDK.
type Progress func(ProgressUpdate) error

// WithChanges couples a typed handler result with the resource changes it
// made. It can be the return type of any typed invoke or job handler:
//
//	return pluginsdk.WithChanges[setResponse]{
//		Value:   setResponse{Revision: rev},
//		Changes: []pluginsdk.ResourceChange{{Subject: "value", Revision: rev}},
//	}, nil
type WithChanges[T any] struct {
	Value   T
	Changes []ResourceChange
}

// encodePayload is implemented by WithChanges so the generic adapters can
// unwrap it. The interface is unexported on purpose: only WithChanges values
// are recognized, and a plugin cannot accidentally satisfy it.
type withChanges interface {
	encodeTyped() ([]byte, []ResourceChange, error)
}

func (w WithChanges[T]) encodeTyped() ([]byte, []ResourceChange, error) {
	b, err := encodeJSON(w.Value)
	return b, w.Changes, err
}
