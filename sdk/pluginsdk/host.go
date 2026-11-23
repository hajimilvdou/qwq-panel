// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Host is the Host Service client of one instance. It is created by the SDK at
// Initialize and is available as [InstanceBase.Host] and [Request.Host].
//
// Every call fills HostCallContext automatically: instance_handle from
// Initialize, operation_id and trace_id from the call being served (or from
// Activate for background work). The instance identity therefore never comes
// from a message field the plugin can choose (review C2).
type Host struct {
	conn   grpc.ClientConnInterface
	handle string
}

// ErrNoHost is returned when the plugin was started without a Host connection.
// It is a domain error with the stable code NO_HOST; [errors.Is] matches it.
var ErrNoHost = &Error{Code: "NO_HOST", Message: "the plugin was started without a Host Service connection"}

// callContext builds the HostCallContext for one call. write marks RPCs that
// modify host state; they are refused while a PlanOperation is running so a
// plan stays side-effect free (ADR-0004 D7).
func (h *Host) callContext(ctx context.Context, write bool) (*platformv1.HostCallContext, error) {
	if h == nil || h.conn == nil {
		return nil, ErrNoHost
	}
	ci, _ := callInfoOf(ctx)
	if write && ci.planning {
		return nil, &Error{Code: "PLAN_SIDE_EFFECT", Message: "host state must not be written while planning an operation"}
	}
	return &platformv1.HostCallContext{
		InstanceHandle: h.handle,
		OperationId:    ci.call.OperationID,
		TraceId:        ci.call.TraceID,
	}, nil
}

// Conn returns the host channel connection of this instance. Capability
// clients are constructed on it, e.g.
// metricsv1.NewMetricsServiceClient(host.Conn()); the plugin token is attached
// to every call automatically (ADR-0013, ADR-0019 decision 1). It returns nil
// when the plugin was started without a Host connection (see [ErrNoHost]).
// The connection is owned by the SDK and must not be closed by the plugin.
func (h *Host) Conn() grpc.ClientConnInterface {
	if h == nil {
		return nil
	}
	return h.conn
}

// CapabilityContext builds the HostCallContext for a capability RPC
// (ADR-0019 decision 1): instance_handle, operation_id and trace_id are filled
// from the call being served, exactly like the built-in Host calls. Capability
// contexts are treated as writes: the SDK cannot verify that a raw capability
// RPC is read-only, so they are refused with PLAN_SIDE_EFFECT while a
// PlanOperation is running, keeping plans side-effect free (ADR-0004 D7).
func (h *Host) CapabilityContext(ctx context.Context) (*platformv1.HostCallContext, error) {
	return h.callContext(ctx, true)
}

// AutonomousOperationPrefix is the reserved operation_id prefix used by an
// active background plugin instance (manifest.lifecycle.background == true)
// when performing guarded autonomous host capability writes (such as brute-force
// IP banning, SSH port timeout rollback, or periodic traffic quota enforcement).
const AutonomousOperationPrefix = "auton:"

// CapabilityContextAutonomous builds a HostCallContext for background daemon
// goroutines started inside Activate via InstanceBase.Go. If ctx already carries
// a dispatched OperationID it is preserved; otherwise "auton:<reason>" is used
// so the host can evaluate its autonomous write allowlist and rate limits.
// Calling it during PlanOperation always fails with PLAN_SIDE_EFFECT.
func (h *Host) CapabilityContextAutonomous(ctx context.Context, reason string) (*platformv1.HostCallContext, error) {
	if h == nil || h.conn == nil {
		return nil, ErrNoHost
	}
	ci, _ := callInfoOf(ctx)
	if ci.planning {
		return nil, &Error{Code: "PLAN_SIDE_EFFECT", Message: "host state must not be written while planning an operation"}
	}
	opID := ci.call.OperationID
	if opID == "" {
		cleanReason := strings.TrimSpace(reason)
		if cleanReason == "" {
			cleanReason = "background"
		}
		for i := 0; i < len(cleanReason); i++ {
			c := cleanReason[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
				return nil, &Error{Code: "INVALID_AUTONOMOUS_REASON", Message: "invalid autonomous capability reason"}
			}
		}
		opID = AutonomousOperationPrefix + cleanReason
	}
	return &platformv1.HostCallContext{
		InstanceHandle: h.handle,
		OperationId:    opID,
		TraceId:        ci.call.TraceID,
	}, nil
}

// CapabilityContextReadOnly 构造只读能力上下文，允许 Plan 读取宿主事实。
// 该方法不授予写权限；宿主按真实 RPC effect 和 operation 派发状态校验写入。
func (h *Host) CapabilityContextReadOnly(ctx context.Context) (*platformv1.HostCallContext, error) {
	return h.callContext(ctx, false)
}

// GetState reads one key. found is false for a missing key; that is not an
// error.
func (h *Host) GetState(ctx context.Context, key string) (value []byte, revision string, found bool, err error) {
	hc, err := h.callContext(ctx, false)
	if err != nil {
		return nil, "", false, err
	}
	resp, err := platformv1.NewHostStateServiceClient(h.conn).GetState(ctx, &platformv1.GetStateRequest{Context: hc, Key: key})
	if err != nil {
		return nil, "", false, errorFromStatus(err)
	}
	return resp.GetValueJson(), resp.GetRevision(), resp.GetFound(), nil
}

// PutOption is the optimistic concurrency guard of a PutState call. The zero
// value is an unconditional write. MustNotExist wins when both fields are set.
type PutOption struct {
	MustNotExist     bool
	ExpectedRevision string
}

// PutState writes one key and returns its new revision. A failed guard is
// reported as REVISION_CONFLICT; use [IsConflict] to detect it.
func (h *Host) PutState(ctx context.Context, key string, valueJSON []byte, opt PutOption) (string, error) {
	hc, err := h.callContext(ctx, true)
	if err != nil {
		return "", err
	}
	req := &platformv1.PutStateRequest{Context: hc, Key: key, ValueJson: valueJSON}
	switch {
	case opt.MustNotExist:
		req.Precondition = &platformv1.PutStateRequest_MustNotExist{MustNotExist: true}
	case opt.ExpectedRevision != "":
		req.Precondition = &platformv1.PutStateRequest_ExpectedRevision{ExpectedRevision: opt.ExpectedRevision}
	}
	resp, err := platformv1.NewHostStateServiceClient(h.conn).PutState(ctx, req)
	if err != nil {
		return "", errorFromStatus(err)
	}
	return resp.GetRevision(), nil
}

// DeleteState deletes one key. expectedRevision empty means an unconditional
// delete; a mismatch is reported as REVISION_CONFLICT.
func (h *Host) DeleteState(ctx context.Context, key, expectedRevision string) error {
	hc, err := h.callContext(ctx, true)
	if err != nil {
		return err
	}
	_, err = platformv1.NewHostStateServiceClient(h.conn).DeleteState(ctx,
		&platformv1.DeleteStateRequest{Context: hc, Key: key, ExpectedRevision: expectedRevision})
	return errorFromStatus(err)
}

// ListState returns one page. pageToken empty starts at the beginning; pageSize
// 0 means 100 (the host caps it at 1000). Use [KV.Each] to iterate all pages.
func (h *Host) ListState(ctx context.Context, prefix, pageToken string, pageSize uint32, includeValues bool) (*platformv1.ListStateResponse, error) {
	hc, err := h.callContext(ctx, false)
	if err != nil {
		return nil, err
	}
	resp, err := platformv1.NewHostStateServiceClient(h.conn).ListState(ctx, &platformv1.ListStateRequest{
		Context: hc, Prefix: prefix, PageToken: pageToken, PageSize: pageSize, IncludeValues: includeValues,
	})
	if err != nil {
		return nil, errorFromStatus(err)
	}
	return resp, nil
}

// EventDraft is a plugin-controlled event. event_id, sequence, time, actor and
// delivery class are assigned by the host.
type EventDraft struct {
	// Type is dotted, e.g. "security.alert". Types starting with "resource."
	// or "operation." are reserved for the host and are rejected here.
	Type          string
	SchemaVersion string
	Subject       string // relative subject
	Payload       []byte
}

// PublishEvent publishes one event and returns its host-assigned id and
// sequence.
func (h *Host) PublishEvent(ctx context.Context, draft EventDraft) (*platformv1.PublishEventResponse, error) {
	hc, err := h.callContext(ctx, true)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(draft.Type, "resource.") || strings.HasPrefix(draft.Type, "operation.") {
		return nil, &Error{Code: "PROTOCOL_ERROR", Message: "event types starting with resource. or operation. are reserved for the host"}
	}
	if err := validateEventSubject(draft.Subject); err != nil {
		return nil, err
	}
	resp, err := platformv1.NewHostEventsServiceClient(h.conn).PublishEvent(ctx, &platformv1.PublishEventRequest{
		Context: hc,
		Event: &platformv1.EventDraft{
			Type: draft.Type, SchemaVersion: draft.SchemaVersion, Subject: draft.Subject,
			PayloadJson: draft.Payload,
		},
	})
	if err != nil {
		return nil, errorFromStatus(err)
	}
	return resp, nil
}

// SubscribeEvents opens the event stream. The returned stream must be consumed
// with Recv; use [Host.ConsumeEvents] to handle acknowledgements. lastAcked 0
// resumes from the cursor the host stored for this subscription.
func (h *Host) SubscribeEvents(ctx context.Context, subscription string, topics []string, lastAcked uint64) (grpc.ServerStreamingClient[platformv1.SubscribeEventsResponse], error) {
	hc, err := h.callContext(ctx, false)
	if err != nil {
		return nil, err
	}
	stream, err := platformv1.NewHostEventsServiceClient(h.conn).SubscribeEvents(ctx, &platformv1.SubscribeEventsRequest{
		Context: hc, Topics: topics, LastAckedSequence: lastAcked, Subscription: subscription,
	})
	if err != nil {
		return nil, errorFromStatus(err)
	}
	return stream, nil
}

// ConsumeEvents subscribes and calls fn for every event, acknowledging each
// reliable event after fn returned nil (cumulative ack). It returns nil when
// the stream ends, after the final ack, or when ctx is canceled.
func (h *Host) ConsumeEvents(ctx context.Context, subscription string, topics []string, lastAcked uint64, fn func(*platformv1.Event) error) error {
	stream, err := h.SubscribeEvents(ctx, subscription, topics, lastAcked)
	if err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errorFromStatus(err)
		}
		event := msg.GetEvent()
		if err := fn(event); err != nil {
			return err
		}
		if err := h.AckEvents(ctx, subscription, event.GetSequence()); err != nil {
			return err
		}
	}
}

// AckEvents acknowledges every reliable event of subscription up to and
// including sequence.
func (h *Host) AckEvents(ctx context.Context, subscription string, sequence uint64) error {
	hc, err := h.callContext(ctx, false)
	if err != nil {
		return err
	}
	_, err = platformv1.NewHostEventsServiceClient(h.conn).AckEvents(ctx,
		&platformv1.AckEventsRequest{Context: hc, Subscription: subscription, Sequence: sequence})
	return errorFromStatus(err)
}

// ReportChanges publishes resource changes made outside Invoke and RunJob,
// e.g. by a timer after Activate (ADR-0004 D3). Subjects are validated first.
func (h *Host) ReportChanges(ctx context.Context, changes ...ResourceChange) error {
	if err := validateChanges(changes); err != nil {
		return err
	}
	hc, err := h.callContext(ctx, true)
	if err != nil {
		return err
	}
	_, err = platformv1.NewHostEventsServiceClient(h.conn).ReportChanges(ctx,
		&platformv1.ReportChangesRequest{Context: hc, Changes: changesToProto(changes)})
	return errorFromStatus(err)
}

// GetConfig reads this instance's config snapshot. revision empty means the
// currently applied revision.
func (h *Host) GetConfig(ctx context.Context, revision string) (configJSON []byte, appliedRevision string, err error) {
	hc, err := h.callContext(ctx, false)
	if err != nil {
		return nil, "", err
	}
	resp, err := platformv1.NewHostConfigServiceClient(h.conn).GetConfig(ctx,
		&platformv1.GetConfigRequest{Context: hc, Revision: revision})
	if err != nil {
		return nil, "", errorFromStatus(err)
	}
	return resp.GetConfigJson(), resp.GetRevision(), nil
}

// RevealSecret reveals one secret. It needs the secret.reveal capability and a
// currently dispatched operation, so it fails when the call context has no
// operation_id. Every call is audited and rate limited by the host; prefer
// host-performed actions (ARCH §5.6).
func (h *Host) RevealSecret(ctx context.Context, secretRef, purpose string) ([]byte, error) {
	hc, err := h.callContext(ctx, false)
	if err != nil {
		return nil, err
	}
	if hc.GetOperationId() == "" {
		return nil, &Error{Code: "MISSING_OPERATION_ID", Message: "RevealSecret requires a dispatched operation"}
	}
	resp, err := platformv1.NewHostSecretsServiceClient(h.conn).RevealSecret(ctx,
		&platformv1.RevealSecretRequest{Context: hc, SecretRef: secretRef, Purpose: purpose})
	if err != nil {
		return nil, errorFromStatus(err)
	}
	return resp.GetValue(), nil
}

// AuditRecord is a plugin-written audit entry. The host fills actor, time and
// plugin identity and marks source=plugin.
type AuditRecord struct {
	Action  string
	Subject string
	Outcome platformv1.AuditOutcome
	Details []byte
}

// WriteAudit writes one audit record. Auditing has its own quota (review S10).
func (h *Host) WriteAudit(ctx context.Context, record AuditRecord) error {
	hc, err := h.callContext(ctx, false)
	if err != nil {
		return err
	}
	_, err = platformv1.NewHostAuditServiceClient(h.conn).WriteAudit(ctx, &platformv1.WriteAuditRequest{
		Context: hc,
		Record: &platformv1.AuditRecord{
			Action: record.Action, Subject: record.Subject, Outcome: record.Outcome, DetailsJson: record.Details,
		},
	})
	return errorFromStatus(err)
}

// InvokeRequest is a plugin-to-plugin call (review C3). It is point to point and
// host mediated: the host checks plugin.invoke:<plugin_id>/<operation>, validates
// the schema, propagates the deadline, audits and routes to the ACTIVE
// generation.
type InvokeRequest struct {
	TargetPluginID   string
	TargetInstanceID string
	// TargetNodeID empty means the caller's node. Only placement=controller
	// plugins may target another node.
	TargetNodeID string
	Operation    string
	APIVersion   string
	Payload      []byte
	// IdempotencyKey deduplicates retries of this call; scoped to the calling
	// instance. An invoke-mode parent can use its operation_id.
	IdempotencyKey string
}

// InvokePlugin calls another plugin through the host.
func (h *Host) InvokePlugin(ctx context.Context, req InvokeRequest) (*platformv1.InvokePluginResponse, error) {
	hc, err := h.callContext(ctx, true)
	if err != nil {
		return nil, err
	}
	resp, err := platformv1.NewHostInvokeServiceClient(h.conn).InvokePlugin(ctx, &platformv1.InvokePluginRequest{
		Context:          hc,
		TargetPluginId:   req.TargetPluginID,
		TargetInstanceId: req.TargetInstanceID,
		TargetNodeId:     req.TargetNodeID,
		Operation:        req.Operation,
		ApiVersion:       req.APIVersion,
		PayloadJson:      req.Payload,
		IdempotencyKey:   req.IdempotencyKey,
	})
	if err != nil {
		return nil, errorFromStatus(err)
	}
	return resp, nil
}

// WaitOperation waits once for an operation this instance created with
// InvokePlugin. timeout 0 returns the current state immediately; the host caps
// the wait at 60 s and at the gRPC deadline.
func (h *Host) WaitOperation(ctx context.Context, operationID string, timeout time.Duration) (*platformv1.WaitOperationResponse, error) {
	hc, err := h.callContext(ctx, false)
	if err != nil {
		return nil, err
	}
	ms := uint32(0)
	if timeout > 0 {
		ms = uint32(timeout.Milliseconds())
	}
	if ms > 60000 {
		// The host caps the wait at 60 s anyway (platform.proto, WaitOperation).
		ms = 60000
	}
	resp, err := platformv1.NewHostInvokeServiceClient(h.conn).WaitOperation(ctx, &platformv1.WaitOperationRequest{
		Context: hc, OperationId: operationID, TimeoutMs: ms,
	})
	if err != nil {
		return nil, errorFromStatus(err)
	}
	return resp, nil
}

// AwaitOperation long-polls WaitOperation until the operation reaches a
// terminal state, needs approval, or the state is unknown to this ABI minor.
// The unknown-state rule is deliberate: a newer minor's state cannot be
// classified by this SDK, so the caller decides (see REPORT.md).
func (h *Host) AwaitOperation(ctx context.Context, operationID string) (*platformv1.WaitOperationResponse, error) {
	for {
		resp, err := h.WaitOperation(ctx, operationID, 30*time.Second)
		if err != nil {
			return nil, err
		}
		switch resp.GetState() {
		case platformv1.OperationState_OPERATION_STATE_PENDING,
			platformv1.OperationState_OPERATION_STATE_APPROVED,
			platformv1.OperationState_OPERATION_STATE_RUNNING:
			continue
		}
		return resp, nil
	}
}

// CancelOperation cancels an operation this instance created.
func (h *Host) CancelOperation(ctx context.Context, operationID string) (platformv1.OperationState, error) {
	hc, err := h.callContext(ctx, true)
	if err != nil {
		return platformv1.OperationState_OPERATION_STATE_UNSPECIFIED, err
	}
	resp, err := platformv1.NewHostInvokeServiceClient(h.conn).CancelOperation(ctx,
		&platformv1.CancelOperationRequest{Context: hc, OperationId: operationID})
	if err != nil {
		return platformv1.OperationState_OPERATION_STATE_UNSPECIFIED, errorFromStatus(err)
	}
	return resp.GetState(), nil
}

// KV returns the typed state helpers of this instance.
func (h *Host) KV() *KV { return &KV{host: h} }

// KV is the typed wrapper over HostStateService. Values are JSON documents of
// at most 1 MiB; keys are namespaced to the calling instance by the host.
type KV struct{ host *Host }

// StateEntry is one ListState entry.
type StateEntry struct {
	Key      string
	Revision string
	// Value is only set when the listing asked for values.
	Value []byte
}

// GetJSON reads key into v. found is false for a missing key; that is not an
// error. v may be nil to only fetch the revision.
func (kv *KV) GetJSON(ctx context.Context, key string, v any) (revision string, found bool, err error) {
	value, revision, found, err := kv.host.GetState(ctx, key)
	if err != nil || !found {
		return revision, found, err
	}
	if v == nil {
		return revision, true, nil
	}
	if err := json.Unmarshal(value, v); err != nil {
		return revision, true, &Error{Code: "PROTOCOL_ERROR", Message: "the host returned a value that is not the expected JSON"}
	}
	return revision, true, nil
}

// PutJSON marshals v and writes key with the guard opt.
func (kv *KV) PutJSON(ctx context.Context, key string, v any, opt PutOption) (string, error) {
	value, err := jsonValue(v)
	if err != nil {
		return "", err
	}
	return kv.host.PutState(ctx, key, value, opt)
}

// Delete deletes key; expectedRevision empty is unconditional.
func (kv *KV) Delete(ctx context.Context, key, expectedRevision string) error {
	return kv.host.DeleteState(ctx, key, expectedRevision)
}

// Each iterates every entry with prefix across pages. fn returning an error
// stops the iteration and returns that error.
func (kv *KV) Each(ctx context.Context, prefix string, pageSize uint32, includeValues bool, fn func(StateEntry) error) error {
	token := ""
	seen := map[string]bool{}
	for {
		resp, err := kv.host.ListState(ctx, prefix, token, pageSize, includeValues)
		if err != nil {
			return err
		}
		for _, e := range resp.GetEntries() {
			entry := StateEntry{Key: e.GetKey(), Revision: e.GetRevision(), Value: e.GetValueJson()}
			if err := fn(entry); err != nil {
				return err
			}
		}
		next := resp.GetNextPageToken()
		if next == "" {
			return nil
		}
		if seen[next] {
			return &Error{Code: "PROTOCOL_ERROR", Message: "the host returned the same ListState page token twice"}
		}
		seen[next] = true
		token = next
	}
}

// List collects every entry with prefix, including values. The host cuts pages
// by bytes, but a host limit can still refuse a page: with large values pass a
// small pageSize, or use [KV.Each] without values.
func (kv *KV) List(ctx context.Context, prefix string, pageSize uint32) ([]StateEntry, error) {
	var out []StateEntry
	err := kv.Each(ctx, prefix, pageSize, true, func(e StateEntry) error {
		out = append(out, e)
		return nil
	})
	return out, err
}

// jsonValue marshals a KV value. A json.RawMessage must already be valid JSON.
func jsonValue(v any) ([]byte, error) {
	if raw, ok := v.(json.RawMessage); ok {
		if !json.Valid(raw) {
			return nil, &Error{Code: "VALIDATION_FAILED", Message: "the value is not valid JSON"}
		}
		return append([]byte(nil), raw...), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, &Error{Code: "VALIDATION_FAILED", Message: "the value cannot be encoded as JSON"}
	}
	return b, nil
}
