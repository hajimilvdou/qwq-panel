// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"time"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// maxIdempotencyKey bounds the deduplication key of an InvokePlugin call.
const maxIdempotencyKey = 128

// invokeService implements HostInvokeService. The server validates only the
// message shape; the Invoker owns capability checks, schema validation, routing
// to the ACTIVE generation and the operation state machine. The caller identity
// passed to the Invoker comes from Config and the verified peer, never from
// HostCallContext, so a plugin cannot invoke on behalf of another instance.
type invokeService struct {
	platformv1.UnimplementedHostInvokeServiceServer
	s *Server
}

// InvokePlugin mediates one plugin-to-plugin call.
func (x *invokeService) InvokePlugin(ctx context.Context, req *platformv1.InvokePluginRequest) (*platformv1.InvokePluginResponse, error) {
	if x.s.cfg.Invoke == nil {
		return nil, unavailable("plugin invocation")
	}
	if err := validateInvokeRequest(req, x.s.lim); err != nil {
		return nil, err
	}
	meta := callMetaOf(req.GetContext())
	result, err := x.s.cfg.Invoke.InvokePlugin(ctx, InvokeCall{
		CallerPluginID:    x.s.cfg.PluginID,
		CallerInstanceID:  x.s.cfg.InstanceID,
		ParentOperationID: meta.OperationID,
		TraceID:           meta.TraceID,
		TargetPluginID:    req.GetTargetPluginId(),
		TargetInstanceID:  req.GetTargetInstanceId(),
		TargetNodeID:      req.GetTargetNodeId(),
		Operation:         req.GetOperation(),
		APIVersion:        req.GetApiVersion(),
		PayloadJSON:       req.GetPayloadJson(),
		IdempotencyKey:    req.GetIdempotencyKey(),
	})
	if err != nil {
		return nil, x.s.dependencyError("invoke plugin", err)
	}
	return &platformv1.InvokePluginResponse{
		PayloadJson: append([]byte(nil), result.PayloadJSON...),
		Error:       domainErrorProto(result.Error),
		OperationId: result.OperationID,
		State:       operationStateProto(result.State),
	}, nil
}

// WaitOperation waits for an operation this instance created. The server caps
// the wait at Limits.WaitTimeout (60 s by default, the ABI cap) and at the gRPC
// deadline of the call.
func (x *invokeService) WaitOperation(ctx context.Context, req *platformv1.WaitOperationRequest) (*platformv1.WaitOperationResponse, error) {
	if x.s.cfg.Invoke == nil {
		return nil, unavailable("plugin invocation")
	}
	if err := validateOperationID(req.GetOperationId()); err != nil {
		return nil, err
	}
	timeout := time.Duration(req.GetTimeoutMs()) * time.Millisecond
	if timeout > x.s.lim.WaitTimeout {
		timeout = x.s.lim.WaitTimeout
	}
	snapshot, err := x.s.cfg.Invoke.WaitOperation(ctx, WaitCall{
		CallerPluginID:   x.s.cfg.PluginID,
		CallerInstanceID: x.s.cfg.InstanceID,
		OperationID:      req.GetOperationId(),
		Timeout:          timeout,
	})
	if err != nil {
		return nil, x.s.dependencyError("wait operation", err)
	}
	return &platformv1.WaitOperationResponse{
		State:      operationStateProto(snapshot.State),
		ResultJson: append([]byte(nil), snapshot.ResultJSON...),
		Error:      domainErrorProto(snapshot.Error),
		Progress:   progressProto(snapshot.Progress),
	}, nil
}

// CancelOperation cancels an operation this instance created and returns the
// state the Invoker observed.
func (x *invokeService) CancelOperation(ctx context.Context, req *platformv1.CancelOperationRequest) (*platformv1.CancelOperationResponse, error) {
	if x.s.cfg.Invoke == nil {
		return nil, unavailable("plugin invocation")
	}
	if err := validateOperationID(req.GetOperationId()); err != nil {
		return nil, err
	}
	state, err := x.s.cfg.Invoke.CancelOperation(ctx, CancelCall{
		CallerPluginID:   x.s.cfg.PluginID,
		CallerInstanceID: x.s.cfg.InstanceID,
		OperationID:      req.GetOperationId(),
	})
	if err != nil {
		return nil, x.s.dependencyError("cancel operation", err)
	}
	return &platformv1.CancelOperationResponse{State: operationStateProto(state)}, nil
}

// validateInvokeRequest checks the shape of an InvokePlugin request. Target
// resolution and the capability plugin.invoke:<plugin_id>/<operation> belong to
// the Invoker; the caller identity is not part of the message.
func validateInvokeRequest(req *platformv1.InvokePluginRequest, limits Limits) error {
	if !validIdentifier(req.GetTargetPluginId(), 128) {
		return invalidArg("invalid target plugin id")
	}
	if target := req.GetTargetInstanceId(); target != "" && !validIdentifier(target, 128) {
		return invalidArg("invalid target instance id")
	}
	if node := req.GetTargetNodeId(); node != "" && !validIdentifier(node, 128) {
		return invalidArg("invalid target node id")
	}
	if !validIdentifier(req.GetOperation(), 128) {
		return invalidArg("invalid operation name")
	}
	if version := req.GetApiVersion(); len(version) > 64 || !visibleASCII(version) {
		return invalidArg("invalid api version")
	}
	payload := req.GetPayloadJson()
	if len(payload) > limits.MaxValueBytes {
		return limitError("invoke.payload_bytes", int64(limits.MaxValueBytes))
	}
	if len(payload) > 0 && !jsonValid(payload) {
		return invalidArg("the invoke payload must be a JSON document")
	}
	if key := req.GetIdempotencyKey(); len(key) > maxIdempotencyKey || !visibleASCII(key) {
		return invalidArg("invalid idempotency key")
	}
	return nil
}

// validateOperationID checks the opaque host operation id of WaitOperation and
// CancelOperation. The id is not parsed; it is only bounded and kept printable.
func validateOperationID(id string) error {
	if id == "" {
		return invalidArg("an operation id is required")
	}
	if len(id) > maxIDFieldLen || !visibleASCII(id) {
		return invalidArg("invalid operation id")
	}
	return nil
}
