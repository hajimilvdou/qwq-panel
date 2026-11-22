// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// maxPublicBody is the ABI's public route body limit in each direction.
const maxPublicBody = 4 << 20

// Invoke runs one synchronous operation.
func (s *Server) Invoke(ctx context.Context, req *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
	in, release, err := s.admit(req.GetContext())
	if err != nil {
		return nil, err
	}
	defer release()

	rc := req.GetContext()
	if err := in.checkAPIVersion(s.manifest, req.GetOperation(), req.GetApiVersion()); err != nil {
		return &platformv1.InvokeResponse{Error: errorDetail(err, rc.GetLocale())}, nil
	}
	h := in.ops.invokes[req.GetOperation()]
	if h == nil {
		return &platformv1.InvokeResponse{Error: unknownOperation(rc.GetLocale(), req.GetOperation())}, nil
	}
	pre := preconditionsFromProto(req.GetPreconditions())
	ictx := withPreconditions(in.callContext(ctx, rc, req.GetAttempt(), false), pre)
	call, _ := CallFromContext(ictx)
	resp, err := safely(in, "invoke", func() (Response, error) {
		return h(ictx, Request{
			Operation:     req.GetOperation(),
			APIVersion:    req.GetApiVersion(),
			Attempt:       req.GetAttempt(),
			Payload:       req.GetPayloadJson(),
			Preconditions: pre,
			call:          call,
			host:          in.host,
		})
	})
	if err != nil {
		in.logOperation("invoke", rc, err)
		return &platformv1.InvokeResponse{Error: errorDetail(err, rc.GetLocale())}, nil
	}
	if err := validateChanges(resp.Changes); err != nil {
		in.logOperation("invoke", rc, err)
		return &platformv1.InvokeResponse{Error: errorDetail(err, rc.GetLocale())}, nil
	}
	return &platformv1.InvokeResponse{
		PayloadJson: resp.Payload,
		Changes:     changesToProto(resp.Changes),
	}, nil
}

// RunJob runs one long operation as a stream: zero or more progress messages,
// then exactly one terminal message (platform.proto, "RunJob stream rules").
// The stream context is canceled by the host on cancel, timeout or a broken
// stream; the handler must stop and leave its state consistent.
func (s *Server) RunJob(req *platformv1.RunJobRequest, stream grpc.ServerStreamingServer[platformv1.RunJobResponse]) error {
	in, release, err := s.admit(req.GetContext())
	if err != nil {
		return err
	}
	defer release()

	rc := req.GetContext()
	sender := &jobSender{stream: stream}
	if err := in.checkAPIVersion(s.manifest, req.GetOperation(), req.GetApiVersion()); err != nil {
		return sender.terminal(&platformv1.JobProgress{Error: errorDetail(err, rc.GetLocale())})
	}
	h := in.ops.jobs[req.GetOperation()]
	if h == nil {
		return sender.terminal(&platformv1.JobProgress{Error: unknownOperation(rc.GetLocale(), req.GetOperation())})
	}
	pre := preconditionsFromProto(req.GetPreconditions())
	ictx := withPreconditions(in.callContext(stream.Context(), rc, req.GetAttempt(), false), pre)
	call, _ := CallFromContext(ictx)
	result, err := safely(in, "run_job", func() (Result, error) {
		return h(ictx, Request{
			Operation:     req.GetOperation(),
			APIVersion:    req.GetApiVersion(),
			Attempt:       req.GetAttempt(),
			Payload:       req.GetPayloadJson(),
			Preconditions: pre,
			call:          call,
			host:          in.host,
		}, sender.progress)
	})
	if err != nil {
		if ictx.Err() != nil {
			// The stream is gone. Nothing can be delivered; leave state to the
			// handler and log for diagnosis.
			in.logOperation("run_job canceled", rc, err)
			return nil
		}
		in.logOperation("run_job", rc, err)
		return sender.terminal(&platformv1.JobProgress{Error: errorDetail(err, rc.GetLocale())})
	}
	if err := validateChanges(result.Changes); err != nil {
		in.logOperation("run_job", rc, err)
		return sender.terminal(&platformv1.JobProgress{Error: errorDetail(err, rc.GetLocale())})
	}
	return sender.terminal(&platformv1.JobProgress{Percent: 100, Completed: true, ResultJson: result.Payload,
		Changes: changesToProto(result.Changes)})
}

// PlanOperation previews a plannable operation. Handlers must not have side
// effects; the Host client refuses state writes while the plan is computed.
func (s *Server) PlanOperation(ctx context.Context, req *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
	in, release, err := s.admit(req.GetContext())
	if err != nil {
		return nil, err
	}
	defer release()

	rc := req.GetContext()
	if err := in.checkAPIVersion(s.manifest, req.GetOperation(), req.GetApiVersion()); err != nil {
		return &platformv1.PlanOperationResponse{Error: errorDetail(err, rc.GetLocale())}, nil
	}
	h := in.ops.plans[req.GetOperation()]
	if h == nil {
		return &platformv1.PlanOperationResponse{Error: notPlannable(rc.GetLocale(), req.GetOperation())}, nil
	}
	ictx := in.callContext(ctx, rc, 0, true)
	call, _ := CallFromContext(ictx)
	plan, err := safely(in, "plan", func() (Plan, error) {
		return h(ictx, Request{
			Operation:  req.GetOperation(),
			APIVersion: req.GetApiVersion(),
			Payload:    req.GetPayloadJson(),
			call:       call,
			host:       in.host,
		})
	})
	if err != nil {
		in.logOperation("plan", rc, err)
		return &platformv1.PlanOperationResponse{Error: errorDetail(err, rc.GetLocale())}, nil
	}
	if err := validatePlan(plan); err != nil {
		in.logOperation("plan", rc, err)
		return &platformv1.PlanOperationResponse{Error: errorDetail(err, rc.GetLocale())}, nil
	}
	return &platformv1.PlanOperationResponse{
		Changes:       plannedChangesToProto(plan.Changes),
		Preconditions: preconditionsToProto(plan.Preconditions),
		Warnings:      violationsToProto(plan.Warnings),
	}, nil
}

// ServePublicRoute serves one request for a route declared with the
// public.route capability. The host owns TLS, rate limits and header
// stripping; the plugin only sees the routed request.
func (s *Server) ServePublicRoute(ctx context.Context, req *platformv1.ServePublicRouteRequest) (*platformv1.ServePublicRouteResponse, error) {
	in, release, err := s.admit(req.GetContext())
	if err != nil {
		return nil, err
	}
	defer release()

	rc := req.GetContext()
	h, ok := in.author.(PublicRouteHandler)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this plugin serves no public routes")
	}
	if len(req.GetBody()) > maxPublicBody {
		return nil, status.Errorf(codes.InvalidArgument, "public route request body is larger than %d bytes", maxPublicBody)
	}
	ictx := in.callContext(ctx, rc, 0, false)
	call, _ := CallFromContext(ictx)
	resp, err := safely(in, "public_route", func() (PublicRouteResponse, error) {
		return h.ServePublicRoute(ictx, PublicRouteRequest{
			Route:    req.GetRoute(),
			Method:   req.GetMethod(),
			Path:     req.GetPath(),
			RawQuery: req.GetRawQuery(),
			Headers:  headersFromProto(req.GetHeaders()),
			Body:     req.GetBody(),
			Call:     call,
		})
	})
	if err != nil {
		in.logOperation("public_route", rc, err)
		return nil, publicRouteStatus(err)
	}
	if len(resp.Body) > maxPublicBody {
		return nil, status.Errorf(codes.Internal, "public route response body is larger than %d bytes", maxPublicBody)
	}
	st := resp.Status
	if st == 0 {
		st = 200
	}
	if st < 100 || st > 599 {
		return nil, status.Errorf(codes.Internal, "public route returned invalid status %d", st)
	}
	return &platformv1.ServePublicRouteResponse{Status: st, Headers: headersToProto(resp.Headers), Body: resp.Body}, nil
}

// admit resolves the instance and admits one request that runs plugin code.
func (s *Server) admit(rc *platformv1.RequestContext) (*instance, func(), error) {
	in, err := s.instance(rc)
	if err != nil {
		return nil, nil, err
	}
	release, err := in.begin()
	if err != nil {
		return nil, nil, err
	}
	return in, release, nil
}

// checkAPIVersion rejects an api_version other than the manifest's. The call
// reached this process, so a mismatch is a domain error and the gRPC status
// stays OK.
func (in *instance) checkAPIVersion(m *manifest.Manifest, operation, apiVersion string) error {
	if apiVersion == "" {
		return nil
	}
	for _, op := range m.Operations {
		if op.Name != operation {
			continue
		}
		if apiVersion != op.APIVersion {
			return Errorf("UNSUPPORTED_API_VERSION", "operation %q has api_version %q, not %q",
				operation, op.APIVersion, apiVersion)
		}
		return nil
	}
	return nil
}

// logOperation logs a handler failure with the request correlation fields.
// Domain errors are expected outcomes (the host shows them to the user), so they
// are logged at info level; unexpected Go errors are errors.
func (in *instance) logOperation(what string, rc *platformv1.RequestContext, err error) {
	args := []any{
		slog.String("rpc", what),
		slog.String("request_id", rc.GetRequestId()),
		slog.String("operation_id", rc.GetOperationId()),
		slog.String("trace_id", rc.GetTraceId()),
		slog.String("error", err.Error()),
	}
	var domain *Error
	if errors.As(err, &domain) {
		in.log.Info(what+" failed", args...)
		return
	}
	in.log.Error(what+" failed", args...)
}

// jobSender enforces the RunJob stream rules: any number of progress messages
// followed by exactly one terminal message.
type jobSender struct {
	stream grpc.ServerStreamingServer[platformv1.RunJobResponse]

	mu       sync.Mutex
	finished bool
}

// progress sends one progress message. It returns an error when the stream is
// gone or the terminal message was already sent, so a handler can stop.
func (j *jobSender) progress(u ProgressUpdate) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.finished {
		return fmt.Errorf("pluginsdk: progress reported after the job finished")
	}
	if err := validateProgress(u); err != nil {
		return err
	}
	if err := validateChanges(u.Changes); err != nil {
		return err
	}
	err := j.stream.Send(&platformv1.RunJobResponse{Progress: &platformv1.JobProgress{
		Percent:   u.Percent,
		Message:   u.Message,
		Step:      u.Step,
		StepIndex: u.StepIndex,
		StepCount: u.StepCount,
		Changes:   changesToProto(u.Changes),
	}})
	if err != nil && j.stream.Context().Err() != nil {
		return j.stream.Context().Err()
	}
	return err
}

// terminal sends the one terminal message of the stream.
func (j *jobSender) terminal(p *platformv1.JobProgress) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.finished {
		return fmt.Errorf("pluginsdk: terminal message already sent")
	}
	j.finished = true
	if err := j.stream.Context().Err(); err != nil {
		// The host canceled; a terminal message cannot be delivered.
		return nil
	}
	return j.stream.Send(&platformv1.RunJobResponse{Progress: p})
}

// validateProgress checks the fields the host renders without clamping them.
func validateProgress(u ProgressUpdate) error {
	if u.Percent > 100 {
		return Errorf("PROTOCOL_ERROR", "progress percent %d is above 100", u.Percent)
	}
	if u.StepCount > 0 {
		if u.StepIndex == 0 || u.StepIndex > u.StepCount {
			return Errorf("PROTOCOL_ERROR", "progress step %d/%d is out of range", u.StepIndex, u.StepCount)
		}
	}
	return nil
}

// unknownOperation is the domain answer for an operation the manifest does not
// declare or the plugin did not register.
func unknownOperation(locale, operation string) *platformv1.ErrorDetail {
	return &platformv1.ErrorDetail{
		Code:    "UNKNOWN_OPERATION",
		Message: Localize(locale, "未知操作 "+operation, "unknown operation "+operation),
	}
}

// notPlannable is the domain answer when PlanOperation is called for an
// operation without plannable=true.
func notPlannable(locale, operation string) *platformv1.ErrorDetail {
	return &platformv1.ErrorDetail{
		Code:    "NOT_PLANNABLE",
		Message: Localize(locale, "操作 "+operation+" 不支持预演", "operation "+operation+" cannot be planned"),
	}
}

// publicRouteStatus maps a route handler failure to the only channel a public
// route response has: the gRPC status (ServePublicRouteResponse has no
// ErrorDetail).
func publicRouteStatus(err error) error {
	var domain *Error
	if !errors.As(err, &domain) {
		return status.Error(codes.Internal, "the plugin failed to serve the route")
	}
	switch domain.Code {
	case "VALIDATION_FAILED":
		return status.Error(codes.InvalidArgument, domain.Message)
	case "PRECONDITION_FAILED", "FAILED_PRECONDITION":
		return status.Error(codes.FailedPrecondition, domain.Message)
	case "PERMISSION_DENIED":
		return status.Error(codes.PermissionDenied, domain.Message)
	case "NOT_FOUND":
		return status.Error(codes.NotFound, domain.Message)
	}
	return status.Error(codes.Internal, domain.Message)
}

// preconditionsFromProto converts host-supplied preconditions.
func preconditionsFromProto(ps []*platformv1.Precondition) []Precondition {
	if len(ps) == 0 {
		return nil
	}
	out := make([]Precondition, len(ps))
	for i, p := range ps {
		out[i] = Precondition{Subject: p.GetSubject(), Revision: p.GetRevision()}
	}
	return out
}

// preconditionsToProto converts plugin-supplied preconditions.
func preconditionsToProto(ps []Precondition) []*platformv1.Precondition {
	if len(ps) == 0 {
		return nil
	}
	out := make([]*platformv1.Precondition, len(ps))
	for i, p := range ps {
		out[i] = &platformv1.Precondition{Subject: p.Subject, Revision: p.Revision}
	}
	return out
}

// changesToProto converts plugin-supplied resource changes.
func changesToProto(cs []ResourceChange) []*platformv1.ResourceChange {
	if len(cs) == 0 {
		return nil
	}
	out := make([]*platformv1.ResourceChange, len(cs))
	for i, c := range cs {
		out[i] = &platformv1.ResourceChange{
			Subject:         c.Subject,
			Revision:        c.Revision,
			ChangedPointers: c.ChangedPointers,
			Deleted:         c.Deleted,
		}
	}
	return out
}

// plannedChangesToProto converts a plan's changes.
func plannedChangesToProto(cs []PlannedChange) []*platformv1.PlannedChange {
	if len(cs) == 0 {
		return nil
	}
	out := make([]*platformv1.PlannedChange, len(cs))
	for i, c := range cs {
		out[i] = &platformv1.PlannedChange{
			Kind:        plannedChangeKindProto(c.Kind),
			Subject:     c.Subject,
			Pointer:     c.Pointer,
			BeforeJson:  c.Before,
			AfterJson:   c.After,
			Reversible:  c.Reversible,
			Description: c.Description,
		}
	}
	return out
}

func plannedChangeKindProto(k PlannedChangeKind) platformv1.PlannedChange_Kind {
	switch k {
	case ChangeCreate:
		return platformv1.PlannedChange_KIND_CREATE
	case ChangeUpdate:
		return platformv1.PlannedChange_KIND_UPDATE
	case ChangeDelete:
		return platformv1.PlannedChange_KIND_DELETE
	}
	return platformv1.PlannedChange_KIND_UNSPECIFIED
}

// headersFromProto converts public route headers.
func headersFromProto(hs []*platformv1.HttpHeader) []HTTPHeader {
	if len(hs) == 0 {
		return nil
	}
	out := make([]HTTPHeader, len(hs))
	for i, h := range hs {
		out[i] = HTTPHeader{Name: h.GetName(), Value: h.GetValue()}
	}
	return out
}

// headersToProto converts public route headers.
func headersToProto(hs []HTTPHeader) []*platformv1.HttpHeader {
	if len(hs) == 0 {
		return nil
	}
	out := make([]*platformv1.HttpHeader, len(hs))
	for i, h := range hs {
		out[i] = &platformv1.HttpHeader{Name: h.Name, Value: h.Value}
	}
	return out
}
