// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"encoding/json"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// secretsService implements HostSecretsService. A reveal is the most sensitive
// call of the ABI, so it requires three independent things: a verified peer (the
// interceptor), a secret reference the SecretRevealer accepts for this
// instance, and a HostCallContext.operation_id that is currently dispatched.
// Every accepted attempt is audited before the material leaves the process;
// reveals are rate limited per plugin.
type secretsService struct {
	platformv1.UnimplementedHostSecretsServiceServer
	s       *Server
	limiter *tokenBucket
}

// newSecretsService builds the service with the reveal quota of Limits.
func newSecretsService(s *Server) *secretsService {
	return &secretsService{
		s:       s,
		limiter: newTokenBucket(s.lim.SecretRevealsPerMinute, defaultBurst(s.lim.SecretRevealsPerMinute)),
	}
}

// RevealSecret returns one secret value. The operation_id is not proof of
// anything by itself: the SecretRevealer must confirm that the operation is
// dispatched to this instance and has not finished.
func (x *secretsService) RevealSecret(ctx context.Context, req *platformv1.RevealSecretRequest) (*platformv1.RevealSecretResponse, error) {
	meta := callMetaOf(req.GetContext())
	if meta.OperationID == "" {
		x.auditFailure(ctx, req.GetSecretRef(), "missing_operation_id", AuditDenied, meta)
		return nil, status.Error(codes.FailedPrecondition, "RevealSecret requires a dispatched operation_id")
	}
	if err := validateSecretRef(req.GetSecretRef()); err != nil {
		return nil, err
	}
	if err := validatePurpose(req.GetPurpose()); err != nil {
		return nil, err
	}
	if x.s.cfg.Secrets == nil {
		return nil, unavailable("secret storage")
	}
	// scope 只来自宿主已验签的授予列表，purpose 请求字段仍只是审计文本。
	var scopes []string
	for _, scope := range []string{"config", "operation"} {
		if capabilityMatches(x.s.cfg.GrantedCapabilities, "secret.reveal", scope, false) {
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 0 {
		x.auditFailure(ctx, req.GetSecretRef(), "scope_denied", AuditDenied, meta)
		return nil, status.Error(codes.PermissionDenied, "secret reveal scope is not granted")
	}
	now := x.s.clock.Now()
	if !x.limiter.allow(now) {
		x.auditFailure(ctx, req.GetSecretRef(), "rate_limited", AuditDenied, meta)
		return nil, status.Error(codes.ResourceExhausted, "secret reveals are rate limited")
	}
	value, err := x.s.cfg.Secrets.Reveal(ctx, req.GetSecretRef(), meta.OperationID, scopes)
	if err != nil {
		outcome := AuditFailure
		if errors.Is(err, ErrSecretDenied) || errors.Is(err, ErrOperationNotDispatched) {
			outcome = AuditDenied
		}
		x.auditFailure(ctx, req.GetSecretRef(), "", outcome, meta)
		return nil, x.s.dependencyError("reveal secret", err)
	}
	// Audit before returning the material: a reveal that cannot be recorded
	// must not happen (fail closed).
	if err := x.s.writeAudit(ctx, AuditRecord{
		Action:      "secret.reveal",
		Subject:     req.GetSecretRef(),
		Outcome:     AuditSuccess,
		DetailsJSON: revealDetails(req.GetPurpose()),
		OperationID: meta.OperationID,
		TraceID:     meta.TraceID,
	}); err != nil {
		clear(value)
		return nil, x.s.sinkError("audit secret reveal", err)
	}
	return &platformv1.RevealSecretResponse{Value: value}, nil
}

// auditFailure records a refused reveal on a best-effort basis: the call is
// already failing, and an audit outage must not turn a denial into a different
// status.
func (x *secretsService) auditFailure(ctx context.Context, ref, reason string, outcome AuditOutcome, meta callMeta) {
	details, _ := json.Marshal(struct {
		Reason string `json:"reason,omitempty"`
	}{Reason: reason})
	if err := x.s.writeAudit(ctx, AuditRecord{
		Action:      "secret.reveal",
		Subject:     clipString(ref, maxSecretRefLen),
		Outcome:     outcome,
		DetailsJSON: details,
		OperationID: meta.OperationID,
		TraceID:     meta.TraceID,
	}); err != nil {
		x.s.log.Warn("could not audit a refused secret reveal", "error", err)
	}
}

// revealDetails is the audit detail of a successful reveal. It records the
// declared purpose (untrusted text) and never the value.
func revealDetails(purpose string) []byte {
	details, err := json.Marshal(struct {
		Purpose string `json:"purpose,omitempty"`
	}{Purpose: clipString(purpose, 1024)})
	if err != nil {
		return nil
	}
	return details
}
