// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"errors"
	"time"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// errAuditUnavailable marks a missing audit sink. A secret reveal treats it as
// fatal (fail closed); WriteAudit maps it to UNAVAILABLE.
var errAuditUnavailable = errors.New("hostsvc: audit sink is not configured")

// auditQuota is the per-plugin audit budget (review S10): AuditQueue bounds
// concurrent writes and AuditPerMinute bounds the rate. Both are checked before
// the sink is called so a plugin cannot flood the host by writing audits.
type auditQuota struct {
	slots     chan struct{}
	bucket    *tokenBucket
	perMinute int
}

// newAuditQuota builds the quota.
func newAuditQuota(queue, perMinute int) *auditQuota {
	return &auditQuota{
		slots:     make(chan struct{}, max(1, queue)),
		bucket:    newTokenBucket(perMinute, defaultBurst(perMinute)),
		perMinute: perMinute,
	}
}

// acquire reserves a slot and a token. A full queue or an empty bucket is a
// LimitError, which the server reports as RESOURCE_EXHAUSTED.
func (q *auditQuota) acquire(now time.Time) error {
	select {
	case q.slots <- struct{}{}:
	default:
		return &LimitError{Name: "audit.queue", Max: int64(cap(q.slots))}
	}
	if !q.bucket.allow(now) {
		<-q.slots
		return &LimitError{Name: "audit.rate_per_minute", Max: int64(q.perMinute)}
	}
	return nil
}

// release frees the slot of a finished write.
func (q *auditQuota) release() { <-q.slots }

// writeAudit fills the host-known fields, applies the quota and calls the sink.
// The plugin cannot set PluginID, InstanceID, Source, OccurredAt, actor or
// operation: those are host facts.
func (s *Server) writeAudit(ctx context.Context, record AuditRecord) error {
	if s.cfg.Audit == nil {
		return errAuditUnavailable
	}
	now := s.clock.Now()
	if err := s.auditQuota.acquire(now); err != nil {
		return err
	}
	defer s.auditQuota.release()
	record.PluginID = s.cfg.PluginID
	record.InstanceID = s.cfg.InstanceID
	record.Source = "plugin"
	if record.OccurredAt.IsZero() {
		record.OccurredAt = now
	}
	return s.cfg.Audit.Write(ctx, record)
}

// auditService implements HostAuditService.
type auditService struct {
	platformv1.UnimplementedHostAuditServiceServer
	s *Server
}

// WriteAudit validates one plugin record and hands it to the AuditSink.
func (x *auditService) WriteAudit(ctx context.Context, req *platformv1.WriteAuditRequest) (*platformv1.WriteAuditResponse, error) {
	if x.s.cfg.Audit == nil {
		return nil, unavailable("audit")
	}
	record := req.GetRecord()
	if record == nil {
		return nil, invalidArg("an audit record is required")
	}
	if err := validateAuditAction(record.GetAction()); err != nil {
		return nil, err
	}
	if err := validateAuditSubject(record.GetSubject()); err != nil {
		return nil, err
	}
	outcome, ok := auditOutcomeFromProto(record.GetOutcome())
	if !ok {
		return nil, invalidArg("unknown audit outcome")
	}
	if err := validateDetailsJSON(record.GetDetailsJson()); err != nil {
		return nil, err
	}
	meta := callMetaOf(req.GetContext())
	if err := x.s.writeAudit(ctx, AuditRecord{
		Action:      record.GetAction(),
		Subject:     record.GetSubject(),
		Outcome:     outcome,
		DetailsJSON: append([]byte(nil), record.GetDetailsJson()...),
		OperationID: meta.OperationID,
		TraceID:     meta.TraceID,
	}); err != nil {
		return nil, x.s.sinkError("write audit", err)
	}
	return &platformv1.WriteAuditResponse{}, nil
}
