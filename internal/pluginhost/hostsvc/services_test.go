// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// TestConfigSnapshot covers the read-only config view.
func TestConfigSnapshot(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	response, err := ts.Config().GetConfig(ctx, &platformv1.GetConfigRequest{Context: callContext()})
	wantOK(t, err, "GetConfig")
	if response.GetRevision() != "cfg-1" || string(response.GetConfigJson()) != `{"enabled":true}` {
		t.Fatalf("GetConfig = %q %s", response.GetRevision(), response.GetConfigJson())
	}
	if _, err := ts.Config().GetConfig(ctx, &platformv1.GetConfigRequest{Context: callContext(), Revision: "cfg-1"}); err != nil {
		t.Fatalf("GetConfig with the applied revision: %v", err)
	}
	if _, err := ts.Config().GetConfig(ctx, &platformv1.GetConfigRequest{Context: callContext(), Revision: "cfg-0"}); statusCode(err) != codes.NotFound {
		t.Fatalf("GetConfig with a stale revision: %v", err)
	}
}

// TestConfigErrors maps a broken source and a missing source.
func TestConfigErrors(t *testing.T) {
	b := newBundle()
	b.config.snapshot = []byte("not json")
	ts := startServerWith(t, b, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	if _, err := ts.Config().GetConfig(ctx, &platformv1.GetConfigRequest{Context: callContext()}); statusCode(err) != codes.Internal {
		t.Fatalf("invalid snapshot: %v", err)
	}

	unwired := startServer(t, func(cfg *hostsvc.Config) { cfg.Config = nil })
	ctx2, cancel2 := rpcContext(t)
	defer cancel2()
	if _, err := unwired.Config().GetConfig(ctx2, &platformv1.GetConfigRequest{Context: callContext()}); statusCode(err) != codes.Unavailable {
		t.Fatalf("missing config source: %v", err)
	}
}

// TestRevealSecret checks the successful path and the audit record.
func TestRevealSecret(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	response, err := ts.Secrets().RevealSecret(ctx, &platformv1.RevealSecretRequest{
		Context: callContext(), SecretRef: "sec_abc", Purpose: "connect to upstream",
	})
	wantOK(t, err, "RevealSecret")
	if string(response.GetValue()) != "s3cr3t" {
		t.Fatalf("RevealSecret value = %q", response.GetValue())
	}
	calls := ts.bundle.secrets.callsSnapshot()
	if len(calls) != 1 || calls[0].Ref != "sec_abc" || calls[0].OperationID != "op_test" {
		t.Fatalf("revealer calls = %+v", calls)
	}
	records := ts.bundle.audit.snapshot()
	if len(records) != 1 {
		t.Fatalf("audit records = %d, want 1", len(records))
	}
	record := records[0]
	if record.Action != "secret.reveal" || record.Subject != "sec_abc" || record.Outcome != hostsvc.AuditSuccess {
		t.Fatalf("audit record = %+v", record)
	}
	if record.PluginID != "noop" || record.InstanceID != "default" || record.Source != "plugin" {
		t.Fatalf("host-filled audit fields = %+v", record)
	}
	if record.OperationID != "op_test" || record.TraceID != "trace_test" || record.OccurredAt.IsZero() {
		t.Fatalf("audit correlation fields = %+v", record)
	}
	if !strings.Contains(string(record.DetailsJSON), "connect to upstream") {
		t.Fatalf("audit details = %s", record.DetailsJSON)
	}
}

func TestSecretScopes(t *testing.T) {
	for _, test := range []struct{ name, scope string }{
		{name: "none"},
		{name: "operation", scope: "operation"},
		{name: "wildcard", scope: "*"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ts := startServer(t, func(cfg *hostsvc.Config) {
				cfg.GrantedCapabilities = nil
				if test.scope != "" {
					cfg.GrantedCapabilities = []*platformv1.Capability{{Name: "secret.reveal", Scope: test.scope}}
				}
			})
			ctx, cancel := rpcContext(t)
			defer cancel()
			_, err := ts.Secrets().RevealSecret(ctx, &platformv1.RevealSecretRequest{
				Context: callContext(), SecretRef: "sec_abc", Purpose: "config operation secret.reveal:*",
			})
			calls := ts.bundle.secrets.callsSnapshot()
			if test.scope == "operation" {
				wantOK(t, err, "operation RevealSecret")
				if len(calls) != 1 || len(calls[0].Scopes) != 1 || calls[0].Scopes[0] != "operation" {
					t.Fatal("request audit text changed the host-selected secret scope")
				}
			} else if statusCode(err) != codes.PermissionDenied || len(calls) != 0 {
				t.Fatalf("missing/wildcard secret scope: code=%v backend_calls=%d error=%v", statusCode(err), len(calls), err)
			}
		})
	}
}

// TestRevealSecretRequiresOperation rejects a reveal without a dispatched
// operation and records the denial.
func TestRevealSecretRequiresOperation(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	call := callContext()
	call.OperationId = ""
	_, err := ts.Secrets().RevealSecret(ctx, &platformv1.RevealSecretRequest{
		Context: call, SecretRef: "sec_abc",
	})
	wantCode(t, err, codes.FailedPrecondition, "RevealSecret without an operation")
	if calls := ts.bundle.secrets.callsSnapshot(); len(calls) != 0 {
		t.Fatalf("the revealer was called without an operation: %+v", calls)
	}
	records := ts.bundle.audit.snapshot()
	if len(records) != 1 || records[0].Outcome != hostsvc.AuditDenied {
		t.Fatalf("audit record = %+v", records)
	}
}

// TestRevealSecretErrors maps the revealer sentinels and fails closed when the
// audit record cannot be written.
func TestRevealSecretErrors(t *testing.T) {
	request := func() *platformv1.RevealSecretRequest {
		return &platformv1.RevealSecretRequest{Context: callContext(), SecretRef: "sec_abc"}
	}

	t.Run("denied", func(t *testing.T) {
		b := newBundle()
		b.secrets.err = hostsvc.ErrSecretDenied
		ts := startServerWith(t, b, nil)
		ctx, cancel := rpcContext(t)
		defer cancel()
		_, err := ts.Secrets().RevealSecret(ctx, request())
		wantCode(t, err, codes.PermissionDenied, "denied reveal")
		records := b.audit.snapshot()
		if len(records) != 1 || records[0].Outcome != hostsvc.AuditDenied {
			t.Fatalf("audit record = %+v", records)
		}
	})

	t.Run("operation not dispatched", func(t *testing.T) {
		b := newBundle()
		b.secrets.err = fmt.Errorf("host: %w", hostsvc.ErrOperationNotDispatched)
		ts := startServerWith(t, b, nil)
		ctx, cancel := rpcContext(t)
		defer cancel()
		_, err := ts.Secrets().RevealSecret(ctx, request())
		wantCode(t, err, codes.FailedPrecondition, "operation not dispatched")
		records := b.audit.snapshot()
		if len(records) != 1 || records[0].Outcome != hostsvc.AuditDenied {
			t.Fatalf("audit record = %+v", records)
		}
	})

	t.Run("audit outage fails closed", func(t *testing.T) {
		b := newBundle()
		b.audit.err = errors.New("audit storage is down")
		ts := startServerWith(t, b, nil)
		ctx, cancel := rpcContext(t)
		defer cancel()
		response, err := ts.Secrets().RevealSecret(ctx, request())
		if response != nil {
			t.Fatal("a reveal whose audit failed returned the value")
		}
		wantCode(t, err, codes.Unavailable, "audit outage")
		if calls := b.secrets.callsSnapshot(); len(calls) != 1 {
			t.Fatalf("revealer calls = %+v", calls)
		}
	})

	t.Run("no audit sink fails closed", func(t *testing.T) {
		ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Audit = nil })
		ctx, cancel := rpcContext(t)
		defer cancel()
		response, err := ts.Secrets().RevealSecret(ctx, request())
		if response != nil {
			t.Fatal("a reveal without an audit sink returned the value")
		}
		wantCode(t, err, codes.Unavailable, "missing audit sink")
	})

	t.Run("no secret source", func(t *testing.T) {
		ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Secrets = nil })
		ctx, cancel := rpcContext(t)
		defer cancel()
		_, err := ts.Secrets().RevealSecret(ctx, request())
		wantCode(t, err, codes.Unavailable, "missing secret source")
	})

	t.Run("invalid reference", func(t *testing.T) {
		ts := startServer(t, nil)
		ctx, cancel := rpcContext(t)
		defer cancel()
		for _, ref := range []string{"", "sec_\x01bad", strings.Repeat("s", 257)} {
			_, err := ts.Secrets().RevealSecret(ctx, &platformv1.RevealSecretRequest{
				Context: callContext(), SecretRef: ref,
			})
			wantCode(t, err, codes.InvalidArgument, "invalid secret reference")
		}
		_, err := ts.Secrets().RevealSecret(ctx, &platformv1.RevealSecretRequest{
			Context: callContext(), SecretRef: "sec_abc", Purpose: strings.Repeat("p", 1025),
		})
		wantCode(t, err, codes.InvalidArgument, "purpose over the limit")
	})
}

// TestRevealSecretRateLimit checks the per-plugin reveal quota.
func TestRevealSecretRateLimit(t *testing.T) {
	limits := hostsvc.DefaultLimits()
	limits.SecretRevealsPerMinute = 4 // one token of burst
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Limits = limits })
	ctx, cancel := rpcContext(t)
	defer cancel()
	request := func() *platformv1.RevealSecretRequest {
		return &platformv1.RevealSecretRequest{Context: callContext(), SecretRef: "sec_abc"}
	}
	if _, err := ts.Secrets().RevealSecret(ctx, request()); err != nil {
		t.Fatalf("first reveal: %v", err)
	}
	_, err := ts.Secrets().RevealSecret(ctx, request())
	wantCode(t, err, codes.ResourceExhausted, "second reveal over the quota")
}

// TestWriteAudit checks field mapping and validation.
func TestWriteAudit(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	call := callContext()
	call.OperationId = "op_audit"
	call.TraceId = "trace_audit"
	_, err := ts.Audit().WriteAudit(ctx, &platformv1.WriteAuditRequest{
		Context: call,
		Record: &platformv1.AuditRecord{
			Action:      "scan.start",
			Subject:     "baseline",
			Outcome:     platformv1.AuditOutcome_AUDIT_OUTCOME_SUCCESS,
			DetailsJson: []byte(`{"target":"local"}`),
		},
	})
	wantOK(t, err, "WriteAudit")
	records := ts.bundle.audit.snapshot()
	if len(records) != 1 {
		t.Fatalf("audit records = %d", len(records))
	}
	record := records[0]
	if record.Action != "scan.start" || record.Subject != "baseline" || record.Outcome != hostsvc.AuditSuccess ||
		string(record.DetailsJSON) != `{"target":"local"}` {
		t.Fatalf("audit record = %+v", record)
	}
	if record.PluginID != "noop" || record.InstanceID != "default" || record.Source != "plugin" ||
		record.OperationID != "op_audit" || record.TraceID != "trace_audit" || record.OccurredAt.IsZero() {
		t.Fatalf("host-filled fields = %+v", record)
	}

	big := strings.Repeat("x", 65<<10)
	bad := []struct {
		name   string
		record *platformv1.AuditRecord
	}{
		{"empty action", &platformv1.AuditRecord{Subject: "s"}},
		{"bad action", &platformv1.AuditRecord{Action: "bad action", Subject: "s"}},
		{"control character in subject", &platformv1.AuditRecord{Action: "a.b", Subject: "s\x00"}},
		{"unknown outcome", &platformv1.AuditRecord{Action: "a.b", Outcome: platformv1.AuditOutcome(99)}},
		{"invalid details", &platformv1.AuditRecord{Action: "a.b", DetailsJson: []byte("nope")}},
		{"oversized details", &platformv1.AuditRecord{Action: "a.b", DetailsJson: []byte(`"` + big + `"`)}},
	}
	for _, test := range bad {
		t.Run(test.name, func(t *testing.T) {
			_, err := ts.Audit().WriteAudit(ctx, &platformv1.WriteAuditRequest{Context: callContext(), Record: test.record})
			if statusCode(err) != codes.InvalidArgument && statusCode(err) != codes.ResourceExhausted {
				t.Fatalf("%s: %v", test.name, err)
			}
		})
	}
	if len(ts.bundle.audit.snapshot()) != 1 {
		t.Fatal("a rejected audit record reached the sink")
	}
}

// TestAuditQueueIsBounded holds the audit sink and checks that a second write
// is refused instead of queued without a bound.
func TestAuditQueueIsBounded(t *testing.T) {
	b := newBundle()
	b.audit.block = make(chan struct{})
	b.audit.entered = make(chan struct{}, 4)
	limits := hostsvc.DefaultLimits()
	limits.AuditQueue = 1
	limits.AuditPerMinute = 120
	ts := startServerWith(t, b, func(cfg *hostsvc.Config) { cfg.Limits = limits })

	ctx, cancel := rpcContext(t)
	defer cancel()
	request := func() *platformv1.WriteAuditRequest {
		return &platformv1.WriteAuditRequest{
			Context: callContext(),
			Record:  &platformv1.AuditRecord{Action: "test.action", Subject: "s"},
		}
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := ts.Audit().WriteAudit(ctx, request())
		firstDone <- err
	}()
	select {
	case <-b.audit.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the audit sink was never entered")
	}
	_, err := ts.Audit().WriteAudit(ctx, request())
	wantCode(t, err, codes.ResourceExhausted, "second audit while the first is blocked")
	close(b.audit.block)
	select {
	case err := <-firstDone:
		wantOK(t, err, "first audit")
	case <-time.After(5 * time.Second):
		t.Fatal("the first audit did not finish")
	}
}

// TestAuditRateIsLimited checks the per-plugin audit quota.
func TestAuditRateIsLimited(t *testing.T) {
	limits := hostsvc.DefaultLimits()
	limits.AuditPerMinute = 4 // one token of burst
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Limits = limits })
	ctx, cancel := rpcContext(t)
	defer cancel()
	request := func() *platformv1.WriteAuditRequest {
		return &platformv1.WriteAuditRequest{
			Context: callContext(),
			Record:  &platformv1.AuditRecord{Action: "test.action"},
		}
	}
	if _, err := ts.Audit().WriteAudit(ctx, request()); err != nil {
		t.Fatalf("first audit: %v", err)
	}
	_, err := ts.Audit().WriteAudit(ctx, request())
	wantCode(t, err, codes.ResourceExhausted, "second audit over the quota")
}

// TestAuditUnavailable checks the missing dependency.
func TestAuditUnavailable(t *testing.T) {
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Audit = nil })
	ctx, cancel := rpcContext(t)
	defer cancel()
	_, err := ts.Audit().WriteAudit(ctx, &platformv1.WriteAuditRequest{
		Context: callContext(),
		Record:  &platformv1.AuditRecord{Action: "test.action"},
	})
	wantCode(t, err, codes.Unavailable, "WriteAudit without a sink")
}

// TestInvokePlugin checks forwarding, the authoritative caller identity and the
// response mapping.
func TestInvokePlugin(t *testing.T) {
	b := newBundle()
	b.invoke.invokeResult = hostsvc.InvokeResult{
		PayloadJSON: []byte(`{"ok":true}`),
		OperationID: "op_child",
		State:       hostsvc.OperationRunning,
	}
	ts := startServerWith(t, b, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	response, err := ts.Invoke().InvokePlugin(ctx, &platformv1.InvokePluginRequest{
		Context:          callContext(),
		TargetPluginId:   "other",
		TargetInstanceId: "default",
		TargetNodeId:     "local",
		Operation:        "echo",
		ApiVersion:       "v1",
		PayloadJson:      []byte(`{"x":1}`),
		IdempotencyKey:   "idem-1",
	})
	wantOK(t, err, "InvokePlugin")
	if string(response.GetPayloadJson()) != `{"ok":true}` || response.GetOperationId() != "op_child" ||
		response.GetState() != platformv1.OperationState_OPERATION_STATE_RUNNING || response.GetError() != nil {
		t.Fatalf("InvokePlugin response = %+v", response)
	}
	calls := b.invoke.invokeSnapshot()
	if len(calls) != 1 {
		t.Fatalf("invoker calls = %d", len(calls))
	}
	call := calls[0]
	if call.CallerPluginID != "noop" || call.CallerInstanceID != "default" {
		t.Fatalf("caller identity = %+v", call)
	}
	if call.ParentOperationID != "op_test" || call.TraceID != "trace_test" {
		t.Fatalf("correlation fields = %+v", call)
	}
	if call.TargetPluginID != "other" || call.TargetInstanceID != "default" || call.TargetNodeID != "local" ||
		call.Operation != "echo" || call.APIVersion != "v1" || call.IdempotencyKey != "idem-1" ||
		string(call.PayloadJSON) != `{"x":1}` {
		t.Fatalf("forwarded call = %+v", call)
	}

	// A domain failure is an ErrorDetail with status OK.
	b.invoke.invokeResult = hostsvc.InvokeResult{
		OperationID: "op_child",
		State:       hostsvc.OperationFailed,
		Error: &hostsvc.DomainError{
			Code: "PRECONDITION_FAILED", Message: "the resource changed", Retryable: true,
			DetailsJSON: []byte(`{"subject":"x"}`),
		},
	}
	response, err = ts.Invoke().InvokePlugin(ctx, &platformv1.InvokePluginRequest{
		Context: callContext(), TargetPluginId: "other", Operation: "echo",
	})
	wantOK(t, err, "InvokePlugin domain failure")
	if response.GetError().GetCode() != "PRECONDITION_FAILED" || !response.GetError().GetRetryable() ||
		string(response.GetError().GetDetailsJson()) != `{"subject":"x"}` ||
		response.GetState() != platformv1.OperationState_OPERATION_STATE_FAILED {
		t.Fatalf("domain error response = %+v", response)
	}

	bad := []*platformv1.InvokePluginRequest{
		{Context: callContext(), Operation: "echo"},
		{Context: callContext(), TargetPluginId: "bad id", Operation: "echo"},
		{Context: callContext(), TargetPluginId: "other"},
		{Context: callContext(), TargetPluginId: "other", Operation: "echo", PayloadJson: []byte("nope")},
		{Context: callContext(), TargetPluginId: "other", Operation: "echo", IdempotencyKey: "bad key"},
	}
	for _, request := range bad {
		_, err := ts.Invoke().InvokePlugin(ctx, request)
		wantCode(t, err, codes.InvalidArgument, "invalid InvokePlugin request")
	}
}

// TestInvokePluginPayloadLimit checks the payload bound.
func TestInvokePluginPayloadLimit(t *testing.T) {
	limits := hostsvc.DefaultLimits()
	limits.MaxValueBytes = 16
	limits.MaxTotalBytes = 1 << 20
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Limits = limits })
	ctx, cancel := rpcContext(t)
	defer cancel()
	_, err := ts.Invoke().InvokePlugin(ctx, &platformv1.InvokePluginRequest{
		Context: callContext(), TargetPluginId: "other", Operation: "echo",
		PayloadJson: []byte(`{"a":"0123456789"}`),
	})
	wantCode(t, err, codes.ResourceExhausted, "oversized invoke payload")
}

// TestWaitAndCancelOperation checks the caps and the forwarded identity.
func TestWaitAndCancelOperation(t *testing.T) {
	b := newBundle()
	b.invoke.waitSnapshot = hostsvc.OperationSnapshot{
		State:      hostsvc.OperationSucceeded,
		ResultJSON: []byte(`{"done":true}`),
		Progress:   &hostsvc.Progress{Percent: 100, Step: "finish", StepIndex: 2, StepCount: 2, Message: "done"},
	}
	b.invoke.cancelState = hostsvc.OperationCanceled
	ts := startServerWith(t, b, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()

	response, err := ts.Invoke().WaitOperation(ctx, &platformv1.WaitOperationRequest{
		Context: callContext(), OperationId: "op_child", TimeoutMs: 120_000,
	})
	wantOK(t, err, "WaitOperation")
	if response.GetState() != platformv1.OperationState_OPERATION_STATE_SUCCEEDED ||
		string(response.GetResultJson()) != `{"done":true}` {
		t.Fatalf("WaitOperation response = %+v", response)
	}
	progress := response.GetProgress()
	if progress.GetPercent() != 100 || progress.GetStep() != "finish" ||
		progress.GetStepIndex() != 2 || progress.GetStepCount() != 2 || progress.GetMessage() != "done" {
		t.Fatalf("progress = %+v", progress)
	}
	waitCalls := b.invoke.waitSnapshotCalls()
	if len(waitCalls) != 1 {
		t.Fatalf("wait calls = %d", len(b.invoke.waitCalls))
	}
	wait := waitCalls[0]
	if wait.CallerPluginID != "noop" || wait.CallerInstanceID != "default" || wait.OperationID != "op_child" {
		t.Fatalf("wait call = %+v", wait)
	}
	if wait.Timeout != 60*time.Second {
		t.Fatalf("wait timeout = %v, want the 60 s cap", wait.Timeout)
	}

	if _, err := ts.Invoke().WaitOperation(ctx, &platformv1.WaitOperationRequest{
		Context: callContext(), OperationId: "op_child",
	}); err != nil {
		t.Fatalf("WaitOperation with timeout 0: %v", err)
	}
	if got := b.invoke.waitSnapshotCalls()[1].Timeout; got != 0 {
		t.Fatalf("timeout 0 became %v", got)
	}
	if _, err := ts.Invoke().WaitOperation(ctx, &platformv1.WaitOperationRequest{Context: callContext()}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("WaitOperation without an operation id: %v", err)
	}

	cancelResponse, err := ts.Invoke().CancelOperation(ctx, &platformv1.CancelOperationRequest{
		Context: callContext(), OperationId: "op_child",
	})
	wantOK(t, err, "CancelOperation")
	if cancelResponse.GetState() != platformv1.OperationState_OPERATION_STATE_CANCELED {
		t.Fatalf("CancelOperation state = %v", cancelResponse.GetState())
	}
	cancelCalls := b.invoke.cancelSnapshot()
	cancelCall := cancelCalls[0]
	if cancelCall.CallerPluginID != "noop" || cancelCall.CallerInstanceID != "default" || cancelCall.OperationID != "op_child" {
		t.Fatalf("cancel call = %+v", cancelCall)
	}
	if _, err := ts.Invoke().CancelOperation(ctx, &platformv1.CancelOperationRequest{Context: callContext()}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("CancelOperation without an operation id: %v", err)
	}
}

// TestInvokeUnavailable checks the missing Invoker dependency.
func TestInvokeUnavailable(t *testing.T) {
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Invoke = nil })
	ctx, cancel := rpcContext(t)
	defer cancel()
	if _, err := ts.Invoke().InvokePlugin(ctx, &platformv1.InvokePluginRequest{
		Context: callContext(), TargetPluginId: "other", Operation: "echo",
	}); statusCode(err) != codes.Unavailable {
		t.Fatalf("InvokePlugin without an invoker: %v", err)
	}
	if _, err := ts.Invoke().WaitOperation(ctx, &platformv1.WaitOperationRequest{
		Context: callContext(), OperationId: "op_child",
	}); statusCode(err) != codes.Unavailable {
		t.Fatalf("WaitOperation without an invoker: %v", err)
	}
	if _, err := ts.Invoke().CancelOperation(ctx, &platformv1.CancelOperationRequest{
		Context: callContext(), OperationId: "op_child",
	}); statusCode(err) != codes.Unavailable {
		t.Fatalf("CancelOperation without an invoker: %v", err)
	}
}
