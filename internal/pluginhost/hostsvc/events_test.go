// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// draft returns a valid event draft.
func draft() *platformv1.EventDraft {
	return &platformv1.EventDraft{
		Type:          "security.alert",
		SchemaVersion: "1",
		Subject:       "baseline",
		PayloadJson:   []byte(`{"level":"high"}`),
	}
}

// TestPublishEvent covers the publish happy path and every validation rule the
// host enforces on a plugin draft.
func TestPublishEvent(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()

	response, err := ts.Events().PublishEvent(ctx, &platformv1.PublishEventRequest{Context: callContext(), Event: draft()})
	wantOK(t, err, "PublishEvent")
	if response.GetEventId() != "evt_1" || response.GetSequence() != 1 {
		t.Fatalf("PublishEvent = %q/%d", response.GetEventId(), response.GetSequence())
	}
	published, _, _ := ts.bundle.events.snapshot()
	if len(published) != 1 {
		t.Fatalf("sink received %d drafts", len(published))
	}
	if got := published[0]; got.Type != "security.alert" || got.Subject != "baseline" ||
		got.SchemaVersion != "1" || got.OperationID != "op_test" || got.TraceID != "trace_test" {
		t.Fatalf("sink draft = %+v", got)
	}

	bad := []struct {
		name  string
		draft *platformv1.EventDraft
	}{
		{"reserved type", &platformv1.EventDraft{Type: "resource.changed", Subject: "x"}},
		{"reserved operation type", &platformv1.EventDraft{Type: "operation.finished", Subject: "x"}},
		{"empty type", &platformv1.EventDraft{Type: "", Subject: "x"}},
		{"bad type", &platformv1.EventDraft{Type: "security..alert", Subject: "x"}},
		{"empty subject", &platformv1.EventDraft{Type: "security.alert", Subject: ""}},
		{"empty subject segment", &platformv1.EventDraft{Type: "security.alert", Subject: "a//b"}},
		{"dot segment", &platformv1.EventDraft{Type: "security.alert", Subject: "a/./b"}},
		{"dotdot segment", &platformv1.EventDraft{Type: "security.alert", Subject: "a/../b"}},
		{"long subject segment", &platformv1.EventDraft{Type: "security.alert", Subject: strings.Repeat("a", 129)}},
		{"space in subject", &platformv1.EventDraft{Type: "security.alert", Subject: "a b"}},
		{"invalid payload", &platformv1.EventDraft{Type: "security.alert", Subject: "x", PayloadJson: []byte("nope")}},
		{"bad schema version", &platformv1.EventDraft{Type: "security.alert", Subject: "x", SchemaVersion: "1 2"}},
	}
	for _, test := range bad {
		t.Run(test.name, func(t *testing.T) {
			_, err := ts.Events().PublishEvent(ctx, &platformv1.PublishEventRequest{Context: callContext(), Event: test.draft})
			wantCode(t, err, codes.InvalidArgument, test.name)
		})
	}
	if _, err := ts.Events().PublishEvent(ctx, &platformv1.PublishEventRequest{Context: callContext()}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("missing draft: %v", err)
	}
	published, _, _ = ts.bundle.events.snapshot()
	if len(published) != 1 {
		t.Fatalf("a rejected publish reached the sink (%d drafts)", len(published))
	}
}

// TestReportChanges checks subject validation and the deletion rules.
func TestReportChanges(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()

	_, err := ts.Events().ReportChanges(ctx, &platformv1.ReportChangesRequest{
		Context: callContext(),
		Changes: []*platformv1.ResourceChange{
			{Subject: "baseline", Revision: "r2", ChangedPointers: []string{"/enabled"}},
			{Subject: "logs/old", Deleted: true},
		},
	})
	wantOK(t, err, "ReportChanges")
	_, changes, _ := ts.bundle.events.snapshot()
	if len(changes) != 1 || len(changes[0].Changes) != 2 {
		t.Fatalf("sink received %+v", changes)
	}
	if changes[0].OperationID != "op_test" || changes[0].TraceID != "trace_test" {
		t.Fatalf("change set metadata = %+v", changes[0])
	}
	first := changes[0].Changes[0]
	if first.Subject != "baseline" || first.Revision != "r2" || first.Deleted ||
		len(first.ChangedPointers) != 1 || first.ChangedPointers[0] != "/enabled" {
		t.Fatalf("first change = %+v", first)
	}
	if !changes[0].Changes[1].Deleted || changes[0].Changes[1].Revision != "" {
		t.Fatalf("deleted change = %+v", changes[0].Changes[1])
	}

	bad := []struct {
		name   string
		change *platformv1.ResourceChange
	}{
		{"empty subject", &platformv1.ResourceChange{Subject: "", Revision: "r"}},
		{"empty segment", &platformv1.ResourceChange{Subject: "a//b", Revision: "r"}},
		{"dotdot", &platformv1.ResourceChange{Subject: "../x", Revision: "r"}},
		{"deleted with revision", &platformv1.ResourceChange{Subject: "x", Deleted: true, Revision: "r"}},
		{"change without revision", &platformv1.ResourceChange{Subject: "x"}},
		{"bad pointer", &platformv1.ResourceChange{Subject: "x", Revision: "r", ChangedPointers: []string{"pointer"}}},
	}
	for _, test := range bad {
		t.Run(test.name, func(t *testing.T) {
			_, err := ts.Events().ReportChanges(ctx, &platformv1.ReportChangesRequest{
				Context: callContext(), Changes: []*platformv1.ResourceChange{test.change},
			})
			wantCode(t, err, codes.InvalidArgument, test.name)
		})
	}
	_, changes, _ = ts.bundle.events.snapshot()
	if len(changes) != 1 {
		t.Fatalf("a rejected change reached the sink (%d batches)", len(changes))
	}
}

// TestAckEvents checks cursor validation and the sink acknowledgement.
func TestAckEvents(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	_, err := ts.Events().AckEvents(ctx, &platformv1.AckEventsRequest{
		Context: callContext(), Subscription: "sub1", Sequence: 7,
	})
	wantOK(t, err, "AckEvents")
	_, _, acks := ts.bundle.events.snapshot()
	if len(acks) != 1 || acks[0] != (ackCall{Subscription: "sub1", Sequence: 7}) {
		t.Fatalf("acks = %+v", acks)
	}
	if _, err := ts.Events().AckEvents(ctx, &platformv1.AckEventsRequest{
		Context: callContext(), Subscription: "sub1", Sequence: 0,
	}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("zero sequence: %v", err)
	}
	if _, err := ts.Events().AckEvents(ctx, &platformv1.AckEventsRequest{
		Context: callContext(), Subscription: "Bad!", Sequence: 1,
	}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("invalid subscription: %v", err)
	}
}

// TestEventsSpoolFull holds the single spool worker in the sink and checks that
// a full spool is RESOURCE_EXHAUSTED rather than an unbounded queue.
func TestEventsSpoolFull(t *testing.T) {
	b := newBundle()
	b.events.block = make(chan struct{})
	b.events.entered = make(chan struct{}, 8)
	limits := hostsvc.DefaultLimits()
	limits.EventSpool = 1
	ts := startServerWith(t, b, func(cfg *hostsvc.Config) { cfg.Limits = limits })

	ctx, cancel := rpcContext(t)
	defer cancel()
	results := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, err := ts.Events().PublishEvent(ctx, &platformv1.PublishEventRequest{Context: callContext(), Event: draft()})
			results <- err
		}()
	}
	select {
	case <-b.events.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the spool worker never reached the sink")
	}
	// Give the two other publishers time to fill the one free slot or be
	// rejected while the worker is still blocked.
	time.Sleep(250 * time.Millisecond)
	close(b.events.block)

	var got []codes.Code
	for i := 0; i < 3; i++ {
		select {
		case err := <-results:
			got = append(got, statusCode(err))
		case <-time.After(5 * time.Second):
			t.Fatal("a publisher did not finish after the sink was released")
		}
	}
	exhausted := 0
	for _, code := range got {
		switch code {
		case codes.OK:
		case codes.ResourceExhausted:
			exhausted++
		default:
			t.Fatalf("unexpected publish status %v in %v", code, got)
		}
	}
	if exhausted != 1 {
		t.Fatalf("publish statuses = %v, want exactly one ResourceExhausted", got)
	}
}

// TestEventsSinkFailure maps journal failures to UNAVAILABLE.
func TestEventsSinkFailure(t *testing.T) {
	b := newBundle()
	b.events.err = errors.New("journal is down")
	ts := startServerWith(t, b, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	_, err := ts.Events().PublishEvent(ctx, &platformv1.PublishEventRequest{Context: callContext(), Event: draft()})
	wantCode(t, err, codes.Unavailable, "PublishEvent with a broken sink")
	_, err = ts.Events().ReportChanges(ctx, &platformv1.ReportChangesRequest{
		Context: callContext(),
		Changes: []*platformv1.ResourceChange{{Subject: "x", Revision: "r"}},
	})
	wantCode(t, err, codes.Unavailable, "ReportChanges with a broken sink")
	_, err = ts.Events().AckEvents(ctx, &platformv1.AckEventsRequest{Context: callContext(), Subscription: "sub", Sequence: 1})
	wantCode(t, err, codes.Unavailable, "AckEvents with a broken sink")
}

// TestSubscribeEventsAndResume checks topic filtering, the ack cursor and both
// ways to select a start position.
func TestSubscribeEventsAndResume(t *testing.T) {
	ts := startServer(t, nil)
	ingest := func(sequence uint64, eventType string) {
		t.Helper()
		subject := "plugins/noop/resources/x"
		if err := ts.srv.Ingest(eventBuilder(sequence, eventType, subject, []byte(fmt.Sprintf(`{"n":%d}`, sequence)))); err != nil {
			t.Fatalf("Ingest(%d): %v", sequence, err)
		}
	}
	ingest(1, "security.alert")
	ingest(2, "security.alert")
	ingest(3, "ops.done")
	ingest(4, "security.audit")

	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	stream, err := ts.Events().SubscribeEvents(ctx1, &platformv1.SubscribeEventsRequest{
		Context: callContext(), Topics: []string{"security.*"}, Subscription: "sub1",
	})
	wantOK(t, err, "SubscribeEvents")
	for _, want := range []uint64{1, 2, 4} {
		event := recvEvent(t, stream)
		if event.GetSequence() != want {
			t.Fatalf("received sequence %d, want %d", event.GetSequence(), want)
		}
	}
	cancel1()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if _, err := ts.Events().AckEvents(ctx2, &platformv1.AckEventsRequest{
		Context: callContext(), Subscription: "sub1", Sequence: 2,
	}); err != nil {
		t.Fatalf("AckEvents: %v", err)
	}

	// last_acked_sequence 0 resumes from the stored cursor (2), so only 4 is
	// left under the security.* filter.
	stream2, err := ts.Events().SubscribeEvents(ctx2, &platformv1.SubscribeEventsRequest{
		Context: callContext(), Topics: []string{"security.*"}, Subscription: "sub1",
	})
	wantOK(t, err, "SubscribeEvents resume")
	event := recvEvent(t, stream2)
	if event.GetSequence() != 4 || event.GetType() != "security.audit" ||
		!strings.HasPrefix(event.GetSubject(), "plugins/noop/resources/") {
		t.Fatalf("resumed event = %+v", event)
	}

	// An explicit cursor overrides the stored one.
	stream3, err := ts.Events().SubscribeEvents(ctx2, &platformv1.SubscribeEventsRequest{
		Context: callContext(), Topics: []string{"security.*"}, Subscription: "sub2", LastAckedSequence: 3,
	})
	wantOK(t, err, "SubscribeEvents explicit cursor")
	if got := recvEvent(t, stream3).GetSequence(); got != 4 {
		t.Fatalf("explicit cursor received sequence %d, want 4", got)
	}

	// Validation of the subscription name.
	badCtx, badCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer badCancel()
	badStream, err := ts.Events().SubscribeEvents(badCtx, &platformv1.SubscribeEventsRequest{
		Context: callContext(), Subscription: "Not Valid",
	})
	if err == nil {
		_, err = badStream.Recv()
	}
	wantCode(t, err, codes.InvalidArgument, "invalid subscription")
}

// TestEventsSubscriptionLimit checks the concurrent subscription bound.
func TestEventsSubscriptionLimit(t *testing.T) {
	limits := hostsvc.DefaultLimits()
	limits.MaxSubscriptions = 1
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Limits = limits })
	if err := ts.srv.Ingest(eventBuilder(1, "security.alert", "plugins/noop/resources/x", []byte(`{}`))); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()
	stream1, err := ts.Events().SubscribeEvents(ctx1, &platformv1.SubscribeEventsRequest{
		Context: callContext(), Subscription: "one",
	})
	wantOK(t, err, "first subscription")
	if got := recvEvent(t, stream1).GetSequence(); got != 1 {
		t.Fatalf("first subscription received %d", got)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	stream2, err := ts.Events().SubscribeEvents(ctx2, &platformv1.SubscribeEventsRequest{
		Context: callContext(), Subscription: "two",
	})
	if err == nil {
		_, err = stream2.Recv()
	}
	wantCode(t, err, codes.ResourceExhausted, "second subscription over the limit")
}

// TestIngestValidation checks the host-side entry point.
func TestIngestValidation(t *testing.T) {
	ts := startServer(t, nil)
	if err := ts.srv.Ingest(nil); err == nil {
		t.Fatal("Ingest accepted nil")
	}
	if err := ts.srv.Ingest(eventBuilder(0, "security.alert", "x", []byte(`{}`))); err == nil {
		t.Fatal("Ingest accepted a zero sequence")
	}
	if err := ts.srv.Ingest(eventBuilder(1, "", "x", []byte(`{}`))); err == nil {
		t.Fatal("Ingest accepted an empty type")
	}
	if err := ts.srv.Ingest(eventBuilder(1, "security.alert", "x", []byte("nope"))); err == nil {
		t.Fatal("Ingest accepted a non-JSON payload")
	}
	if err := ts.srv.Ingest(eventBuilder(1, "security.alert", "plugins/noop/resources/x", []byte(`{}`))); err != nil {
		t.Fatalf("Ingest rejected a valid event: %v", err)
	}
}

// TestEventsUnavailable checks the missing EventSink dependency.
func TestEventsUnavailable(t *testing.T) {
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Events = nil })
	ctx, cancel := rpcContext(t)
	defer cancel()
	_, err := ts.Events().PublishEvent(ctx, &platformv1.PublishEventRequest{Context: callContext(), Event: draft()})
	wantCode(t, err, codes.Unavailable, "PublishEvent without a sink")
	_, err = ts.Events().ReportChanges(ctx, &platformv1.ReportChangesRequest{
		Context: callContext(),
		Changes: []*platformv1.ResourceChange{{Subject: "x", Revision: "r"}},
	})
	wantCode(t, err, codes.Unavailable, "ReportChanges without a sink")
}

// TestAckCursorIsBounded checks that acking an unbounded number of distinct
// subscription names cannot grow the local cursor map.
func TestAckCursorIsBounded(t *testing.T) {
	limits := hostsvc.DefaultLimits()
	limits.MaxSubscriptionCursors = 1
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Limits = limits })
	ctx, cancel := rpcContext(t)
	defer cancel()
	ack := func(subscription string) error {
		_, err := ts.Events().AckEvents(ctx, &platformv1.AckEventsRequest{
			Context: callContext(), Subscription: subscription, Sequence: 1,
		})
		return err
	}
	wantOK(t, ack("one"), "first ack")
	wantCode(t, ack("two"), codes.ResourceExhausted, "ack over the cursor limit")
	wantOK(t, ack("one"), "acking an existing subscription")
	_, _, acks := ts.bundle.events.snapshot()
	if len(acks) != 2 {
		t.Fatalf("sink acks = %d, want 2 (the rejected name must not reach the sink)", len(acks))
	}
}

// recvEvent receives one event or fails the test.
func recvEvent(t *testing.T, stream grpc.ServerStreamingClient[platformv1.SubscribeEventsResponse]) *platformv1.Event {
	t.Helper()
	response, err := stream.Recv()
	wantOK(t, err, "SubscribeEvents.Recv")
	if response.GetEvent() == nil {
		t.Fatal("SubscribeEvents returned an empty response")
	}
	return response.GetEvent()
}
