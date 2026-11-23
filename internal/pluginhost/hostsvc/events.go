// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// maxChangedPointers bounds the RFC 6901 pointers of one ResourceChange.
const maxChangedPointers = 64

// eventsService implements HostEventsService.
//
// Publishing goes through a bounded spool with a single worker, so the host
// journal sees events in the order the plugin sent them and a slow sink applies
// backpressure instead of letting memory grow. Subscribing serves the bounded
// local buffer that Server.Ingest fills from the node journal; the buffer is a
// hand-off, not the durable journal, so a subscriber that falls behind loses
// the oldest entries (logged) and reliable replay remains the journal's job.
type eventsService struct {
	platformv1.UnimplementedHostEventsServiceServer
	s       *Server
	log     *eventLog
	cursors *cursorStore
	spool   *publishSpool

	mu   sync.Mutex
	subs int
}

// newEventsService builds the service; the spool is nil when no EventSink is
// configured, which makes publishing unavailable but keeps Ingest and
// Subscribe usable.
func newEventsService(s *Server) *eventsService {
	return &eventsService{
		s:       s,
		log:     newEventLog(s.lim.EventSpool, s.lim.EventSpoolBytes),
		cursors: newCursorStore(s.lim.MaxSubscriptionCursors),
		spool:   s.spool,
	}
}

// PublishEvent validates the draft, queues it on the bounded spool and waits
// for the sink. A full spool is RESOURCE_EXHAUSTED.
func (x *eventsService) PublishEvent(ctx context.Context, req *platformv1.PublishEventRequest) (*platformv1.PublishEventResponse, error) {
	if x.spool == nil {
		return nil, unavailable("event publishing")
	}
	draft := req.GetEvent()
	if draft == nil {
		return nil, invalidArg("an event draft is required")
	}
	if err := validateEventDraft(draft, x.s.lim); err != nil {
		return nil, err
	}
	meta := callMetaOf(req.GetContext())
	ref, err := x.spool.publish(ctx, EventDraft{
		Type:          draft.GetType(),
		SchemaVersion: draft.GetSchemaVersion(),
		Subject:       draft.GetSubject(),
		PayloadJSON:   append([]byte(nil), draft.GetPayloadJson()...),
		OperationID:   meta.OperationID,
		TraceID:       meta.TraceID,
	})
	if err != nil {
		return nil, x.s.sinkError("publish event", err)
	}
	if x.s.cfg.OnEventPublished != nil {
		x.s.cfg.OnEventPublished(x.s.cfg.PluginID, draft, ref.EventID)
	}
	return &platformv1.PublishEventResponse{EventId: ref.EventID, Sequence: ref.Sequence}, nil
}

// ReportChanges validates every change before handing the set to the sink, so a
// malformed subject cannot produce a partial batch.
func (x *eventsService) ReportChanges(ctx context.Context, req *platformv1.ReportChangesRequest) (*platformv1.ReportChangesResponse, error) {
	if x.s.cfg.Events == nil {
		return nil, unavailable("change reporting")
	}
	changes := req.GetChanges()
	if len(changes) > x.s.lim.MaxChanges {
		return nil, limitError("changes.count", int64(x.s.lim.MaxChanges))
	}
	out := make([]ResourceChange, 0, len(changes))
	for _, change := range changes {
		if change == nil {
			return nil, invalidArg("a resource change is required")
		}
		if err := validateRelativeSubject(change.GetSubject()); err != nil {
			return nil, err
		}
		if len(change.GetRevision()) > 256 {
			return nil, invalidArg("the change revision is too long")
		}
		if change.GetDeleted() && change.GetRevision() != "" {
			return nil, invalidArg("a deleted resource change must have an empty revision")
		}
		if !change.GetDeleted() && change.GetRevision() == "" {
			return nil, invalidArg("a resource change must carry the revision after the change")
		}
		if len(change.GetChangedPointers()) > maxChangedPointers {
			return nil, limitError("changes.pointers", maxChangedPointers)
		}
		if err := validatePointers(change.GetChangedPointers()); err != nil {
			return nil, err
		}
		out = append(out, ResourceChange{
			Subject:         change.GetSubject(),
			Revision:        change.GetRevision(),
			ChangedPointers: append([]string(nil), change.GetChangedPointers()...),
			Deleted:         change.GetDeleted(),
		})
	}
	if len(out) == 0 {
		return &platformv1.ReportChangesResponse{}, nil
	}
	meta := callMetaOf(req.GetContext())
	if err := x.s.cfg.Events.ReportChanges(ctx, ChangeSet{
		OperationID: meta.OperationID,
		TraceID:     meta.TraceID,
		Changes:     out,
	}); err != nil {
		return nil, x.s.sinkError("report changes", err)
	}
	return &platformv1.ReportChangesResponse{}, nil
}

// AckEvents advances the durable cursor of one subscription. The cursor is
// updated locally first and restored when the sink refuses the
// acknowledgement, so a failed journal ack still replays.
func (x *eventsService) AckEvents(ctx context.Context, req *platformv1.AckEventsRequest) (*platformv1.AckEventsResponse, error) {
	if err := validateSubscription(req.GetSubscription()); err != nil {
		return nil, err
	}
	if req.GetSequence() == 0 {
		return nil, invalidArg("the acknowledged sequence must be positive")
	}
	previous, existed := x.cursors.lookup(req.GetSubscription())
	if err := x.cursors.advance(req.GetSubscription(), req.GetSequence()); err != nil {
		return nil, x.s.dependencyError("store event cursor", err)
	}
	if x.s.cfg.Events != nil {
		if err := x.s.cfg.Events.Ack(ctx, req.GetSubscription(), req.GetSequence()); err != nil {
			x.cursors.restore(req.GetSubscription(), previous, existed)
			return nil, x.s.sinkError("ack events", err)
		}
	}
	return &platformv1.AckEventsResponse{}, nil
}

// SubscribeEvents streams every buffered event of the topics after the ack
// position, then waits for new ones. last_acked_sequence 0 resumes from the
// cursor this instance stored for the subscription.
func (x *eventsService) SubscribeEvents(req *platformv1.SubscribeEventsRequest, stream grpc.ServerStreamingServer[platformv1.SubscribeEventsResponse]) error {
	ctx := stream.Context()
	if err := validateSubscription(req.GetSubscription()); err != nil {
		return err
	}
	topics := req.GetTopics()
	if len(topics) > 64 {
		return limitError("subscription.topics", 64)
	}
	for _, topic := range topics {
		if err := validateEventTopic(topic); err != nil {
			return err
		}
	}
	if err := x.reserveSubscription(); err != nil {
		return err
	}
	defer x.releaseSubscription()

	subscription := req.GetSubscription()
	last := req.GetLastAckedSequence()
	if last == 0 {
		last = x.cursors.get(subscription)
	}
	x.s.log.Info("event subscription opened", "subscription", subscription, "from", last)
	defer x.s.log.Info("event subscription closed", "subscription", subscription)
	for {
		// Capture the notification channel before reading, so an event that
		// arrives between the read and the wait is never missed.
		watch := x.log.watch()
		events, oldest, lost := x.log.since(last, topics)
		if lost {
			x.s.log.Warn("event subscriber fell behind the local buffer", "subscription", subscription, "oldest", oldest)
			if oldest > 0 {
				last = oldest - 1
			}
			events, _, _ = x.log.since(last, topics)
		}
		for _, event := range events {
			if err := stream.Send(&platformv1.SubscribeEventsResponse{Event: event}); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			last = event.GetSequence()
		}
		if len(events) > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-x.s.baseCtx.Done():
			return nil
		case <-watch:
		}
	}
}

// ingest appends one host event to the local subscription buffer. Server.Ingest
// is the only caller.
func (x *eventsService) ingest(event *platformv1.Event) error {
	if event == nil {
		return errors.New("hostsvc: nil event")
	}
	if event.GetSequence() == 0 {
		return errors.New("hostsvc: ingested event has no sequence")
	}
	if err := validateEventType(event.GetType()); err != nil {
		return fmt.Errorf("hostsvc: ingest event: %w", err)
	}
	payload := event.GetPayloadJson()
	if len(payload) > x.s.lim.MaxEventBytes {
		return &LimitError{Name: "event.payload_bytes", Max: int64(x.s.lim.MaxEventBytes)}
	}
	if len(payload) > 0 && !jsonValid(payload) {
		return errors.New("hostsvc: ingested event payload is not JSON")
	}
	x.log.append(event)
	return nil
}

// reserveSubscription applies Limits.MaxSubscriptions.
func (x *eventsService) reserveSubscription() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.subs >= x.s.lim.MaxSubscriptions {
		return limitError("subscriptions", int64(x.s.lim.MaxSubscriptions))
	}
	x.subs++
	return nil
}

// releaseSubscription gives a subscription slot back.
func (x *eventsService) releaseSubscription() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.subs--
}

// validateEventDraft checks a plugin event. The host owns "resource." and
// "operation." event types (platform.proto, "Host: events").
func validateEventDraft(draft *platformv1.EventDraft, limits Limits) error {
	eventType := draft.GetType()
	if strings.HasPrefix(eventType, "resource.") || strings.HasPrefix(eventType, "operation.") {
		return invalidArg("event types starting with resource. or operation. are reserved for the host")
	}
	if err := validateEventType(eventType); err != nil {
		return err
	}
	if version := draft.GetSchemaVersion(); len(version) > 64 || !visibleASCII(version) {
		return invalidArg("invalid event schema version")
	}
	if err := validateRelativeSubject(draft.GetSubject()); err != nil {
		return err
	}
	payload := draft.GetPayloadJson()
	if len(payload) > limits.MaxEventBytes {
		return limitError("event.payload_bytes", int64(limits.MaxEventBytes))
	}
	if len(payload) > 0 && !jsonValid(payload) {
		return invalidArg("the event payload must be a JSON document")
	}
	return nil
}

// callMeta is the correlation part of HostCallContext. The instance handle is
// deliberately absent: identity comes from the listener and the verified peer.
type callMeta struct {
	OperationID string
	TraceID     string
}

// callMetaOf extracts bounded correlation identifiers. A plugin can put
// anything there; the values only reach logs and audit records, never an
// authorization decision.
func callMetaOf(call *platformv1.HostCallContext) callMeta {
	return callMeta{
		OperationID: clipString(call.GetOperationId(), maxIDFieldLen),
		TraceID:     clipString(call.GetTraceId(), maxIDFieldLen),
	}
}

// publishSpool serializes PublishEvent through one worker and bounds the number
// of in-flight jobs. Publishing waits for the sink so the plugin gets the
// journal identity, which means the spool depth is also the number of
// publishers that may block.
type publishSpool struct {
	sink EventSink
	jobs chan *publishJob
	stop chan struct{}
	done chan struct{}

	stopOnce sync.Once
}

// publishJob is one queued publish. The worker writes ref/err and closes done;
// the close is the happens-before edge the waiting publisher relies on.
type publishJob struct {
	ctx   context.Context
	draft EventDraft
	done  chan struct{}
	ref   EventRef
	err   error
}

// finish records the outcome and wakes the waiting publisher.
func (j *publishJob) finish(ref EventRef, err error) {
	j.ref, j.err = ref, err
	close(j.done)
}

// newPublishSpool starts the single worker. capacity must be positive.
func newPublishSpool(sink EventSink, capacity int) *publishSpool {
	spool := &publishSpool{
		sink: sink,
		jobs: make(chan *publishJob, capacity),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go spool.run()
	return spool
}

// run delivers jobs in order until close is called.
func (sp *publishSpool) run() {
	defer close(sp.done)
	for {
		select {
		case <-sp.stop:
			sp.failQueued()
			return
		case job := <-sp.jobs:
			ref, err := sp.sink.Publish(job.ctx, job.draft)
			job.finish(ref, err)
		}
	}
}

// failQueued wakes every publisher whose job has not been picked up yet.
func (sp *publishSpool) failQueued() {
	for {
		select {
		case job := <-sp.jobs:
			job.finish(EventRef{}, errSpoolClosed)
		default:
			return
		}
	}
}

// publish enqueues one job and waits for the sink or the caller's context. A
// full spool is a LimitError, never a block: RESOURCE_EXHAUSTED is the ABI's
// backpressure signal.
func (sp *publishSpool) publish(ctx context.Context, draft EventDraft) (EventRef, error) {
	job := &publishJob{ctx: ctx, draft: draft, done: make(chan struct{})}
	select {
	case <-sp.stop:
		return EventRef{}, errSpoolClosed
	default:
	}
	select {
	case sp.jobs <- job:
	default:
		return EventRef{}, &LimitError{Name: "event_spool", Max: int64(cap(sp.jobs))}
	}
	select {
	case <-job.done:
		return job.ref, job.err
	case <-ctx.Done():
		return EventRef{}, ctx.Err()
	}
}

// close stops the worker. It does not wait forever for a sink call that is
// already running; queued publishers are failed immediately.
func (sp *publishSpool) close() {
	sp.stopOnce.Do(func() { close(sp.stop) })
	sp.failQueued()
	select {
	case <-sp.done:
	case <-time.After(2 * time.Second):
	}
}

// eventLog is the bounded local buffer behind SubscribeEvents. It keeps whole
// events (never partial payloads) and evicts from the front.
type eventLog struct {
	mu         sync.Mutex
	entries    []*platformv1.Event
	bytes      int64
	maxEntries int
	maxBytes   int64
	notify     chan struct{}
}

// newEventLog returns an empty buffer.
func newEventLog(maxEntries int, maxBytes int64) *eventLog {
	return &eventLog{
		maxEntries: max(1, maxEntries),
		maxBytes:   max(1, maxBytes),
		notify:     make(chan struct{}),
	}
}

// append adds an event, evicts the oldest ones while a bound is exceeded and
// wakes every subscriber.
func (l *eventLog) append(event *platformv1.Event) {
	size := eventSize(event)
	l.mu.Lock()
	l.entries = append(l.entries, event)
	l.bytes += size
	for len(l.entries) > l.maxEntries || (l.bytes > l.maxBytes && len(l.entries) > 1) {
		dropped := l.entries[0]
		l.entries = l.entries[1:]
		l.bytes -= eventSize(dropped)
	}
	close(l.notify)
	l.notify = make(chan struct{})
	l.mu.Unlock()
}

// watch returns the channel that is closed on the next append.
func (l *eventLog) watch() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.notify
}

// since returns the matching events after seq, the oldest retained sequence and
// whether events after seq were already evicted.
func (l *eventLog) since(seq uint64, topics []string) (events []*platformv1.Event, oldest uint64, lost bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > 0 {
		oldest = l.entries[0].GetSequence()
	}
	if oldest > 0 && seq+1 < oldest {
		lost = true
	}
	for _, event := range l.entries {
		if event.GetSequence() <= seq {
			continue
		}
		if !matchTopic(topics, event.GetType()) {
			continue
		}
		events = append(events, event)
	}
	return events, oldest, lost
}

// eventSize is the approximate memory of one retained event, payload included.
func eventSize(event *platformv1.Event) int64 {
	return int64(len(event.GetPayloadJson()) + len(event.GetEventId()) + len(event.GetType()) +
		len(event.GetSubject()) + len(event.GetTraceId()) + len(event.GetOperationId()) + 128)
}

// cursorStore keeps the ack position per subscription. Its size is bounded by
// Limits.MaxSubscriptionCursors, so a plugin cannot grow the Agent's memory by
// acking an unbounded number of distinct subscription names. A subscription
// name is validated before it reaches the store.
type cursorStore struct {
	mu      sync.Mutex
	cursors map[string]uint64
	max     int
}

// newCursorStore returns an empty store that holds at most max subscriptions.
func newCursorStore(maxSubscriptions int) *cursorStore {
	return &cursorStore{
		cursors: make(map[string]uint64),
		max:     max(1, maxSubscriptions),
	}
}

// get returns the stored cursor or 0.
func (c *cursorStore) get(subscription string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursors[subscription]
}

// lookup returns the stored cursor and whether the subscription exists.
func (c *cursorStore) lookup(subscription string) (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sequence, ok := c.cursors[subscription]
	return sequence, ok
}

// advance stores a cursor. A lower sequence never moves a cursor backwards; a
// new subscription is refused once the store is full.
func (c *cursorStore) advance(subscription string, sequence uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, exists := c.cursors[subscription]
	if !exists && len(c.cursors) >= c.max {
		return &LimitError{Name: "event_subscription_cursors", Max: int64(c.max)}
	}
	if sequence > current {
		c.cursors[subscription] = sequence
	}
	return nil
}

// restore puts a cursor back after a failed sink acknowledgement. An entry that
// did not exist before is removed again.
func (c *cursorStore) restore(subscription string, previous uint64, existed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existed {
		c.cursors[subscription] = previous
		return
	}
	delete(c.cursors, subscription)
}
