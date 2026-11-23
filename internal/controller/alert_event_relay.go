// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// AlertDispatchInvoker wakes notify.hub on demand and dispatches notify.dispatch
// as a host-internal system actor.
type AlertDispatchInvoker interface {
	DispatchInternalAlert(ctx context.Context, payloadJSON []byte) error
}

// AlertEventPayload is the normalized alert event shape published by builtin
// plugins via Host.PublishEvent(EventDraft{Type: "<domain>.alert", ...}).
type AlertEventPayload struct {
	EventID   string            `json:"event_id,omitempty"`
	Source    string            `json:"source"`
	Severity  string            `json:"severity"` // info | warn | critical
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	DedupKey  string            `json:"dedup_key,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	Timestamp time.Time         `json:"timestamp,omitempty"`
}

// notifyDispatchArgs matches plugins/builtin/notify.hub/schemas/notify.dispatch.request.json
// which enforces "additionalProperties": false and permits only these 6 fields.
type notifyDispatchArgs struct {
	Source   string            `json:"source"`
	Severity string            `json:"severity,omitempty"`
	Title    string            `json:"title"`
	Message  string            `json:"message,omitempty"`
	DedupKey string            `json:"dedup_key,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
}

const (
	alertRateLimitPerPlugin = 10
	alertRateLimitWindow    = time.Minute
)

// AlertEventRelay forwards "*.alert" plugin events to notify.hub through a
// bounded 64-item queue so hot paths never block and 1C1G memory stays bounded.
type AlertEventRelay struct {
	invoker AlertDispatchInvoker
	logger  *slog.Logger
	queue   chan AlertEventPayload
	now     func() time.Time

	mu            sync.Mutex
	pluginWindows map[string][]time.Time
	cancel        context.CancelFunc
	started       bool
	stopped       bool
	wg            sync.WaitGroup
}

// NewAlertEventRelay constructs a bounded alert relay (queue capacity 64).
func NewAlertEventRelay(invoker AlertDispatchInvoker, logger *slog.Logger) *AlertEventRelay {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &AlertEventRelay{
		invoker:       invoker,
		logger:        logger,
		queue:         make(chan AlertEventPayload, 64),
		now:           time.Now,
		pluginWindows: make(map[string][]time.Time),
	}
}

// Start runs the single serial delivery goroutine until ctx is canceled or Stop is called.
func (r *AlertEventRelay) Start(ctx context.Context) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.started || r.stopped {
		r.mu.Unlock()
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.started = true
	r.wg.Add(1)
	r.mu.Unlock()

	go func() {
		defer r.wg.Done()
		for {
			select {
			case <-runCtx.Done():
				return
			case ev, ok := <-r.queue:
				if !ok {
					return
				}
				r.deliverOne(runCtx, ev)
			}
		}
	}()
}

// Stop stops the relay and waits for the worker goroutine to exit.
func (r *AlertEventRelay) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.stopped {
		r.stopped = true
		if r.cancel != nil {
			r.cancel()
		}
		close(r.queue)
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// OnPluginEvent inspects each persisted plugin event and enqueues "*.alert"
// events after forcing Source to the verified publishing plugin ID.
func (r *AlertEventRelay) OnPluginEvent(publisherPluginID string, draft *platformv1.EventDraft, assignedEventID string) {
	if r == nil || draft == nil || !strings.HasSuffix(draft.GetType(), ".alert") {
		return
	}
	var payload AlertEventPayload
	if err := json.Unmarshal(draft.GetPayloadJson(), &payload); err != nil {
		return
	}
	if strings.TrimSpace(payload.Title) == "" {
		return
	}
	payload.Source = publisherPluginID
	if assignedEventID != "" {
		payload.EventID = assignedEventID
	}
	if payload.Severity != "info" && payload.Severity != "warn" && payload.Severity != "critical" {
		payload.Severity = "warn"
	}
	nowFn := r.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC()
	if payload.Timestamp.IsZero() {
		payload.Timestamp = now
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	if !r.allowPluginAlertLocked(publisherPluginID, now) {
		r.logger.Warn("alert relay per-plugin rate limit exceeded, dropping alert",
			"source", publisherPluginID, "event_id", payload.EventID, "title", payload.Title)
		return
	}
	select {
	case r.queue <- payload:
	default:
		r.logger.Warn("alert relay queue full, dropping alert to protect memory budget",
			"source", publisherPluginID, "event_id", payload.EventID, "title", payload.Title)
	}
}

func (r *AlertEventRelay) allowPluginAlertLocked(pluginID string, now time.Time) bool {
	if r.pluginWindows == nil {
		r.pluginWindows = make(map[string][]time.Time)
	}
	cutoff := now.Add(-alertRateLimitWindow)
	ts := r.pluginWindows[pluginID]
	keep := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= alertRateLimitPerPlugin {
		r.pluginWindows[pluginID] = keep
		return false
	}
	r.pluginWindows[pluginID] = append(keep, now)
	return true
}

func (r *AlertEventRelay) deliverOne(parent context.Context, ev AlertEventPayload) {
	if r.invoker == nil {
		return
	}
	args := notifyDispatchArgs{
		Source:   ev.Source,
		Severity: ev.Severity,
		Title:    ev.Title,
		Message:  ev.Message,
		DedupKey: ev.DedupKey,
		Tags:     ev.Tags,
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if err := r.invoker.DispatchInternalAlert(ctx, raw); err != nil {
		if !strings.Contains(err.Error(), "not installed") && !strings.Contains(err.Error(), "not found") {
			r.logger.Warn("notify.hub internal alert delivery failed", "source", ev.Source, "event_id", ev.EventID, "err", err)
		}
	}
}

// DispatchInternalAlert wakes notify.hub on demand (when installed & enabled)
// and dispatches notify.dispatch as a host system actor.
func (c *Controller) DispatchInternalAlert(ctx context.Context, payloadJSON []byte) error {
	if c == nil || c.closed.Load() || c.ops == nil {
		return errors.New("controller not ready")
	}
	u := c.Updater()
	if u == nil {
		return errors.New("notify.hub not installed")
	}
	if _, ok := u.Active("notify.hub"); !ok {
		return errors.New("notify.hub not installed")
	}
	enabled, err := u.Enabled(ctx, "notify.hub")
	if err != nil || !enabled {
		return errors.New("notify.hub not found or disabled")
	}
	nodeID := c.ops.NodeID()
	if nodeID == "" {
		nodeID = "local"
	}
	opCtx := operations.WithPermissionMode(ctx, operations.PermissionFull)
	resp, err := c.ops.Run(opCtx, operations.RunRequest{
		Actor:  actor.SystemActor("alert_relay"),
		Action: "notify.hub/notify.dispatch",
		NodeID: nodeID,
		Target: operations.Target{
			NodeID:     nodeID,
			PluginID:   "notify.hub",
			InstanceID: DefaultInstanceID,
		},
		Args: payloadJSON,
	})
	if err != nil {
		return err
	}
	if resp != nil && resp.Operation != nil && (resp.Operation.Status == operations.Failed || resp.Operation.Status == operations.Rejected) {
		if resp.Operation.Error != nil && resp.Operation.Error.Detail != "" {
			return problem.New(problem.PluginUnavailable, "%s", resp.Operation.Error.Detail)
		}
		return errors.New("notify.dispatch failed")
	}
	return nil
}
