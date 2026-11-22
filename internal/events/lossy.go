// SPDX-License-Identifier: AGPL-3.0-only

package events

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// Defaults of LossyConfig.
const (
	DefaultLossyTopics      = 64
	DefaultLossySubscribers = 256
	DefaultLossyKeys        = 64
)

// ErrTooManyTopics is returned when Lossy has no room for another topic.
var ErrTooManyTopics = errors.New("events: too many lossy topics")

// Lossy is the in-memory fanout for realtime samples: metrics, presence and
// other high-rate values that are useless once stale (ARCH §4.2). Samples are
// coalesced per key — a subscriber always sees the newest value of a key, never
// a backlog — so the fanout has a fixed capacity per subscriber and never
// grows the process. Nothing is journaled and nothing is replayed; counters
// report what was coalesced or dropped.
//
// Lossy is safe for concurrent use and never blocks a publisher on a slow
// subscriber.
type Lossy struct {
	cfg LossyConfig

	mu     sync.Mutex
	topics map[string]map[*LossySubscription]struct{}
	stats  lossyCounters
}

// LossyConfig bounds a Lossy fanout.
type LossyConfig struct {
	// Topics bounds the number of live topics (default DefaultLossyTopics).
	Topics int
	// Subscribers bounds subscribers per topic (default DefaultLossySubscribers).
	Subscribers int
	// Keys bounds the distinct samples buffered for one subscriber
	// (default DefaultLossyKeys).
	Keys int
}

// LossyStats reports lossy fanout counters (ARCH §13).
type LossyStats struct {
	Topics      int
	Subscribers int
	// Published counts published samples.
	Published int64
	// Coalesced counts samples replaced by a newer value of the same key.
	Coalesced int64
	// Dropped counts samples discarded because a subscriber's key set was full.
	Dropped int64
}

type lossyCounters struct {
	published, coalesced, dropped atomic.Int64
}

// NewLossy returns a lossy fanout with the given bounds.
func NewLossy(cfg LossyConfig) *Lossy {
	if cfg.Topics <= 0 {
		cfg.Topics = DefaultLossyTopics
	}
	if cfg.Subscribers <= 0 {
		cfg.Subscribers = DefaultLossySubscribers
	}
	if cfg.Keys <= 0 {
		cfg.Keys = DefaultLossyKeys
	}
	return &Lossy{cfg: cfg, topics: make(map[string]map[*LossySubscription]struct{})}
}

// LossySubscription is one subscriber of a lossy topic.
type LossySubscription struct {
	l      *Lossy
	topic  string
	keys   map[string]any
	notify chan struct{}
	closed bool
}

// Subscribe joins a topic.
func (l *Lossy) Subscribe(topic string) (*LossySubscription, error) {
	if topic == "" {
		return nil, errors.New("events: lossy topic is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	subs := l.topics[topic]
	if subs == nil {
		if len(l.topics) >= l.cfg.Topics {
			return nil, ErrTooManyTopics
		}
		subs = make(map[*LossySubscription]struct{})
		l.topics[topic] = subs
	}
	if len(subs) >= l.cfg.Subscribers {
		return nil, ErrTooManySubscribers
	}
	s := &LossySubscription{
		l:      l,
		topic:  topic,
		keys:   make(map[string]any),
		notify: make(chan struct{}, 1),
	}
	subs[s] = struct{}{}
	return s, nil
}

// Publish offers a sample to every subscriber of topic. No subscriber, a full
// key set or a newer value for the same key all just adjust the counters.
func (l *Lossy) Publish(topic, key string, v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	subs := l.topics[topic]
	if len(subs) == 0 {
		return
	}
	l.stats.published.Add(1)
	for s := range subs {
		if s.closed {
			continue
		}
		if _, ok := s.keys[key]; ok {
			s.keys[key] = v
			l.stats.coalesced.Add(1)
			s.signal()
			continue
		}
		if len(s.keys) >= l.cfg.Keys {
			l.stats.dropped.Add(1)
			continue
		}
		s.keys[key] = v
		s.signal()
	}
}

// Stats returns the counters.
func (l *Lossy) Stats() LossyStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, subs := range l.topics {
		n += len(subs)
	}
	return LossyStats{
		Topics:      len(l.topics),
		Subscribers: n,
		Published:   l.stats.published.Load(),
		Coalesced:   l.stats.coalesced.Load(),
		Dropped:     l.stats.dropped.Load(),
	}
}

// signal wakes the consumer without blocking. l.mu must be held.
func (s *LossySubscription) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Next returns the next pending sample, waiting until one arrives or ctx ends.
// It returns false when the subscription is closed or ctx is done. Samples of
// different keys may arrive in any order; samples of one key always arrive in
// publish order with stale values merged away.
func (s *LossySubscription) Next(ctx context.Context) (any, bool) {
	for {
		s.l.mu.Lock()
		if s.closed {
			s.l.mu.Unlock()
			return nil, false
		}
		for k, v := range s.keys {
			delete(s.keys, k)
			if len(s.keys) > 0 {
				s.signal()
			}
			s.l.mu.Unlock()
			return v, true
		}
		s.l.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, false
		case <-s.notify:
		}
	}
}

// Close leaves the topic. It is safe to call more than once.
func (s *LossySubscription) Close() {
	s.l.mu.Lock()
	defer s.l.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.keys = nil
	if subs := s.l.topics[s.topic]; subs != nil {
		delete(subs, s)
		if len(subs) == 0 {
			delete(s.l.topics, s.topic)
		}
	}
	s.signal()
}
