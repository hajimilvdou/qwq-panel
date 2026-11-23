// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EnvIdleTTL configures optional scale-to-zero idle hibernation for on_demand
// plugins (for example "180s" or "3m"). Empty or non-positive values disable
// idle hibernation.
const EnvIdleTTL = "QWQ_PLUGIN_IDLE_TTL"

// IdleTTLFromEnv parses EnvIdleTTL. Unset, invalid, or non-positive values
// return 0 (disabled).
func IdleTTLFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(EnvIdleTTL))
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// IdleDrainer tracks in-flight RPCs for a plugin process. When in-flight calls
// drop to zero and no request has been active for at least idleTTL, onDrain is
// called once so the process can stop gracefully and exit cleanly.
type IdleDrainer struct {
	idleTTL      time.Duration
	inFlight     atomic.Int64
	lastActiveNs atomic.Int64
	stopOnce     sync.Once
	stopCh       chan struct{}
}

// NewIdleDrainer starts a background idle watcher that calls onDrain once the
// process has been idle with zero in-flight requests for idleTTL. A non-positive
// idleTTL returns nil (disabled).
func NewIdleDrainer(idleTTL time.Duration, onDrain func()) *IdleDrainer {
	if idleTTL <= 0 {
		return nil
	}
	d := &IdleDrainer{
		idleTTL: idleTTL,
		stopCh:  make(chan struct{}),
	}
	d.lastActiveNs.Store(time.Now().UnixNano())
	go d.watchLoop(onDrain)
	return d
}

// BeginRequest marks an active request and returns a release callback to invoke
// when the request finishes. Safe on a nil receiver.
func (d *IdleDrainer) BeginRequest() func() {
	if d == nil {
		return func() {}
	}
	d.inFlight.Add(1)
	d.lastActiveNs.Store(time.Now().UnixNano())
	var once sync.Once
	return func() {
		once.Do(func() {
			d.lastActiveNs.Store(time.Now().UnixNano())
			d.inFlight.Add(-1)
		})
	}
}

// Close stops the background watcher. Safe to call multiple times or on nil.
func (d *IdleDrainer) Close() {
	if d == nil {
		return
	}
	d.stopOnce.Do(func() { close(d.stopCh) })
}

func (d *IdleDrainer) watchLoop(onDrain func()) {
	checkInterval := d.idleTTL / 6
	if d.idleTTL >= 30*time.Second {
		if checkInterval < 5*time.Second {
			checkInterval = 5 * time.Second
		}
	} else if checkInterval < 10*time.Millisecond {
		checkInterval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case now := <-ticker.C:
			if d.inFlight.Load() > 0 {
				continue
			}
			idleFor := time.Duration(now.UnixNano() - d.lastActiveNs.Load())
			if idleFor >= d.idleTTL {
				d.Close()
				if onDrain != nil {
					onDrain()
				}
				return
			}
		}
	}
}
