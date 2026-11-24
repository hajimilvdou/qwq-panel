// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StagedBind represents a TCP listener that has been pre-bound in Phase 1
// before SQLite commits the new address. Calling Commit() activates serving and
// schedules retirement of the old listener; calling Abort() closes the new
// listener immediately and restores any displaced overlapping listener.
type StagedBind struct {
	owner            *liveHTTPListener
	ln               net.Listener
	reqAddr          string
	displacedReqAddr string
	done             bool
}

// Commit activates the staged listener and retires the previous listener after
// a grace window so in-flight HTTP responses finish cleanly.
func (s *StagedBind) Commit() {
	if s == nil || s.done {
		return
	}
	s.done = true
	s.owner.commitBind(s.ln, s.reqAddr)
}

// Abort releases the pre-bound listener if DB persistence or validation failed,
// restoring any overlapping listener that had to be temporarily released.
func (s *StagedBind) Abort() {
	if s == nil || s.done {
		return
	}
	s.done = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	if s.displacedReqAddr != "" {
		s.owner.restoreDisplaced(s.displacedReqAddr)
	}
}

type retiringEntry struct {
	reqAddr    string
	actualAddr string
	timer      *time.Timer
}

// liveHTTPListener owns the active TCP listener of `qwq serve-controller` and
// supports two-phase live port hot-rebind (`PrepareBind` -> DB commit ->
// `Commit`/`Abort`), retiring listener reclamation for quick `A -> B -> A`
// switches, and full retiring FD cleanup on shutdown.
type liveHTTPListener struct {
	srv            *http.Server
	useTLS         bool
	logger         *slog.Logger
	errCh          chan error
	mu             sync.Mutex
	current        net.Listener
	currentReqAddr string
	retiring       map[net.Listener]*retiringEntry
	closing        atomic.Bool
}

func newLiveHTTPListener(srv *http.Server, useTLS bool, logger *slog.Logger) *liveHTTPListener {
	return &liveHTTPListener{
		srv:      srv,
		useTLS:   useTLS,
		logger:   logger,
		errCh:    make(chan error, 1),
		retiring: make(map[net.Listener]*retiringEntry),
	}
}

// Start binds addr and starts serving in a background goroutine.
func (l *liveHTTPListener) Start(addr string) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.current = ln
	l.currentReqAddr = addr
	l.mu.Unlock()
	go l.serveOne(ln)
	return ln.Addr(), nil
}

// PrepareBind performs Phase 1 of a two-phase address switch: if newAddr
// conflicts with a retiring listener from a recent switch, it reclaims and
// closes it first. When switching listen host on the same port (e.g.
// 127.0.0.1:8443 <-> 0.0.0.0:8443 <-> [::]:8443), the current overlapping
// listener is temporarily released before binding newAddr (existing HTTP
// connections remain alive in http.Server); if binding or DB commit fails, the
// previous address is immediately restored.
func (l *liveHTTPListener) PrepareBind(newAddr string) (*StagedBind, error) {
	l.reclaimRetiringAddr(newAddr)

	var (
		displacedLn      net.Listener
		displacedReqAddr string
	)
	l.mu.Lock()
	if l.current != nil && (addrsConflict(l.currentReqAddr, newAddr) || addrsConflict(l.current.Addr().String(), newAddr)) {
		displacedLn = l.current
		displacedReqAddr = l.currentReqAddr
		if _, p, err := net.SplitHostPort(displacedReqAddr); err != nil || p == "0" || p == "" {
			displacedReqAddr = displacedLn.Addr().String()
		}
		l.current = nil
		l.currentReqAddr = ""
	}
	l.mu.Unlock()

	if displacedLn != nil {
		_ = displacedLn.Close()
	}

	newLn, err := net.Listen("tcp", newAddr)
	if err != nil {
		if displacedReqAddr != "" {
			l.restoreDisplaced(displacedReqAddr)
		}
		return nil, err
	}
	return &StagedBind{owner: l, ln: newLn, reqAddr: newAddr, displacedReqAddr: displacedReqAddr}, nil
}

func (l *liveHTTPListener) restoreDisplaced(addr string) {
	if addr == "" || l.closing.Load() {
		return
	}
	restored, err := net.Listen("tcp", addr)
	if err != nil {
		if l.logger != nil {
			l.logger.Error("failed to restore displaced panel listener", "addr", addr, "error", err)
		}
		return
	}
	l.mu.Lock()
	if l.closing.Load() || l.current != nil {
		l.mu.Unlock()
		_ = restored.Close()
		return
	}
	l.current = restored
	l.currentReqAddr = addr
	l.mu.Unlock()
	go l.serveOne(restored)
}

// Rebind performs a single-call hot-rebind using PrepareBind + Commit.
func (l *liveHTTPListener) Rebind(newAddr string) error {
	staged, err := l.PrepareBind(newAddr)
	if err != nil {
		return err
	}
	staged.Commit()
	return nil
}

func (l *liveHTTPListener) reclaimRetiringAddr(targetAddr string) {
	l.mu.Lock()
	var toClose []net.Listener
	for ln, ent := range l.retiring {
		if addrsConflict(ent.reqAddr, targetAddr) || addrsConflict(ent.actualAddr, targetAddr) {
			ent.timer.Stop()
			delete(l.retiring, ln)
			toClose = append(toClose, ln)
		}
	}
	l.mu.Unlock()
	for _, ln := range toClose {
		_ = ln.Close()
	}
}

// addrsConflict reports whether two TCP listen addresses cannot coexist on the
// same host (same port with identical host or either side being a wildcard
// 0.0.0.0 / :: / "").
func addrsConflict(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	ha, pa, errA := net.SplitHostPort(a)
	hb, pb, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || pa != pb {
		return false
	}
	na := normalizeListenHost(ha)
	nb := normalizeListenHost(hb)
	return na == nb || na == "*" || nb == "*"
}

// sameListenAddr reports whether two host:port listen specs refer to the same
// bind target, normalizing equivalent wildcard hosts ("", "0.0.0.0", "::", "[::]")
// on the same port.
func sameListenAddr(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	ha, pa, errA := net.SplitHostPort(a)
	hb, pb, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || pa != pb {
		return false
	}
	return normalizeListenHost(ha) == normalizeListenHost(hb)
}

func normalizeListenHost(h string) string {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]"))
	switch s {
	case "", "0.0.0.0", "::":
		return "*"
	default:
		return s
	}
}

func (l *liveHTTPListener) commitBind(newLn net.Listener, newReqAddr string) {
	l.mu.Lock()
	if l.closing.Load() {
		l.mu.Unlock()
		_ = newLn.Close()
		return
	}
	oldLn := l.current
	oldReqAddr := l.currentReqAddr
	l.current = newLn
	l.currentReqAddr = newReqAddr
	if oldLn != nil {
		oldActualAddr := oldLn.Addr().String()
		tmr := time.AfterFunc(5*time.Second, func() {
			l.mu.Lock()
			delete(l.retiring, oldLn)
			l.mu.Unlock()
			_ = oldLn.Close()
		})
		l.retiring[oldLn] = &retiringEntry{reqAddr: oldReqAddr, actualAddr: oldActualAddr, timer: tmr}
	}
	l.mu.Unlock()

	go l.serveOne(newLn)
	if l.logger != nil {
		l.logger.Info("panel listener hot-rebound", "addr", newLn.Addr().String())
	}
}

// Close stops accepting new connections on the active and all retiring listeners.
func (l *liveHTTPListener) Close() {
	l.closing.Store(true)
	l.mu.Lock()
	ln := l.current
	l.current = nil
	retiring := make([]net.Listener, 0, len(l.retiring))
	for rln, ent := range l.retiring {
		ent.timer.Stop()
		retiring = append(retiring, rln)
	}
	clear(l.retiring)
	l.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, rln := range retiring {
		_ = rln.Close()
	}
}

func (l *liveHTTPListener) serveOne(ln net.Listener) {
	var err error
	if l.useTLS {
		err = l.srv.ServeTLS(ln, "", "")
	} else {
		err = l.srv.Serve(ln)
	}
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return
	}
	if l.closing.Load() {
		return
	}
	l.mu.Lock()
	stillCurrent := l.current == ln
	l.mu.Unlock()
	if !stillCurrent && errors.Is(err, net.ErrClosed) {
		return
	}
	select {
	case l.errCh <- err:
	default:
	}
}
