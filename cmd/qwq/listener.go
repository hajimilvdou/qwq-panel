// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const listenerRetireGrace = 5 * time.Second

// trackedConnListener tracks all accepted TCP connections of one listener
// generation so tightening listen_host from public (0.0.0.0 / ::) back to
// loopback (127.0.0.1 / ::1) can actively evict surviving external HTTP/2 and
// SSE long-lived connections once the grace window ends.
type trackedConnListener struct {
	net.Listener
	shared *liveHTTPListener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
}

func newTrackedConnListener(inner net.Listener, shared *liveHTTPListener) *trackedConnListener {
	return &trackedConnListener{
		Listener: inner,
		shared:   shared,
		conns:    make(map[net.Conn]struct{}),
	}
}

func (tl *trackedConnListener) Accept() (net.Conn, error) {
	c, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wc := &trackedConn{Conn: c, parent: tl, shared: tl.shared}
	tl.mu.Lock()
	tl.conns[wc] = struct{}{}
	tl.mu.Unlock()
	if tl.shared != nil {
		tl.shared.trackConn(wc)
	}
	return wc, nil
}

func (tl *trackedConnListener) remove(c net.Conn) {
	tl.mu.Lock()
	delete(tl.conns, c)
	tl.mu.Unlock()
}

func closeNonLoopbackConnSlice(snapshot []net.Conn) int {
	closed := 0
	for _, c := range snapshot {
		if c.RemoteAddr() == nil {
			continue
		}
		host, _, err := net.SplitHostPort(c.RemoteAddr().String())
		if err != nil {
			continue
		}
		if ip, perr := netip.ParseAddr(host); perr == nil && ip.Unmap().IsLoopback() {
			continue
		}
		_ = c.Close()
		closed++
	}
	return closed
}

// CloseNonLoopbackConns actively closes all established connections whose
// remote peer is not a loopback address (127.0.0.1 / ::1).
func (tl *trackedConnListener) CloseNonLoopbackConns() int {
	if tl == nil {
		return 0
	}
	tl.mu.Lock()
	snapshot := make([]net.Conn, 0, len(tl.conns))
	for c := range tl.conns {
		snapshot = append(snapshot, c)
	}
	tl.mu.Unlock()
	return closeNonLoopbackConnSlice(snapshot)
}

type trackedConn struct {
	net.Conn
	parent    *trackedConnListener
	shared    *liveHTTPListener
	closeOnce sync.Once
}

// NetConn exposes the underlying net.Conn so middleware (e.g. stealth drop's
// SetLinger(0)) can unwrap *tls.Conn -> *trackedConn -> *net.TCPConn.
func (tc *trackedConn) NetConn() net.Conn {
	return tc.Conn
}

func (tc *trackedConn) Close() error {
	var err error
	tc.closeOnce.Do(func() {
		tc.parent.remove(tc)
		if tc.shared != nil {
			tc.shared.untrackConn(tc)
		}
		err = tc.Conn.Close()
	})
	return err
}

// WrapListenerForSharedServer wraps rawLn with a trackedConnListener and, when
// TLS is enabled, a tls.NewListener using an isolated clone of baseTLS so
// concurrent hot-rebind listeners can safely call srv.Serve(serveLn) without
// racing on srv.TLSConfig (as srv.ServeTLS would).
func WrapListenerForSharedServer(rawLn net.Listener, useTLS bool, baseTLS *tls.Config) (*trackedConnListener, net.Listener) {
	return wrapListenerForSharedServer(rawLn, useTLS, baseTLS, nil)
}

func wrapListenerForSharedServer(rawLn net.Listener, useTLS bool, baseTLS *tls.Config, shared *liveHTTPListener) (*trackedConnListener, net.Listener) {
	tln := newTrackedConnListener(rawLn, shared)
	if !useTLS || baseTLS == nil {
		return tln, tln
	}
	cloned := baseTLS.Clone()
	if len(cloned.NextProtos) == 0 {
		cloned.NextProtos = []string{"h2", "http/1.1"}
	}
	return tln, tls.NewListener(tln, cloned)
}

// IsLoopbackOnlyHost reports whether host refers exclusively to loopback.
func IsLoopbackOnlyHost(host string) bool {
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

func addrIsLoopbackOnly(addr string) bool {
	h, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return IsLoopbackOnlyHost(addr)
	}
	return IsLoopbackOnlyHost(h)
}

// StagedBind represents a TCP listener that has been pre-bound in Phase 1
// before SQLite commits the new address. Calling Commit() activates serving and
// schedules retirement of the old listener; calling Abort() closes the new
// listener immediately and restores any displaced overlapping listener.
type StagedBind struct {
	owner            *liveHTTPListener
	ln               net.Listener
	reqAddr          string
	displacedReqAddr string
	displacedTracked *trackedConnListener
	done             bool
}

// Commit activates the staged listener and retires the previous listener after
// a grace window so in-flight HTTP responses finish cleanly.
func (s *StagedBind) Commit() {
	if s == nil || s.done {
		return
	}
	s.done = true
	s.owner.commitBind(s.ln, s.reqAddr, s.displacedReqAddr, s.displacedTracked)
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
	tracked    *trackedConnListener
	timer      *time.Timer
}

// liveHTTPListener owns the active TCP listener of `qwq serve-controller` and
// supports two-phase live port hot-rebind (`PrepareBind` -> DB commit ->
// `Commit`/`Abort`), retiring listener reclamation for quick `A -> B -> A`
// switches, race-free TLS listener wrapping, external connection eviction when
// tightening to loopback, and full retiring FD cleanup on shutdown.
type liveHTTPListener struct {
	srv            *http.Server
	useTLS         bool
	baseTLS        *tls.Config
	retireGrace    time.Duration
	logger         *slog.Logger
	errCh          chan error
	mu             sync.Mutex
	current        net.Listener
	currentTracked *trackedConnListener
	currentReqAddr string
	retiring       map[net.Listener]*retiringEntry
	evictTimers    map[*time.Timer]struct{}
	allConns       map[net.Conn]struct{}
	closing        atomic.Bool
}

func newLiveHTTPListener(srv *http.Server, useTLS bool, logger *slog.Logger) *liveHTTPListener {
	var baseTLS *tls.Config
	if useTLS && srv != nil && srv.TLSConfig != nil {
		baseTLS = srv.TLSConfig.Clone()
	}
	return &liveHTTPListener{
		srv:         srv,
		useTLS:      useTLS,
		baseTLS:     baseTLS,
		retireGrace: listenerRetireGrace,
		logger:      logger,
		errCh:       make(chan error, 1),
		retiring:    make(map[net.Listener]*retiringEntry),
		evictTimers: make(map[*time.Timer]struct{}),
		allConns:    make(map[net.Conn]struct{}),
	}
}

func (l *liveHTTPListener) trackConn(c net.Conn) {
	if l == nil || c == nil {
		return
	}
	l.mu.Lock()
	if l.allConns == nil {
		l.allConns = make(map[net.Conn]struct{})
	}
	l.allConns[c] = struct{}{}
	l.mu.Unlock()
}

func (l *liveHTTPListener) untrackConn(c net.Conn) {
	if l == nil || c == nil {
		return
	}
	l.mu.Lock()
	delete(l.allConns, c)
	l.mu.Unlock()
}

func (l *liveHTTPListener) closeAllNonLoopbackConns() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	snapshot := make([]net.Conn, 0, len(l.allConns))
	for c := range l.allConns {
		snapshot = append(snapshot, c)
	}
	l.mu.Unlock()
	return closeNonLoopbackConnSlice(snapshot)
}

func (l *liveHTTPListener) graceDuration() time.Duration {
	if l.retireGrace > 0 {
		return l.retireGrace
	}
	return listenerRetireGrace
}

// Start binds addr and starts serving in a background goroutine.
func (l *liveHTTPListener) Start(addr string) (net.Addr, error) {
	rawLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tracked, serveLn := wrapListenerForSharedServer(rawLn, l.useTLS, l.baseTLS, l)
	l.mu.Lock()
	l.current = serveLn
	l.currentTracked = tracked
	l.currentReqAddr = addr
	l.mu.Unlock()
	go l.serveOne(serveLn)
	return rawLn.Addr(), nil
}

// PrepareBind performs Phase 1 of a two-phase address switch: if newAddr
// conflicts with a retiring listener from a recent switch, it reclaims and
// closes it first. When switching listen host on the same port (e.g.
// 127.0.0.1:8443 <-> 0.0.0.0:8443 <-> [::]:8443), the current overlapping
// listener is temporarily released before binding newAddr (existing HTTP
// connections remain alive in http.Server); if binding or DB commit fails, the
// previous address is immediately restored.
func (l *liveHTTPListener) PrepareBind(newAddr string) (*StagedBind, error) {
	if l.closing.Load() {
		return nil, net.ErrClosed
	}
	l.reclaimRetiringAddr(newAddr)

	var (
		displacedLn      net.Listener
		displacedTracked *trackedConnListener
		displacedReqAddr string
	)
	l.mu.Lock()
	if l.closing.Load() {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	if l.current != nil && (addrsConflict(l.currentReqAddr, newAddr) || addrsConflict(l.current.Addr().String(), newAddr)) {
		displacedLn = l.current
		displacedTracked = l.currentTracked
		displacedReqAddr = l.currentReqAddr
		if _, p, err := net.SplitHostPort(displacedReqAddr); err != nil || p == "0" || p == "" {
			displacedReqAddr = displacedLn.Addr().String()
		}
		l.current = nil
		l.currentTracked = nil
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
	return &StagedBind{
		owner:            l,
		ln:               newLn,
		reqAddr:          newAddr,
		displacedReqAddr: displacedReqAddr,
		displacedTracked: displacedTracked,
	}, nil
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
		select {
		case l.errCh <- err:
		default:
		}
		return
	}
	tracked, serveLn := wrapListenerForSharedServer(restored, l.useTLS, l.baseTLS, l)
	l.mu.Lock()
	if l.closing.Load() || l.current != nil {
		l.mu.Unlock()
		_ = serveLn.Close()
		return
	}
	l.current = serveLn
	l.currentTracked = tracked
	l.currentReqAddr = addr
	l.mu.Unlock()
	go l.serveOne(serveLn)
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
	ha, pa, errA := net.SplitHostPort(a)
	hb, pb, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || pa != pb || pa == "0" || pa == "" {
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
	case "localhost":
		return "127.0.0.1"
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		ip = ip.Unmap()
		if ip.IsUnspecified() {
			return "*"
		}
		return ip.String()
	}
	return s
}

func (l *liveHTTPListener) commitBind(rawNewLn net.Listener, newReqAddr, displacedReqAddr string, displacedTracked *trackedConnListener) {
	newTracked, serveLn := wrapListenerForSharedServer(rawNewLn, l.useTLS, l.baseTLS, l)
	newIsLoopback := addrIsLoopbackOnly(newReqAddr)
	grace := l.graceDuration()

	l.mu.Lock()
	if l.closing.Load() {
		l.mu.Unlock()
		_ = serveLn.Close()
		return
	}
	oldLn := l.current
	oldTracked := l.currentTracked
	oldReqAddr := l.currentReqAddr
	l.current = serveLn
	l.currentTracked = newTracked
	l.currentReqAddr = newReqAddr
	if oldLn != nil {
		oldActualAddr := oldLn.Addr().String()
		tmr := time.AfterFunc(grace, func() {
			l.mu.Lock()
			delete(l.retiring, oldLn)
			stillLoopback := addrIsLoopbackOnly(l.currentReqAddr)
			l.mu.Unlock()
			_ = oldLn.Close()
			if newIsLoopback && stillLoopback {
				if evicted := l.closeAllNonLoopbackConns(); evicted > 0 && l.logger != nil {
					l.logger.Info("evicted non-loopback connections after tightening panel listener to loopback",
						"old_addr", oldActualAddr, "evicted", evicted)
				}
			}
		})
		l.retiring[oldLn] = &retiringEntry{reqAddr: oldReqAddr, actualAddr: oldActualAddr, tracked: oldTracked, timer: tmr}
	}
	if newIsLoopback && (displacedTracked != nil || (oldLn == nil && !addrIsLoopbackOnly(displacedReqAddr))) {
		var tmr *time.Timer
		tmr = time.AfterFunc(grace, func() {
			l.mu.Lock()
			delete(l.evictTimers, tmr)
			stillLoopback := addrIsLoopbackOnly(l.currentReqAddr)
			l.mu.Unlock()
			if !stillLoopback {
				return
			}
			if evicted := l.closeAllNonLoopbackConns(); evicted > 0 && l.logger != nil {
				l.logger.Info("evicted non-loopback connections after tightening panel listener to loopback",
					"old_addr", displacedReqAddr, "evicted", evicted)
			}
		})
		l.evictTimers[tmr] = struct{}{}
	}
	l.mu.Unlock()

	go l.serveOne(serveLn)
	if l.logger != nil {
		l.logger.Info("panel listener hot-rebound", "addr", rawNewLn.Addr().String())
	}
}

// Close stops accepting new connections on the active and all retiring listeners.
func (l *liveHTTPListener) Close() {
	l.closing.Store(true)
	l.mu.Lock()
	ln := l.current
	l.current = nil
	l.currentTracked = nil
	retiring := make([]net.Listener, 0, len(l.retiring))
	for rln, ent := range l.retiring {
		ent.timer.Stop()
		retiring = append(retiring, rln)
	}
	clear(l.retiring)
	for tmr := range l.evictTimers {
		tmr.Stop()
	}
	clear(l.evictTimers)
	l.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, rln := range retiring {
		_ = rln.Close()
	}
}

func (l *liveHTTPListener) serveOne(ln net.Listener) {
	err := l.srv.Serve(ln)
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
