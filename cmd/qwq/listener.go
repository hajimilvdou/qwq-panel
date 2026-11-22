// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// liveHTTPListener owns the active TCP listener of `qwq serve-controller` and
// supports safe live port hot-rebind when the administrator changes the port
// from the panel UI (PUT /api/v1/system/access).
type liveHTTPListener struct {
	srv     *http.Server
	useTLS  bool
	logger  *slog.Logger
	errCh   chan error
	mu      sync.Mutex
	current net.Listener
	closing atomic.Bool
}

func newLiveHTTPListener(srv *http.Server, useTLS bool, logger *slog.Logger) *liveHTTPListener {
	return &liveHTTPListener{
		srv:    srv,
		useTLS: useTLS,
		logger: logger,
		errCh:  make(chan error, 1),
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
	l.mu.Unlock()
	go l.serveOne(ln)
	return ln.Addr(), nil
}

// Rebind test-binds newAddr first; only if binding succeeds does it start
// serving on newAddr and schedule closing the previous listener after a short
// grace window so the in-flight HTTP response finishes cleanly.
func (l *liveHTTPListener) Rebind(newAddr string) error {
	newLn, err := net.Listen("tcp", newAddr)
	if err != nil {
		return err
	}
	l.mu.Lock()
	oldLn := l.current
	l.current = newLn
	l.mu.Unlock()

	go l.serveOne(newLn)
	if l.logger != nil {
		l.logger.Info("panel listener hot-rebound", "addr", newLn.Addr().String())
	}
	if oldLn != nil {
		time.AfterFunc(5*time.Second, func() {
			_ = oldLn.Close()
		})
	}
	return nil
}

// Close stops accepting new connections on the active listener.
func (l *liveHTTPListener) Close() {
	l.closing.Store(true)
	l.mu.Lock()
	ln := l.current
	l.current = nil
	l.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
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
	// If this listener was replaced by Rebind or we are shutting down, ignore
	// the expected net.ErrClosed error.
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
