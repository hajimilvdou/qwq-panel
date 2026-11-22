// SPDX-License-Identifier: AGPL-3.0-only

// Package netlimit bounds the number of simultaneously open connections a
// listener hands out. Servers facing untrusted peers wrap their listener with
// LimitListener so per-connection limits (such as gRPC MaxConcurrentStreams)
// cannot be multiplied by opening more connections.
package netlimit

import (
	"errors"
	"net"
	"sync"
	"syscall"
)

// ============================================================================
//  LimitListener
// ============================================================================

// LimitListener returns a Listener that has at most n connections open at
// once. Accept blocks while n connections are open; the excess connections
// wait in the kernel backlog until a slot frees. n < 1 is treated as 1.
func LimitListener(ln net.Listener, n int) net.Listener {
	if n < 1 {
		n = 1
	}
	return &limitListener{
		Listener: ln,
		sem:      make(chan struct{}, n),
		done:     make(chan struct{}),
	}
}

type limitListener struct {
	net.Listener
	sem       chan struct{}
	closeOnce sync.Once
	done      chan struct{}
}

// Accept waits for a free slot, then for the next connection. The returned
// connection gives its slot back on its first Close.
func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

// Close closes the underlying listener and wakes any Accept waiting for a slot.
func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// Close closes the connection and releases its slot exactly once.
func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// SyscallConn exposes the underlying descriptor so callers can still read
// socket options such as SO_PEERCRED through the wrapper.
func (c *limitConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.Conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("netlimit: the connection does not expose a descriptor")
	}
	return sc.SyscallConn()
}
