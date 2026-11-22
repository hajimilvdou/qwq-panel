// SPDX-License-Identifier: AGPL-3.0-only

package netlimit_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/netlimit"
)

// TestLimitListenerBoundsOpenConnections checks that the n+1-th connection is
// accepted only after an earlier one is closed, and that Close unblocks Accept.
func TestLimitListenerBoundsOpenConnections(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := netlimit.LimitListener(raw, 2)
	accepted := make(chan net.Conn, 4)
	acceptErr := make(chan error, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- c
		}
	}()

	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
	}
	first := <-accepted
	<-accepted
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted while two were open")
	case <-time.After(200 * time.Millisecond):
	}
	_ = first.Close()
	_ = first.Close() // a double close must not free two slots
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting connection was not accepted after a slot freed")
	}

	_ = ln.Close()
	select {
	case err := <-acceptErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}
