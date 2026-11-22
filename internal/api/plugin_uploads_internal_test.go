// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const gatedBoundary = "XqWqTestBoundary"

// partEnvelope returns the head and tail of a multipart body carrying one
// `package` part; the caller may hold the reader between them.
func partEnvelope() (head, tail string) {
	head = "--" + gatedBoundary + "\r\n" +
		"Content-Disposition: form-data; name=\"package\"; filename=\"x.ppkg\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n"
	tail = "\r\n--" + gatedBoundary + "--\r\n"
	return head, tail
}

// gatedBody is a request body that delivers the part head and payload, then
// blocks until released, then delivers the closing boundary. It lets a test
// hold an upload in flight deterministically.
type gatedBody struct {
	mu       sync.Mutex
	buf      []byte
	pos      int
	tail     []byte
	tailPos  int
	gate     chan struct{}
	released bool
}

func newGatedBody(t *testing.T) *gatedBody {
	t.Helper()
	head, tail := partEnvelope()
	return &gatedBody{buf: []byte(head + "payload-bytes"), tail: []byte(tail), gate: make(chan struct{})}
}

// release lets a blocked read continue.
func (g *gatedBody) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.released {
		g.released = true
		close(g.gate)
	}
}

func (g *gatedBody) Read(p []byte) (int, error) {
	g.mu.Lock()
	if g.pos < len(g.buf) {
		n := copy(p, g.buf[g.pos:])
		g.pos += n
		g.mu.Unlock()
		return n, nil
	}
	if !g.released {
		g.mu.Unlock()
		<-g.gate
		g.mu.Lock()
	}
	if g.tailPos < len(g.tail) {
		n := copy(p, g.tail[g.tailPos:])
		g.tailPos += n
		g.mu.Unlock()
		return n, nil
	}
	g.mu.Unlock()
	return 0, io.EOF
}

// gatedRequest builds a multipart request whose body blocks mid-part.
func gatedRequest(t *testing.T) (*http.Request, *gatedBody) {
	t.Helper()
	body := newGatedBody(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugin-packages", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+gatedBoundary)
	return req, body
}

// fastRequest builds a complete multipart request.
func fastRequest(t *testing.T, payload string) *http.Request {
	t.Helper()
	head, tail := partEnvelope()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugin-packages", strings.NewReader(head+payload+tail))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+gatedBoundary)
	return req
}

func newTestUploads(t *testing.T, clk clock.Clock, ttl time.Duration) *PluginUploads {
	t.Helper()
	up, err := NewPluginUploads(t.TempDir(), ttl, clk)
	if err != nil {
		t.Fatalf("NewPluginUploads: %v", err)
	}
	return up
}

func stagedFiles(t *testing.T, dir string) int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "upload-*.pkg"))
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}

// waitFor polls cond until it holds or the test fails.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestUploadConcurrentBeyondCapRejectedBeforeWrite: 33 uploads held in flight
// from 33 principals. The global cap of 32 must stop the 33rd before a byte is
// written, so the staging directory never holds more than 32 files (GW-07).
func TestUploadConcurrentBeyondCapRejectedBeforeWrite(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	up := newTestUploads(t, clk, time.Minute)

	var (
		mu      sync.Mutex
		bodies  []*gatedBody
		results = make([]error, maxPendingUploads+1)
		done    = make(chan int, maxPendingUploads+1)
	)
	// resultOf reads one worker's outcome under the same lock the worker used.
	resultOf := func(i int) error {
		mu.Lock()
		defer mu.Unlock()
		return results[i]
	}
	refusedCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, err := range results {
			if err != nil {
				n++
			}
		}
		return n
	}
	for i := 0; i <= maxPendingUploads; i++ {
		req, body := gatedRequest(t)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		go func(i int, req *http.Request) {
			_, err := up.Receive(context.Background(), req, fmt.Sprintf("user-%d", i))
			mu.Lock()
			results[i] = err
			mu.Unlock()
			done <- i
		}(i, req)
	}
	// Every goroutine that gets a slot blocks writing its file; wait until the
	// directory holds the cap of them.
	waitFor(t, "32 in-flight uploads", func() bool { return stagedFiles(t, up.dir) == maxPendingUploads })

	// Exactly one upload must have been refused before writing.
	waitFor(t, "the beyond-cap upload to fail", func() bool { return refusedCount() == 1 })
	if got := stagedFiles(t, up.dir); got > maxPendingUploads {
		t.Fatalf("files before write check were not bounded: %d", got)
	}
	for i := range results {
		if err := resultOf(i); err != nil && !problem.HasCode(err, problem.Unavailable) {
			t.Fatalf("refusal = %v, want UNAVAILABLE", err)
		}
	}
	// The one failure is not one of the blocked writers: releasing everyone
	// yields 32 successes.
	for _, b := range bodies {
		b.release()
	}
	for range results {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("uploads did not finish")
		}
	}
	var ok int
	for i := range results {
		if resultOf(i) == nil {
			ok++
		}
	}
	if ok != maxPendingUploads || up.Count() != maxPendingUploads {
		t.Fatalf("ok = %d, count = %d, want %d", ok, up.Count(), maxPendingUploads)
	}
}

// TestUploadPerPrincipalQuota: one account may stage at most four packages,
// in-flight writes included; another account is unaffected.
func TestUploadPerPrincipalQuota(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	up := newTestUploads(t, clk, time.Minute)
	ctx := context.Background()

	for i := 0; i < maxUploadsPerPrincipal; i++ {
		if _, err := up.Receive(ctx, fastRequest(t, "pkg"), "human:alice:"); err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
	}
	files := stagedFiles(t, up.dir)
	if _, err := up.Receive(ctx, fastRequest(t, "pkg"), "human:alice:"); !problem.HasCode(err, problem.RateLimited) {
		t.Fatalf("fifth upload = %v, want RATE_LIMITED", err)
	}
	if got := stagedFiles(t, up.dir); got != files {
		t.Fatalf("a refused upload wrote a file: %d -> %d", files, got)
	}
	// The refusal released its reservation: after one staged upload is
	// removed, alice can stage again.
	var first string
	for id := range up.items {
		first = id
		break
	}
	if err := up.Remove(first); err != nil {
		t.Fatal(err)
	}
	if _, err := up.Receive(ctx, fastRequest(t, "pkg"), "human:alice:"); err != nil {
		t.Fatalf("upload after removal: %v", err)
	}
	// A different principal has its own quota.
	if _, err := up.Receive(ctx, fastRequest(t, "pkg"), "human:bob:"); err != nil {
		t.Fatalf("other principal: %v", err)
	}
}

// TestUploadRejectsWhenDiskFull: the staging preflight answers
// INSUFFICIENT_STORAGE (507) before a byte is written and releases the slot
// for a later attempt.
func TestUploadRejectsWhenDiskFull(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	up := newTestUploads(t, clk, time.Minute)
	up.statfs = func(string) (uint64, error) { return 1 << 20, nil }

	_, err := up.Receive(context.Background(), fastRequest(t, "pkg"), "human:alice:")
	if !problem.HasCode(err, problem.InsufficientStorage) {
		t.Fatalf("full disk = %v, want INSUFFICIENT_STORAGE", err)
	}
	if got := stagedFiles(t, up.dir); got != 0 {
		t.Fatalf("files written on a full disk: %d", got)
	}
	if up.reserved != 0 {
		t.Fatalf("reservation leaked: %d", up.reserved)
	}
	// A statfs failure skips the check instead of blocking uploads, and enough
	// room passes it.
	up.statfs = func(string) (uint64, error) { return 0, errors.New("unsupported") }
	if _, err := up.Receive(context.Background(), fastRequest(t, "pkg"), "human:alice:"); err != nil {
		t.Fatalf("statfs failure blocked the upload: %v", err)
	}
	up.statfs = func(string) (uint64, error) { return uint64(gateway.MaxPackageBytes) + uploadDiskReserve, nil }
	if _, err := up.Receive(context.Background(), fastRequest(t, "pkg"), "human:alice:"); err != nil {
		t.Fatalf("exact reserve boundary: %v", err)
	}
}

// TestUploadSweepLoopRemovesExpired: Run removes expired uploads without any
// request touching them (GW-07).
func TestUploadSweepLoopRemovesExpired(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	up := newTestUploads(t, clk, time.Minute)
	if _, err := up.Receive(context.Background(), fastRequest(t, "pkg"), "human:alice:"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the staged file", func() bool { return stagedFiles(t, up.dir) == 1 })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go up.Run(ctx, 5*time.Millisecond)

	clk.Advance(2 * time.Minute)
	waitFor(t, "the sweep loop to remove the expired upload", func() bool {
		return up.Count() == 0 && stagedFiles(t, up.dir) == 0
	})

	// Cancelling stops the loop.
	cancel()
	time.Sleep(20 * time.Millisecond)
	if _, err := os.Stat(up.dir); err != nil {
		t.Fatal(err)
	}
}
