// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// startFakeHelper starts a Unix-socket server. handle receives one decoded
// request and writes the response itself, so a test can answer slowly, close
// the connection or send malformed bytes. The returned channel yields every
// request the server decoded.
func startFakeHelper(t *testing.T, handle func(req HelperRequest, conn net.Conn)) (socket string, requests <-chan HelperRequest) {
	t.Helper()
	dir := t.TempDir()
	socket = filepath.Join(dir, "helper.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	reqs := make(chan HelperRequest, 8)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				var req HelperRequest
				if err := ReadHelperJSON(conn, &req); err != nil {
					return
				}
				reqs <- req
				handle(req, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return socket, reqs
}

// fastRetry shrinks the connect retry so tests do not sleep.
func fastRetry(t *testing.T) {
	t.Helper()
	oldAttempts, oldBackoff := helperDialAttempts, helperRetryBackoff
	helperDialAttempts, helperRetryBackoff = 3, time.Millisecond
	t.Cleanup(func() { helperDialAttempts, helperRetryBackoff = oldAttempts, oldBackoff })
}

// helperAlphaSpec is a valid spec for a helper request.
func helperAlphaSpec() UnitSpec {
	return UnitSpec{
		ID:         "alpha",
		VersionDir: "/var/lib/qwq-plugins/alpha/1.2.3",
		Entrypoint: "bin/plugin",
		Digest:     "sha256:" + strings.Repeat("a", 64),
		Limits:     &Limits{MemoryMaxMB: 32, CPUQuotaPercent: 20, PIDsMax: 16, FDsMax: 128},
	}
}

func TestDefaultPrivilegedSocket(t *testing.T) {
	if DefaultPrivilegedSocket != "/run/qwq/privileged.sock" {
		t.Errorf("DefaultPrivilegedSocket = %q", DefaultPrivilegedSocket)
	}
	if MaxHelperMessage != 1<<20 {
		t.Errorf("MaxHelperMessage = %d, want 1 MiB", MaxHelperMessage)
	}
}

func TestHelperClientInstall(t *testing.T) {
	token := []byte(strings.Repeat("ab", 32))
	var got HelperRequest
	socket, reqs := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		resp := HelperResponse{
			OK: true,
			Install: &InstallResult{
				ID:        req.Spec.ID,
				Group:     "qwq-p-" + req.Spec.ID,
				UnitFiles: []string{"/etc/systemd/system/qwq-plugin@alpha.service"},
				Dirs:      []string{"/run/qwq/plugin/alpha"},
			},
			Warnings: []string{"the socket unit was not enabled"},
		}
		if err := WriteHelperJSON(conn, resp); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	client := NewHelperClient(socket)
	res, err := client.Install(context.Background(), helperAlphaSpec(), token)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	got = <-reqs
	if got.Op != HelperOpInstall || got.Spec == nil {
		t.Fatalf("request = %+v", got)
	}
	if got.Spec.ID != "alpha" || got.Spec.VersionDir != "/var/lib/qwq-plugins/alpha/1.2.3" {
		t.Errorf("spec = %+v", got.Spec)
	}
	decoded, err := base64.StdEncoding.DecodeString(got.CredentialBase64)
	if err != nil || string(decoded) != string(token) {
		t.Errorf("credential = %q (decode error %v)", decoded, err)
	}
	if res.ID != "alpha" || res.Group != "qwq-p-alpha" {
		t.Errorf("result = %+v", res)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestHelperClientPublish(t *testing.T) {
	socket, reqs := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		resp := HelperResponse{OK: true, Publish: &PublishResult{
			ID: req.PluginID, Version: req.Version, VersionDir: req.VersionDir,
			Files: 4, Dirs: 2,
		}}
		if err := WriteHelperJSON(conn, resp); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	res, err := NewHelperClient(socket).Publish(context.Background(), HelperPublish{
		StagedDir:  "/var/lib/qwq/staging/.staging-abc",
		VersionDir: "/var/lib/qwq-plugins/alpha/1.2.3",
		PluginID:   "alpha",
		Version:    "1.2.3",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got := <-reqs
	if got.Op != HelperOpPublish || got.PluginID != "alpha" || got.Version != "1.2.3" ||
		got.StagedDir != "/var/lib/qwq/staging/.staging-abc" ||
		got.VersionDir != "/var/lib/qwq-plugins/alpha/1.2.3" {
		t.Errorf("publish request = %+v", got)
	}
	if res.ID != "alpha" || res.Files != 4 || res.Dirs != 2 || res.Existing {
		t.Errorf("publish result = %+v", res)
	}
}

func TestHelperClientRemoveReloadPing(t *testing.T) {
	fastRetry(t)
	socket, reqs := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		var resp HelperResponse
		switch req.Op {
		case HelperOpRemove:
			resp = HelperResponse{OK: true, Remove: &RemoveResult{
				ID: req.ID, Group: "qwq-p-" + req.ID,
				Removed: []string{"/var/lib/qwq-plugins/alpha/1.2.3"},
			}, Warnings: []string{"the socket unit could not be disabled"}}
		case HelperOpReload:
			resp = HelperResponse{OK: true}
		case HelperOpPing:
			resp = HelperResponse{OK: true, Version: "9.9.9", UID: 0}
		default:
			resp = HelperResponse{Code: string(problem.ValidationFailed), Error: "unknown operation"}
		}
		if err := WriteHelperJSON(conn, resp); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	client := NewHelperClient(socket)

	removed, err := client.Remove(context.Background(), HelperRemove{
		ID:       "alpha",
		Version:  "1.2.3",
		Paths:    []string{"/var/lib/qwq-plugins/alpha/1.2.3"},
		KeepUnit: true,
	})
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got := <-reqs
	if got.Op != HelperOpRemove || got.ID != "alpha" || got.Version != "1.2.3" ||
		!got.KeepUnit || len(got.Paths) != 1 {
		t.Errorf("remove request = %+v", got)
	}
	if removed.ID != "alpha" || len(removed.Removed) != 1 {
		t.Errorf("remove result = %+v", removed)
	}
	if len(removed.Warnings) != 1 {
		t.Errorf("remove warnings = %v", removed.Warnings)
	}

	if err := client.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := <-reqs; got.Op != HelperOpReload {
		t.Errorf("reload request = %+v", got)
	}

	ping, err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if ping.Version != "9.9.9" || ping.UID != 0 {
		t.Errorf("ping = %+v", ping)
	}
	if got := <-reqs; got.Op != HelperOpPing {
		t.Errorf("ping request = %+v", got)
	}
}

func TestHelperClientRefusalKeepsCode(t *testing.T) {
	socket, _ := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		_ = WriteHelperJSON(conn, HelperResponse{
			Code: string(problem.PreconditionFailed), Error: "plugin alpha is still running",
		})
	})
	_, err := NewHelperClient(socket).Remove(context.Background(), HelperRemove{ID: "alpha"})
	var pe *problem.Error
	if !errors.As(err, &pe) || pe.Code != problem.PreconditionFailed {
		t.Fatalf("error = %v, want PRECONDITION_FAILED", err)
	}
	if !strings.Contains(pe.Detail, "still running") {
		t.Errorf("detail = %q", pe.Detail)
	}
}

func TestHelperClientUnknownErrorCodeIsInternal(t *testing.T) {
	socket, _ := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		_ = WriteHelperJSON(conn, HelperResponse{Code: "MADE_UP", Error: "no"})
	})
	err := NewHelperClient(socket).Reload(context.Background())
	if !problem.HasCode(err, problem.Internal) {
		t.Fatalf("error = %v, want INTERNAL", err)
	}
}

func TestHelperClientTimeout(t *testing.T) {
	socket, _ := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		time.Sleep(300 * time.Millisecond)
	})
	client := NewHelperClient(socket)
	client.Timeout = 50 * time.Millisecond
	_, err := client.Ping(context.Background())
	if !problem.HasCode(err, problem.Timeout) {
		t.Fatalf("error = %v, want TIMEOUT", err)
	}
}

func TestHelperClientDoesNotRetryAnExecutedRequest(t *testing.T) {
	fastRetry(t)
	attempts := 0
	var mu sync.Mutex
	socket, _ := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		// Drop the connection without answering: the request reached the
		// helper, so the client must not retry it.
	})
	client := &HelperClient{Socket: socket, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		attempts++
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	_, err := client.Install(context.Background(), helperAlphaSpec(), nil)
	if err == nil {
		t.Fatal("Install succeeded against a helper that never answered")
	}
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("error = %v, want UNAVAILABLE", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Errorf("dial attempts = %d, want 1 (a sent request must not be retried)", attempts)
	}
}

func TestHelperClientRetriesConnectionFailure(t *testing.T) {
	fastRetry(t)
	socket, reqs := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		_ = WriteHelperJSON(conn, HelperResponse{OK: true, Version: "1"})
	})
	attempts := 0
	client := &HelperClient{Socket: socket, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		attempts++
		if attempts < 3 {
			return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	if _, err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if attempts != 3 {
		t.Errorf("dial attempts = %d, want 3", attempts)
	}
	if got := <-reqs; got.Op != HelperOpPing {
		t.Errorf("request = %+v", got)
	}
}

func TestHelperClientUnreachable(t *testing.T) {
	fastRetry(t)
	client := NewHelperClient(filepath.Join(t.TempDir(), "missing.sock"))
	_, err := client.Ping(context.Background())
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("error = %v, want UNAVAILABLE", err)
	}
}

func TestHelperClientRejectsBadSocket(t *testing.T) {
	for _, socket := range []string{"", "relative.sock", "/run/../run/qwq.sock"} {
		client := NewHelperClient(socket)
		if _, err := client.Ping(context.Background()); !problem.HasCode(err, problem.Unavailable) {
			t.Errorf("socket %q: error = %v, want UNAVAILABLE", socket, err)
		}
	}
}

func TestHelperClientMalformedResponse(t *testing.T) {
	socket, _ := startFakeHelper(t, func(req HelperRequest, conn net.Conn) {
		_, _ = conn.Write([]byte("this is not JSON\n"))
	})
	_, err := NewHelperClient(socket).Ping(context.Background())
	if !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("error = %v, want UNAVAILABLE", err)
	}
}

func TestHelperJSONRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field": `{"op":"ping","bogus":true}`,
		"trailing data": `{"op":"ping"} {"op":"ping"}`,
		"empty":         "",
	} {
		var req HelperRequest
		if err := ReadHelperJSON(strings.NewReader(body), &req); err == nil {
			t.Errorf("%s: ReadHelperJSON accepted %q", name, body)
		}
	}
	var req HelperRequest
	if err := ReadHelperJSON(strings.NewReader("{\"op\":\"ping\"}\n"), &req); err != nil || req.Op != HelperOpPing {
		t.Fatalf("ReadHelperJSON valid message: %+v, %v", req, err)
	}
}

func TestHelperJSONSizeLimit(t *testing.T) {
	big := `{"op":"` + strings.Repeat("a", MaxHelperMessage) + `"}`
	var req HelperRequest
	if err := ReadHelperJSON(strings.NewReader(big), &req); err == nil {
		t.Error("ReadHelperJSON accepted an oversized message")
	}
	if err := WriteHelperJSON(&strings.Builder{}, HelperRequest{Op: strings.Repeat("a", MaxHelperMessage)}); err == nil {
		t.Error("WriteHelperJSON accepted an oversized message")
	}
}
