// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// TestSocketPermissions checks the file modes from ADR-0003: the socket is
// 0660 with the plugin's private group and its directory is 0750.
func TestSocketPermissions(t *testing.T) {
	ts := startServer(t, nil)
	info, err := os.Stat(ts.socket)
	wantOK(t, err, "stat socket")
	if got, want := info.Mode().Perm(), os.FileMode(0o660); got != want {
		t.Errorf("socket mode = %04o, want %04o", got, want)
	}
	dirInfo, err := os.Stat(filepath.Dir(ts.socket))
	wantOK(t, err, "stat socket dir")
	if got, want := dirInfo.Mode().Perm(), os.FileMode(0o750); got != want {
		t.Errorf("socket directory mode = %04o, want %04o", got, want)
	}
}

// TestPeerCredentialsAreKernelProvided proves that the pid/uid the verifier
// sees come from SO_PEERCRED: they are the test process, not anything a client
// could put in a message, and the RPC also works with a forged instance handle.
func TestPeerCredentialsAreKernelProvided(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	response, err := ts.State().GetState(ctx, &platformv1.GetStateRequest{Context: callContext(), Key: "missing"})
	wantOK(t, err, "GetState")
	if response.GetFound() {
		t.Fatal("GetState reported a value for a missing key")
	}
	call, ok := ts.bundle.peer.lastCall()
	if !ok {
		t.Fatal("the peer verifier was never called")
	}
	if call.PID != os.Getpid() {
		t.Errorf("verified pid = %d, want the test process %d", call.PID, os.Getpid())
	}
	if call.UID != os.Getuid() {
		t.Errorf("verified uid = %d, want the test uid %d", call.UID, os.Getuid())
	}
}

// TestUnverifiedPeerIsRejected checks that a peer the verifier refuses cannot
// issue an RPC, and that a later allowed connection succeeds again.
func TestUnverifiedPeerIsRejected(t *testing.T) {
	b := newBundle()
	b.peer.setDeny(true)
	ts := startServerWith(t, b, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ts.State().GetState(ctx, &platformv1.GetStateRequest{Context: callContext(), Key: "k"})
	if err == nil {
		t.Fatal("an RPC from a rejected peer succeeded")
	}
	switch code := status.Code(err); code {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
	default:
		t.Fatalf("rejected peer: got code %v (%v)", code, err)
	}
	if _, ok := b.peer.lastCall(); !ok {
		t.Fatal("the peer verifier was never called")
	}

	// The rejection is per connection: once the verifier accepts, a new
	// connection must work.
	b.peer.setDeny(false)
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := ts.State().GetState(ctx, &platformv1.GetStateRequest{Context: callContext(), Key: "k"})
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("RPC still fails after the peer verifier accepted: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCloseRemovesSocketAndStopsServe checks the documented shutdown contract.
func TestCloseRemovesSocketAndStopsServe(t *testing.T) {
	ts := startServer(t, nil)
	if _, err := os.Stat(ts.socket); err != nil {
		t.Fatalf("socket does not exist before Close: %v", err)
	}
	ts.stop()
	if ts.stopErr != nil {
		t.Fatalf("shutdown failed: %v", ts.stopErr)
	}
	if _, err := os.Stat(ts.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still exists after Close: %v", err)
	}
}

// TestStaleSocketIsReplaced checks the crash-recovery path: a socket file that
// no process answers on is removed instead of blocking startup.
func TestStaleSocketIsReplaced(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	socket := filepath.Join(runDir, "host.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatalf("Close listener: %v", err)
	}
	if _, err := os.Stat(socket); err != nil {
		t.Fatalf("stale socket is missing: %v", err)
	}

	ts := startServerAt(t, newBundle(), dir, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	if _, err := ts.State().GetState(ctx, &platformv1.GetStateRequest{Context: callContext(), Key: "k"}); err != nil {
		t.Fatalf("GetState after stale socket replacement: %v", err)
	}
}

// TestNonSocketPathIsRejected checks that Serve refuses to clobber a regular
// file at the socket path.
func TestNonSocketPathIsRejected(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "run", "host.sock")
	if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(socket, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := validConfig(dir)
	srv, err := hostsvc.New(cfg)
	if err != nil {
		t.Fatalf("hostsvc.New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	err = srv.Serve(context.Background())
	if err == nil {
		t.Fatal("Serve accepted a regular file as a socket path")
	}
	if !strings.Contains(err.Error(), "not a Unix socket") {
		t.Fatalf("Serve error = %v, want a non-socket error", err)
	}
}

// validConfig returns a complete Config below dir.
func validConfig(dir string) hostsvc.Config {
	return hostsvc.Config{
		PluginID:   "noop",
		InstanceID: "default",
		SocketPath: filepath.Join(dir, "run", "host.sock"),
		StateDir:   filepath.Join(dir, "state"),
		Clock:      clock.System{},
		Peer:       &fakePeer{},
	}
}

// TestNewRejectsInvalidConfig checks the fail-fast validation of Config and
// Limits.
func TestNewRejectsInvalidConfig(t *testing.T) {
	valid := func() hostsvc.Config {
		return validConfig(t.TempDir())
	}
	tests := []struct {
		name string
		edit func(*hostsvc.Config)
	}{
		{"missing plugin id", func(c *hostsvc.Config) { c.PluginID = "" }},
		{"invalid plugin id", func(c *hostsvc.Config) { c.PluginID = "bad id" }},
		{"missing instance id", func(c *hostsvc.Config) { c.InstanceID = "" }},
		{"missing socket path", func(c *hostsvc.Config) { c.SocketPath = "" }},
		{"relative socket path", func(c *hostsvc.Config) { c.SocketPath = "host.sock" }},
		{"too long socket path", func(c *hostsvc.Config) { c.SocketPath = "/" + strings.Repeat("a", 120) }},
		{"missing state dir", func(c *hostsvc.Config) { c.StateDir = "" }},
		{"missing peer", func(c *hostsvc.Config) { c.Peer = nil }},
		{"negative limit", func(c *hostsvc.Config) { c.Limits.MaxRequestBytes = -1 }},
		{"value larger than total", func(c *hostsvc.Config) {
			c.Limits.MaxValueBytes = 2 << 20
			c.Limits.MaxTotalBytes = 1 << 20
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid()
			test.edit(&cfg)
			if _, err := hostsvc.New(cfg); err == nil {
				t.Fatal("New accepted an invalid config")
			}
		})
	}
}

// TestListenRejectsGroupWritableOrSymlinkDir: socket 目录由 helper 预建，
// hostsvc 只校验不创建（PRIV-04）；缺失、组可写、符号链接都拒绝。
func TestListenRejectsGroupWritableOrSymlinkDir(t *testing.T) {
	serve := func(cfg hostsvc.Config) error {
		srv, err := hostsvc.New(cfg)
		if err != nil {
			t.Fatalf("hostsvc.New: %v", err)
		}
		defer func() { _ = srv.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		return srv.Serve(ctx)
	}
	missing := t.TempDir()
	if err := serve(validConfig(missing)); err == nil || !strings.Contains(err.Error(), "socket directory") {
		t.Errorf("missing dir: Serve = %v", err)
	}
	loose := t.TempDir()
	if err := os.Mkdir(filepath.Join(loose, "run"), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(loose, "run"), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := serve(validConfig(loose)); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("group-writable dir: Serve = %v", err)
	}
	linked := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, "run")); err != nil {
		t.Fatal(err)
	}
	if err := serve(validConfig(linked)); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Errorf("symlinked dir: Serve = %v", err)
	}
}

// TestHostChannelRejectsWrongToken: 配置了 TokenDigest 时，每个 RPC 都必须在
// metadata 里携带插件 token，且其 SHA-256 与期望值一致（PRIV-05）。
func TestHostChannelRejectsWrongToken(t *testing.T) {
	good := "token-" + strings.Repeat("a", 40)
	want := sha256.Sum256([]byte(good))
	ts := startServer(t, func(c *hostsvc.Config) {
		c.TokenDigest = func(context.Context) ([]byte, error) { return want[:], nil }
	})
	call := func(md ...string) error {
		ctx, cancel := rpcContext(t)
		defer cancel()
		if len(md) > 0 {
			ctx = metadata.AppendToOutgoingContext(ctx, md...)
		}
		_, err := ts.State().GetState(ctx, &platformv1.GetStateRequest{Context: callContext(), Key: "k"})
		return err
	}
	for name, md := range map[string][]string{
		"missing":   nil,
		"wrong":     {pluginsdk.HostTokenMetadataKey, good + "x"},
		"duplicate": {pluginsdk.HostTokenMetadataKey, good, pluginsdk.HostTokenMetadataKey, good},
	} {
		if err := call(md...); status.Code(err) != codes.Unauthenticated {
			t.Errorf("%s token: err = %v, want Unauthenticated", name, err)
		}
	}
	if err := call(pluginsdk.HostTokenMetadataKey, good); err != nil {
		t.Errorf("correct token: %v", err)
	}
}

// TestServerLimitsConnectionsPerInstance checks that one plugin instance can
// hold at most two connections, so MaxConcurrentStreams cannot be multiplied
// by dialing more (PLG-08). The third connection is served only after one of
// the first two closes.
func TestServerLimitsConnectionsPerInstance(t *testing.T) {
	ts := startServer(t, nil)
	dial := func() *grpc.ClientConn {
		t.Helper()
		conn, err := grpc.NewClient("unix://"+ts.socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatalf("grpc.NewClient: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	call := func(conn *grpc.ClientConn, timeout time.Duration, opts ...grpc.CallOption) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, err := platformv1.NewHostConfigServiceClient(conn).GetConfig(ctx, &platformv1.GetConfigRequest{Context: callContext()}, opts...)
		return err
	}

	first := dial()
	wantOK(t, call(first, 10*time.Second), "GetConfig on the first connection")
	wantOK(t, call(ts.Conn(), 10*time.Second), "GetConfig on the second connection")
	third := dial()
	if err := call(third, 500*time.Millisecond); err == nil {
		t.Fatal("a third connection was served while two were open")
	}
	_ = first.Close()
	wantOK(t, call(third, 10*time.Second, grpc.WaitForReady(true)), "GetConfig after a slot freed")
}

// TestInflightLimitRejectsWithResourceExhausted checks the per-instance
// in-flight budget: once 16 calls are running, a further call fails at once
// with RESOURCE_EXHAUSTED instead of queueing (PLG-08).
func TestInflightLimitRejectsWithResourceExhausted(t *testing.T) {
	b := newBundle()
	b.invoke.hold = make(chan struct{})
	b.invoke.entered = make(chan struct{}, 32)
	ts := startServerWith(t, b, nil)
	released := false
	release := func() {
		if !released {
			released = true
			close(b.invoke.hold)
		}
	}
	defer release()

	invoke := func(conn *grpc.ClientConn) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := platformv1.NewHostInvokeServiceClient(conn).InvokePlugin(ctx, &platformv1.InvokePluginRequest{
			Context:          callContext(),
			TargetPluginId:   "other",
			TargetInstanceId: "default",
			TargetNodeId:     "local",
			Operation:        "echo",
			ApiVersion:       "v1",
			PayloadJson:      []byte(`{}`),
			IdempotencyKey:   "idem-1",
		})
		return err
	}
	const limit = 16
	errs := make(chan error, limit)
	for i := 0; i < limit; i++ {
		go func() { errs <- invoke(ts.Conn()) }()
	}
	for i := 0; i < limit; i++ {
		select {
		case <-b.invoke.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d calls reached the handler", i, limit)
		}
	}

	// A second connection has free stream quota, so only the in-flight
	// budget can reject this call.
	other, err := grpc.NewClient("unix://"+ts.socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer other.Close()
	start := time.Now()
	if code := status.Code(invoke(other)); code != codes.ResourceExhausted {
		t.Fatalf("call over the budget = %v, want RESOURCE_EXHAUSTED", code)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the rejection took %v; it must not queue", elapsed)
	}

	release()
	for i := 0; i < limit; i++ {
		wantOK(t, <-errs, "parked InvokePlugin")
	}
	wantOK(t, invoke(other), "InvokePlugin after the budget freed")
}
