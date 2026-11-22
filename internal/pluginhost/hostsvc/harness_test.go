// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// peerCall is one Verify invocation.
type peerCall struct {
	PID int
	UID int
}

// fakePeer is the test PeerVerifier. It records the kernel-verified values and
// can deny every peer, which is how the rejected-connection test drives the
// transport.
type fakePeer struct {
	mu    sync.Mutex
	deny  bool
	calls []peerCall
}

// Verify implements hostsvc.PeerVerifier.
func (p *fakePeer) Verify(pid, uid int) error {
	p.mu.Lock()
	p.calls = append(p.calls, peerCall{PID: pid, UID: uid})
	deny := p.deny
	p.mu.Unlock()
	if deny {
		return errors.New("the peer is not the plugin process")
	}
	return nil
}

// lastCall returns the most recent Verify call.
func (p *fakePeer) lastCall() (peerCall, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return peerCall{}, false
	}
	return p.calls[len(p.calls)-1], true
}

// setDeny changes whether the verifier rejects peers.
func (p *fakePeer) setDeny(deny bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deny = deny
}

// ackCall is one EventSink.Ack.
type ackCall struct {
	Subscription string
	Sequence     uint64
}

// fakeEvents is the test EventSink. A non-nil block channel makes Publish wait
// until it is closed, which is how the spool-full test holds the worker.
type fakeEvents struct {
	mu        sync.Mutex
	published []hostsvc.EventDraft
	changes   []hostsvc.ChangeSet
	acks      []ackCall
	next      uint64
	block     chan struct{}
	entered   chan struct{}
	err       error
}

// Publish implements hostsvc.EventSink.
func (f *fakeEvents) Publish(ctx context.Context, draft hostsvc.EventDraft) (hostsvc.EventRef, error) {
	f.mu.Lock()
	f.published = append(f.published, draft)
	f.next++
	sequence := f.next
	block, entered, err := f.block, f.entered, f.err
	f.mu.Unlock()
	if err != nil {
		return hostsvc.EventRef{}, err
	}
	if block != nil {
		if entered != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		select {
		case <-block:
		case <-ctx.Done():
			return hostsvc.EventRef{}, ctx.Err()
		}
	}
	return hostsvc.EventRef{EventID: "evt_" + strconv.FormatUint(sequence, 10), Sequence: sequence}, nil
}

// ReportChanges implements hostsvc.EventSink.
func (f *fakeEvents) ReportChanges(_ context.Context, set hostsvc.ChangeSet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, set)
	return f.err
}

// Ack implements hostsvc.EventSink.
func (f *fakeEvents) Ack(_ context.Context, subscription string, sequence uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acks = append(f.acks, ackCall{Subscription: subscription, Sequence: sequence})
	return f.err
}

// snapshot returns copies of everything the sink recorded.
func (f *fakeEvents) snapshot() (published []hostsvc.EventDraft, changes []hostsvc.ChangeSet, acks []ackCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostsvc.EventDraft(nil), f.published...),
		append([]hostsvc.ChangeSet(nil), f.changes...),
		append([]ackCall(nil), f.acks...)
}

// fakeConfig is the test ConfigSource.
type fakeConfig struct {
	mu       sync.Mutex
	revision string
	snapshot []byte
	err      error
	calls    int
}

// Current implements hostsvc.ConfigSource.
func (f *fakeConfig) Current(context.Context) (string, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.revision, f.snapshot, f.err
}

// secretCall is one SecretRevealer.Reveal.
type secretCall struct {
	Ref         string
	OperationID string
	Scopes      []string
}

// fakeSecrets is the test SecretRevealer.
type fakeSecrets struct {
	mu    sync.Mutex
	value []byte
	err   error
	calls []secretCall
}

// Reveal implements hostsvc.SecretRevealer.
func (f *fakeSecrets) Reveal(_ context.Context, ref, operationID string, scopes []string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, secretCall{Ref: ref, OperationID: operationID, Scopes: append([]string(nil), scopes...)})
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte(nil), f.value...), nil
}

// callsSnapshot returns the recorded reveal calls.
func (f *fakeSecrets) callsSnapshot() []secretCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]secretCall(nil), f.calls...)
}

// fakeAudit is the test AuditSink. block/entered are used by the quota test.
type fakeAudit struct {
	mu      sync.Mutex
	records []hostsvc.AuditRecord
	err     error
	block   chan struct{}
	entered chan struct{}
}

// Write implements hostsvc.AuditSink.
func (f *fakeAudit) Write(ctx context.Context, record hostsvc.AuditRecord) error {
	f.mu.Lock()
	f.records = append(f.records, record)
	block, entered, err := f.block, f.entered, f.err
	f.mu.Unlock()
	if block != nil {
		if entered != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// snapshot returns the recorded audit records.
func (f *fakeAudit) snapshot() []hostsvc.AuditRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostsvc.AuditRecord(nil), f.records...)
}

// fakeInvoker is the test Invoker.
type fakeInvoker struct {
	mu           sync.Mutex
	invokeCalls  []hostsvc.InvokeCall
	waitCalls    []hostsvc.WaitCall
	cancelCalls  []hostsvc.CancelCall
	invokeResult hostsvc.InvokeResult
	invokeErr    error
	waitSnapshot hostsvc.OperationSnapshot
	waitErr      error
	cancelState  hostsvc.OperationState
	cancelErr    error
	// hold, when set, parks every InvokePlugin call until it is closed;
	// entered receives one value per parked call.
	hold    chan struct{}
	entered chan struct{}
}

// InvokePlugin implements hostsvc.Invoker.
func (f *fakeInvoker) InvokePlugin(_ context.Context, call hostsvc.InvokeCall) (hostsvc.InvokeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invokeCalls = append(f.invokeCalls, call)
	hold, entered := f.hold, f.entered
	result, err := f.invokeResult, f.invokeErr
	f.mu.Unlock()
	if hold != nil {
		entered <- struct{}{}
		<-hold
	}
	f.mu.Lock()
	return result, err
}

// WaitOperation implements hostsvc.Invoker.
func (f *fakeInvoker) WaitOperation(_ context.Context, call hostsvc.WaitCall) (hostsvc.OperationSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.waitCalls = append(f.waitCalls, call)
	return f.waitSnapshot, f.waitErr
}

// CancelOperation implements hostsvc.Invoker.
func (f *fakeInvoker) CancelOperation(_ context.Context, call hostsvc.CancelCall) (hostsvc.OperationState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelCalls = append(f.cancelCalls, call)
	return f.cancelState, f.cancelErr
}

// invokeSnapshot returns the recorded invoke calls.
func (f *fakeInvoker) invokeSnapshot() []hostsvc.InvokeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostsvc.InvokeCall(nil), f.invokeCalls...)
}

// waitSnapshotCalls returns the recorded wait calls.
func (f *fakeInvoker) waitSnapshotCalls() []hostsvc.WaitCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostsvc.WaitCall(nil), f.waitCalls...)
}

// cancelSnapshot returns the recorded cancel calls.
func (f *fakeInvoker) cancelSnapshot() []hostsvc.CancelCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostsvc.CancelCall(nil), f.cancelCalls...)
}

// bundle is one set of fake dependencies.
type bundle struct {
	peer    *fakePeer
	events  *fakeEvents
	config  *fakeConfig
	secrets *fakeSecrets
	audit   *fakeAudit
	invoke  *fakeInvoker
}

// newBundle returns fresh fakes.
func newBundle() *bundle {
	return &bundle{
		peer:    &fakePeer{},
		events:  &fakeEvents{},
		config:  &fakeConfig{revision: "cfg-1", snapshot: []byte(`{"enabled":true}`)},
		secrets: &fakeSecrets{value: []byte("s3cr3t")},
		audit:   &fakeAudit{},
		invoke:  &fakeInvoker{},
	}
}

// testServer is a running host service plus its client connection.
type testServer struct {
	srv     *hostsvc.Server
	dir     string
	socket  string
	conn    *grpc.ClientConn
	bundle  *bundle
	cancel  context.CancelFunc
	serveCh chan error

	stopOnce sync.Once
	stopErr  error
}

// State returns the state service client.
func (ts *testServer) State() platformv1.HostStateServiceClient {
	return platformv1.NewHostStateServiceClient(ts.conn)
}

// Events returns the events service client.
func (ts *testServer) Events() platformv1.HostEventsServiceClient {
	return platformv1.NewHostEventsServiceClient(ts.conn)
}

// Config returns the config service client.
func (ts *testServer) Config() platformv1.HostConfigServiceClient {
	return platformv1.NewHostConfigServiceClient(ts.conn)
}

// Secrets returns the secrets service client.
func (ts *testServer) Secrets() platformv1.HostSecretsServiceClient {
	return platformv1.NewHostSecretsServiceClient(ts.conn)
}

// Audit returns the audit service client.
func (ts *testServer) Audit() platformv1.HostAuditServiceClient {
	return platformv1.NewHostAuditServiceClient(ts.conn)
}

// Invoke returns the invoke service client.
func (ts *testServer) Invoke() platformv1.HostInvokeServiceClient {
	return platformv1.NewHostInvokeServiceClient(ts.conn)
}

// Conn returns the raw client connection, used for streaming calls.
func (ts *testServer) Conn() *grpc.ClientConn { return ts.conn }

// callContext returns a HostCallContext with plausible correlation fields. The
// instance handle is deliberately not trusted by the server.
func callContext() *platformv1.HostCallContext {
	return &platformv1.HostCallContext{
		InstanceHandle: "handle-from-initialize",
		OperationId:    "op_test",
		TraceId:        "trace_test",
	}
}

// stop shuts the server down once and records how Serve returned.
func (ts *testServer) stop() {
	ts.stopOnce.Do(func() {
		ts.cancel()
		if err := ts.srv.Close(); err != nil {
			ts.stopErr = fmt.Errorf("Close: %w", err)
			return
		}
		select {
		case err := <-ts.serveCh:
			if err != nil {
				ts.stopErr = fmt.Errorf("Serve: %w", err)
			}
		case <-time.After(10 * time.Second):
			ts.stopErr = errors.New("Serve did not return after Close")
		}
	})
}

// startServer starts a server in a fresh temporary directory.
func startServer(t *testing.T, tune func(*hostsvc.Config)) *testServer {
	t.Helper()
	return startServerAt(t, newBundle(), t.TempDir(), tune)
}

// startServerWith starts a server with the given bundle in a fresh directory.
func startServerWith(t *testing.T, b *bundle, tune func(*hostsvc.Config)) *testServer {
	t.Helper()
	return startServerAt(t, b, t.TempDir(), tune)
}

// startServerAt starts a server below dir. The socket lives in dir/run and the
// state in dir/state, so a test can stop a server and start another one on the
// same state directory.
func startServerAt(t *testing.T, b *bundle, dir string, tune func(*hostsvc.Config)) *testServer {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED requires Linux")
	}
	socket := filepath.Join(dir, "run", "host.sock")
	cfg := hostsvc.Config{
		PluginID:            "noop",
		InstanceID:          "default",
		SocketPath:          socket,
		CreateSocketDir:     true,
		StateDir:            filepath.Join(dir, "state"),
		Clock:               clock.System{},
		Events:              b.events,
		Config:              b.config,
		Secrets:             b.secrets,
		Audit:               b.audit,
		Invoke:              b.invoke,
		Peer:                b.peer,
		GrantedCapabilities: []*platformv1.Capability{{Name: "secret.reveal", Scope: "config"}},
	}
	if tune != nil {
		tune(&cfg)
	}
	srv, err := hostsvc.New(cfg)
	if err != nil {
		t.Fatalf("hostsvc.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveCh := make(chan error, 1)
	go func() { serveCh <- srv.Serve(ctx) }()
	waitForSocket(t, socket)
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		_ = srv.Close()
		t.Fatalf("grpc.NewClient: %v", err)
	}
	ts := &testServer{
		srv:     srv,
		dir:     dir,
		socket:  socket,
		conn:    conn,
		bundle:  b,
		cancel:  cancel,
		serveCh: serveCh,
	}
	t.Cleanup(func() {
		_ = conn.Close()
		ts.stop()
		if ts.stopErr != nil {
			t.Errorf("shutdown: %v", ts.stopErr)
		}
	})
	return ts
}

// waitForSocket waits until a process accepts connections on path. It dials
// instead of checking os.Stat: a stale socket left by a crash exists on disk
// but refuses connections, and the stale-socket test must not treat that as a
// started server.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %s was not accepting connections: %v", path, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// rpcContext returns a context with the per-test deadline every RPC uses.
func rpcContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// wantCode asserts that err has the given gRPC code.
func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got nil error, want %v", what, want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("%s: got code %v (%v), want %v", what, got, err, want)
	}
}

// wantOK fails the test when err is not nil.
func wantOK(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", what, err)
	}
}

// statusCode returns the gRPC code of err, or OK for nil.
func statusCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	return status.Code(err)
}

// eventBuilder builds an ingested event.
func eventBuilder(sequence uint64, eventType, subject string, payload []byte) *platformv1.Event {
	return &platformv1.Event{
		EventId:          "evt_" + strconv.FormatUint(sequence, 10),
		Sequence:         sequence,
		Type:             eventType,
		SchemaVersion:    "1",
		Subject:          subject,
		OccurredAtUnixMs: 1_700_000_000_000,
		DeliveryClass:    platformv1.DeliveryClass_DELIVERY_CLASS_RELIABLE,
		PayloadJson:      payload,
	}
}
