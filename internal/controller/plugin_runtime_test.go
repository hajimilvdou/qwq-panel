// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/pluginhost/supervisor"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// --- fakes -----------------------------------------------------------------

type fakeSystemctl struct {
	mu      sync.Mutex
	calls   []string
	status  sandbox.UnitStatus
	opErr   error
	showErr error
}

func (f *fakeSystemctl) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeSystemctl) callsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeSystemctl) Start(_ context.Context, unit string) error {
	f.record("start " + unit)
	return f.opErr
}

func (f *fakeSystemctl) Stop(_ context.Context, unit string) error {
	f.record("stop " + unit)
	return f.opErr
}

func (f *fakeSystemctl) Kill(_ context.Context, unit string) error {
	f.record("kill " + unit)
	return f.opErr
}

func (f *fakeSystemctl) Show(_ context.Context, unit string) (sandbox.UnitStatus, error) {
	f.record("show " + unit)
	return f.status, f.showErr
}

// fakeSupervisorUnits is a supervisor.UnitManager that never starts anything.
type fakeSupervisorUnits struct {
	mu    sync.Mutex
	state supervisor.UnitState
	err   error
}

func (f *fakeSupervisorUnits) Start(context.Context, string) error { return f.err }

func (f *fakeSupervisorUnits) Stop(context.Context, string) error { return f.err }

func (f *fakeSupervisorUnits) Kill(context.Context, string) error { return f.err }

func (f *fakeSupervisorUnits) Show(context.Context, string) (supervisor.UnitState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, f.err
}

// fakeHostServer is a supervisor.HostServer that serves nothing.
type fakeHostServer struct{}

func (fakeHostServer) Serve(context.Context, string) (func(), error) { return func() {}, nil }

// testDB opens a migrated database in a temporary directory.
func testDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(t.Context(), storage.Options{Path: filepath.Join(t.TempDir(), "qwq.db")})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// --- UnitManagerAdapter ----------------------------------------------------

func TestUnitManagerAdapter(t *testing.T) {
	ctx := t.Context()
	start := time.Unix(1700000000, 0).UTC()
	sys := &fakeSystemctl{status: sandbox.UnitStatus{
		MainPID:      4242,
		ControlGroup: "/system.slice/system-qwq\\x2dplugin.slice/qwq-plugin@alpha.service",
		ActiveState:  "active",
		SubState:     "running",
		StartTime:    start,
	}}
	units := UnitManagerAdapter{Systemctl: sys, NodeID: "local"}

	if err := units.Start(ctx, "alpha"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := units.Stop(ctx, "alpha"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := units.Kill(ctx, "alpha"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	state, err := units.Show(ctx, "alpha")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if state.MainPID != 4242 || state.ActiveState != "active" || state.SubState != "running" ||
		!state.StartTime.Equal(start) || state.ControlGroup == "" {
		t.Fatalf("Show mapped %+v", state)
	}

	want := []string{
		"start qwq-plugin@alpha.service",
		"stop qwq-plugin@alpha.service",
		"kill qwq-plugin@alpha.service",
		"show qwq-plugin@alpha.service",
	}
	got := sys.callsSnapshot()
	if len(got) != len(want) {
		t.Fatalf("systemctl calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("systemctl calls = %v, want %v", got, want)
		}
	}

	if err := units.Start(ctx, "Alpha!"); err == nil || !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Start(invalid id) = %v, want VALIDATION_FAILED", err)
	}
	var unwired UnitManagerAdapter
	if err := unwired.Start(ctx, "alpha"); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Start(no systemctl) = %v, want UNAVAILABLE", err)
	}
}

func TestUnitManagerAdapterPropagatesSystemctlError(t *testing.T) {
	sys := &fakeSystemctl{opErr: errors.New("polkit denied")}
	units := UnitManagerAdapter{Systemctl: sys}
	if err := units.Stop(t.Context(), "alpha"); err == nil {
		t.Fatal("Stop returned nil for a failing systemctl")
	}
}

// --- peer identity ---------------------------------------------------------

func TestCgroupUnit(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{
			name: "unified escaped slice",
			data: "0::/system.slice/system-qwq\\x2dplugin.slice/qwq-plugin@alpha.service\n",
			want: "qwq-plugin@alpha.service",
		},
		{
			name: "v1 name=systemd",
			data: "4:name=systemd:/system.slice/qwq-plugin@alpha.service\n",
			want: "qwq-plugin@alpha.service",
		},
		{
			name: "socket unit",
			data: "0::/system.slice/qwq-plugin@alpha.socket\n",
			want: "qwq-plugin@alpha.socket",
		},
		{
			name: "no unit component",
			data: "0::/\n",
			want: "",
		},
		{
			name: "empty",
			data: "",
			want: "",
		},
		{
			name: "garbage lines are skipped",
			data: "not a cgroup file\n0::/system.slice/qwq-plugin@beta.service\n",
			want: "qwq-plugin@beta.service",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CgroupUnit(tc.data); got != tc.want {
				t.Fatalf("CgroupUnit(%q) = %q, want %q", tc.data, got, tc.want)
			}
		})
	}
}

// writeCgroup writes a fake /proc/<pid>/cgroup below root.
func writeCgroup(t *testing.T, root string, pid int, content string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPeerVerifier(t *testing.T) {
	const pid = 4242
	proc := t.TempDir()
	writeCgroup(t, proc, pid, "0::/system.slice/system-qwq\\x2dplugin.slice/qwq-plugin@alpha.service\n")

	attached := func(pluginID string) (InstanceInfo, bool) {
		if pluginID != "alpha" {
			return InstanceInfo{}, false
		}
		return InstanceInfo{PluginID: pluginID, MainPID: pid, Generation: "gen-1", Owner: "alpha@gen-1"}, true
	}
	verifier := func() *PeerVerifier {
		return &PeerVerifier{
			PluginID:    "alpha",
			Unit:        supervisor.UnitName("alpha"),
			Instances:   attached,
			ProcRoot:    proc,
			ExpectedUID: func(string) (int, bool) { return 1001, true },
			Logger:      slog.New(slog.DiscardHandler),
		}
	}

	if err := verifier().Verify(pid, 1001); err != nil {
		t.Fatalf("Verify(main pid) = %v", err)
	}
	if err := verifier().Verify(pid+1, 1001); err == nil {
		t.Fatal("Verify accepted a pid that is not the unit's main process")
	}
	if err := verifier().Verify(pid, 0); err == nil {
		t.Fatal("Verify accepted a root peer")
	}
	if err := verifier().Verify(pid, 1002); err == nil {
		t.Fatal("Verify accepted a uid other than the plugin user")
	}

	// Another unit's process (a sibling plugin) is rejected even when the pid
	// matches what the fake instance reports.
	writeCgroup(t, proc, 5000, "0::/system.slice/qwq-plugin@beta.service\n")
	other := verifier()
	other.Instances = func(string) (InstanceInfo, bool) { return InstanceInfo{MainPID: 5000}, true }
	if err := other.Verify(5000, 1001); err == nil {
		t.Fatal("Verify accepted a peer from another unit")
	}

	// While the supervisor has not registered the instance yet, systemd's
	// current MainPID is the fallback.
	fallback := verifier()
	fallback.Instances = func(string) (InstanceInfo, bool) { return InstanceInfo{}, false }
	fallback.MainPID = func(string) (int, error) { return pid, nil }
	if err := fallback.Verify(pid, 1001); err != nil {
		t.Fatalf("Verify(systemd fallback) = %v", err)
	}

	// Without any instance identity the verifier fails closed.
	unknown := verifier()
	unknown.Instances = func(string) (InstanceInfo, bool) { return InstanceInfo{}, false }
	if err := unknown.Verify(pid, 1001); err == nil {
		t.Fatal("Verify accepted a peer without a known instance")
	}

	// A missing cgroup file is a rejection, not a pass.
	missing := verifier()
	missing.Instances = func(string) (InstanceInfo, bool) { return InstanceInfo{MainPID: 9999}, true }
	if err := missing.Verify(9999, 1001); err == nil {
		t.Fatal("Verify accepted a pid without a cgroup file")
	}

	if err := (&PeerVerifier{}).Verify(pid, 1001); err == nil {
		t.Fatal("Verify accepted an unconfigured verifier")
	}
}

func TestReadCgroupUnit(t *testing.T) {
	proc := t.TempDir()
	writeCgroup(t, proc, 7, "0::/system.slice/qwq-plugin@alpha.service\n")
	unit, err := ReadCgroupUnit(proc, 7)
	if err != nil || unit != "qwq-plugin@alpha.service" {
		t.Fatalf("ReadCgroupUnit = %q, %v", unit, err)
	}
	if _, err := ReadCgroupUnit(proc, 8); err == nil {
		t.Fatal("ReadCgroupUnit accepted a pid without a cgroup file")
	}
}

// --- plugin dir resolver ---------------------------------------------------

func TestPluginDirResolver(t *testing.T) {
	dir := t.TempDir()
	resolve := PluginDirResolver(dir)

	if _, err := resolve("alpha"); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("resolve(missing) = %v, want NOT_FOUND", err)
	}
	version := filepath.Join(dir, "alpha", "1.0.0")
	if err := os.MkdirAll(version, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolve("alpha")
	if err != nil || got != version {
		t.Fatalf("resolve(single version) = %q, %v", got, err)
	}

	if err := os.MkdirAll(filepath.Join(dir, "alpha", "2.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve("alpha"); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("resolve(two versions) = %v, want STATE_CONFLICT", err)
	}

	current := filepath.Join(dir, "alpha", "current")
	if err := os.MkdirAll(current, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err = resolve("alpha")
	if err != nil || got != current {
		t.Fatalf("resolve(current) = %q, %v", got, err)
	}

	if _, err := resolve("Alpha!"); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("resolve(invalid id) = %v, want VALIDATION_FAILED", err)
	}
}

func TestPluginDirsResolvesActiveWithRetainedVersions(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"1.0.0", "2.0.0"} {
		if err := os.MkdirAll(filepath.Join(dir, "alpha", v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dirs := &PluginDirs{Root: dir}
	dirs.SetActive(func(id string) (string, bool) { return "2.0.0", id == "alpha" })
	got, err := dirs.Resolve("alpha")
	if want := filepath.Join(dir, "alpha", "2.0.0"); err != nil || got != want {
		t.Fatalf("Resolve = %q, %v; want %q", got, err, want)
	}
	dirs.SetActive(func(string) (string, bool) { return "3.0.0", true })
	if _, err := dirs.Resolve("alpha"); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Resolve(missing active dir) = %v, want PLUGIN_UNAVAILABLE", err)
	}
	if _, err := dirs.Resolve("Alpha!"); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Resolve(invalid id) = %v, want VALIDATION_FAILED", err)
	}
}

func TestPluginDirsNoActiveIsNotFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "alpha", "1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	dirs := &PluginDirs{Root: dir}
	dirs.SetActive(func(string) (string, bool) { return "", false })
	if _, err := dirs.Resolve("alpha"); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("Resolve(no active) = %v, want NOT_FOUND", err)
	}
}

func TestPluginDirsFallsBackWithoutUpdater(t *testing.T) {
	dir := t.TempDir()
	version := filepath.Join(dir, "alpha", "1.0.0")
	if err := os.MkdirAll(version, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := (&PluginDirs{Root: dir}).Resolve("alpha")
	if err != nil || got != version {
		t.Fatalf("Resolve(unbound) = %q, %v; want %q", got, err, version)
	}
}

// --- event sink ------------------------------------------------------------

func TestHostEventSinkPublish(t *testing.T) {
	ctx := t.Context()
	db := testDB(t)
	sink := &hostEventSink{
		db: db, operations: runningFor("alpha", "op_1", "op_2"), pluginID: "alpha", instanceID: "default", nodeID: "local",
	}

	ref, err := sink.Publish(ctx, hostsvc.EventDraft{
		Type:          "security.alert",
		SchemaVersion: "2",
		Subject:       "audit/login",
		PayloadJSON:   []byte(`{"ok":true}`),
		OperationID:   "op_1",
		TraceID:       "tr_1",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if ref.EventID == "" || ref.Sequence == 0 {
		t.Fatalf("Publish ref = %+v", ref)
	}

	var typ, subject, schema, actorKind, actorID, operationID, traceID, payload string
	err = db.Reader().QueryRowContext(ctx, `SELECT type, subject, schema_version, actor_kind, actor_id,
		operation_id, trace_id, payload FROM event_journal WHERE seq = ?`, ref.Sequence).
		Scan(&typ, &subject, &schema, &actorKind, &actorID, &operationID, &traceID, &payload)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if typ != "alpha.security.alert" {
		t.Fatalf("type = %q", typ)
	}
	if subject != "nodes/local/plugins/alpha/instances/default/audit/login" {
		t.Fatalf("subject = %q", subject)
	}
	if schema != "2" || actorKind != string(actor.System) || actorID != "plugin:alpha" ||
		operationID != "op_1" || traceID != "tr_1" {
		t.Fatalf("journal row = type=%q schema=%q actor=%q/%q op=%q trace=%q",
			typ, schema, actorKind, actorID, operationID, traceID)
	}
	if payload != `{"ok":true}` {
		t.Fatalf("payload = %q", payload)
	}

	// An omitted schema version becomes the ABI's "1".
	ref, err = sink.Publish(ctx, hostsvc.EventDraft{Type: "health.ok", Subject: "health"})
	if err != nil {
		t.Fatalf("Publish(default schema): %v", err)
	}
	var gotSchema string
	if err := db.Reader().QueryRowContext(ctx, `SELECT schema_version FROM event_journal WHERE seq = ?`, ref.Sequence).
		Scan(&gotSchema); err != nil {
		t.Fatal(err)
	}
	if gotSchema != "1" {
		t.Fatalf("default schema = %q, want 1", gotSchema)
	}
}

func TestHostEventSinkReportChanges(t *testing.T) {
	ctx := t.Context()
	db := testDB(t)
	sink := &hostEventSink{
		db: db, operations: runningFor("alpha", "op_1", "op_2"), pluginID: "alpha", instanceID: "default", nodeID: "local",
	}

	err := sink.ReportChanges(ctx, hostsvc.ChangeSet{
		OperationID: "op_2",
		TraceID:     "tr_2",
		Changes: []hostsvc.ResourceChange{{
			Subject:         "firewall/rules",
			Revision:        "7",
			ChangedPointers: []string{"/inbound"},
		}},
	})
	if err != nil {
		t.Fatalf("ReportChanges: %v", err)
	}
	var subject, typ, payload string
	err = db.Reader().QueryRowContext(ctx, `SELECT subject, type, payload FROM event_journal
		WHERE type = 'resource.changed' ORDER BY seq DESC LIMIT 1`).Scan(&subject, &typ, &payload)
	if err != nil {
		t.Fatalf("read changed event: %v", err)
	}
	if subject != "nodes/local/plugins/alpha/instances/default/resources/firewall/rules" {
		t.Fatalf("subject = %q", subject)
	}
	var doc struct {
		Kind            string   `json:"kind"`
		Subject         string   `json:"subject"`
		ChangedPointers []string `json:"changed_pointers"`
		OperationID     string   `json:"operation_id"`
	}
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatalf("payload %q: %v", payload, err)
	}
	if doc.Kind != string(storage.Updated) || doc.OperationID != "op_2" {
		t.Fatalf("changed payload = %+v", doc)
	}
	if len(doc.ChangedPointers) != 1 || doc.ChangedPointers[0] != "/inbound" {
		t.Fatalf("changed pointers = %v", doc.ChangedPointers)
	}

	if err := sink.ReportChanges(ctx, hostsvc.ChangeSet{Changes: []hostsvc.ResourceChange{{
		Subject: "firewall/rules", Deleted: true,
	}}}); err != nil {
		t.Fatalf("ReportChanges(delete): %v", err)
	}
	err = db.Reader().QueryRowContext(ctx, `SELECT payload FROM event_journal
		WHERE type = 'resource.changed' ORDER BY seq DESC LIMIT 1`).Scan(&payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kind != string(storage.Deleted) {
		t.Fatalf("delete kind = %q", doc.Kind)
	}

	if err := sink.ReportChanges(ctx, hostsvc.ChangeSet{}); err != nil {
		t.Fatalf("ReportChanges(empty) = %v", err)
	}
	if err := sink.Ack(ctx, "watch", 3); err != nil {
		t.Fatalf("Ack = %v", err)
	}

	var unwired hostEventSink
	if _, err := unwired.Publish(ctx, hostsvc.EventDraft{Type: "a.b", Subject: "x"}); err == nil {
		t.Fatal("Publish without a database returned nil")
	}
	if err := unwired.ReportChanges(ctx, hostsvc.ChangeSet{Changes: []hostsvc.ResourceChange{{Subject: "x"}}}); err == nil {
		t.Fatal("ReportChanges without a database returned nil")
	}
}

// --- config source ---------------------------------------------------------

func TestHostConfigSource(t *testing.T) {
	rev, raw, err := hostConfigSource{}.Current(t.Context())
	if err == nil || rev != "" || len(raw) != 0 {
		t.Fatalf("missing config source must be unavailable: %q, %q, %v", rev, raw, err)
	}
}

// --- secret revealer -------------------------------------------------------

type fakeOperationReader struct {
	op  *operations.Operation
	err error
}

func (f fakeOperationReader) Get(context.Context, actor.Actor, string) (*operations.Operation, error) {
	return f.op, f.err
}

// configSecretDispatch 仅为 X3 存储绑定单测描述已授权 config 操作。
// 真实 executor、撤权、两层 scope 与成员检查由独立真实 operation 回归覆盖。
type configSecretDispatch struct{ reader operationReader }

func (f configSecretDispatch) ResolveDispatchedInstance(ctx context.Context, pluginID, instanceID, nodeID, operationID string) (operations.DispatchedContext, error) {
	op, err := f.reader.Get(ctx, actor.SystemActor("test"), operationID)
	if err != nil || !dispatchedTo(op, pluginID, instanceID, nodeID) {
		return operations.DispatchedContext{}, hostsvc.ErrOperationNotDispatched
	}
	return operations.DispatchedContext{OperationID: operationID, Target: op.Target,
		Action: operations.Action{Capabilities: []operations.Capability{{Name: "secret.reveal", Scope: "config"}}}}, nil
}

func (configSecretDispatch) RevalidateDispatched(context.Context, operations.DispatchedContext) error {
	return nil
}

// testSecrets opens a secret store over db with a fresh key ring.
func testSecrets(t *testing.T, db *storage.DB) *secrets.Store {
	t.Helper()
	keys, err := secrets.LoadKeyRing(t.TempDir())
	if err != nil {
		t.Fatalf("secrets.LoadKeyRing: %v", err)
	}
	store, err := secrets.New(secrets.Options{DB: db, Keys: keys})
	if err != nil {
		t.Fatalf("secrets.New: %v", err)
	}
	return store
}

// putSecret seals value with purpose for the test plugin instance, using the
// production config-secret owner "plugins/<id>" (api.extractPluginSecrets).
func putSecret(t *testing.T, db *storage.DB, store *secrets.Store, purpose string, value []byte) string {
	t.Helper()
	return putSecretOwned(t, db, store, "plugins/alpha", purpose, value)
}

// putSecretOwned seals value with an explicit owner, for owner-binding tests.
func putSecretOwned(t *testing.T, db *storage.DB, store *secrets.Store, owner, purpose string, value []byte) string {
	t.Helper()
	ctx := t.Context()
	var ref secrets.Ref
	err := db.Update(ctx, func(tx *storage.Tx) error {
		r, err := store.Put(ctx, tx, owner, purpose, value)
		ref = r
		return err
	})
	if err != nil {
		t.Fatalf("put secret: %v", err)
	}
	return string(ref)
}

func TestHostSecretRevealer(t *testing.T) {
	ctx := t.Context()
	db := testDB(t)
	store := testSecrets(t, db)
	ref := putSecret(t, db, store, pluginSecretPurpose, []byte("s3cret"))
	otherPurpose := putSecret(t, db, store, "identity.totp", []byte("totp-seed"))

	running := &operations.Operation{
		ID:     "op_1",
		Status: operations.Running,
		Target: operations.Target{NodeID: "local", PluginID: "alpha", InstanceID: "default"},
	}
	revealer := &hostSecretRevealer{
		operations: configSecretDispatch{reader: fakeOperationReader{op: running}},
		secrets:    store,
		pluginID:   "alpha",
		instanceID: "default",
		nodeID:     "local",
		logger:     slog.New(slog.DiscardHandler),
	}

	value, err := revealer.Reveal(ctx, ref, "op_1", []string{"config"})
	if err != nil || string(value) != "s3cret" {
		t.Fatalf("Reveal = %q, %v", value, err)
	}
	// A reference stored for another purpose must not decrypt.
	if _, err := revealer.Reveal(ctx, otherPurpose, "op_1", []string{"config"}); !errors.Is(err, hostsvc.ErrSecretDenied) {
		t.Fatalf("Reveal(wrong purpose) = %v, want ErrSecretDenied", err)
	}
	// A removed reference is denied without leaking whether it existed.
	if err := db.Update(ctx, func(tx *storage.Tx) error {
		return store.Delete(ctx, tx, secrets.Ref(otherPurpose))
	}); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	if _, err := revealer.Reveal(ctx, otherPurpose, "op_1", []string{"config"}); !errors.Is(err, hostsvc.ErrSecretDenied) {
		t.Fatalf("Reveal(missing ref) = %v, want ErrSecretDenied", err)
	}

	if _, err := revealer.Reveal(ctx, ref, "", []string{"config"}); !errors.Is(err, hostsvc.ErrOperationNotDispatched) {
		t.Fatalf("Reveal(no operation) = %v", err)
	}

	cases := []struct {
		name string
		op   *operations.Operation
		err  error
	}{
		{name: "unknown operation", err: problem.New(problem.NotFound, "no such operation")},
		{name: "other plugin", op: &operations.Operation{Status: operations.Running,
			Target: operations.Target{PluginID: "beta", InstanceID: "default"}}},
		{name: "other instance", op: &operations.Operation{Status: operations.Running,
			Target: operations.Target{PluginID: "alpha", InstanceID: "second"}}},
		{name: "other node", op: &operations.Operation{Status: operations.Running,
			Target: operations.Target{NodeID: "node-2", PluginID: "alpha", InstanceID: "default"}}},
		{name: "finished", op: &operations.Operation{Status: operations.Succeeded,
			Target: operations.Target{PluginID: "alpha", InstanceID: "default"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &hostSecretRevealer{
				operations: configSecretDispatch{reader: fakeOperationReader{op: tc.op, err: tc.err}},
				secrets:    store,
				pluginID:   "alpha",
				instanceID: "default",
				nodeID:     "local",
			}
			if _, err := r.Reveal(ctx, ref, "op_1", []string{"config"}); !errors.Is(err, hostsvc.ErrOperationNotDispatched) {
				t.Fatalf("Reveal = %v, want ErrOperationNotDispatched", err)
			}
		})
	}

	var unwired hostSecretRevealer
	if _, err := unwired.Reveal(ctx, ref, "op_1", []string{"config"}); !errors.Is(err, hostsvc.ErrOperationNotDispatched) {
		t.Fatalf("Reveal(unwired) = %v", err)
	}
}

// TestHostSecretRevealerOwnerBinding pins X3: the storage call is bound to the
// plugin's config owner (plugins/<id>) and purpose plugin.config. A reference
// stored for another owner, or for another purpose (e.g. the P6 plugin.operation
// password purpose), is denied without leaking whether it exists. The operation
// dispatch check still runs first.
func TestHostSecretRevealerOwnerBinding(t *testing.T) {
	ctx := t.Context()
	db := testDB(t)
	store := testSecrets(t, db)
	running := &operations.Operation{
		ID:     "op_1",
		Status: operations.Running,
		Target: operations.Target{NodeID: "local", PluginID: "alpha", InstanceID: "default"},
	}
	revealer := &hostSecretRevealer{
		operations: configSecretDispatch{reader: fakeOperationReader{op: running}},
		secrets:    store,
		pluginID:   "alpha",
		instanceID: "default",
		nodeID:     "local",
		logger:     slog.New(slog.DiscardHandler),
	}

	mine := putSecretOwned(t, db, store, "plugins/alpha", pluginSecretPurpose, []byte("s3cret"))
	foreignOwner := putSecretOwned(t, db, store, "plugins/beta", pluginSecretPurpose, []byte("beta-secret"))
	foreignPurpose := putSecretOwned(t, db, store, "plugins/alpha", "plugin.operation", []byte("op-secret"))
	legacyOwner := putSecretOwned(t, db, store, "plugins/alpha/instances/default", pluginSecretPurpose, []byte("legacy"))

	if value, err := revealer.Reveal(ctx, mine, "op_1", []string{"config"}); err != nil || string(value) != "s3cret" {
		t.Fatalf("Reveal(own owner) = %q, %v", value, err)
	}
	for name, ref := range map[string]string{
		"foreign owner":   foreignOwner,
		"foreign purpose": foreignPurpose,
		"legacy owner":    legacyOwner,
	} {
		if _, err := revealer.Reveal(ctx, ref, "op_1", []string{"config"}); !errors.Is(err, hostsvc.ErrSecretDenied) {
			t.Fatalf("Reveal(%s) = %v, want ErrSecretDenied", name, err)
		}
	}
	// The dispatch check still precedes the owner check: a foreign-owner ref
	// with no dispatched operation is refused as not-dispatched, not denied.
	if _, err := revealer.Reveal(ctx, foreignOwner, "", []string{"config"}); !errors.Is(err, hostsvc.ErrOperationNotDispatched) {
		t.Fatalf("Reveal(foreign, no operation) = %v, want ErrOperationNotDispatched", err)
	}
}

// --- audit sink ------------------------------------------------------------

func TestHostAuditSink(t *testing.T) {
	ctx := t.Context()
	db := testDB(t)
	sink := &hostAuditSink{
		db: db, operations: runningFor("alpha", "op_9"), pluginID: "alpha", instanceID: "default", nodeID: "local",
	}

	err := sink.Write(ctx, hostsvc.AuditRecord{
		Action:      "firewall.rule.add",
		Subject:     "rules/22",
		Outcome:     hostsvc.AuditDenied,
		DetailsJSON: []byte(`{"port":22}`),
		OperationID: "op_9",
		TraceID:     "tr_9",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var actorKind, actorID, source, action, subject, outcome, details string
	err = db.Reader().QueryRowContext(ctx, `SELECT actor_kind, actor_id, source, action, subject,
		outcome, details FROM audit_log ORDER BY occurred_at DESC LIMIT 1`).
		Scan(&actorKind, &actorID, &source, &action, &subject, &outcome, &details)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if actorKind != string(actor.System) || actorID != "plugin:alpha" || source != "plugin" {
		t.Fatalf("audit actor/source = %q/%q/%q", actorKind, actorID, source)
	}
	if action != "firewall.rule.add" || outcome != operations.AuditDenied {
		t.Fatalf("audit action/outcome = %q/%q", action, outcome)
	}
	if subject != "nodes/local/plugins/alpha/instances/default/rules/22" {
		t.Fatalf("audit subject = %q", subject)
	}
	var doc struct {
		Host struct {
			PluginID   string `json:"plugin_id"`
			InstanceID string `json:"instance_id"`
			Operation  string `json:"operation_id"`
			Trace      string `json:"trace_id"`
		} `json:"host"`
		Plugin struct {
			Port int `json:"port"`
		} `json:"plugin"`
	}
	if err := json.Unmarshal([]byte(details), &doc); err != nil {
		t.Fatalf("audit details %q: %v", details, err)
	}
	if doc.Host.PluginID != "alpha" || doc.Host.InstanceID != "default" ||
		doc.Host.Operation != "op_9" || doc.Host.Trace != "tr_9" || doc.Plugin.Port != 22 {
		t.Fatalf("audit details = %+v", doc)
	}

	if got := auditOutcome(hostsvc.AuditUnspecified); got != operations.AuditFailure {
		t.Fatalf("auditOutcome(unspecified) = %q", got)
	}
	var unwired hostAuditSink
	if err := unwired.Write(ctx, hostsvc.AuditRecord{Action: "a", Outcome: hostsvc.AuditSuccess}); err == nil {
		t.Fatal("Write without a database returned nil")
	}
}

// runningFor is an operation reader that knows the given ids as operations
// running for pluginID's default instance on node "local".
func runningFor(pluginID string, ids ...string) operationsByID {
	out := operationsByID{}
	for _, id := range ids {
		out[id] = &operations.Operation{ID: id, Status: operations.Running,
			Target: operations.Target{NodeID: "local", PluginID: pluginID, InstanceID: "default"}}
	}
	return out
}

// TestHostSinksDropUnverifiedOperationID: an operation id the plugin reports is
// only written to the journal, a resource.changed origin or the audit log when
// the host's record says it is running for that instance (EXT-01).
func TestHostSinksDropUnverifiedOperationID(t *testing.T) {
	ctx := t.Context()
	db := testDB(t)
	reader := runningFor("beta", "op_beta")
	reader["op_done"] = &operations.Operation{ID: "op_done", Status: operations.Succeeded,
		Target: operations.Target{NodeID: "local", PluginID: "alpha", InstanceID: "default"}}
	events := &hostEventSink{db: db, operations: reader, pluginID: "alpha", instanceID: "default", nodeID: "local"}
	audits := &hostAuditSink{db: db, operations: reader, pluginID: "alpha", instanceID: "default", nodeID: "local"}
	unwired := &hostEventSink{db: db, pluginID: "alpha", instanceID: "default", nodeID: "local"}

	for _, id := range []string{"op_beta", "op_done", "op_unknown"} {
		ref, err := events.Publish(ctx, hostsvc.EventDraft{Type: "x", Subject: "s", OperationID: id})
		if err != nil {
			t.Fatalf("Publish(%s): %v", id, err)
		}
		var got string
		if err := db.Reader().QueryRowContext(ctx, `SELECT operation_id FROM event_journal WHERE seq = ?`,
			ref.Sequence).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Fatalf("Publish(%s) journal operation_id = %q, want empty", id, got)
		}
		if err := events.ReportChanges(ctx, hostsvc.ChangeSet{OperationID: id,
			Changes: []hostsvc.ResourceChange{{Subject: "r"}}}); err != nil {
			t.Fatalf("ReportChanges(%s): %v", id, err)
		}
		if err := db.Reader().QueryRowContext(ctx, `SELECT operation_id FROM event_journal
			WHERE type = 'resource.changed' ORDER BY seq DESC LIMIT 1`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Fatalf("ReportChanges(%s) origin operation_id = %q, want empty", id, got)
		}
		if err := audits.Write(ctx, hostsvc.AuditRecord{Action: "a", Outcome: hostsvc.AuditSuccess,
			OperationID: id}); err != nil {
			t.Fatalf("Write(%s): %v", id, err)
		}
		var details string
		if err := db.Reader().QueryRowContext(ctx, `SELECT operation_id, details FROM audit_log
			ORDER BY rowid DESC LIMIT 1`).Scan(&got, &details); err != nil {
			t.Fatal(err)
		}
		if got != "" || strings.Contains(details, id) {
			t.Fatalf("audit(%s) operation_id = %q details = %s", id, got, details)
		}
	}
	ref, err := unwired.Publish(ctx, hostsvc.EventDraft{Type: "x", Subject: "s", OperationID: "op_beta"})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db.Reader().QueryRowContext(ctx, `SELECT operation_id FROM event_journal WHERE seq = ?`,
		ref.Sequence).Scan(&got); err != nil || got != "" {
		t.Fatalf("unwired Publish operation_id = %q, %v", got, err)
	}
}

// --- dispatcher ------------------------------------------------------------

type fakePluginClient struct {
	mu sync.Mutex

	planReq  *platformv1.PlanOperationRequest
	planResp *platformv1.PlanOperationResponse
	planErr  error

	invokeReq  *platformv1.InvokeRequest
	invokeResp *platformv1.InvokeResponse
	invokeErr  error

	runReq      *platformv1.RunJobRequest
	runProgress []*platformv1.JobProgress
	runErr      error

	cancelID  string
	cancelErr error
}

func (f *fakePluginClient) Plan(_ context.Context, req *platformv1.PlanOperationRequest) (*platformv1.PlanOperationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.planReq = req
	return f.planResp, f.planErr
}

func (f *fakePluginClient) Invoke(_ context.Context, req *platformv1.InvokeRequest) (*platformv1.InvokeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invokeReq = req
	return f.invokeResp, f.invokeErr
}

func (f *fakePluginClient) RunJob(_ context.Context, req *platformv1.RunJobRequest, progress func(*platformv1.JobProgress) error) error {
	f.mu.Lock()
	f.runReq = req
	msgs := f.runProgress
	err := f.runErr
	f.mu.Unlock()
	for _, msg := range msgs {
		if perr := progress(msg); perr != nil {
			return perr
		}
	}
	return err
}

func (f *fakePluginClient) Cancel(_ context.Context, operationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelID = operationID
	return f.cancelErr
}

func (f *fakePluginClient) snapshot() (*platformv1.PlanOperationRequest, *platformv1.InvokeRequest, *platformv1.RunJobRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.planReq, f.invokeReq, f.runReq
}

type fakeClients struct {
	client    PluginClient
	attachErr error
	liveErr   error
	attached  []string
	liveCalls []string
}

func (f *fakeClients) attach(_ context.Context, pluginID string) (PluginClient, error) {
	f.attached = append(f.attached, pluginID)
	if f.attachErr != nil {
		return nil, f.attachErr
	}
	return f.client, nil
}

func (f *fakeClients) live(pluginID string) (PluginClient, error) {
	f.liveCalls = append(f.liveCalls, pluginID)
	if f.liveErr != nil {
		return nil, f.liveErr
	}
	return f.client, nil
}

func TestPluginDispatcherPlan(t *testing.T) {
	ctx := t.Context()
	client := &fakePluginClient{planResp: &platformv1.PlanOperationResponse{
		Changes: []*platformv1.PlannedChange{{
			Kind:        platformv1.PlannedChange_KIND_UPDATE,
			Subject:     "rules/1",
			Pointer:     "/port",
			BeforeJson:  []byte(`{"port":80}`),
			AfterJson:   []byte(`{"port":8080}`),
			Reversible:  true,
			Description: "open 8080",
		}},
		Violations: []*platformv1.FieldViolation{{Pointer: "/port", Code: "IN_USE", Message: "busy"}},
		Warnings:   []*platformv1.FieldViolation{{Pointer: "/port", Code: "PRIVILEGED", Message: "needs root"}},
		Preconditions: []*platformv1.Precondition{
			{Subject: "rules/1", Revision: "3"},
		},
	}}
	clients := &fakeClients{client: client}
	dispatcher := &pluginDispatcher{clients: clients}

	preview, err := dispatcher.Plan(ctx, operations.PluginPlanRequest{
		Actor:       actor.Actor{Kind: actor.AIAgent, ID: "dlg_1", OnBehalfOf: "usr_1"},
		OperationID: "op_1",
		TraceID:     "tr_1",
		RequestID:   "req_1",
		Locale:      "zh-CN",
		NodeID:      "local",
		PluginID:    "alpha",
		InstanceID:  "default",
		Operation:   "firewall.apply",
		APIVersion:  "1",
		Payload:     json.RawMessage(`{"port":8080}`),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(clients.attached) != 1 || clients.attached[0] != "alpha" {
		t.Fatalf("attached = %v", clients.attached)
	}
	req, _, _ := client.snapshot()
	if req.GetOperation() != "firewall.apply" || req.GetApiVersion() != "1" ||
		string(req.GetPayloadJson()) != `{"port":8080}` {
		t.Fatalf("plan request = %+v", req)
	}
	cc := req.GetContext()
	if cc.GetOperationId() != "op_1" || cc.GetTraceId() != "tr_1" || cc.GetRequestId() != "req_1" ||
		cc.GetNodeId() != "local" || cc.GetInstanceId() != "default" || cc.GetLocale() != "zh-CN" {
		t.Fatalf("plan context = %+v", cc)
	}
	if cc.GetActor().GetKind() != platformv1.ActorKind_ACTOR_KIND_AI_AGENT ||
		cc.GetActor().GetId() != "dlg_1" || cc.GetActor().GetOnBehalfOf() != "usr_1" {
		t.Fatalf("plan actor = %+v", cc.GetActor())
	}

	if len(preview.Changes) != 1 {
		t.Fatalf("changes = %+v", preview.Changes)
	}
	change := preview.Changes[0]
	if change.Kind != "update" || change.Subject != "rules/1" || change.Pointer != "/port" ||
		string(change.Before) != `{"port":80}` || string(change.After) != `{"port":8080}` ||
		!change.Reversible || change.Source != string(operations.PluginSource) ||
		change.PluginID != "alpha" || change.Description != "open 8080" {
		t.Fatalf("change = %+v", change)
	}
	if len(preview.Violations) != 1 || preview.Violations[0].Code != "IN_USE" {
		t.Fatalf("violations = %+v", preview.Violations)
	}
	if len(preview.Warnings) != 1 || preview.Warnings[0].Code != "PRIVILEGED" {
		t.Fatalf("warnings = %+v", preview.Warnings)
	}
	if len(preview.Preconditions) != 1 || preview.Preconditions[0].Subject != "rules/1" ||
		preview.Preconditions[0].Revision != "3" {
		t.Fatalf("preconditions = %+v", preview.Preconditions)
	}
	if plannedKind(platformv1.PlannedChange_KIND_UNSPECIFIED) != "" {
		t.Fatal("unspecified change kind did not map to the empty host kind")
	}
}

func TestPluginDispatcherErrors(t *testing.T) {
	ctx := t.Context()
	client := &fakePluginClient{
		planErr:   problem.New(problem.PluginUnavailable, "plugin is gone"),
		invokeErr: problem.New(problem.Timeout, "plugin timed out"),
		runErr:    problem.New(problem.PluginError, "plugin failed the job"),
		cancelErr: problem.New(problem.PluginUnavailable, "plugin is gone"),
	}
	clients := &fakeClients{client: client}
	dispatcher := &pluginDispatcher{clients: clients}

	if _, err := dispatcher.Plan(ctx, operations.PluginPlanRequest{PluginID: "alpha"}); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Plan error = %v", err)
	}
	if _, err := dispatcher.Invoke(ctx, operations.PluginInvokeRequest{PluginID: "alpha"}); !problem.HasCode(err, problem.Timeout) {
		t.Fatalf("Invoke error = %v", err)
	}
	if err := dispatcher.RunJob(ctx, operations.PluginRunJobRequest{PluginID: "alpha"}, func(operations.JobProgress) error { return nil }); !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("RunJob error = %v", err)
	}
	if err := dispatcher.Cancel(ctx, operations.PluginCancelRequest{PluginID: "alpha", OperationID: "op_1"}); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Cancel error = %v", err)
	}
	if len(clients.liveCalls) != 1 {
		t.Fatalf("Cancel used live clients = %v", clients.liveCalls)
	}

	attachFailure := &fakeClients{attachErr: problem.New(problem.PluginUnavailable, "no unit")}
	failing := &pluginDispatcher{clients: attachFailure}
	if _, err := failing.Plan(ctx, operations.PluginPlanRequest{PluginID: "alpha"}); !problem.HasCode(err, problem.PluginUnavailable) {
		t.Fatalf("Plan(attach failure) = %v", err)
	}
}

func TestPluginDispatcherInvoke(t *testing.T) {
	ctx := t.Context()
	client := &fakePluginClient{invokeResp: &platformv1.InvokeResponse{
		PayloadJson: []byte(`{"applied":true}`),
		Changes:     []*platformv1.ResourceChange{{Subject: "rules/1", Revision: "9", ChangedPointers: []string{"/port"}}},
	}}
	dispatcher := &pluginDispatcher{clients: &fakeClients{client: client}}

	resp, err := dispatcher.Invoke(ctx, operations.PluginInvokeRequest{
		Actor:         actor.SystemActor("controller"),
		OperationID:   "op_2",
		Attempt:       2,
		TraceID:       "tr_2",
		RequestID:     "req_2",
		NodeID:        "local",
		PluginID:      "alpha",
		InstanceID:    "default",
		Operation:     "firewall.apply",
		APIVersion:    "1",
		Payload:       json.RawMessage(`{"port":8080}`),
		Preconditions: []operations.Precondition{{Subject: "rules/1", Revision: "8"}},
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if string(resp.Result) != `{"applied":true}` {
		t.Fatalf("result = %s", resp.Result)
	}
	if len(resp.Changes) != 1 || resp.Changes[0].Subject != "rules/1" ||
		resp.Changes[0].Revision != "9" || len(resp.Changes[0].ChangedPointers) != 1 {
		t.Fatalf("changes = %+v", resp.Changes)
	}

	client.mu.Lock()
	req := client.invokeReq
	client.mu.Unlock()
	if req.GetAttempt() != 2 || req.GetOperation() != "firewall.apply" {
		t.Fatalf("invoke request = %+v", req)
	}
	pre := req.GetPreconditions()
	if len(pre) != 1 || pre[0].GetSubject() != "rules/1" || pre[0].GetRevision() != "8" {
		t.Fatalf("preconditions = %+v", pre)
	}
	if req.GetContext().GetOperationId() != "op_2" || req.GetContext().GetActor().GetKind() != platformv1.ActorKind_ACTOR_KIND_SYSTEM {
		t.Fatalf("invoke context = %+v", req.GetContext())
	}
}

func TestPluginDispatcherRunJob(t *testing.T) {
	ctx := t.Context()
	client := &fakePluginClient{runProgress: []*platformv1.JobProgress{
		{
			Percent:   40,
			Message:   "copying",
			Step:      "copy",
			StepIndex: 1,
			StepCount: 3,
			Changes:   []*platformv1.ResourceChange{{Subject: "files/a", Revision: "4"}},
		},
		{
			Completed:  true,
			Percent:    100,
			ResultJson: []byte(`{"copied":2}`),
		},
	}}
	dispatcher := &pluginDispatcher{clients: &fakeClients{client: client}}

	var got []operations.JobProgress
	err := dispatcher.RunJob(ctx, operations.PluginRunJobRequest{
		Actor:       actor.SystemActor("controller"),
		OperationID: "op_3",
		NodeID:      "local",
		PluginID:    "alpha",
		InstanceID:  "default",
		Operation:   "files.copy",
		APIVersion:  "1",
		Payload:     json.RawMessage(`{}`),
	}, func(p operations.JobProgress) error {
		got = append(got, p)
		return nil
	})
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("progress messages = %d", len(got))
	}
	if got[0].Percent == nil || *got[0].Percent != 40 || got[0].Step != "copy" ||
		got[0].StepIndex != 1 || got[0].StepCount != 3 || got[0].Message != "copying" {
		t.Fatalf("progress[0] = %+v", got[0])
	}
	if len(got[0].Changes) != 1 || got[0].Changes[0].Subject != "files/a" {
		t.Fatalf("progress changes = %+v", got[0].Changes)
	}
	if !got[1].Completed || got[1].Percent == nil || *got[1].Percent != 100 ||
		string(got[1].Result) != `{"copied":2}` {
		t.Fatalf("progress[1] = %+v", got[1])
	}

	// A terminal error message is delivered as a host problem, and the client
	// returns it as an error once the callback saw it (supervisor.Client
	// contract); the fake mirrors that contract.
	failing := &fakePluginClient{
		runProgress: []*platformv1.JobProgress{{
			Error: &platformv1.ErrorDetail{Code: "PRECONDITION_FAILED", Message: "revision changed"},
		}},
		runErr: problem.New(problem.PreconditionFailed, "revision changed"),
	}
	dispatcher = &pluginDispatcher{clients: &fakeClients{client: failing}}
	var terminal operations.JobProgress
	err = dispatcher.RunJob(ctx, operations.PluginRunJobRequest{PluginID: "alpha", OperationID: "op_4"},
		func(p operations.JobProgress) error {
			terminal = p
			return nil
		})
	if err == nil || !problem.HasCode(err, problem.PreconditionFailed) {
		t.Fatalf("RunJob(terminal error) = %v", err)
	}
	if terminal.Error == nil || !problem.HasCode(terminal.Error, problem.PreconditionFailed) {
		t.Fatalf("terminal progress = %+v", terminal)
	}
}

func TestPluginDispatcherCancel(t *testing.T) {
	ctx := t.Context()
	client := &fakePluginClient{}
	clients := &fakeClients{client: client}
	dispatcher := &pluginDispatcher{clients: clients}

	if err := dispatcher.Cancel(ctx, operations.PluginCancelRequest{PluginID: "alpha", OperationID: "op_5"}); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	client.mu.Lock()
	got := client.cancelID
	client.mu.Unlock()
	if got != "op_5" {
		t.Fatalf("cancel id = %q", got)
	}
	if len(clients.attached) != 0 {
		t.Fatalf("Cancel attached the plugin: %v", clients.attached)
	}
}

// --- invoker ---------------------------------------------------------------

type fakeWaiter struct {
	op    *operations.Operation
	err   error
	calls int
}

func (f *fakeWaiter) Wait(context.Context, actor.Actor, string, time.Duration) (*operations.Operation, error) {
	f.calls++
	return f.op, f.err
}

type fakeCanceler struct {
	req   operations.CancelRequest
	resp  *operations.Response
	err   error
	calls int
}

func (f *fakeCanceler) Cancel(_ context.Context, req operations.CancelRequest) (*operations.Response, error) {
	f.calls++
	f.req = req
	return f.resp, f.err
}

// operationsByID answers Get the way operations.Service does for a caller that
// may read everything: by id, and NOT_FOUND otherwise. An ownership check that
// looks up the wrong id, or asks as an actor without that right, cannot pass.
type operationsByID map[string]*operations.Operation

func (f operationsByID) Get(_ context.Context, a actor.Actor, id string) (*operations.Operation, error) {
	if op, ok := f[id]; ok && a.Kind == actor.System {
		return op, nil
	}
	return nil, problem.New(problem.NotFound, "no such operation")
}

// notOwnedCase is one lookup the ownership check must refuse.
type notOwnedCase struct {
	name   string
	reader operationReader
}

// notOwnedCases are the answers alpha/default must be refused for. Each one
// ends in the same response, so a plugin cannot tell them apart.
func notOwnedCases() []notOwnedCase {
	return []notOwnedCase{
		{"other plugin", fakeOperationReader{op: &operations.Operation{Status: operations.Running,
			Target: operations.Target{PluginID: "beta", InstanceID: "default"}}}},
		{"other instance", fakeOperationReader{op: &operations.Operation{Status: operations.Running,
			Target: operations.Target{PluginID: "alpha", InstanceID: "second"}}}},
		{"host operation awaiting approval", fakeOperationReader{op: &operations.Operation{
			Status: operations.AwaitingApproval}}},
		{"unknown operation", fakeOperationReader{err: problem.New(problem.NotFound, "no such operation")}},
		// ADR-0011 §6: work dispatched to the instance is not work it created.
		{"dispatched to this instance", fakeOperationReader{op: &operations.Operation{Status: operations.Running,
			Target: operations.Target{PluginID: "alpha", InstanceID: "default"}}}},
		{"child of another instance's operation", operationsByID{
			"op_2": {ID: "op_2", ParentOperationID: "op_beta", Status: operations.Running,
				Target: operations.Target{PluginID: "gamma", InstanceID: "default"}},
			"op_beta": {ID: "op_beta", Status: operations.Running,
				Target: operations.Target{PluginID: "beta", InstanceID: "default"}},
		}},
	}
}

// wantNotOwned checks the single refusal of the ownership check.
func wantNotOwned(t *testing.T, err error) {
	t.Helper()
	const want = "the operation was not created by this plugin instance"
	if status.Code(err) != codes.NotFound || status.Convert(err).Message() != want {
		t.Fatalf("err = %v, want NOT_FOUND %q", err, want)
	}
}

// TestHostInvokerWaitChecksOwnershipFirst covers the side channel: a plugin
// must not be able to wait on, or learn the outcome of, an operation that is not
// its own, so the wait never starts.
func TestHostInvokerWaitChecksOwnershipFirst(t *testing.T) {
	ctx := t.Context()
	for _, tc := range notOwnedCases() {
		t.Run(tc.name, func(t *testing.T) {
			waiter := &fakeWaiter{op: &operations.Operation{Status: operations.Succeeded}}
			invoker := &hostInvoker{reader: tc.reader, waiter: waiter, pluginID: "alpha", instanceID: "default"}

			_, err := invoker.WaitOperation(ctx, hostsvc.WaitCall{OperationID: "op_2", Timeout: time.Minute})
			if waiter.calls != 0 {
				t.Fatalf("Wait ran %d times before the ownership check", waiter.calls)
			}
			wantNotOwned(t, err)
		})
	}

	// A missing reader must not skip the check.
	waiter := &fakeWaiter{op: &operations.Operation{Status: operations.Succeeded}}
	noReader := &hostInvoker{waiter: waiter, pluginID: "alpha", instanceID: "default"}
	if _, err := noReader.WaitOperation(ctx, hostsvc.WaitCall{OperationID: "op_2"}); err == nil || waiter.calls != 0 {
		t.Fatalf("WaitOperation(no reader) = %v after %d waits", err, waiter.calls)
	}
}

// TestHostInvokerCancelChecksOwnershipFirst covers the cancel path: a plugin
// must not be able to stop work that is not its own, so the cancel never starts.
func TestHostInvokerCancelChecksOwnershipFirst(t *testing.T) {
	ctx := t.Context()
	canceled := &operations.Response{Operation: &operations.Operation{Status: operations.Canceled}}
	for _, tc := range notOwnedCases() {
		t.Run(tc.name, func(t *testing.T) {
			canceler := &fakeCanceler{resp: canceled}
			invoker := &hostInvoker{reader: tc.reader, canceler: canceler, pluginID: "alpha", instanceID: "default"}

			state, err := invoker.CancelOperation(ctx, hostsvc.CancelCall{OperationID: "op_2"})
			if canceler.calls != 0 {
				t.Fatalf("Cancel ran %d times before the ownership check", canceler.calls)
			}
			wantNotOwned(t, err)
			if state != hostsvc.OperationUnspecified {
				t.Fatalf("state = %q, want unspecified", state)
			}
		})
	}

	// A missing reader must not skip the check.
	canceler := &fakeCanceler{resp: canceled}
	noReader := &hostInvoker{canceler: canceler, pluginID: "alpha", instanceID: "default"}
	if _, err := noReader.CancelOperation(ctx, hostsvc.CancelCall{OperationID: "op_2"}); err == nil || canceler.calls != 0 {
		t.Fatalf("CancelOperation(no reader) = %v after %d cancels", err, canceler.calls)
	}
}

// TestHostInvokerOwnershipLookupFailureIsRetryable separates a storage failure
// from a refusal: the plugin gets a retryable UNAVAILABLE that reveals nothing
// about the operation, the cause goes to the host log, and neither Wait nor
// Cancel starts.
func TestHostInvokerOwnershipLookupFailureIsRetryable(t *testing.T) {
	ctx := t.Context()
	var logs strings.Builder
	reader := fakeOperationReader{err: errors.New("database is locked")}
	waiter := &fakeWaiter{op: &operations.Operation{Status: operations.Succeeded}}
	canceler := &fakeCanceler{resp: &operations.Response{Operation: &operations.Operation{Status: operations.Canceled}}}
	invoker := &hostInvoker{reader: reader, waiter: waiter, canceler: canceler,
		logger: slog.New(slog.NewTextHandler(&logs, nil)), pluginID: "alpha", instanceID: "default"}

	_, waitErr := invoker.WaitOperation(ctx, hostsvc.WaitCall{OperationID: "op_2", Timeout: time.Minute})
	_, cancelErr := invoker.CancelOperation(ctx, hostsvc.CancelCall{OperationID: "op_2"})
	for name, err := range map[string]error{"Wait": waitErr, "Cancel": cancelErr} {
		if status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "database") {
			t.Fatalf("%s err = %v, want a bare UNAVAILABLE", name, err)
		}
	}
	if waiter.calls != 0 || canceler.calls != 0 {
		t.Fatalf("Wait ran %d times and Cancel %d times after a failed lookup", waiter.calls, canceler.calls)
	}
	if got := strings.Count(logs.String(), "database is locked"); got != 2 {
		t.Fatalf("the cause was logged %d times, want 2:\n%s", got, logs.String())
	}
}

// TestHostInvokerProtectsRealOperations runs the production wiring against the
// real operation manager: a plugin cannot stop a host operation that waits for a
// human decision. It also fails if a dependency is missing from the wiring,
// because the refusal would then be UNAVAILABLE.
func TestHostInvokerProtectsRealOperations(t *testing.T) {
	e := newAgentEnv(t)
	ctx := e.t.Context()
	pending := e.pending(operations.PermissionSafe, 1)
	invoker := newTestRuntime(t).newHostInvoker(e.c.HostDeps(), "alpha")

	_, err := invoker.WaitOperation(ctx, hostsvc.WaitCall{OperationID: pending.OperationID})
	wantNotOwned(t, err)
	_, err = invoker.CancelOperation(ctx, hostsvc.CancelCall{OperationID: pending.OperationID})
	wantNotOwned(t, err)

	op, err := e.c.Operations().Get(ctx, humanActor(e.admin), pending.OperationID)
	if err != nil {
		t.Fatalf("Get operation: %v", err)
	}
	if op.Status != operations.AwaitingApproval || op.CancelRequested {
		t.Fatalf("operation = %s (cancel requested %v), want it untouched", op.Status, op.CancelRequested)
	}
}

func TestHostInvokerWaitAndCancel(t *testing.T) {
	ctx := t.Context()
	percent := 60
	// op_1 is a child this instance created with InvokePlugin: its parent is
	// an operation dispatched to alpha/default.
	op := &operations.Operation{
		ID:                "op_1",
		ParentOperationID: "op_parent",
		Status:            operations.Running,
		Target:            operations.Target{PluginID: "beta", InstanceID: "default"},
		Result:            json.RawMessage(`{"done":false}`),
		Progress:          &operations.Progress{Percent: &percent, Step: "copy", StepIndex: 2, StepCount: 4, Message: "half"},
	}
	waiter := &fakeWaiter{op: op}
	canceler := &fakeCanceler{resp: &operations.Response{Operation: &operations.Operation{
		ID: "op_1", Status: operations.Canceled,
	}}}
	invoker := &hostInvoker{
		reader: operationsByID{
			"op_1":      op,
			"op_parent": {ID: "op_parent", Status: operations.Running, Target: operations.Target{PluginID: "alpha", InstanceID: "default"}},
			// A controller-placement parent has no instance.
			"op_controller":        {ID: "op_controller", ParentOperationID: "op_controller_parent", Status: operations.Running},
			"op_controller_parent": {ID: "op_controller_parent", Status: operations.Running, Target: operations.Target{PluginID: "alpha"}},
		},
		waiter:     waiter,
		canceler:   canceler,
		pluginID:   "alpha",
		instanceID: "default",
	}

	snapshot, err := invoker.WaitOperation(ctx, hostsvc.WaitCall{OperationID: "op_1"})
	if err != nil {
		t.Fatalf("WaitOperation: %v", err)
	}
	if snapshot.State != hostsvc.OperationRunning || string(snapshot.ResultJSON) != `{"done":false}` {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot.Progress == nil || snapshot.Progress.Percent != 60 || snapshot.Progress.Step != "copy" || snapshot.Progress.StepIndex != 2 {
		t.Fatalf("snapshot progress = %+v", snapshot.Progress)
	}
	if _, err := invoker.WaitOperation(ctx, hostsvc.WaitCall{OperationID: "op_controller"}); err != nil {
		t.Fatalf("WaitOperation(controller placement): %v", err)
	}

	state, err := invoker.CancelOperation(ctx, hostsvc.CancelCall{OperationID: "op_1"})
	if err != nil {
		t.Fatalf("CancelOperation: %v", err)
	}
	if state != hostsvc.OperationCanceled {
		t.Fatalf("cancel state = %q", state)
	}
	if canceler.req.OperationID != "op_1" || canceler.req.Actor.ID != "plugin:alpha" ||
		canceler.req.Idempotency.Key != "plugin-cancel:op_1" {
		t.Fatalf("cancel request = %+v", canceler.req)
	}

	// An error past the ownership check keeps its own meaning.
	failing := &hostInvoker{reader: operationsByID{"op_1": op, "op_parent": {ID: "op_parent",
		Target: operations.Target{PluginID: "alpha", InstanceID: "default"}}},
		canceler: &fakeCanceler{err: problem.New(problem.StateConflict, "The operation already finished.")},
		pluginID: "alpha", instanceID: "default"}
	if _, err := failing.CancelOperation(ctx, hostsvc.CancelCall{OperationID: "op_1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("CancelOperation(failure) = %v, want FAILED_PRECONDITION", err)
	}

	var unwired hostInvoker
	if _, err := unwired.WaitOperation(ctx, hostsvc.WaitCall{OperationID: "op_1"}); err == nil {
		t.Fatal("WaitOperation(unwired) returned nil")
	}
	if _, err := unwired.CancelOperation(ctx, hostsvc.CancelCall{OperationID: "op_1"}); err == nil {
		t.Fatal("CancelOperation(unwired) returned nil")
	}
}

// --- runtime ---------------------------------------------------------------

func newTestRuntime(t *testing.T) *PluginRuntime {
	t.Helper()
	return newTestRuntimeAt(t, t.TempDir())
}

// newTestRuntimeAt builds a runtime whose run, data and plugin directories all
// live below dir, so a test can "restart" the host on the same data.
func newTestRuntimeAt(t *testing.T, dir string) *PluginRuntime {
	t.Helper()
	rt, err := NewPluginRuntime(PluginRuntimeOptions{
		Units:     &fakeSupervisorUnits{},
		PluginDir: func(string) (string, error) { return filepath.Join(dir, "plugins", "alpha", "1.0.0"), nil },
		RunDir:    filepath.Join(dir, "run"),
		StateDir:  filepath.Join(dir, "data", "plugin-state"),
		Host:      func(string) (supervisor.HostServer, error) { return fakeHostServer{}, nil },
		Logger:    slog.New(slog.DiscardHandler),
		Clock:     clock.System{},
	})
	if err != nil {
		t.Fatalf("NewPluginRuntime: %v", err)
	}
	t.Cleanup(rt.Stop)
	return rt
}

func TestNewPluginRuntimeValidation(t *testing.T) {
	if _, err := NewPluginRuntime(PluginRuntimeOptions{}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("NewPluginRuntime(no units) = %v", err)
	}
	if _, err := NewPluginRuntime(PluginRuntimeOptions{Units: &fakeSupervisorUnits{}}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("NewPluginRuntime(no plugin dir) = %v", err)
	}
	if _, err := NewPluginRuntime(PluginRuntimeOptions{
		Units:     &fakeSupervisorUnits{},
		PluginDir: func(string) (string, error) { return "", nil },
		RunDir:    "relative/run",
		StateDir:  "/var/lib/qwq/plugin-state",
	}); err == nil {
		t.Fatal("NewPluginRuntime accepted a relative run dir")
	}
	// The plugin KV store must live on persistent storage; there is no
	// silent fallback to the tmpfs run dir (PLG-06).
	for _, stateDir := range []string{"", "relative/state"} {
		if _, err := NewPluginRuntime(PluginRuntimeOptions{
			Units:     &fakeSupervisorUnits{},
			PluginDir: func(string) (string, error) { return "", nil },
			StateDir:  stateDir,
		}); !problem.HasCode(err, problem.ValidationFailed) {
			t.Errorf("NewPluginRuntime(StateDir=%q) = %v, want VALIDATION_FAILED", stateDir, err)
		}
	}
}

func TestPluginRuntimeStartStop(t *testing.T) {
	ctx := t.Context()
	rt := newTestRuntime(t)

	if rt.Dispatcher() == nil {
		t.Fatal("Dispatcher is nil")
	}
	if rt.Supervisor() == nil {
		t.Fatal("Supervisor is nil")
	}
	if _, err := rt.Dispatcher().Plan(ctx, operations.PluginPlanRequest{PluginID: "alpha"}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Plan before Start = %v, want UNAVAILABLE", err)
	}
	if err := rt.Start(ctx, HostDeps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := rt.Start(ctx, HostDeps{}); err != nil {
		t.Fatalf("Start(again) = %v", err)
	}
	rt.Stop()
	rt.Stop()
	if err := rt.Start(ctx, HostDeps{}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Start after Stop = %v, want UNAVAILABLE", err)
	}

	var nilRuntime *PluginRuntime
	if nilRuntime.Dispatcher() != nil {
		t.Fatal("nil runtime has a dispatcher")
	}
	if nilRuntime.Supervisor() != nil {
		t.Fatal("nil runtime has a supervisor")
	}
	if err := nilRuntime.Start(ctx, HostDeps{}); err == nil {
		t.Fatal("nil runtime started")
	}
	nilRuntime.Stop()
}

func TestPluginRuntimeHostServer(t *testing.T) {
	ctx := t.Context()
	rt := newTestRuntime(t)

	host, err := rt.HostServer("alpha")
	if err != nil {
		t.Fatalf("HostServer: %v", err)
	}
	if _, err := host.Serve(ctx, "beta"); err == nil {
		t.Fatal("Serve accepted a duplicate plugin id")
	}
	if _, err := host.Serve(ctx, "alpha"); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Serve before Start = %v, want UNAVAILABLE", err)
	}
	if _, err := rt.HostServer("Alpha!"); err == nil {
		t.Fatal("HostServer accepted an invalid plugin id")
	}
	var nilRuntime *PluginRuntime
	if _, err := nilRuntime.HostServer("alpha"); err == nil {
		t.Fatal("nil runtime built a host server")
	}
}

func TestPluginRuntimeHostDepsDefault(t *testing.T) {
	// Without a database the host service keeps state and peer checks and
	// reports the journal-dependent services as unavailable.
	rt := newTestRuntime(t)
	if err := rt.Start(t.Context(), HostDeps{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deps, ok := rt.depsSnapshot()
	if !ok || deps.DB != nil || deps.Ops != nil {
		t.Fatalf("deps = %+v", deps)
	}
}

func TestNewHostServiceConfig(t *testing.T) {
	ctx := t.Context()
	rt := newTestRuntime(t)
	if err := rt.Start(ctx, HostDeps{Clock: clock.System{}, Logger: slog.New(slog.DiscardHandler), NodeID: "local"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	srv, err := rt.newHostService("alpha")
	if err != nil {
		t.Fatalf("newHostService: %v", err)
	}
	_ = srv.Close()
	if _, err := os.Stat(filepath.Join(rt.opts.StateDir, "alpha")); err != nil {
		t.Fatalf("state dir was not created below the data dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rt.opts.RunDir, "state")); !os.IsNotExist(err) {
		t.Errorf("state was created below the tmpfs run dir: %v", err)
	}
	if _, err := rt.newHostService("Alpha!"); err == nil {
		t.Fatal("newHostService accepted an invalid plugin id")
	}
}

// --- controller wiring -----------------------------------------------------

func TestControllerStopsPluginRuntime(t *testing.T) {
	rt := newTestRuntime(t)
	opts := testOptions(t)
	opts.PluginRuntime = rt

	c, err := New(t.Context(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.PluginRuntime() != rt {
		t.Fatal("Controller.PluginRuntime did not return the runtime")
	}
	if c.Clock() == nil || c.IDs() == nil || c.Logger() == nil {
		t.Fatal("Controller accessors returned nil")
	}
	deps := c.HostDeps()
	if deps.DB == nil || deps.Ops == nil || deps.Secrets == nil || deps.Clock == nil {
		t.Fatalf("HostDeps = %+v", deps)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := rt.Start(t.Context(), HostDeps{}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("Start after controller Close = %v, want UNAVAILABLE", err)
	}
}

// TestPluginStateSurvivesRuntimeRestart: 插件 KV 写在 DataDir 下，清空
// RunDir（模拟重启机器，/run 是 tmpfs）后新运行时仍能读回（PLG-06）。
func TestPluginStateSurvivesRuntimeRestart(t *testing.T) {
	dir := t.TempDir()
	rt := newTestRuntimeAt(t, dir)
	if err := rt.Start(t.Context(), HostDeps{Clock: clock.System{}, Logger: slog.New(slog.DiscardHandler), NodeID: "local"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	srv, err := rt.newHostService("alpha")
	if err != nil {
		t.Fatalf("newHostService: %v", err)
	}
	_ = srv.Close()
	state := filepath.Join(rt.opts.StateDir, "alpha", "state.json")
	if err := os.WriteFile(state, []byte(`{"k":"v"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rt.Stop()
	if err := os.RemoveAll(filepath.Join(dir, "run")); err != nil {
		t.Fatal(err)
	}
	_ = newTestRuntimeAt(t, dir)
	if got, err := os.ReadFile(state); err != nil || string(got) != `{"k":"v"}` {
		t.Errorf("state after restart = %q, %v", got, err)
	}
}

// TestPluginStateMigratesFromRunDir: 旧布局 <RunDir>/state/<id>/state.json 在
// 启动时一次性迁到 StateDir；新位置已有文件时不覆盖。
func TestPluginStateMigratesFromRunDir(t *testing.T) {
	dir := t.TempDir()
	for id, body := range map[string]string{"alpha": `{"old":"alpha"}`, "beta": `{"old":"beta"}`} {
		legacy := filepath.Join(dir, "run", "state", id)
		if err := os.MkdirAll(legacy, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacy, "state.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kept := filepath.Join(dir, "data", "plugin-state", "beta")
	if err := os.MkdirAll(kept, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kept, "state.json"), []byte(`{"new":"beta"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := newTestRuntimeAt(t, dir)
	moved := filepath.Join(rt.opts.StateDir, "alpha", "state.json")
	if got, err := os.ReadFile(moved); err != nil || string(got) != `{"old":"alpha"}` {
		t.Errorf("migrated alpha state = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "state", "alpha", "state.json")); !os.IsNotExist(err) {
		t.Errorf("legacy alpha state was not removed: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(kept, "state.json")); string(got) != `{"new":"beta"}` {
		t.Errorf("migration overwrote the newer beta state: %q", got)
	}
}
