// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// putState calls PutState and requires success.
func putState(t *testing.T, ctx context.Context, client platformv1.HostStateServiceClient, req *platformv1.PutStateRequest) *platformv1.PutStateResponse {
	t.Helper()
	req.Context = callContext()
	response, err := client.PutState(ctx, req)
	wantOK(t, err, "PutState "+req.GetKey())
	return response
}

// getState calls GetState and requires success.
func getState(t *testing.T, ctx context.Context, client platformv1.HostStateServiceClient, key string) *platformv1.GetStateResponse {
	t.Helper()
	response, err := client.GetState(ctx, &platformv1.GetStateRequest{Context: callContext(), Key: key})
	wantOK(t, err, "GetState "+key)
	return response
}

// TestStateCRUDAndPagination covers the full HostStateService surface: guards,
// revisions, deletion and multi-page listing.
func TestStateCRUDAndPagination(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	client := ts.State()

	rev1 := putState(t, ctx, client, &platformv1.PutStateRequest{
		Key:          "k1",
		ValueJson:    []byte(`{"n":1}`),
		Precondition: &platformv1.PutStateRequest_MustNotExist{MustNotExist: true},
	}).GetRevision()
	if rev1 == "" {
		t.Fatal("PutState returned an empty revision")
	}
	got := getState(t, ctx, client, "k1")
	if !got.GetFound() || got.GetRevision() != rev1 || !bytes.Equal(got.GetValueJson(), []byte(`{"n":1}`)) {
		t.Fatalf("GetState = found:%v revision:%q value:%s", got.GetFound(), got.GetRevision(), got.GetValueJson())
	}

	putState(t, ctx, client, &platformv1.PutStateRequest{Key: "k2", ValueJson: []byte(`{"n":2}`)})
	putState(t, ctx, client, &platformv1.PutStateRequest{Key: "k3", ValueJson: []byte(`{"n":3}`)})
	putState(t, ctx, client, &platformv1.PutStateRequest{Key: "k4", ValueJson: []byte(`{"n":4}`)})

	page1, err := client.ListState(ctx, &platformv1.ListStateRequest{
		Context: callContext(), Prefix: "k", PageSize: 2, IncludeValues: true,
	})
	wantOK(t, err, "ListState first page")
	if len(page1.GetEntries()) != 2 || page1.GetEntries()[0].GetKey() != "k1" || page1.GetEntries()[1].GetKey() != "k2" {
		t.Fatalf("first page = %v", keyNames(page1.GetEntries()))
	}
	if !bytes.Equal(page1.GetEntries()[0].GetValueJson(), []byte(`{"n":1}`)) {
		t.Fatalf("first page lost the value: %s", page1.GetEntries()[0].GetValueJson())
	}
	if page1.GetNextPageToken() == "" {
		t.Fatal("first page has no next page token")
	}
	page2, err := client.ListState(ctx, &platformv1.ListStateRequest{
		Context: callContext(), Prefix: "k", PageSize: 2, PageToken: page1.GetNextPageToken(),
	})
	wantOK(t, err, "ListState second page")
	if got := keyNames(page2.GetEntries()); !equalStrings(got, []string{"k3", "k4"}) {
		t.Fatalf("second page = %v", got)
	}
	if page2.GetNextPageToken() != "" {
		t.Fatalf("second page has a next page token %q", page2.GetNextPageToken())
	}
	if page2.GetEntries()[0].GetValueJson() != nil {
		t.Fatal("a page that did not ask for values returned one")
	}

	all, err := client.ListState(ctx, &platformv1.ListStateRequest{Context: callContext(), Prefix: "k"})
	wantOK(t, err, "ListState all")
	if len(all.GetEntries()) != 4 {
		t.Fatalf("default page size returned %d entries, want 4", len(all.GetEntries()))
	}
	empty, err := client.ListState(ctx, &platformv1.ListStateRequest{Context: callContext(), Prefix: "zzz"})
	wantOK(t, err, "ListState empty prefix")
	if len(empty.GetEntries()) != 0 || empty.GetNextPageToken() != "" {
		t.Fatalf("empty prefix returned %d entries", len(empty.GetEntries()))
	}
	missing := getState(t, ctx, client, "absent")
	if missing.GetFound() || missing.GetRevision() != "" || missing.GetValueJson() != nil {
		t.Fatalf("GetState(absent) = %+v", missing)
	}

	// A matching expected_revision is the new compare-and-swap base.
	client2 := ts.State()
	rev2 := putState(t, ctx, client2, &platformv1.PutStateRequest{
		Key: "k1", ValueJson: []byte(`{"n":10}`),
		Precondition: &platformv1.PutStateRequest_ExpectedRevision{ExpectedRevision: rev1},
	}).GetRevision()
	if rev2 == rev1 || rev2 == "" {
		t.Fatalf("PutState with expected_revision returned %q (old %q)", rev2, rev1)
	}
	_, err = client2.PutState(ctx, &platformv1.PutStateRequest{
		Key: "k1", ValueJson: []byte(`{"n":11}`),
		Precondition: &platformv1.PutStateRequest_ExpectedRevision{ExpectedRevision: rev1},
		Context:      callContext(),
	})
	wantCode(t, err, codes.Aborted, "stale expected_revision")

	_, err = client2.PutState(ctx, &platformv1.PutStateRequest{
		Key: "k1", ValueJson: []byte(`{"n":12}`),
		Precondition: &platformv1.PutStateRequest_MustNotExist{MustNotExist: true},
		Context:      callContext(),
	})
	wantCode(t, err, codes.Aborted, "must_not_exist on an existing key")

	_, err = client2.DeleteState(ctx, &platformv1.DeleteStateRequest{
		Context: callContext(), Key: "k1", ExpectedRevision: "not-the-revision",
	})
	wantCode(t, err, codes.Aborted, "delete with a stale revision")

	if _, err := client2.DeleteState(ctx, &platformv1.DeleteStateRequest{Context: callContext(), Key: "k1", ExpectedRevision: rev2}); err != nil {
		t.Fatalf("DeleteState with the current revision: %v", err)
	}
	if getState(t, ctx, client2, "k1").GetFound() {
		t.Fatal("GetState found a deleted key")
	}
	if _, err := client2.DeleteState(ctx, &platformv1.DeleteStateRequest{Context: callContext(), Key: "k1"}); err != nil {
		t.Fatalf("unconditional delete of an absent key: %v", err)
	}

	// An empty expected_revision is the "key must not exist" guard.
	putState(t, ctx, client2, &platformv1.PutStateRequest{
		Key: "k5", ValueJson: []byte(`{}`),
		Precondition: &platformv1.PutStateRequest_ExpectedRevision{ExpectedRevision: ""},
	})
	_, err = client2.PutState(ctx, &platformv1.PutStateRequest{
		Key: "k5", ValueJson: []byte(`{}`),
		Precondition: &platformv1.PutStateRequest_ExpectedRevision{ExpectedRevision: ""},
		Context:      callContext(),
	})
	wantCode(t, err, codes.Aborted, "empty expected_revision on an existing key")

	// The instance handle is not an identity: a forged one changes nothing.
	if response, err := client2.GetState(ctx, &platformv1.GetStateRequest{
		Context: &platformv1.HostCallContext{InstanceHandle: "another-instance"},
		Key:     "k5",
	}); err != nil || !response.GetFound() {
		t.Fatalf("GetState with a forged instance handle: %v (found %v)", err, response.GetFound())
	}
}

// TestStateValidation covers the key/value grammar and the paging token.
func TestStateValidation(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	client := ts.State()
	valid := &platformv1.PutStateRequest{Context: callContext(), Key: "ok", ValueJson: []byte(`{}`)}

	cases := []struct {
		name    string
		request *platformv1.PutStateRequest
	}{
		{"empty key", &platformv1.PutStateRequest{Context: callContext(), Key: "", ValueJson: []byte(`{}`)}},
		{"space in key", &platformv1.PutStateRequest{Context: callContext(), Key: "bad key", ValueJson: []byte(`{}`)}},
		{"long key", &platformv1.PutStateRequest{Context: callContext(), Key: strings.Repeat("a", 257), ValueJson: []byte(`{}`)}},
		{"invalid JSON", &platformv1.PutStateRequest{Context: callContext(), Key: "k", ValueJson: []byte("not json")}},
		{"empty value", &platformv1.PutStateRequest{Context: callContext(), Key: "k", ValueJson: nil}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.PutState(ctx, test.request)
			wantCode(t, err, codes.InvalidArgument, test.name)
		})
	}
	if _, err := client.PutState(ctx, valid); err != nil {
		t.Fatalf("valid PutState: %v", err)
	}
	if _, err := client.PutState(ctx, &platformv1.PutStateRequest{Context: callContext(), Key: "ok", ValueJson: []byte(`{}`)}); err != nil {
		t.Fatalf("unconditional overwrite: %v", err)
	}
	if _, err := client.DeleteState(ctx, &platformv1.DeleteStateRequest{Context: callContext(), Key: ""}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("empty delete key: %v", err)
	}
	if _, err := client.ListState(ctx, &platformv1.ListStateRequest{Context: callContext(), Prefix: "bad prefix"}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("invalid list prefix: %v", err)
	}
	if _, err := client.ListState(ctx, &platformv1.ListStateRequest{Context: callContext(), PageToken: "%%%"}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("invalid page token: %v", err)
	}
}

// TestStateLimits checks the per-value and per-instance size limits and that a
// rejected write leaves no trace.
func TestStateLimits(t *testing.T) {
	limits := hostsvc.DefaultLimits()
	limits.MaxValueBytes = 32
	limits.MaxTotalBytes = 64
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Limits = limits })
	ctx, cancel := rpcContext(t)
	defer cancel()
	client := ts.State()

	oversized := []byte(`"` + strings.Repeat("x", 40) + `"`)
	_, err := client.PutState(ctx, &platformv1.PutStateRequest{Context: callContext(), Key: "big", ValueJson: oversized})
	wantCode(t, err, codes.ResourceExhausted, "value over MaxValueBytes")

	value := []byte(`{"a":"0123456789ab"}`)
	if len(value) != 20 {
		t.Fatalf("test value is %d bytes, expected 20", len(value))
	}
	putState(t, ctx, client, &platformv1.PutStateRequest{Context: callContext(), Key: "k1", ValueJson: value})
	putState(t, ctx, client, &platformv1.PutStateRequest{Context: callContext(), Key: "k2", ValueJson: value})
	_, err = client.PutState(ctx, &platformv1.PutStateRequest{Context: callContext(), Key: "k3", ValueJson: value})
	wantCode(t, err, codes.ResourceExhausted, "total state over MaxTotalBytes")
	if getState(t, ctx, client, "k3").GetFound() {
		t.Fatal("a rejected write stored the value")
	}

	// Replacing a value with a smaller one frees room again.
	putState(t, ctx, client, &platformv1.PutStateRequest{Context: callContext(), Key: "k2", ValueJson: []byte(`{"a":1}`)})
	if _, err := client.PutState(ctx, &platformv1.PutStateRequest{Context: callContext(), Key: "k3", ValueJson: value}); err != nil {
		t.Fatalf("PutState after shrinking another value: %v", err)
	}

	// The built-in store must not persist a value beyond the state file.
	if _, err := client.PutState(ctx, &platformv1.PutStateRequest{Context: callContext(), Key: "k4", ValueJson: []byte("not json")}); statusCode(err) != codes.InvalidArgument {
		t.Fatalf("invalid JSON accepted: %v", err)
	}
}

// TestStatePersistsAcrossRestart checks the on-disk layout and that revisions
// survive an Agent restart (same state directory, new Server).
func TestStatePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	first := startServerAt(t, newBundle(), dir, nil)
	ctx, cancel := rpcContext(t)
	revision := putState(t, ctx, first.State(), &platformv1.PutStateRequest{
		Context: callContext(), Key: "persist", ValueJson: []byte(`{"v":1}`),
	}).GetRevision()
	first.stop()
	if first.stopErr != nil {
		t.Fatalf("first shutdown: %v", first.stopErr)
	}
	cancel()

	path := filepath.Join(dir, "state", "state.json")
	raw, err := os.ReadFile(path)
	wantOK(t, err, "read state file")
	if !bytes.Contains(raw, []byte(`"format":1`)) || !bytes.Contains(raw, []byte(`"persist"`)) {
		t.Fatalf("state file does not look like the documented format: %s", raw)
	}
	info, err := os.Stat(path)
	wantOK(t, err, "stat state file")
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Errorf("state file mode = %04o, want %04o", got, want)
	}

	ctx, cancel = rpcContext(t)
	defer cancel()
	second := startServerAt(t, newBundle(), dir, nil)
	got := getState(t, ctx, second.State(), "persist")
	if !got.GetFound() || got.GetRevision() != revision || !bytes.Equal(got.GetValueJson(), []byte(`{"v":1}`)) {
		t.Fatalf("state after restart = found:%v revision:%q value:%s", got.GetFound(), got.GetRevision(), got.GetValueJson())
	}
	next := putState(t, ctx, second.State(), &platformv1.PutStateRequest{
		Context: callContext(), Key: "persist", ValueJson: []byte(`{"v":2}`),
		Precondition: &platformv1.PutStateRequest_ExpectedRevision{ExpectedRevision: revision},
	})
	if next.GetRevision() == revision {
		t.Fatalf("revision did not advance after restart: %q", revision)
	}
}

// TestStateCASIsAtomic checks that concurrent compare-and-swap writes against
// one revision produce exactly one winner.
func TestStateCASIsAtomic(t *testing.T) {
	ts := startServer(t, nil)
	ctx, cancel := rpcContext(t)
	defer cancel()
	client := ts.State()
	revision := putState(t, ctx, client, &platformv1.PutStateRequest{
		Context: callContext(), Key: "cas", ValueJson: []byte(`{"n":0}`),
	}).GetRevision()

	const workers = 8
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := client.PutState(ctx, &platformv1.PutStateRequest{
				Context:      callContext(),
				Key:          "cas",
				ValueJson:    []byte(fmt.Sprintf(`{"n":%d}`, index+1)),
				Precondition: &platformv1.PutStateRequest_ExpectedRevision{ExpectedRevision: revision},
			})
			results <- err
		}(i)
	}
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		switch statusCode(err) {
		case codes.OK:
			winners++
		case codes.Aborted:
		default:
			t.Fatalf("unexpected CAS result: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("CAS winners = %d, want exactly 1", winners)
	}
}

// TestRequestSizeLimit checks the gRPC receive limit.
func TestRequestSizeLimit(t *testing.T) {
	limits := hostsvc.DefaultLimits()
	limits.MaxRequestBytes = 512
	limits.MaxValueBytes = 1024
	limits.MaxTotalBytes = 1 << 20
	ts := startServer(t, func(cfg *hostsvc.Config) { cfg.Limits = limits })
	ctx, cancel := rpcContext(t)
	defer cancel()
	value := []byte(`"` + strings.Repeat("x", 600) + `"`)
	_, err := ts.State().PutState(ctx, &platformv1.PutStateRequest{
		Context: callContext(), Key: "k", ValueJson: value,
	})
	wantCode(t, err, codes.ResourceExhausted, "request over MaxRequestBytes")
}

// TestStateStoreOverride checks that Config.State takes precedence over the
// built-in file store.
func TestStateStoreOverride(t *testing.T) {
	store := &memoryState{entries: map[string]hostsvc.StateEntry{}}
	ts := startServer(t, func(cfg *hostsvc.Config) {
		cfg.State = store
		cfg.StateDir = ""
	})
	ctx, cancel := rpcContext(t)
	defer cancel()
	putState(t, ctx, ts.State(), &platformv1.PutStateRequest{Context: callContext(), Key: "k", ValueJson: []byte(`{"x":1}`)})
	if _, ok := store.entries["k"]; !ok {
		t.Fatal("the custom StateStore did not receive the write")
	}
}

// memoryState is a minimal StateStore used to prove that Config.State is
// honoured (the built-in store is exercised by every other state test).
type memoryState struct {
	entries map[string]hostsvc.StateEntry
	next    int
}

// Get implements hostsvc.StateStore.
func (m *memoryState) Get(context.Context, string) (hostsvc.StateEntry, bool, error) {
	return hostsvc.StateEntry{}, false, errors.New("not used by this test")
}

// Put implements hostsvc.StateStore.
func (m *memoryState) Put(_ context.Context, key string, value []byte, _ hostsvc.StateGuard) (string, error) {
	m.next++
	revision := strings.Repeat("r", m.next)
	m.entries[key] = hostsvc.StateEntry{Key: key, Revision: revision, Value: append([]byte(nil), value...)}
	return revision, nil
}

// Delete implements hostsvc.StateStore.
func (m *memoryState) Delete(context.Context, string, string) error { return nil }

// List implements hostsvc.StateStore.
func (m *memoryState) List(context.Context, string, string, int, bool) (hostsvc.StatePage, error) {
	return hostsvc.StatePage{}, nil
}

// keyNames extracts the keys of a page.
func keyNames(entries []*platformv1.StateEntry) []string {
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.GetKey()
	}
	return names
}

// equalStrings compares two string slices.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestListStateByteBoundedPaging(t *testing.T) {
	ts := startServer(t, func(c *hostsvc.Config) { c.Limits.MaxTotalBytes = 16 << 20 })
	ctx := t.Context()
	client := ts.State()
	value := []byte(`"` + strings.Repeat("v", 1<<20-2) + `"`)
	for i := 0; i < 5; i++ {
		putState(t, ctx, client, &platformv1.PutStateRequest{Key: fmt.Sprintf("big/%d", i), ValueJson: value})
	}
	var keys []string
	pages, token := 0, ""
	for {
		page, err := client.ListState(ctx, &platformv1.ListStateRequest{
			Context: callContext(), Prefix: "big/", PageSize: 100, PageToken: token, IncludeValues: true,
		})
		wantOK(t, err, "ListState")
		if len(page.GetEntries()) == 0 {
			t.Fatal("a page made no progress")
		}
		pages++
		for _, e := range page.GetEntries() {
			keys = append(keys, e.GetKey())
		}
		if token = page.GetNextPageToken(); token == "" {
			break
		}
	}
	if pages < 2 || len(keys) != 5 || keys[0] != "big/0" || keys[4] != "big/4" {
		t.Fatalf("pages = %d, keys = %v", pages, keys)
	}
}
