// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// createProvider runs CreateProvider in its own transaction.
func (h *testHost) createProvider(in CreateProviderInput) *AIProvider {
	h.t.Helper()
	var p *AIProvider
	err := h.db.Update(context.Background(), func(tx *storage.Tx) error {
		var err error
		p, err = h.svc.CreateProvider(context.Background(), tx, in)
		return err
	})
	if err != nil {
		h.t.Fatalf("CreateProvider: %v", err)
	}
	return p
}

// updateProvider runs UpdateProvider in its own transaction and returns the error.
func (h *testHost) updateProvider(in UpdateProviderInput) (*AIProvider, error) {
	h.t.Helper()
	var p *AIProvider
	err := h.db.Update(context.Background(), func(tx *storage.Tx) error {
		var err error
		p, err = h.svc.UpdateProvider(context.Background(), tx, in)
		return err
	})
	return p, err
}

// deleteProvider runs DeleteProvider in its own transaction and returns the error.
func (h *testHost) deleteProvider(in DeleteProviderInput) error {
	h.t.Helper()
	return h.db.Update(context.Background(), func(tx *storage.Tx) error {
		return h.svc.DeleteProvider(context.Background(), tx, in)
	})
}

// auditCount counts the audit rows of one action.
func (h *testHost) auditCount(action string) int {
	h.t.Helper()
	var n int
	if err := h.db.Reader().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		h.t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// changedPayloads returns the resource.changed payloads of one subject in order.
func (h *testHost) changedPayloads(subject string) []map[string]any {
	h.t.Helper()
	rows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT payload FROM event_journal WHERE type = 'resource.changed' AND subject = ? ORDER BY seq`, subject)
	if err != nil {
		h.t.Fatalf("read events: %v", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			h.t.Fatalf("scan event: %v", err)
		}
		var p map[string]any
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			h.t.Fatalf("decode event payload: %v", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatalf("events: %v", err)
	}
	return out
}

// newProviderHost opens a host with a real secret store and the default
// outbound-controlled model client (no test HTTPClient), so the egress policy
// is the one the host runs with.
func newProviderHost(t *testing.T) (*testHost, *secrets.Store) {
	t.Helper()
	keyDir := t.TempDir()
	var store *secrets.Store
	h := newTestHost(t, func(o *Options) {
		keys, err := secrets.LoadKeyRing(keyDir)
		if err != nil {
			t.Fatalf("keys: %v", err)
		}
		st, err := secrets.New(secrets.Options{DB: o.DB, Keys: keys})
		if err != nil {
			t.Fatalf("secrets.New: %v", err)
		}
		store = st
		o.Secrets = st
	})
	return h, store
}

// providerInput is the usual create input of the tests.
func providerInput(name string) CreateProviderInput {
	return CreateProviderInput{
		Actor: ownerHuman, Name: name, BaseURL: "https://api.example.com/v1", Model: "gpt-test",
	}
}

// TestProviderLifecycle walks create, list, update and delete with their
// events and audit rows.
func TestProviderLifecycle(t *testing.T) {
	h, _ := newProviderHost(t)
	ctx := context.Background()

	bad := providerInput("bad url")
	bad.BaseURL = "ftp://api.example.com"
	var perr error
	err := h.db.Update(ctx, func(tx *storage.Tx) error {
		_, perr = h.svc.CreateProvider(ctx, tx, bad)
		return nil
	})
	if err != nil || !problem.HasCode(perr, problem.ValidationFailed) {
		t.Fatalf("bad base_url = %v, want VALIDATION_FAILED", perr)
	}

	a := h.createProvider(providerInput("Primary"))
	if a.ID == "" || a.Kind != "openai_compatible" || a.Revision == "" || a.HasAPIKey() || a.IsDefault {
		t.Fatalf("created = %+v", a)
	}
	// Names are unique.
	var dupErr error
	err = h.db.Update(ctx, func(tx *storage.Tx) error {
		_, dupErr = h.svc.CreateProvider(ctx, tx, providerInput("Primary"))
		return nil
	})
	if err != nil || !problem.HasCode(dupErr, problem.StateConflict) {
		t.Fatalf("duplicate name = %v, want STATE_CONFLICT", dupErr)
	}

	got, err := h.svc.GetProvider(ctx, a.ID)
	if err != nil || got.Name != "Primary" {
		t.Fatalf("GetProvider = %+v, %v", got, err)
	}
	if _, err := h.svc.GetProvider(ctx, "aip_missing"); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("missing provider = %v, want NOT_FOUND", err)
	}

	// Update: name and model, stale revision refused.
	newName, newModel := "Renamed", "gpt-next"
	if _, err := h.updateProvider(UpdateProviderInput{
		Actor: ownerHuman, ProviderID: a.ID, ExpectedRevision: 9999, Name: &newName,
	}); !problem.HasCode(err, problem.RevisionConflict) {
		t.Fatalf("stale revision = %v, want REVISION_CONFLICT", err)
	}
	rev, err := revisionInt(a.Revision)
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	updated, err := h.updateProvider(UpdateProviderInput{
		Actor: ownerHuman, ProviderID: a.ID, ExpectedRevision: rev, Name: &newName, Model: &newModel,
	})
	if err != nil || updated.Name != "Renamed" || updated.Model != "gpt-next" {
		t.Fatalf("UpdateProvider = %+v, %v", updated, err)
	}
	if updated.Revision == a.Revision {
		t.Fatal("update did not move the revision")
	}
	events := h.changedPayloads(providerSubject(a.ID))
	if len(events) != 2 {
		t.Fatalf("events = %v", events)
	}
	pointers, _ := events[1]["changed_pointers"].([]any)
	if len(pointers) != 2 || pointers[0] != "/name" || pointers[1] != "/model" {
		t.Fatalf("changed pointers = %v", pointers)
	}
	if h.auditCount("ai_provider.created") != 1 || h.auditCount("ai_provider.updated") != 1 {
		t.Fatalf("audit rows: created=%d updated=%d", h.auditCount("ai_provider.created"), h.auditCount("ai_provider.updated"))
	}

	// Delete with the current revision.
	cur, _ := h.svc.GetProvider(ctx, a.ID)
	rev, _ = revisionInt(cur.Revision)
	if err := h.deleteProvider(DeleteProviderInput{Actor: ownerHuman, ProviderID: a.ID, ExpectedRevision: rev}); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if _, err := h.svc.GetProvider(ctx, a.ID); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("deleted provider = %v, want NOT_FOUND", err)
	}
	if h.auditCount("ai_provider.deleted") != 1 {
		t.Fatal("delete wrote no audit row")
	}
}

// TestProviderDefaultSwitch: setting a new default flips the previous one in
// the same transaction, with its own event and revision.
func TestProviderDefaultSwitch(t *testing.T) {
	h, _ := newProviderHost(t)
	ctx := context.Background()

	in := providerInput("First")
	in.IsDefault = true
	a := h.createProvider(in)
	if !a.IsDefault {
		t.Fatal("first provider is not the default")
	}
	in = providerInput("Second")
	in.IsDefault = true
	b := h.createProvider(in)

	got, err := h.svc.GetProvider(ctx, a.ID)
	if err != nil || got.IsDefault {
		t.Fatalf("old default = %+v, %v", got, err)
	}
	if got.Revision == a.Revision {
		t.Fatal("flipping the default did not move the old provider's revision")
	}
	events := h.changedPayloads(providerSubject(a.ID))
	last := events[len(events)-1]
	pointers, _ := last["changed_pointers"].([]any)
	if len(pointers) != 1 || pointers[0] != "/is_default" {
		t.Fatalf("flip event pointers = %v", pointers)
	}

	// The default provider cannot be deleted while another one exists.
	rev, _ := revisionInt(b.Revision)
	if err := h.deleteProvider(DeleteProviderInput{Actor: ownerHuman, ProviderID: b.ID, ExpectedRevision: rev}); !problem.HasCode(err, problem.StateConflict) {
		t.Fatalf("deleting the default = %v, want STATE_CONFLICT", err)
	}
	// Clearing the flag makes it deletable.
	off := false
	rev, _ = revisionInt(b.Revision)
	cur, err := h.updateProvider(UpdateProviderInput{Actor: ownerHuman, ProviderID: b.ID, ExpectedRevision: rev, IsDefault: &off})
	if err != nil {
		t.Fatalf("unset default: %v", err)
	}
	rev, _ = revisionInt(cur.Revision)
	if err := h.deleteProvider(DeleteProviderInput{Actor: ownerHuman, ProviderID: b.ID, ExpectedRevision: rev}); err != nil {
		t.Fatalf("delete after unsetting default: %v", err)
	}
}

// TestProviderAPIKey: the key is a secret of the provider's own namespace,
// write-only, and its changes publish resource.changed.
func TestProviderAPIKey(t *testing.T) {
	h, _ := newProviderHost(t)
	ctx := context.Background()

	a := h.createProvider(providerInput("Keyed"))
	const key = "sk-test-0123456789abcdef"
	got, err := h.svc.SetProviderAPIKey(ctx, ownerHuman, a.ID, key)
	if err != nil || !got.HasAPIKey() {
		t.Fatalf("SetProviderAPIKey = %+v, %v", got, err)
	}
	if n := h.secretCount(providerSecretOwner(a.ID)); n != 1 {
		t.Fatalf("secret rows = %d, want 1", n)
	}
	var owner, purpose string
	if err := h.db.Reader().QueryRowContext(ctx,
		`SELECT owner, purpose FROM secrets LIMIT 1`).Scan(&owner, &purpose); err != nil {
		t.Fatalf("read secret row: %v", err)
	}
	if owner != providerSecretOwner(a.ID) || purpose != providerKeyPurpose {
		t.Fatalf("secret owner/purpose = %q/%q", owner, purpose)
	}
	events := h.changedPayloads(providerSubject(a.ID))
	last := events[len(events)-1]
	pointers, _ := last["changed_pointers"].([]any)
	if len(pointers) != 1 || pointers[0] != "/has_api_key" {
		t.Fatalf("key event pointers = %v", pointers)
	}
	if h.auditCount("ai_provider.api_key.set") != 1 {
		t.Fatal("set key wrote no audit row")
	}
	// The plaintext is nowhere but the secret row.
	var leaks int
	for _, tc := range [][2]string{
		{"audit_log", "details"}, {"event_journal", "payload"}, {"ai_providers", "base_url"},
	} {
		if err := h.db.Reader().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+tc[0]+` WHERE instr(COALESCE(`+tc[1]+`, ''), ?) > 0`, key).Scan(&leaks); err != nil {
			t.Fatalf("scan %s: %v", tc[0], err)
		}
		if leaks != 0 {
			t.Fatalf("the key leaked into %s.%s", tc[0], tc[1])
		}
	}

	cleared, err := h.svc.ClearProviderAPIKey(ctx, ownerHuman, a.ID)
	if err != nil || cleared.HasAPIKey() {
		t.Fatalf("ClearProviderAPIKey = %+v, %v", cleared, err)
	}
	if n := h.secretCount(providerSecretOwner(a.ID)); n != 0 {
		t.Fatalf("secret rows after clear = %d", n)
	}
	// Clearing twice changes nothing.
	if _, err := h.svc.ClearProviderAPIKey(ctx, ownerHuman, a.ID); err != nil {
		t.Fatalf("second clear: %v", err)
	}
}

// TestProviderBaseURLChangeClearsKey: the key is bound to the address it was
// stored for; moving the address drops it instead of carrying it along.
func TestProviderBaseURLChangeClearsKey(t *testing.T) {
	h, _ := newProviderHost(t)
	ctx := context.Background()

	a := h.createProvider(providerInput("Moved"))
	keyed, err := h.svc.SetProviderAPIKey(ctx, ownerHuman, a.ID, "sk-bound-to-the-address")
	if err != nil {
		t.Fatalf("SetProviderAPIKey: %v", err)
	}
	rev, _ := revisionInt(keyed.Revision)
	moved := "https://other.example.com/v1"
	cur, err := h.updateProvider(UpdateProviderInput{Actor: ownerHuman, ProviderID: a.ID, ExpectedRevision: rev, BaseURL: &moved})
	if err != nil {
		t.Fatalf("UpdateProvider: %v", err)
	}
	if cur.HasAPIKey() {
		t.Fatal("the key survived a base_url change")
	}
	if n := h.secretCount(providerSecretOwner(a.ID)); n != 0 {
		t.Fatalf("secret rows = %d, want 0", n)
	}
	if h.auditCount("ai_provider.api_key.clear") != 1 {
		t.Fatal("the clearing of the key wrote no audit row")
	}

	// Changing anything else keeps the key.
	keyed2, err := h.svc.SetProviderAPIKey(ctx, ownerHuman, a.ID, "sk-kept")
	if err != nil {
		t.Fatalf("SetProviderAPIKey: %v", err)
	}
	rev, _ = revisionInt(keyed2.Revision)
	model := "gpt-other"
	cur, err = h.updateProvider(UpdateProviderInput{Actor: ownerHuman, ProviderID: a.ID, ExpectedRevision: rev, Model: &model})
	if err != nil || !cur.HasAPIKey() {
		t.Fatalf("model change dropped the key: %+v, %v", cur, err)
	}
}

// TestResolveProvider: the resolver answers the named provider or the default,
// reveals the key through RevealOwned, and a planted foreign reference fails.
func TestResolveProvider(t *testing.T) {
	h, store := newProviderHost(t)
	ctx := context.Background()

	if _, found, err := h.svc.ResolveProvider(ctx, ""); err != nil || found {
		t.Fatalf("resolve without providers = %v, %v", found, err)
	}
	in := providerInput("Default one")
	in.IsDefault = true
	a := h.createProvider(in)
	if _, err := h.svc.SetProviderAPIKey(ctx, ownerHuman, a.ID, "sk-provider-key"); err != nil {
		t.Fatalf("SetProviderAPIKey: %v", err)
	}
	ep, found, err := h.svc.ResolveProvider(ctx, "")
	if err != nil || !found || ep.ID != a.ID || ep.BaseURL != a.BaseURL || ep.Model != a.Model {
		t.Fatalf("default resolve = %+v, %v, %v", ep, found, err)
	}
	if string(ep.Key) != "sk-provider-key" {
		t.Fatalf("key = %q", ep.Key)
	}
	clear(ep.Key)
	if _, found, err := h.svc.ResolveProvider(ctx, "aip_missing"); err != nil || found {
		t.Fatalf("missing resolve = %v, %v", found, err)
	}
	if ep, found, err := h.svc.ResolveProvider(ctx, a.ID); err != nil || !found || ep.ID != a.ID {
		t.Fatalf("named resolve = %+v, %v, %v", ep, found, err)
	}

	// A planted reference to another owner's secret never opens.
	foreign := h.putSecret(store, "users/usr_someone", "agent.native.api_key", "sk-foreign")
	h.exec(`UPDATE ai_providers SET api_key_ref = ? WHERE provider_id = ?`, string(foreign), a.ID)
	if _, _, err := h.svc.ResolveProvider(ctx, a.ID); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("foreign reference = %v, want UNAVAILABLE", err)
	}
}

// modelsServer is a fake provider endpoint that only serves GET /models.
func modelsServer(t *testing.T, status int) (*httptest.Server, *[]string) {
	t.Helper()
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		auth = append(auth, r.Header.Get("Authorization"))
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"gpt-test"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &auth
}

// TestTestProvider: the probe classifies the outcome without echoing anything
// but ok/latency/category.
func TestTestProvider(t *testing.T) {
	h, _ := newNativeHost(t)
	ctx := context.Background()

	okSrv, auth := modelsServer(t, http.StatusOK)
	a := h.createProvider(CreateProviderInput{Actor: ownerHuman, Name: "Ok", BaseURL: okSrv.URL, Model: "m"})
	if _, err := h.svc.SetProviderAPIKey(ctx, ownerHuman, a.ID, "sk-probe"); err != nil {
		t.Fatalf("SetProviderAPIKey: %v", err)
	}
	probe, err := h.svc.TestProvider(ctx, a.ID)
	if err != nil || !probe.OK || probe.Category != "" {
		t.Fatalf("probe = %+v, %v", probe, err)
	}
	if probe.LatencyMS < 0 {
		t.Fatalf("latency = %d", probe.LatencyMS)
	}
	if len(*auth) != 1 || (*auth)[0] != "Bearer sk-probe" {
		t.Fatalf("auth headers = %v", *auth)
	}

	for i, c := range []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, "auth"},
		{http.StatusForbidden, "auth"},
		{http.StatusNotFound, "4xx"},
		{http.StatusBadGateway, "5xx"},
	} {
		srv, _ := modelsServer(t, c.status)
		p := h.createProvider(CreateProviderInput{
			Actor: ownerHuman, Name: "Status " + strconv.Itoa(i), BaseURL: srv.URL, Model: "m",
		})
		probe, err := h.svc.TestProvider(ctx, p.ID)
		if err != nil || probe.OK || probe.Category != c.want {
			t.Fatalf("status %d probe = %+v, %v, want %s", c.status, probe, err, c.want)
		}
	}

	// A closed port is a network failure.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := "http://" + l.Addr().String()
	_ = l.Close()
	p := h.createProvider(CreateProviderInput{Actor: ownerHuman, Name: "Dead", BaseURL: dead, Model: "m"})
	if probe, err := h.svc.TestProvider(ctx, p.ID); err != nil || probe.OK || probe.Category != "network" {
		t.Fatalf("dead endpoint probe = %+v, %v", probe, err)
	}
	if _, err := h.svc.TestProvider(ctx, "aip_missing"); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("missing provider probe = %v, want NOT_FOUND", err)
	}
}

// TestTestProviderEgressDenied: with the host's own client, a loopback address
// is refused before the request leaves, and the answer is the fixed category.
func TestTestProviderEgressDenied(t *testing.T) {
	h, _ := newProviderHost(t)
	ctx := context.Background()
	srv, _ := modelsServer(t, http.StatusOK)
	a := h.createProvider(CreateProviderInput{Actor: ownerHuman, Name: "Loopback", BaseURL: srv.URL, Model: "m"})
	probe, err := h.svc.TestProvider(ctx, a.ID)
	if err != nil || probe.OK || probe.Category != "denied" {
		t.Fatalf("loopback probe = %+v, %v, want denied", probe, err)
	}
}

// TestCores: the native core is available; the external CLIs are announced with
// a reason until P6 wires them.
func TestCores(t *testing.T) {
	h, _ := newNativeHost(t)
	cores := h.svc.Cores()
	if len(cores) != 6 {
		t.Fatalf("cores = %+v", cores)
	}
	if cores[0].Core != CoreNative || !cores[0].Available || cores[0].Reason != "" {
		t.Fatalf("native core = %+v", cores[0])
	}
	for _, c := range cores[1:] {
		if c.Available || c.Reason == "" {
			t.Fatalf("external core = %+v", c)
		}
	}
}

// revisionInt parses a stored revision.
func revisionInt(raw string) (int64, error) {
	return strconv.ParseInt(raw, 10, 64)
}

// TestSessionProviderResolution: a session without its own endpoint takes the
// endpoint, the default model and the key from its provider; the session's own
// endpoint always wins and never borrows the provider's key.
func TestSessionProviderResolution(t *testing.T) {
	h, _ := newNativeHost(t)
	ctx := context.Background()

	provSrv := newModelServer(t, modelReply{content: "ok from provider"})
	p := h.createProvider(CreateProviderInput{
		Actor: ownerHuman, Name: "Global", BaseURL: provSrv.srv.URL, Model: "gpt-provider", IsDefault: true,
	})
	if _, err := h.svc.SetProviderAPIKey(ctx, ownerHuman, p.ID, "sk-provider-key"); err != nil {
		t.Fatalf("SetProviderAPIKey: %v", err)
	}

	// The named provider supplies endpoint, model and key.
	named := h.create(ownerHuman, CreateRequest{
		Config: json.RawMessage(fmt.Sprintf(`{"provider_id":%q}`, p.ID)),
	})
	h.send(ownerHuman, named.ID, "hello")
	h.waitTurn(named.ID)
	if got := provSrv.request(0)["model"]; got != "gpt-provider" {
		t.Fatalf("model = %v", got)
	}
	if auth := provSrv.authorizations(); len(auth) != 1 || auth[0] != "Bearer sk-provider-key" {
		t.Fatalf("authorization = %v", auth)
	}

	// Without provider_id the default provider applies; config.model overrides.
	def := h.create(ownerHuman, CreateRequest{Config: json.RawMessage(`{"model":"gpt-override"}`)})
	h.send(ownerHuman, def.ID, "hello")
	h.waitTurn(def.ID)
	if got := provSrv.request(1)["model"]; got != "gpt-override" {
		t.Fatalf("override model = %v", got)
	}

	// A session with its own endpoint keeps it and uses its own key; the
	// provider is not contacted.
	ownSrv := newModelServer(t, modelReply{content: "ok from own"})
	own := h.create(ownerHuman, CreateRequest{Config: nativeConfigJSON(ownSrv.srv.URL, "gpt-own")})
	h.setAPIKey(ownerHuman, own.ID, "sk-session-own")
	h.send(ownerHuman, own.ID, "hello")
	h.waitTurn(own.ID)
	if auth := ownSrv.authorizations(); len(auth) != 1 || auth[0] != "Bearer sk-session-own" {
		t.Fatalf("own authorization = %v", auth)
	}
	if provSrv.callCount() != 2 {
		t.Fatalf("the provider was contacted for a self-configured session (%d calls)", provSrv.callCount())
	}
}

// TestSessionProviderConfigValidation: provider_id and base_url exclude each
// other, an unknown provider fails before the message is stored, and deleting
// a provider surfaces as UNAVAILABLE on the next send.
func TestSessionProviderConfigValidation(t *testing.T) {
	h, _ := newNativeHost(t)
	ctx := context.Background()

	p := h.createProvider(providerInput("Configured"))
	both := json.RawMessage(fmt.Sprintf(`{"provider_id":%q,"base_url":"https://x.example.com"}`, p.ID))
	if _, err := h.svc.Create(ctx, ownerHuman, CreateRequest{Config: both}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("provider_id with base_url = %v, want VALIDATION_FAILED", err)
	}
	malformed := json.RawMessage(`{"provider_id":"nope"}`)
	if _, err := h.svc.Create(ctx, ownerHuman, CreateRequest{Config: malformed}); !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("malformed provider_id = %v, want VALIDATION_FAILED", err)
	}

	missing := h.create(ownerHuman, CreateRequest{
		Config: json.RawMessage(`{"provider_id":"aip_00000000000000000000000000"}`),
	})
	if _, err := h.svc.Send(ctx, ownerHuman, missing.ID, SendRequest{Content: "hi"}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("missing provider send = %v, want UNAVAILABLE", err)
	}

	// A provider deleted after the session was created: the next send answers
	// UNAVAILABLE instead of failing the turn.
	tmp := h.createProvider(CreateProviderInput{Actor: ownerHuman, Name: "Temp", BaseURL: "https://temp.example.com", Model: "m"})
	rec := h.create(ownerHuman, CreateRequest{Config: json.RawMessage(fmt.Sprintf(`{"provider_id":%q}`, tmp.ID))})
	rev, err := revisionInt(tmp.Revision)
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	if err := h.deleteProvider(DeleteProviderInput{Actor: ownerHuman, ProviderID: tmp.ID, ExpectedRevision: rev}); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if _, err := h.svc.Send(ctx, ownerHuman, rec.ID, SendRequest{Content: "hi"}); !problem.HasCode(err, problem.Unavailable) {
		t.Fatalf("send after provider delete = %v, want UNAVAILABLE", err)
	}
}
