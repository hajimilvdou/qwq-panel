// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 真实适配器边界回归 ========================

func TestCloudflareLostCreateResponseUsesAtomicOwnershipMarker(t *testing.T) {
	f := newWireFixture(t, dns.Cloudflare)
	f.api.records = []map[string]any{{"id": strings.Repeat("f", 32), "type": "TXT", "name": "_acme-challenge.proxy.example.com", "content": "existing", "ttl": 300, "proxied": false, "comment": "user comment"}}
	request := f.challenge(t)
	f.api.lose = true
	result, err := f.manager.PresentChallenge(context.Background(), request)
	if err != nil || result.State != dns.Applied {
		t.Fatalf("lost response did not reconcile: %v %v", result, err)
	}
	if _, err := f.manager.PresentChallenge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if f.api.writes != 1 {
		t.Fatalf("create was replayed: %d", f.api.writes)
	}
	f.api.lose = false
	if err := f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, request.CertificateID, request.AttemptID); err != nil {
		t.Fatal(err)
	}
	if len(f.api.records) != 1 || f.api.records[0]["content"] != "existing" || f.api.deletes != 1 {
		t.Fatal("cleanup removed unrelated TXT or failed to remove owned record")
	}
}

func TestAliyunLostCreateIDRemainsUnknownAndNeverDeletesMatchingTXT(t *testing.T) {
	f := newWireFixture(t, dns.Aliyun)
	f.api.records = []map[string]any{{"RecordId": "1", "RR": "_acme-challenge.proxy", "Type": "TXT", "Value": "existing", "TTL": 600, "Line": "default", "Status": "ENABLE"}}
	request := f.challenge(t)
	f.api.lose = true
	for range 2 {
		result, err := f.manager.PresentChallenge(context.Background(), request)
		if result.State != dns.Unknown || fault.Code(err) != "OUTCOME_UNKNOWN" {
			t.Fatalf("lost ID was incorrectly owned: %v %v", result, err)
		}
	}
	if f.api.writes != 1 {
		t.Fatal("Aliyun unknown create was replayed")
	}
	if err := f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, request.CertificateID, request.AttemptID); err == nil {
		t.Fatal("unknown Aliyun record was deleted")
	}
	if len(f.api.records) != 2 || f.api.deletes != 0 {
		t.Fatal("matching foreign TXT was not retained")
	}
}

func TestAliyunConfirmedCreateIDIsPersistedAndOwnedCleanupUsesSignedPOST(t *testing.T) {
	f := newWireFixture(t, dns.Aliyun)
	request := f.challenge(t)
	result, err := f.manager.PresentChallenge(context.Background(), request)
	if err != nil || result.State != dns.Applied || result.RecordID == "" {
		t.Fatalf("create = %v %v", result, err)
	}
	for range 2 {
		if err := f.manager.CleanupChallenge(context.Background(), f.caller, f.scope, request.CertificateID, request.AttemptID); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.api.records) != 0 || f.api.deletes != 1 || f.api.writes != 2 {
		t.Fatal("Aliyun cleanup was missing or replayed")
	}
}

func TestProvidersKeepExplicitRateLimitRefusalAndRetryAfter(t *testing.T) {
	for _, kind := range []dns.ProviderKind{dns.Cloudflare, dns.Aliyun} {
		t.Run(string(kind), func(t *testing.T) {
			f := newWireFixture(t, kind)
			request := f.challenge(t)
			f.api.status = 429
			result, err := f.manager.PresentChallenge(context.Background(), request)
			if result.State != dns.Rejected || fault.Code(err) != "RATE_LIMITED" || fault.Retry(err) != f.now.Add(2*time.Minute) {
				t.Fatalf("rate refusal = %v %v", result, err)
			}
			if f.api.writes != 1 || len(f.api.records) != 0 {
				t.Fatal("rate limited write was retried")
			}
		})
	}
}

func TestProviderMetadataChangeBlocksMutationBeforeNetworkWrite(t *testing.T) {
	for _, kind := range []dns.ProviderKind{dns.Cloudflare, dns.Aliyun} {
		t.Run(string(kind), func(t *testing.T) {
			f := newWireFixture(t, kind)
			if kind == dns.Cloudflare {
				f.api.records = []map[string]any{{"id": strings.Repeat("b", 32), "type": "A", "name": "proxy.example.com", "content": "192.0.2.1", "ttl": 300, "proxied": false, "comment": "initial", "tags": []string{}}}
			} else {
				f.api.records = []map[string]any{{"RecordId": "1", "RR": "proxy", "Type": "A", "Value": "192.0.2.1", "TTL": 600, "Line": "telecom", "Status": "ENABLE"}}
			}
			records, err := f.provider.List(context.Background(), f.scope)
			if err != nil {
				t.Fatal(err)
			}
			before := records[0]
			if kind == dns.Cloudflare {
				f.api.records[0]["tags"] = []string{"changed"}
			} else {
				f.api.records[0]["Status"] = "DISABLE"
			}
			after := before
			after.Value, after.ProviderRevision = "192.0.2.2", ""
			if _, err := f.provider.Update(context.Background(), f.scope, before, after); fault.Code(err) != "REVISION_CONFLICT" {
				t.Fatalf("metadata race = %v", err)
			}
			if f.api.writes != 0 {
				t.Fatal("stale record was mutated")
			}
		})
	}
}

func TestAliyunUpdatePreservesOriginalLineAndRejectsForeignRecordID(t *testing.T) {
	f := newWireFixture(t, dns.Aliyun)
	f.api.records = []map[string]any{{"RecordId": "1", "RR": "proxy", "Type": "A", "Value": "192.0.2.1", "TTL": 600, "Line": "telecom", "Status": "ENABLE"}}
	records, err := f.provider.List(context.Background(), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	after := records[0]
	after.Value, after.ProviderRevision = "192.0.2.2", ""
	if _, err := f.provider.Update(context.Background(), f.scope, records[0], after); err != nil {
		t.Fatal(err)
	}
	if f.api.records[0]["Line"] != "telecom" {
		t.Fatal("update reset the original DNS line")
	}
	records, err = f.provider.List(context.Background(), f.scope)
	if err != nil {
		t.Fatal(err)
	}
	f.api.foreign = true
	if err := f.provider.Delete(context.Background(), f.scope, records[0]); fault.Code(err) != "ZONE_DENIED" {
		t.Fatalf("foreign ID = %v", err)
	}
	if f.api.deletes != 0 {
		t.Fatal("foreign zone record was deleted")
	}
}

func TestProviderScopeRevocationAndPrivateDataNeverSerialize(t *testing.T) {
	for _, kind := range []dns.ProviderKind{dns.Cloudflare, dns.Aliyun} {
		t.Run(string(kind), func(t *testing.T) {
			f := newWireFixture(t, kind)
			f.source.revoked = true
			if _, err := f.provider.List(context.Background(), f.scope); fault.Code(err) != "CREDENTIAL_REVOKED" {
				t.Fatalf("revocation = %v", err)
			}
			if f.api.requests != 0 {
				t.Fatal("revoked credentials reached the network")
			}
			data, err := json.Marshal(f.source.value)
			if err != nil || string(data) != `{"redacted":true}` {
				t.Fatal("credentials serialized private fields")
			}
			for _, text := range []string{fmt.Sprintf("%v", f.source.value), fmt.Sprintf("%#v", f.source.value)} {
				if strings.Contains(text, f.source.value.AccessKeyID) && f.source.value.AccessKeyID != "" {
					t.Fatal("credentials logged private fields")
				}
			}
			changed := f.scope
			changed.ZoneName = "other.example.com"
			if _, err := f.provider.List(context.Background(), changed); fault.Code(err) != "SCOPE_INVALID" {
				t.Fatal("adapter accepted changed scope")
			}
		})
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestProviderAmbiguousServerResponsesNeverBecomeSafeWriteRetries(t *testing.T) {
	for _, kind := range []dns.ProviderKind{dns.Cloudflare, dns.Aliyun} {
		t.Run(string(kind), func(t *testing.T) {
			f := newWireFixture(t, kind)
			calls := 0
			transport := responseTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				body := `{"RequestId":"request-1","Code":"UnrecognizedServerFailure"}`
				status := 500
				if kind == dns.Cloudflare {
					body = `{"success":true,"result":{"id":"00000000000000000000000000000001"},"errors":[{"code":81057}]}`
					status = 200
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			registry, err := New(Options{Source: f.source, Client: &http.Client{Transport: transport}})
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := registry.For(context.Background(), f.scope)
			if err != nil {
				t.Fatal(err)
			}
			_, err = adapter.Create(context.Background(), f.scope, dns.Record{Type: dns.TXT, Name: "_acme-challenge.proxy.example.com", Value: strings.Repeat("a", 43), TTL: 600, ManagedBy: strings.Repeat("a", 64)})
			if fault.Code(err) != "OUTCOME_UNKNOWN" || calls != 1 {
				t.Fatalf("ambiguous write response = %v, calls %d", err, calls)
			}
		})
	}
}

func TestProviderRedirectAndOversizedReadFailClosed(t *testing.T) {
	f := newWireFixture(t, dns.Cloudflare)
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprint(oversized), func(t *testing.T) {
			calls := 0
			transport := responseTransport(func(*http.Request) (*http.Response, error) {
				calls++
				response := &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"http://127.0.0.1/private"}}, Body: io.NopCloser(strings.NewReader(""))}
				if oversized {
					response.StatusCode = 200
					response.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBytes+1)))
				}
				return response, nil
			})
			registry, err := New(Options{Source: f.source, Client: &http.Client{Transport: transport}})
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := registry.For(context.Background(), f.scope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = adapter.List(context.Background(), f.scope); err == nil || calls != 1 {
				t.Fatalf("unbounded read/redirect = %v, calls %d", err, calls)
			}
		})
	}
}
