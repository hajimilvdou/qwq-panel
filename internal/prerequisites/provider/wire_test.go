// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
)

// ======================== 显式 API 协议 fixture ========================

type wireClock struct{ now time.Time }

func (c wireClock) Now() time.Time                         { return c.now }
func (c wireClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type wireCredentials struct {
	mu      sync.Mutex
	scope   dns.Scope
	value   Credentials
	reads   int
	revoked bool
}

func (s *wireCredentials) Read(ctx context.Context, scope dns.Scope) (Credentials, error) {
	if err := ctx.Err(); err != nil {
		return Credentials{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.revoked || (scope != s.scope && scope.ProviderID != "") {
		return Credentials{}, fault.New("CREDENTIAL_REVOKED", "fixture 授权失效")
	}
	return Credentials{Kind: s.value.Kind, Token: append([]byte(nil), s.value.Token...), AccessKeyID: s.value.AccessKeyID, AccessKeySecret: append([]byte(nil), s.value.AccessKeySecret...)}, nil
}

type wireAuthorization struct{ source *wireCredentials }

func (a wireAuthorization) Authorize(ctx context.Context, caller dns.Caller, scope dns.Scope, _ dns.Access) error {
	if caller.OwnerID != "owner-1" || caller.OperationID == "" || scope != a.source.scope {
		return fault.New("PERMISSION_DENIED", "fixture 范围拒绝")
	}
	return ctx.Err()
}

// ======================== 协议 fixture 的原请求授权接缝 ========================
// HTTP 协议回归沿用固定 fixture 范围；真实 CA 日志及逐 TXT 许可由 hostauth 回归覆盖。
func (a wireAuthorization) ChallengeContext(ctx context.Context, intent dns.ChallengeIntent) (context.Context, error) {
	if err := a.Authorize(ctx, intent.Caller, intent.Scope, dns.Challenge); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (a wireAuthorization) AuthorizeChallengeSource(ctx context.Context, caller dns.Caller, scope dns.Scope, _, _ string) error {
	return a.Authorize(ctx, caller, scope, dns.Cleanup)
}

func (a wireAuthorization) AuthorizeChallengeCleanup(ctx context.Context, owned dns.OwnedChallenge) error {
	return a.Authorize(ctx, owned.Caller(), owned.Scope(), dns.Cleanup)
}

var _ dns.ChallengeAuthorizations = wireAuthorization{}

type wireAPI struct {
	mu       sync.Mutex
	t        *testing.T
	source   *wireCredentials
	records  []map[string]any
	requests int
	writes   int
	deletes  int
	sequence int
	lose     bool
	status   int
	foreign  bool
	nonces   map[string]bool
}

func (a *wireAPI) response(status int, value any) *http.Response {
	data, err := json.Marshal(value)
	if err != nil {
		a.t.Fatal(err)
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data))}
}

func (a *wireAPI) cfResult(value any, list bool) *http.Response {
	result := map[string]any{"success": true, "result": value, "errors": []any{}}
	if list {
		result["result_info"] = map[string]any{"page": 1, "per_page": 100, "count": len(a.records), "total_count": len(a.records), "total_pages": 1}
	}
	return a.response(http.StatusOK, result)
}

func (a *wireAPI) RoundTrip(request *http.Request) (*http.Response, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests++
	if request.URL.Scheme != "https" || request.URL.User != nil {
		a.t.Fatal("endpoint must remain fixed HTTPS")
	}
	if a.source.scope.Kind == dns.Cloudflare {
		return a.cloudflare(request)
	}
	return a.aliyun(request)
}

func (a *wireAPI) cloudflare(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "api.cloudflare.com" || request.Header.Get("Authorization") != "Bearer "+string(a.source.value.Token) {
		a.t.Fatal("Cloudflare fixed host/auth mismatch")
	}
	collection := "/client/v4/zones/" + a.source.scope.ZoneID + "/dns_records"
	if !strings.HasPrefix(request.URL.Path, collection) {
		a.t.Fatal("Cloudflare zone path escaped")
	}
	id := strings.TrimPrefix(request.URL.Path, collection+"/")
	if request.Method == http.MethodGet {
		if request.URL.Path == collection {
			return a.cfResult(a.records, true), nil
		}
		for _, record := range a.records {
			if record["id"] == id {
				return a.cfResult(record, false), nil
			}
		}
		return a.response(http.StatusNotFound, map[string]any{"success": false, "result": nil}), nil
	}
	a.writes++
	if a.status != 0 {
		response := a.response(a.status, map[string]any{"success": false, "result": nil, "errors": []any{map[string]int{"code": 10000}}})
		response.Header.Set("Retry-After", "120")
		return response, nil
	}
	switch request.Method {
	case http.MethodPost:
		var body map[string]any
		if json.NewDecoder(request.Body).Decode(&body) != nil {
			a.t.Fatal("invalid Cloudflare JSON")
		}
		a.sequence++
		body["id"] = fmt.Sprintf("%032x", a.sequence)
		body["tags"] = []any{}
		a.records = append(a.records, body)
		if a.lose {
			return nil, io.EOF
		}
		return a.cfResult(body, false), nil
	case http.MethodPatch:
		var body map[string]any
		if json.NewDecoder(request.Body).Decode(&body) != nil {
			a.t.Fatal("invalid Cloudflare patch")
		}
		for _, record := range a.records {
			if record["id"] == id {
				for key, value := range body {
					record[key] = value
				}
				return a.cfResult(record, false), nil
			}
		}
	case http.MethodDelete:
		for index, record := range a.records {
			if record["id"] == id {
				a.records = append(a.records[:index], a.records[index+1:]...)
				a.deletes++
				return a.cfResult(map[string]any{"id": id}, false), nil
			}
		}
	}
	a.t.Fatal("unexpected Cloudflare method")
	return nil, io.EOF
}

func (a *wireAPI) aliyun(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || request.URL.Host != "alidns.aliyuncs.com" || request.URL.RawQuery != "" {
		a.t.Fatal("Aliyun endpoint must use fixed POST body")
	}
	data, err := io.ReadAll(request.Body)
	if err != nil {
		a.t.Fatal(err)
	}
	parameters, err := url.ParseQuery(string(data))
	if err != nil {
		a.t.Fatal(err)
	}
	signature := parameters.Get("Signature")
	parameters.Del("Signature")
	if parameters.Get("AccessKeyId") != a.source.value.AccessKeyID || parameters.Get("SignatureMethod") != "HMAC-SHA1" || parameters.Get("Version") != "2015-01-09" || signature != aliyunSignature(http.MethodPost, parameters, a.source.value.AccessKeySecret) {
		a.t.Fatal("Aliyun RPC signature mismatch")
	}
	nonce := parameters.Get("SignatureNonce")
	if len(nonce) != 48 || a.nonces[nonce] {
		a.t.Fatal("Aliyun nonce was missing or reused")
	}
	a.nonces[nonce] = true
	requestID := fmt.Sprintf("request-%d", a.requests)
	switch parameters.Get("Action") {
	case "DescribeDomainRecords":
		if parameters.Get("DomainName") != a.source.scope.ZoneName {
			a.t.Fatal("Aliyun escaped authorized domain")
		}
		return a.response(200, map[string]any{"RequestId": requestID, "PageNumber": 1, "PageSize": 100, "TotalCount": len(a.records), "DomainRecords": map[string]any{"Record": a.records}}), nil
	case "DescribeDomainRecordInfo":
		for _, record := range a.records {
			if record["RecordId"] == parameters.Get("RecordId") {
				domain := a.source.scope.ZoneName
				if a.foreign {
					domain = "other.example.net"
				}
				resp := make(map[string]any, len(record)+2)
				for k, v := range record {
					resp[k] = v
				}
				resp["RequestId"] = requestID
				resp["DomainName"] = domain
				return a.response(200, resp), nil
			}
		}
		return a.response(400, map[string]any{"RequestId": requestID, "Code": "InvalidRecordId.NotFound"}), nil
	case "AddDomainRecord", "UpdateDomainRecord", "DeleteDomainRecord":
		a.writes++
		if a.status != 0 {
			response := a.response(a.status, map[string]any{"Code": "Throttling.User", "RequestId": requestID})
			response.Header.Set("Retry-After", "120")
			return response, nil
		}
		id := parameters.Get("RecordId")
		if parameters.Get("Action") == "AddDomainRecord" {
			a.sequence++
			id = strconv.Itoa(a.sequence)
			ttl, _ := strconv.Atoi(parameters.Get("TTL"))
			a.records = append(a.records, map[string]any{"RecordId": id, "RR": parameters.Get("RR"), "Type": parameters.Get("Type"), "Value": parameters.Get("Value"), "TTL": ttl, "Line": parameters.Get("Line"), "Status": "ENABLE", "Locked": false})
			if a.lose {
				return nil, io.EOF
			}
		} else {
			for index, record := range a.records {
				if record["RecordId"] == id {
					if parameters.Get("Action") == "DeleteDomainRecord" {
						a.records = append(a.records[:index], a.records[index+1:]...)
						a.deletes++
					} else {
						ttl, _ := strconv.Atoi(parameters.Get("TTL"))
						record["RR"], record["Type"], record["Value"], record["TTL"], record["Line"] = parameters.Get("RR"), parameters.Get("Type"), parameters.Get("Value"), ttl, parameters.Get("Line")
					}
					break
				}
			}
		}
		return a.response(200, map[string]any{"RequestId": requestID, "RecordId": id}), nil
	}
	a.t.Fatal("unexpected Aliyun action")
	return nil, io.EOF
}

type wireFixture struct {
	source   *wireCredentials
	api      *wireAPI
	provider dns.Provider
	manager  *dns.Manager
	scope    dns.Scope
	caller   dns.Caller
	now      time.Time
}

func newWireFixture(t *testing.T, kind dns.ProviderKind) *wireFixture {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	credentials := Credentials{Kind: kind}
	zoneID := strings.Repeat("a", 32)
	if kind == dns.Cloudflare {
		credentials.Token = []byte(base64.RawURLEncoding.EncodeToString(secret))
	} else {
		credentials.AccessKeyID = "fixture-access-id"
		credentials.AccessKeySecret = []byte(base64.RawURLEncoding.EncodeToString(secret))
		zoneID = "42"
	}
	clear(secret)
	t.Cleanup(credentials.Clear)
	scope := dns.Scope{ProviderID: "provider-1", Kind: kind, ZoneID: zoneID, ZoneName: "example.com", Revision: "scope-1"}
	source := &wireCredentials{scope: scope, value: credentials}
	api := &wireAPI{t: t, source: source, sequence: 100, nonces: map[string]bool{}}
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	registry, err := New(Options{Source: source, Client: &http.Client{Transport: api}, Clock: wireClock{now}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := registry.For(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := dns.New(dns.Options{Repository: &testsupport.MemoryStore{}, Providers: registry, Authorizer: wireAuthorization{source}, Clock: wireClock{now}})
	if err != nil {
		t.Fatal(err)
	}
	return &wireFixture{source: source, api: api, provider: provider, manager: manager, scope: scope, caller: dns.Caller{OwnerID: "owner-1", OperationID: "operation-1"}, now: now}
}

func (f *wireFixture) challenge(t *testing.T) dns.ChallengeRequest {
	t.Helper()
	snapshot, err := f.manager.List(context.Background(), f.caller, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	return dns.ChallengeRequest{Caller: f.caller, Scope: f.scope, CertificateID: "certificate-1", AttemptID: "challenge-1", SAN: "proxy.example.com", Value: strings.Repeat("a", 43), ExpectedRevision: snapshot.Revision}
}
