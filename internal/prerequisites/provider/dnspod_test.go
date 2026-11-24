// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

func TestDNSPodTC3SignatureAndCRUD(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	secretID := "AKIDtestSecretId12345"
	secretKey := []byte("TestSecretKeyValue9876543210")

	scope := dns.Scope{
		ProviderID: "prov-dnspod",
		Kind:       dns.DNSPod,
		ZoneID:     "100001",
		ZoneName:   "example.com",
		Revision:   "scope-rev-1",
	}

	type storedRec struct {
		id    uint64
		sub   string
		rtype string
		val   string
		ttl   uint32
		line  string
		mx    *uint16
	}
	records := map[uint64]*storedRec{}
	var nextID uint64 = 2000

	transport := responseTransport(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Host != dnspodHost {
			t.Fatalf("unexpected DNSPod request %s %s", req.Method, req.URL)
		}
		action := req.Header.Get("X-TC-Action")
		rawBody, _ := io.ReadAll(req.Body)
		wantAuth, wantTS := dnspodAuthorization(secretID, secretKey, action, rawBody, now)
		if req.Header.Get("Authorization") != wantAuth || req.Header.Get("X-TC-Timestamp") != wantTS {
			t.Fatalf("TC3 signature mismatch for %s: got=%q want=%q", action, req.Header.Get("Authorization"), wantAuth)
		}
		var body map[string]any
		_ = json.Unmarshal(rawBody, &body)

		respond := func(respObj map[string]any) (*http.Response, error) {
			respObj["RequestId"] = "req-dnspod-1"
			b, _ := json.Marshal(map[string]any{"Response": respObj})
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(b)))}, nil
		}

		switch action {
		case "DescribeDomainList":
			return respond(map[string]any{
				"DomainCountInfo": map[string]any{"AllTotal": 1},
				"DomainList":      []map[string]any{{"DomainId": 100001, "Name": "example.com"}},
			})
		case "DescribeRecordList":
			if len(records) == 0 {
				return respond(map[string]any{
					"Error": map[string]any{"Code": "ResourceNotFound.NoDataOfRecord", "Message": "no records"},
				})
			}
			list := make([]map[string]any, 0, len(records))
			for _, r := range records {
				item := map[string]any{
					"RecordId": r.id, "Name": r.sub, "Type": r.rtype,
					"Value": r.val, "TTL": r.ttl, "Line": r.line, "Status": "ENABLE",
				}
				if r.mx != nil {
					item["MX"] = *r.mx
				}
				list = append(list, item)
			}
			return respond(map[string]any{
				"RecordCountInfo": map[string]any{"TotalCount": len(list), "ListCount": len(list)},
				"RecordList":      list,
			})
		case "DescribeRecord":
			id := uint64(body["RecordId"].(float64))
			r, ok := records[id]
			if !ok {
				return respond(map[string]any{"Error": map[string]any{"Code": "ResourceNotFound.RecordIdInvalid", "Message": "missing"}})
			}
			info := map[string]any{
				"Id": r.id, "SubDomain": r.sub, "RecordType": r.rtype,
				"Value": r.val, "TTL": r.ttl, "RecordLine": r.line, "Enabled": 1,
			}
			if r.mx != nil {
				info["MX"] = *r.mx
			}
			return respond(map[string]any{"RecordInfo": info})
		case "CreateRecord":
			nextID++
			r := &storedRec{
				id:    nextID,
				sub:   body["SubDomain"].(string),
				rtype: body["RecordType"].(string),
				val:   body["Value"].(string),
				ttl:   uint32(body["TTL"].(float64)),
				line:  body["RecordLine"].(string),
			}
			if mxVal, ok := body["MX"].(float64); ok {
				v := uint16(mxVal)
				r.mx = &v
			}
			records[r.id] = r
			return respond(map[string]any{"RecordId": r.id})
		case "ModifyRecord":
			id := uint64(body["RecordId"].(float64))
			r := records[id]
			r.sub = body["SubDomain"].(string)
			r.rtype = body["RecordType"].(string)
			r.val = body["Value"].(string)
			r.ttl = uint32(body["TTL"].(float64))
			r.line = body["RecordLine"].(string)
			if mxVal, ok := body["MX"].(float64); ok {
				v := uint16(mxVal)
				r.mx = &v
			}
			return respond(map[string]any{"RecordId": id})
		case "DeleteRecord":
			id := uint64(body["RecordId"].(float64))
			delete(records, id)
			return respond(map[string]any{})
		default:
			t.Fatalf("unexpected DNSPod action %q", action)
			return nil, nil
		}
	})

	fakeClk := clock.NewFake(now)
	zones, err := Discover(context.Background(), Credentials{
		Kind:            dns.DNSPod,
		AccessKeyID:     secretID,
		AccessKeySecret: append([]byte(nil), secretKey...),
	}, Options{Client: &http.Client{Transport: transport}, Clock: fakeClk})
	if err != nil || len(zones) != 1 || zones[0].ID != "100001" || zones[0].Name != "example.com" {
		t.Fatalf("Discover = %v, %v", zones, err)
	}

	src := &wireCredentials{
		scope: scope,
		value: Credentials{Kind: dns.DNSPod, AccessKeyID: secretID, AccessKeySecret: append([]byte(nil), secretKey...)},
	}
	reg, err := New(Options{Source: src, Client: &http.Client{Transport: transport}, Clock: fakeClk})
	if err != nil {
		t.Fatal(err)
	}
	prov, err := reg.For(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}

	// Empty zone (ResourceNotFound.NoDataOfRecord) returns empty slice cleanly
	initial, err := prov.List(context.Background(), scope)
	if err != nil || len(initial) != 0 {
		t.Fatalf("empty List = %v, %v", initial, err)
	}

	// Create MX record
	created, err := prov.Create(context.Background(), scope, dns.Record{
		Type:  dns.MX,
		Name:  "example.com",
		Value: "10 mail.example.com",
		TTL:   600,
	})
	if err != nil || created.ID == "" || created.Value != "10 mail.example.com" {
		t.Fatalf("Create MX = %v, %v", created, err)
	}

	// List & Update MX record (verifying revision matches between DescribeRecordList and DescribeRecord!)
	listed, err := prov.List(context.Background(), scope)
	if err != nil || len(listed) != 1 || listed[0].Value != "10 mail.example.com" {
		t.Fatalf("List after create = %v, %v", listed, err)
	}
	after := listed[0]
	after.Value = "20 mx2.example.com"
	after.ProviderRevision = ""
	if _, err := prov.Update(context.Background(), scope, listed[0], after); err != nil {
		t.Fatalf("Update MX = %v", err)
	}

	// Stale before must fail with REVISION_CONFLICT
	if err := prov.Delete(context.Background(), scope, listed[0]); fault.Code(err) != "REVISION_CONFLICT" {
		t.Fatalf("stale Delete = %v", err)
	}

	// Fresh Delete succeeds
	fresh, err := prov.List(context.Background(), scope)
	if err != nil || len(fresh) != 1 || fresh[0].Value != "20 mx2.example.com" {
		t.Fatalf("List after update = %v, %v", fresh, err)
	}
	if err := prov.Delete(context.Background(), scope, fresh[0]); err != nil {
		t.Fatalf("Delete = %v", err)
	}
}
