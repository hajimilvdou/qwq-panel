// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
)

func TestAliyunGetUsesDirectDescribeDomainRecordInfoWithoutFullListScan(t *testing.T) {
	f := newWireFixture(t, dns.Aliyun)
	f.api.records = []map[string]any{
		{"RecordId": "9001", "RR": "api", "Type": "A", "Value": "198.51.100.10", "TTL": 600, "Line": "telecom", "Status": "ENABLE"},
	}

	// Obtain initial record revision via List
	records, err := f.provider.List(context.Background(), f.scope)
	if err != nil || len(records) != 1 {
		t.Fatalf("List failed: records=%v err=%v", records, err)
	}
	before := records[0]

	// Wrap f.api to count Actions during Update and Delete
	var mu sync.Mutex
	actionCounts := map[string]int{}
	spy := responseTransport(func(req *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		params, _ := url.ParseQuery(string(raw))
		mu.Lock()
		actionCounts[params.Get("Action")]++
		mu.Unlock()
		req.Body = io.NopCloser(io.MultiReader(io.NopCloser(urlBodyReader(raw))))
		return f.api.RoundTrip(req)
	})

	reg, err := New(Options{Source: f.source, Client: &http.Client{Transport: spy}, Clock: wireClock{f.now}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.For(context.Background(), f.scope)
	if err != nil {
		t.Fatal(err)
	}

	after := before
	after.Value = "198.51.100.20"
	after.ProviderRevision = ""
	if _, err := p.Update(context.Background(), f.scope, before, after); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	mu.Lock()
	infoCalls := actionCounts["DescribeDomainRecordInfo"]
	listCalls := actionCounts["DescribeDomainRecords"]
	updateCalls := actionCounts["UpdateDomainRecord"]
	mu.Unlock()

	if infoCalls != 1 || updateCalls != 1 {
		t.Fatalf("expected 1 DescribeDomainRecordInfo and 1 UpdateDomainRecord, got info=%d update=%d", infoCalls, updateCalls)
	}
	if listCalls != 0 {
		t.Fatalf("O(1) Aliyun get must NOT call DescribeDomainRecords full pagination, got %d calls", listCalls)
	}
}

func urlBodyReader(b []byte) io.Reader {
	return &byteSliceReader{b: b}
}

type byteSliceReader struct {
	b []byte
	i int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
