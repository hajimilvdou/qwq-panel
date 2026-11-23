// SPDX-License-Identifier: AGPL-3.0-only

package resolve

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"golang.org/x/net/dns/dnsmessage"
)

// ======================== 显式 DNS 来源与 CAA fixture ========================

type fixtureDiscovery struct{ addresses []netip.Addr }

func (f fixtureDiscovery) NameServers(context.Context, string) ([]string, error) {
	return []string{"ns.example.com"}, nil
}
func (f fixtureDiscovery) Addresses(context.Context, string) ([]netip.Addr, error) {
	return f.addresses, nil
}

type exchangeFunc func(context.Context, netip.Addr, dnsmessage.Question, bool) (dnsmessage.Message, error)

func (f exchangeFunc) Query(ctx context.Context, server netip.Addr, q dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
	return f(ctx, server, q, recursive)
}

func fixtureScope() dns.Scope {
	return dns.Scope{ProviderID: "provider-1", Kind: dns.Cloudflare, ZoneID: strings.Repeat("a", 32), ZoneName: "example.com", Revision: "scope-1"}
}
func dnsName(t *testing.T, name string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func response(q dnsmessage.Question, recursive bool, answers []dnsmessage.Resource) dnsmessage.Message {
	return dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: !recursive, RecursionAvailable: recursive}, Questions: []dnsmessage.Question{q}, Answers: answers}
}
func caa(t *testing.T, name string, flags byte, tag, value string) dnsmessage.Resource {
	t.Helper()
	raw := append([]byte{flags, byte(len(tag))}, []byte(tag)...)
	raw = append(raw, []byte(value)...)
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsName(t, name), Type: typeCAA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.UnknownResource{Type: typeCAA, Data: raw}}
}
func cname(t *testing.T, name, target string) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsName(t, name), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: dnsName(t, target)}}
}

func TestObserveIncludesAuthoritativeAndRecursiveTXTFragments(t *testing.T) {
	queries := 0
	exchange := exchangeFunc(func(_ context.Context, _ netip.Addr, q dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
		queries++
		return response(q, recursive, []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{"first", "second"}}}}), nil
	})
	r, err := New(Options{Discovery: fixtureDiscovery{[]netip.Addr{netip.MustParseAddr("203.0.113.53")}}, Exchange: exchange})
	if err != nil {
		t.Fatal(err)
	}
	observations, err := r.Observe(context.Background(), fixtureScope(), "_acme-challenge.proxy.example.com", dns.TXT)
	if err != nil || len(observations) != 6 || queries != 6 {
		t.Fatalf("sources = %v %v", observations, err)
	}
	if observations[0].Kind != dns.Authoritative || observations[1].Kind != dns.Recursive {
		t.Fatal("source provenance was lost")
	}
	for _, sample := range observations {
		if len(sample.Values) != 1 || sample.Values[0] != "firstsecond" || sample.CollectedAt.IsZero() {
			t.Fatal("TXT fragments or sample time invalid")
		}
	}
}

func TestObserveRejectsUnsafeNameServerBeforeQuery(t *testing.T) {
	queries := 0
	r, err := New(Options{Discovery: fixtureDiscovery{[]netip.Addr{netip.MustParseAddr("127.0.0.1")}}, Exchange: exchangeFunc(func(context.Context, netip.Addr, dnsmessage.Question, bool) (dnsmessage.Message, error) {
		queries++
		return dnsmessage.Message{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Observe(context.Background(), fixtureScope(), "proxy.example.com", dns.A); fault.Code(err) != "DNS_UNSAFE_SERVER" || queries != 0 {
		t.Fatalf("unsafe source = %v queries %d", err, queries)
	}
}

func TestObserveRejectsNonAuthoritativeAndMismatchedQuestion(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(strings.ToUpper(map[bool]string{false: "flags", true: "question"}[mismatch]), func(t *testing.T) {
			r, err := New(Options{Discovery: fixtureDiscovery{[]netip.Addr{netip.MustParseAddr("203.0.113.53")}}, Exchange: exchangeFunc(func(_ context.Context, _ netip.Addr, q dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
				result := response(q, recursive, nil)
				if mismatch {
					result.Questions[0].Type = dnsmessage.TypeAAAA
				} else {
					result.Authoritative = false
				}
				return result, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Observe(context.Background(), fixtureScope(), "proxy.example.com", dns.A); fault.Code(err) != "DNS_INVALID_RESPONSE" {
				t.Fatalf("invalid provenance = %v", err)
			}
		})
	}
}

func TestCAAInheritanceWildcardCriticalAndAccountRestrictions(t *testing.T) {
	cases := []struct {
		name         string
		records      []dnsmessage.Resource
		san, account string
		allowed      bool
	}{
		{"parent allows", []dnsmessage.Resource{caa(t, "example.com.", 0, "issue", "letsencrypt.org")}, "proxy.example.com", "", true},
		{"wildcard override", []dnsmessage.Resource{caa(t, "example.com.", 0, "issue", "letsencrypt.org"), caa(t, "example.com.", 0, "issuewild", "other.example")}, "*.proxy.example.com", "", false},
		{"critical unknown", []dnsmessage.Resource{caa(t, "example.com.", 0, "issue", "letsencrypt.org"), caa(t, "example.com.", 128, "newtag", "unknown")}, "proxy.example.com", "", false},
		{"account denied", []dnsmessage.Resource{caa(t, "example.com.", 0, "issue", "letsencrypt.org; accounturi=https://acme.example/account/1")}, "proxy.example.com", "https://acme.example/account/2", false},
		{"dns01 allowed", []dnsmessage.Resource{caa(t, "example.com.", 0, "issue", "letsencrypt.org; validationmethods=dns-01")}, "proxy.example.com", "", true},
		{"http01 denied", []dnsmessage.Resource{caa(t, "example.com.", 0, "issue", "letsencrypt.org; validationmethods=http-01")}, "proxy.example.com", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(Options{Exchange: exchangeFunc(func(_ context.Context, _ netip.Addr, q dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
				answers := []dnsmessage.Resource{}
				if q.Name.String() == "example.com." {
					answers = tc.records
				}
				return response(q, recursive, answers), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			err = r.CheckCAA(context.Background(), fixtureScope(), []string{tc.san}, tc.account)
			if tc.allowed && err != nil {
				t.Fatal(err)
			}
			if !tc.allowed && fault.Code(err) != "CAA_FORBIDDEN" {
				t.Fatalf("CAA = %v", err)
			}
		})
	}
}

func TestCAAChasesAliasThenClimbsOriginalParentOnly(t *testing.T) {
	targetParentQueried := false
	r, err := New(Options{Exchange: exchangeFunc(func(_ context.Context, _ netip.Addr, q dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
		answers := []dnsmessage.Resource{}
		switch q.Name.String() {
		case "proxy.example.com.":
			answers = []dnsmessage.Resource{cname(t, "proxy.example.com.", "tenant.hosting.test.")}
		case "example.com.":
			answers = []dnsmessage.Resource{caa(t, "example.com.", 0, "issue", "letsencrypt.org")}
		case "hosting.test.":
			targetParentQueried = true
			answers = []dnsmessage.Resource{caa(t, "hosting.test.", 0, "issue", "other.example")}
		}
		return response(q, recursive, answers), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CheckCAA(context.Background(), fixtureScope(), []string{"proxy.example.com"}, ""); err != nil {
		t.Fatal(err)
	}
	if targetParentQueried {
		t.Fatal("hosting parent CAA was transplanted to customer domain")
	}
}

func TestCAARecursiveDisagreementAndAliasLoopFailClosed(t *testing.T) {
	for _, loop := range []bool{false, true} {
		t.Run(map[bool]string{false: "disagreement", true: "loop"}[loop], func(t *testing.T) {
			r, err := New(Options{Exchange: exchangeFunc(func(_ context.Context, server netip.Addr, q dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
				answers := []dnsmessage.Resource{}
				if loop {
					answers = []dnsmessage.Resource{cname(t, q.Name.String(), q.Name.String())}
				} else if server.String() == "1.1.1.1" {
					answers = []dnsmessage.Resource{caa(t, q.Name.String(), 0, "issue", "letsencrypt.org")}
				}
				return response(q, recursive, answers), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.CheckCAA(context.Background(), fixtureScope(), []string{"proxy.example.com"}, ""); err == nil {
				t.Fatal("invalid CAA sources allowed issuance")
			}
		})
	}
}

func TestObserveRejectsNXDOMAINWithMatchingTXTAnswer(t *testing.T) {
	r, err := New(Options{Discovery: fixtureDiscovery{[]netip.Addr{netip.MustParseAddr("203.0.113.53")}}, Exchange: exchangeFunc(func(_ context.Context, _ netip.Addr, q dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
		message := response(q, recursive, []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{"forged"}}}})
		message.RCode = dnsmessage.RCodeNameError
		return message, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Observe(context.Background(), fixtureScope(), "_acme-challenge.proxy.example.com", dns.TXT); fault.Code(err) != "DNS_INVALID_RESPONSE" {
		t.Fatalf("contradictory NXDOMAIN = %v", err)
	}
}

func TestCAATotalQueryBudgetIncludesEveryAliasAndResolver(t *testing.T) {
	queries := 0
	r, err := New(Options{Exchange: exchangeFunc(func(_ context.Context, _ netip.Addr, q dnsmessage.Question, recursive bool) (dnsmessage.Message, error) {
		queries++
		name := q.Name.String()
		depth := strings.Count(name, "alias.")
		answers := []dnsmessage.Resource{}
		if strings.Contains(name, "proxy") && depth < 6 {
			answers = []dnsmessage.Resource{cname(t, name, "alias."+name)}
		}
		return response(q, recursive, answers), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	sans := []string{}
	for index := 0; index < 64; index++ {
		sans = append(sans, fmt.Sprintf("proxy%d.example.com", index))
	}
	if err := r.CheckCAA(context.Background(), fixtureScope(), sans, ""); fault.Code(err) != "RESOURCE_EXHAUSTED" || queries > 256 {
		t.Fatalf("query budget = %v, queries %d", err, queries)
	}
}
