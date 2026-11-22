// SPDX-License-Identifier: AGPL-3.0-only

package names

import "testing"

func TestDNSNormalizationAndLabelBoundary(t *testing.T) {
	for _, invalid := range []string{"example.com.attacker.test/", " example.com", "example..com", "example.com\x00", "-bad.example.com", "http://example.com", "127.0.0.1"} {
		if _, err := DNS(invalid, false); err == nil {
			t.Fatalf("accepted invalid name %q", invalid)
		}
	}
	name, err := DNS("PROXY.Example.COM.", false)
	if err != nil || name != "proxy.example.com" {
		t.Fatalf("normalized = %q, %v", name, err)
	}
	if !InZone(name, "example.com") || InZone("example.com.attacker.test", "example.com") || InZone("badexample.com", "example.com") {
		t.Fatal("zone boundary was not enforced")
	}
	if _, err := DNS("_acme-challenge.proxy.example.com", true); err != nil {
		t.Fatal(err)
	}
	if _, err := DNS("_acme-challenge.proxy.example.com", false); err == nil {
		t.Fatal("underscore accepted for certificate SAN")
	}
}

func TestOnlyLeftmostWildcardSANIsAllowed(t *testing.T) {
	if name, err := SAN("*.EXAMPLE.com"); err != nil || name != "*.example.com" {
		t.Fatalf("SAN = %q, %v", name, err)
	}
	for _, invalid := range []string{"foo.*.example.com", "*.*.example.com", "*.127.0.0.1"} {
		if _, err := SAN(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}
