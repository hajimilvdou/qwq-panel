// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseOverridesDefaults(t *testing.T) {
	c, err := Parse([]byte(`{"http": {"listen": "0.0.0.0:443", "tls": {"mode": "acme", "domains": ["panel.example.com"], "email": "ops@example.com"}}, "log": {"level": "debug"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.Listen != "0.0.0.0:443" || c.HTTP.TLS.Mode != TLSACME || c.Log.Level != "debug" {
		t.Fatalf("%+v", c)
	}
	if c.DataDir != "/var/lib/qwq" || c.Log.Format != "json" {
		t.Fatalf("defaults lost: %+v", c)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"unknown field":      {`{"dta_dir": "/x"}`, "unknown field"},
		"trailing data":      {`{} {}`, "unexpected data"},
		"future role":        {`{"role": "agent"}`, "not available in this release"},
		"relative data dir":  {`{"data_dir": "var/lib/qwq"}`, "data_dir"},
		"unclean run dir":    {`{"run_dir": "/run/../run/qwq"}`, "run_dir"},
		"root dir":           {`{"data_dir": "/"}`, "data_dir"},
		"bad listen":         {`{"http": {"listen": "8443"}}`, "http.listen"},
		"empty listen host":  {`{"http": {"listen": ":8443"}}`, "host is required"},
		"hostname listen":    {`{"http": {"listen": "panel.example.com:8443"}}`, "IP address or localhost"},
		"bad port":           {`{"http": {"listen": "127.0.0.1:70000"}}`, "invalid port"},
		"bad proxy":          {`{"http": {"trusted_proxies": ["10.0.0.0/33"]}}`, "trusted_proxies[0]"},
		"http origin":        {`{"http": {"public_origins": ["http://panel.example.com"]}}`, "public_origins[0]"},
		"origin with path":   {`{"http": {"public_origins": ["https://panel.example.com/x"]}}`, "public_origins[0]"},
		"acme no domains":    {`{"http": {"tls": {"mode": "acme"}}}`, "http.tls.domains"},
		"acme ip domain":     {`{"http": {"tls": {"mode": "acme", "domains": ["203.0.113.5"]}}}`, "not a DNS name"},
		"acme upper domain":  {`{"http": {"tls": {"mode": "acme", "domains": ["Panel.example.com"]}}}`, "not a DNS name"},
		"acme http dir":      {`{"http": {"tls": {"mode": "acme", "domains": ["a.example.com"], "directory_url": "http://x"}}}`, "directory_url"},
		"acme off port 443":  {`{"http": {"listen": "0.0.0.0:8443", "tls": {"mode": "acme", "domains": ["a.example.com"]}}}`, "requires port 443"},
		"proxy on public ip": {`{"http": {"listen": "0.0.0.0:8443", "trusted_proxies": ["127.0.0.1"], "tls": {"mode": "proxy"}}}`, "requires a loopback"},
		"proxy no proxies":   {`{"http": {"tls": {"mode": "proxy"}}}`, "trusted_proxies"},
		"self-signed domain": {`{"http": {"tls": {"mode": "self_signed", "domains": ["a.example.com"]}}}`, "apply to mode"},
		"unknown tls mode":   {`{"http": {"tls": {"mode": "auto"}}}`, "http.tls.mode"},
		"bad log level":      {`{"log": {"level": "trace"}}`, "log.level"},
		"bad log format":     {`{"log": {"format": "xml"}}`, "log.format"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.in))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestValidateReportsAllErrors(t *testing.T) {
	_, err := Parse([]byte(`{"data_dir": "x", "run_dir": "y", "log": {"level": "z"}}`))
	for _, want := range []string{"data_dir", "run_dir", "log.level"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %s in %v", want, err)
		}
	}
}

func TestProxyModeAccepted(t *testing.T) {
	_, err := Parse([]byte(`{"http": {"listen": "127.0.0.1:8080", "trusted_proxies": ["127.0.0.1", "10.0.0.0/8"], "tls": {"mode": "proxy"}}}`))
	if err != nil {
		t.Fatal(err)
	}
}

// The CA validates TLS-ALPN-01, the only challenge the listener answers, on
// port 443. Any other port must fail at startup and name the modes that work
// next to a web server that already owns 443 (DEP-06).
func TestACMERequiresPort443(t *testing.T) {
	parse := func(listen string) error {
		_, err := Parse([]byte(`{"http": {"listen": "` + listen + `", "tls": {"mode": "acme", "domains": ["panel.example.com"]}}}`))
		return err
	}
	for _, listen := range []string{"0.0.0.0:443", "[::]:443", "203.0.113.5:443"} {
		if err := parse(listen); err != nil {
			t.Errorf("listen %s: %v", listen, err)
		}
	}
	for _, listen := range []string{"0.0.0.0:8443", "127.0.0.1:8443", "0.0.0.0:80", "[::]:4430"} {
		err := parse(listen)
		if err == nil {
			t.Errorf("listen %s accepted in acme mode", listen)
			continue
		}
		for _, want := range []string{"http.listen", "requires port 443", `"proxy"`, `"self_signed"`, "docs/operations/coexistence-baota.md"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("listen %s: %q missing in %v", listen, want, err)
			}
		}
	}
	// An unparsable listener is reported once, not as a port mismatch too.
	if err := parse("8443"); err == nil || strings.Contains(err.Error(), "requires port 443") {
		t.Errorf("bad listen: %v", err)
	}
}

func TestHTTPLoopback(t *testing.T) {
	for listen, want := range map[string]bool{
		"127.0.0.1:8443": true, "localhost:8443": true, "[::1]:8443": true,
		"0.0.0.0:8443": false, "[::]:443": false, "203.0.113.5:8443": false, "8443": false, "": false,
	} {
		if got := (HTTP{Listen: listen}).Loopback(); got != want {
			t.Errorf("Loopback(%q) = %v, want %v", listen, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "qwq.json")
	if _, err := Load(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if err := os.WriteFile(p, []byte(`{"log": {"format": "text"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.Log.Format != "text" {
		t.Fatalf("Load = %+v, %v", c, err)
	}
	big := make([]byte, maxFileSize+10)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(p, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("big file: %v", err)
	}
}

func TestAgentModelEgressAllow(t *testing.T) {
	c, err := Parse([]byte(`{"agent":{"model_egress_allow":["10.1.2.3/8","127.0.0.1:11434","localhost:8080"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	prefixes, addrs, err := ParseEgressAllow(c.Agent.ModelEgressAllow)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 1 || prefixes[0].String() != "10.0.0.0/8" || len(addrs) != 3 {
		t.Fatalf("prefixes = %v, addrs = %v", prefixes, addrs)
	}
	for _, bad := range []string{`"example.com:80"`, `"10.0.0.1"`, `"127.0.0.1:0"`} {
		if _, err := Parse([]byte(`{"agent":{"model_egress_allow":[` + bad + `]}}`)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
