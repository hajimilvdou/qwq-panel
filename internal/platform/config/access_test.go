// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"
)

func TestEntryPathAndDisguiseValidation(t *testing.T) {
	p, err := ValidateEntryPath("/jsnsjx8k/")
	if err != nil || p != "jsnsjx8k" {
		t.Fatalf("ValidateEntryPath = %q, %v", p, err)
	}
	if p, err := ValidateEntryPath(""); err != nil || p != "" {
		t.Fatalf("empty entry path = %q, %v", p, err)
	}
	for _, bad := range []string{"ab", "api", "setup", "login", "a/b", "-bad", "bad path", "readyz"} {
		if _, err := ValidateEntryPath(bad); err == nil {
			t.Errorf("ValidateEntryPath(%q) = nil, want error", bad)
		}
	}

	d, err := NormalizeDisguise("")
	if err != nil || d != DisguiseDrop {
		t.Fatalf("NormalizeDisguise('') = %q, %v", d, err)
	}
	for _, valid := range []string{"drop", "nginx_404", "nginx_403", "blank_404", "custom_html"} {
		if got, err := NormalizeDisguise(valid); err != nil || got != valid {
			t.Errorf("NormalizeDisguise(%q) = %q, %v", valid, got, err)
		}
	}
	if _, err := NormalizeDisguise("bogus"); err == nil {
		t.Error("NormalizeDisguise(bogus) = nil, want error")
	}

	dom, err := NormalizePanelDomain("https://Panel.Example.COM/")
	if err != nil || dom != "panel.example.com" {
		t.Fatalf("NormalizePanelDomain = %q, %v", dom, err)
	}
	if _, err := NormalizePanelDomain("192.168.1.1"); err == nil {
		t.Error("NormalizePanelDomain accepted IP")
	}

	rnd, err := GenerateRandomEntryPath()
	if err != nil || len(rnd) != 10 {
		t.Fatalf("GenerateRandomEntryPath = %q, %v", rnd, err)
	}
	if _, err := ValidateEntryPath(rnd); err != nil {
		t.Fatalf("generated path invalid: %v", err)
	}
}

func TestDomainAutoBypass(t *testing.T) {
	h := HTTP{
		Listen:    "127.0.0.1:43210",
		TLS:       TLS{Mode: TLSSelfSigned},
		EntryPath: "jsnsjx8k",
	}
	if r := h.DomainAutoBypassReason(); r != "" {
		t.Fatalf("direct IP bypass = %q, want empty", r)
	}
	if got := h.EffectiveEntryPath(); got != "jsnsjx8k" {
		t.Fatalf("EffectiveEntryPath = %q, want jsnsjx8k", got)
	}

	// PanelDomain auto-disables entry path.
	h.PanelDomain = "panel.example.com"
	if r := h.DomainAutoBypassReason(); r != "panel_domain" || h.EffectiveEntryPath() != "" {
		t.Fatalf("panel_domain bypass = %q / %q", r, h.EffectiveEntryPath())
	}

	// Explicit false keeps entry path active even with PanelDomain.
	off := false
	h.AutoDisableOnDomain = &off
	if r := h.DomainAutoBypassReason(); r != "" || h.EffectiveEntryPath() != "jsnsjx8k" {
		t.Fatalf("auto_disable=false = %q / %q", r, h.EffectiveEntryPath())
	}

	// TLSProxy auto-disables entry path by default.
	p := HTTP{
		Listen:         "127.0.0.1:43210",
		TLS:            TLS{Mode: TLSProxy},
		TrustedProxies: []string{"127.0.0.1"},
		EntryPath:      "jsnsjx8k",
	}
	if r := p.DomainAutoBypassReason(); r != "tls_proxy" || p.EffectiveEntryPath() != "" {
		t.Fatalf("tls_proxy bypass = %q / %q", r, p.EffectiveEntryPath())
	}

	// PublicOrigins with a DNS domain auto-disables; IP origin does not.
	ipOrigin := HTTP{
		Listen:        "0.0.0.0:43210",
		TLS:           TLS{Mode: TLSSelfSigned},
		PublicOrigins: []string{"https://203.0.113.5:43210"},
		EntryPath:     "jsnsjx8k",
	}
	if r := ipOrigin.DomainAutoBypassReason(); r != "" {
		t.Fatalf("IP public_origin should not bypass, got %q", r)
	}
	domOrigin := ipOrigin
	domOrigin.PublicOrigins = []string{"https://panel.example.com"}
	if r := domOrigin.DomainAutoBypassReason(); r != "public_origin" || domOrigin.EffectiveEntryPath() != "" {
		t.Fatalf("domain public_origin bypass = %q / %q", r, domOrigin.EffectiveEntryPath())
	}

	// Parse accepts new fields and rejects invalid disguise_html size.
	_, err := Parse([]byte(`{"http": {"listen": "127.0.0.1:43210", "entry_path": "jsnsjx8k", "disguise": "nginx_404", "panel_domain": "panel.example.com", "auto_disable_on_domain": true}}`))
	if err != nil {
		t.Fatalf("Parse valid access config: %v", err)
	}
	huge := `{"http": {"disguise": "custom_html", "disguise_html": "` + strings.Repeat("a", MaxDisguiseHTMLBytes+10) + `"}}`
	if _, err := Parse([]byte(huge)); err == nil || !strings.Contains(err.Error(), "disguise_html") {
		t.Fatalf("expected huge disguise_html error, got %v", err)
	}
}
