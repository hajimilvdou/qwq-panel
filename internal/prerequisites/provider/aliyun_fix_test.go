// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
)

func TestAliyunZoneIDAcceptsUUIDAndRecordIDRequiresDigits(t *testing.T) {
	uuidZone := "00efd71a-770e-4255-b54e-6fe5659baffe"
	if !aliyunZoneID(uuidZone) {
		t.Fatalf("aliyunZoneID rejected standard Aliyun UUID DomainId %q", uuidZone)
	}
	if aliyunID(uuidZone) {
		t.Fatalf("aliyunID record validator must still reject non-digit UUID %q", uuidZone)
	}
	if !aliyunZoneID("123456789") || !aliyunID("123456789") {
		t.Fatal("digit IDs should remain valid")
	}
	if aliyunZoneID("00efd71a_770e_4255_b54e_6fe5659baffe") || aliyunZoneID("../etc/passwd") {
		t.Fatal("invalid zone IDs must be rejected")
	}

	reg, err := New(Options{Source: discoveryCredentials{credentials: Credentials{
		Kind:            dns.Aliyun,
		AccessKeyID:     "LTAI5tTestKeyId123456",
		AccessKeySecret: []byte("TestSecretValue1234567890abcdef"),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.For(context.Background(), dns.Scope{
		ProviderID: "prov_aliyun",
		Kind:       dns.Aliyun,
		ZoneID:     uuidZone,
		ZoneName:   "example.com",
		Revision:   "rev_001",
	}); err != nil {
		t.Fatalf("Registry.For rejected valid Aliyun UUID ZoneID: %v", err)
	}
}

func TestAliyunRPCEncodePreservesTildePerPOPSpec(t *testing.T) {
	spf := "v=spf1 include:spf.example.com ~all"
	got := rpcEncode(spf)
	if strings.Contains(got, "%7E") || !strings.Contains(got, "~all") {
		t.Fatalf("rpcEncode failed to keep literal tilde: %q", got)
	}
	params := url.Values{"Value": []string{spf}}
	sig := aliyunSignature("POST", params, []byte("secret-key"))
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}
}
