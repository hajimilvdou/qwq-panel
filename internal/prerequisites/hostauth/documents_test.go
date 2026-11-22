// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
)

// ======================== 严格输入：对象、引用、凭据和持久文档 ========================

func TestHostDocumentsRejectAmbiguousAndUnboundedJSON(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`null`), []byte(`[]`), []byte(`{"provider_id":"one","provider_id":"two"}`),
		[]byte(`{"provider_id":"one"} {}`), []byte(`{"unknown":true}`),
		[]byte(`{"provider_id":"one","nested":{"key":1,"key":2}}`),
		[]byte("{\"provider_id\":\"\xff\"}"),
		[]byte(strings.Repeat(" ", 1025) + `{}`),
	} {
		var result ProviderArgs
		if strictObject(raw, &result, 1024) {
			t.Fatal("含歧义、未知字段、无效编码或超预算的 JSON 被接受")
		}
	}
	var accepted ProviderArgs
	if !strictObject([]byte(`{"provider_id":"one"}`), &accepted, 1024) || accepted.ProviderID != "one" {
		t.Fatal("合法单对象不能解码")
	}
	deep := `{"provider_id":` + strings.Repeat("[", 66) + `0` + strings.Repeat("]", 66) + `}`
	var generic map[string]any
	if strictObject([]byte(deep), &generic, 1024) {
		t.Fatal("过深 JSON 绕过了深度预算")
	}
}

func TestHostCredentialDocumentsRejectMixedKindsAndUnsafeBytes(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`null`), []byte(`{"token":"first","token":"second"}`),
		[]byte(`{"token":"value","access_key_id":"id"}`), []byte(`{"token":"value","api_url":"https://other.test"}`),
		[]byte(`{"token":"bad\nvalue"}`), []byte(`{"token":"bad\tvalue"}`), []byte(`{"token":" value"}`),
		[]byte(`{"token":"中文"}`), []byte(`{"token":"value"} {}`),
		[]byte(`{"token":"` + strings.Repeat("x", 4097) + `"}`),
	} {
		credentials, err := decodeCredentials(raw, dns.Cloudflare)
		credentials.Clear()
		if err == nil {
			t.Fatal("混合字段或不安全提供商凭据被接受")
		}
	}
	credentials, err := decodeCredentials([]byte(`{"access_key_id":"valid-id","access_key_secret":"valid-secret"}`), dns.Aliyun)
	credentials.Clear()
	if err != nil {
		t.Fatal("合法阿里云凭据被拒绝")
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`"sec_invalid"`), json.RawMessage(`{"$secret":"invalid"}`), json.RawMessage(`{"$secret":"invalid","owner":"other"}`), json.RawMessage(`null`)} {
		if _, accepted := operationSecret(raw); accepted {
			t.Fatal("伪造或字符串形式秘密引用被接受")
		}
	}
	if bytes.Contains([]byte(credentials.String()), []byte("valid-secret")) {
		t.Fatal("凭据进入日志文本")
	}
}
