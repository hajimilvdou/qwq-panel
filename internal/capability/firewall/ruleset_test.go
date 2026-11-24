// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testRuleset = `{"nftables":[{"table":{"family":"inet","name":"qwq"}},{"chain":{"family":"inet","table":"qwq","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},{"rule":{"family":"inet","table":"qwq","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8080}},{"accept":null}]}}]}`

func TestRulesetGuardsAndDeterminism(t *testing.T) {
	ruleset, err := Normalize([]byte(testRuleset), []uint32{22, 8443}, []uint32{8443, 22})
	if err != nil {
		t.Fatal(err)
	}
	a, err := ruleset.Definition()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ruleset.Definition()
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("rendering was not deterministic")
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Nftables) != 7 {
		t.Fatalf("objects=%d, want table, chain, four guards, user rule", len(doc.Nftables))
	}
	for i, name := range []string{"qwq:preserve", "qwq:preserve-icmpv6", "qwq:loopback", "qwq:established"} {
		if !bytes.Contains(doc.Nftables[i+2]["rule"], []byte(name)) {
			t.Fatalf("host protection %q did not precede user rules", name)
		}
	}
	if !bytes.Contains(doc.Nftables[3]["rule"], []byte("nd-neighbor-solicit")) {
		t.Fatal("ICMPv6 NDP guard is missing nd-neighbor-solicit")
	}
	second, err := Normalize(a, []uint32{22, 8443}, []uint32{22, 8443})
	if err != nil {
		t.Fatal(err)
	}
	c, err := second.Definition()
	if err != nil || !bytes.Equal(a, c) {
		t.Fatal("applying an exported ruleset duplicated the guards")
	}
}

func TestRulesetRejectsUnsafeInput(t *testing.T) {
	cases := map[string]string{
		"other table":           strings.ReplaceAll(testRuleset, `"qwq"`, `"unrelated"`),
		"other family":          strings.ReplaceAll(testRuleset, `"inet"`, `"ip"`),
		"other hook":            strings.ReplaceAll(testRuleset, `"hook":"input"`, `"hook":"output"`),
		"priority":              strings.ReplaceAll(testRuleset, `"prio":0`, `"prio":-300`),
		"missing priority":      strings.ReplaceAll(testRuleset, `"prio":0,`, ``),
		"other chain":           strings.ReplaceAll(testRuleset, `"chain":"input"`, `"chain":"ban"`),
		"command input":         `{"nftables":[{"flush":{"ruleset":null}}]}`,
		"extra table attribute": strings.Replace(testRuleset, `"name":"qwq"`, `"name":"qwq","flags":["owner"]`, 1),
		"duplicate key":         strings.Replace(testRuleset, `"right":8080`, `"right":8080,"right":22`, 1),
		"invalid port":          strings.Replace(testRuleset, `"right":8080`, `"right":65536`, 1),
		"operator":              strings.Replace(testRuleset, `"op":"=="`, `"op":"!="`, 1),
		"redirect":              strings.Replace(testRuleset, `{"accept":null}`, `{"redirect":{"port":22}}`, 1),
		"jump":                  strings.Replace(testRuleset, `{"accept":null}`, `{"jump":{"target":"other"}}`, 1),
		"late match":            strings.Replace(testRuleset, `"expr":[`, `"expr":[{"drop":null},`, 1),
		"trailing":              testRuleset + ` {}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Normalize([]byte(raw), []uint32{22}, []uint32{22}); err == nil {
				t.Fatal("unsafe input was accepted")
			}
		})
	}
	if _, err := Normalize([]byte(testRuleset), []uint32{22, 8443}, []uint32{22}); err == nil {
		t.Fatal("missing host ports accepted")
	}
	if _, err := Normalize([]byte(testRuleset), nil, nil); err == nil {
		t.Fatal("missing host facts accepted")
	}
}

func TestRulesetTransactionOwnsOnlyInput(t *testing.T) {
	r, err := Normalize([]byte(testRuleset), []uint32{22}, []uint32{22})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := r.Transaction(true, true)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(tx, []byte(`"delete":{"table"`)) || bytes.Contains(tx, []byte(`"flush"`)) {
		t.Fatal("transaction deletes the whole table or flushes unrelated state")
	}
	if !bytes.Contains(tx, []byte(`"delete":{"chain":{"family":"inet","table":"qwq","name":"input"}}`)) {
		t.Fatal("input chain was not replaced atomically")
	}
	if bytes.Contains(tx, []byte(`"set"`)) && !bytes.Contains(tx, []byte(`"right":{"set"`)) {
		t.Fatal("transaction changed ban sets")
	}
	initial, err := r.Transaction(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(initial, []byte(`"add":{"table"`)) || bytes.Contains(initial, []byte(`"delete"`)) {
		t.Fatal("initial transaction is invalid")
	}
}

func TestRulesetPortRangeAndUDPGuards(t *testing.T) {
	rangeRuleset := `{"nftables":[` +
		`{"table":{"family":"inet","name":"qwq"}},` +
		`{"chain":{"family":"inet","table":"qwq","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},` +
		`{"rule":{"family":"inet","table":"qwq","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[20000,30000]}}},{"accept":null}],"comment":"hysteria2-hop"}}` +
		`]}`
	r, err := NormalizeWithUDP([]byte(rangeRuleset), []uint32{22, 8443}, []uint32{22, 8443}, []uint32{443})
	if err != nil {
		t.Fatalf("NormalizeWithUDP with port range failed: %v", err)
	}
	def, err := r.Definition()
	if err != nil {
		t.Fatalf("Definition: %v", err)
	}
	if !bytes.Contains(def, []byte(`"qwq:preserve-udp"`)) {
		t.Fatalf("expected qwq:preserve-udp guard in definition: %s", def)
	}
	if !bytes.Contains(def, []byte(`{"range":[20000,30000]}`)) {
		t.Fatalf("expected port range [20000,30000] in definition: %s", def)
	}
	// 无效端口段（起 > 止 或 越界）必须被拒绝
	for _, bad := range []string{`{"range":[30000,20000]}`, `{"range":[0,100]}`, `{"range":[100,65536]}`} {
		badDoc := strings.Replace(rangeRuleset, `{"range":[20000,30000]}`, bad, 1)
		if _, err := Normalize([]byte(badDoc), []uint32{22}, []uint32{22}); err == nil {
			t.Fatalf("expected invalid port range %s to be rejected", bad)
		}
	}
	// ParseFirewallPortOrRange 测试
	elem, lo, hi, err := ParseFirewallPortOrRange("20000-30000")
	if err != nil || elem != "20000-30000" || lo != 20000 || hi != 30000 {
		t.Fatalf("ParseFirewallPortOrRange(20000-30000): elem=%q lo=%d hi=%d err=%v", elem, lo, hi, err)
	}
}
