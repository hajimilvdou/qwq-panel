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
	if len(doc.Nftables) != 6 {
		t.Fatalf("objects=%d, want table, chain, three guards, user rule", len(doc.Nftables))
	}
	for i, name := range []string{"qwq:preserve", "qwq:loopback", "qwq:established"} {
		if !bytes.Contains(doc.Nftables[i+2]["rule"], []byte(name)) {
			t.Fatal("host protection did not precede user rules")
		}
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
