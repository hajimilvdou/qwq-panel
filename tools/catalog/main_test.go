// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"
)

// document builds a one-route OpenAPI document. action is the indented body of
// x-qwq-action ("" omits the extension) and extra is appended to the operation.
func document(action, extra string) []byte {
	var b strings.Builder
	b.WriteString("openapi: 3.1.0\npaths:\n  /api/v1/panel/listen:\n    put:\n      operationId: setPanelListen\n")
	if action != "" {
		b.WriteString("      x-qwq-action:\n" + action)
	}
	b.WriteString(extra)
	b.WriteString("      responses:\n        '202':\n          description: Accepted.\n")
	return []byte(b.String())
}

// listenAction is a host action that changes where the panel listens.
func listenAction(effect, risk string) string {
	return "        id: host.panel.listen\n" +
		"        summary: Change the panel listener\n" +
		"        effect: " + effect + "\n" +
		"        risk: " + risk + "\n" +
		"        mode: invoke\n" +
		"        idempotent: true\n" +
		"        plannable: false\n" +
		"        permission: host.panel:update\n" +
		"        timeout_ms: 30000\n"
}

// TestReachabilityExtension covers x-qwq-reachability (ADR-0016): the flag is
// generated into the catalog entry, and a route that cannot honestly carry it
// fails generation instead of shipping a mislabelled action.
func TestReachabilityExtension(t *testing.T) {
	const marked = "      x-qwq-reachability: true\n"

	out, err := generate(document(listenAction("write", "high"), marked))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(string(out), `"reachability":true`) {
		t.Fatalf("the flag is missing from the generated catalog:\n%s", out)
	}

	plain, err := generate(document(listenAction("write", "high"), ""))
	if err != nil {
		t.Fatalf("generate without the extension: %v", err)
	}
	if strings.Contains(string(plain), "reachability") {
		t.Fatalf("an unmarked action carries the flag:\n%s", plain)
	}
	off, err := generate(document(listenAction("write", "medium"), "      x-qwq-reachability: false\n"))
	if err != nil {
		t.Fatalf("generate with an explicit false: %v", err)
	}
	if strings.Contains(string(off), "reachability") {
		t.Fatalf("an explicit false is emitted:\n%s", off)
	}

	rejected := map[string][]byte{
		"a medium risk":       document(listenAction("write", "medium"), marked),
		"a read action":       document(listenAction("read", "high"), marked),
		"a non-boolean value": document(listenAction("write", "high"), "      x-qwq-reachability: sometimes\n"),
		"no x-qwq-action":     document("", marked),
	}
	for name, src := range rejected {
		if _, err := generate(src); err == nil || !strings.Contains(err.Error(), reachabilityKey) {
			t.Errorf("%s: error = %v, want one naming %s", name, err, reachabilityKey)
		}
	}
}
