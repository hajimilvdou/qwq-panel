// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

// ======================== 纯预演摘要与身份比较 ========================
func TestIntentSummaryComparesReferencesWithoutExposingThem(t *testing.T) {
	intent, err := coreapi.Decode(testIntent(t))
	if err != nil {
		t.Fatal(err)
	}
	before, err := state.Summarize(intent)
	if err != nil || before.Validate() != nil {
		t.Fatalf("valid intent summary was rejected: %v", err)
	}
	intent.Inbound.Users[0].UUID.ID = "sec_00000000000000000000000002"
	after, err := state.Summarize(intent)
	if err != nil || after.UserRefsDigest == before.UserRefsDigest || after.PrivateKeyRefDigest != before.PrivateKeyRefDigest {
		t.Fatal("summary did not distinguish the changed reference group")
	}
	public, err := json.Marshal(after.PublicIntentSummary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sec_", "private_key", "refs_digest", "short_ids_digest", "sha256:", "uuid"} {
		if strings.Contains(string(public), forbidden) {
			t.Fatal("public preview exposed authentication identity or material")
		}
	}
}

func TestIntentSummaryIsImmutableAndReferenceOrderingIndependent(t *testing.T) {
	intent, err := coreapi.Decode(testIntent(t))
	if err != nil {
		t.Fatal(err)
	}
	intent.Inbound.Users = append(intent.Inbound.Users, coreapi.User{ID: "bob", UUID: coreapi.SecretRef{ID: "sec_00000000000000000000000002"}})
	first, err := state.Summarize(intent)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(intent.Inbound.Users)
	second, err := state.Summarize(intent)
	if err != nil || first.UserRefsDigest != second.UserRefsDigest || !slices.Equal(first.UserIDs, second.UserIDs) {
		t.Fatal("input order changed the reference set identity")
	}
	intent.Inbound.Users[0].ID = "changed"
	intent.Inbound.Security.ServerNames[0] = "changed.example"
	if slices.Contains(second.UserIDs, "changed") || second.ServerNames[0] == "changed.example" {
		t.Fatal("summary shared mutable slices with desired intent")
	}
}
