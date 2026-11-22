// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
)

// TestIsSessionActor covers the predicate the controller uses to route a native
// agent session to the owner's RBAC role instead of a delegation record.
func TestIsSessionActor(t *testing.T) {
	session := actor.Actor{
		Kind: actor.AIAgent, ID: SessionActorID("sess_01test"), OnBehalfOf: "usr_01test",
	}
	if !IsSessionActor(session) {
		t.Fatal("a session actor was not recognised")
	}
	if got, want := SessionActorID("sess_01test"), "session:sess_01test"; got != want {
		t.Fatalf("SessionActorID = %q, want %q", got, want)
	}
	for _, a := range []actor.Actor{
		{Kind: actor.AIAgent, ID: "dlg_01test", OnBehalfOf: "usr_01test"},
		{Kind: actor.AIAgent, ID: SessionActorPrefix, OnBehalfOf: "usr_01test"},
		{Kind: actor.Human, ID: SessionActorID("sess_01test")},
		{Kind: actor.Service, ID: "svc_01test"},
		{Kind: actor.System, ID: SessionActorID("sess_01test")},
	} {
		if IsSessionActor(a) {
			t.Fatalf("%+v was taken for a session actor", a)
		}
	}
}
