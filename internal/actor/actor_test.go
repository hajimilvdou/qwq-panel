// SPDX-License-Identifier: AGPL-3.0-only

package actor

import (
	"context"
	"encoding/json"
	"testing"
)

func TestValid(t *testing.T) {
	good := []Actor{
		{Kind: Human, ID: "usr_1", SessionID: "ses_1"},
		{Kind: AIAgent, ID: "dlg_1", OnBehalfOf: "usr_1"},
		{Kind: Service, ID: "svc_1"},
		{Kind: Service, ID: "svc_1", OnBehalfOf: "usr_1"},
		SystemActor("reconciler"),
	}
	for _, a := range good {
		if err := a.Valid(); err != nil {
			t.Errorf("%+v: %v", a, err)
		}
	}
	bad := []Actor{
		{Kind: Human, ID: "usr_1", OnBehalfOf: "usr_2"},
		{Kind: AIAgent, ID: "dlg_1"},
		{Kind: "robot", ID: "x"},
		{Kind: Human},
	}
	for _, a := range bad {
		if a.Valid() == nil {
			t.Errorf("%+v accepted", a)
		}
	}
}

func TestHumanSessionAndContext(t *testing.T) {
	if (Actor{Kind: AIAgent, ID: "dlg_1", OnBehalfOf: "usr_1", SessionID: "ses_1"}).IsHumanSession() {
		t.Fatal("AI actor counted as human session")
	}
	a := Actor{Kind: Human, ID: "usr_1", SessionID: "ses_1"}
	got, ok := From(With(context.Background(), a))
	if !ok || got != a || !got.IsHumanSession() {
		t.Fatalf("%+v %v", got, ok)
	}
	if _, ok := From(context.Background()); ok {
		t.Fatal("empty context has an actor")
	}
}

// ======================== 私有会话元数据与公开三元组 ========================

func TestSessionOwnerKindIsPrivate(t *testing.T) {
	original := Actor{Kind: AIAgent, ID: "session:ses_1", OnBehalfOf: "svc_1", OnBehalfOfKind: Service}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields["on_behalf_of_kind"] != nil {
		t.Fatalf("公开 Actor 契约被私有字段扩大: %s", encoded)
	}
	var reloaded Actor
	if err := json.Unmarshal(encoded, &reloaded); err != nil {
		t.Fatal(err)
	}
	if reloaded.Kind != original.Kind || reloaded.ID != original.ID || reloaded.OnBehalfOf != original.OnBehalfOf || reloaded.OnBehalfOfKind != "" {
		t.Fatalf("公开主体三元组或重载边界不一致: %+v", reloaded)
	}
	if err := json.Unmarshal([]byte(`{"kind":"ai_agent","id":"session:ses_1","on_behalf_of":"svc_1","on_behalf_of_kind":"human"}`), &reloaded); err != nil {
		t.Fatal(err)
	}
	if reloaded.OnBehalfOfKind != "" {
		t.Fatal("客户端 JSON 注入了宿主私有主体类型")
	}
}
