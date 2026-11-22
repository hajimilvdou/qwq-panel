// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
)

func TestChangedSetsRevisionAndOrigin(t *testing.T) {
	db := open(t, Options{})
	ctx := context.Background()
	ai := actor.Actor{Kind: actor.AIAgent, ID: "dlg_1", OnBehalfOf: "usr_1"}
	var rev int64
	err := db.Update(ctx, func(tx *Tx) error {
		tx.SetOrigin(Origin{Actor: ai, OperationID: "op_1", TraceID: "t1", NodeID: "local"})
		var err error
		rev, err = tx.Changed(ctx, Change{Subject: "users/usr_2", Kind: Updated, Pointers: []string{"/display_name"}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	evs, _ := db.EventsAfter(ctx, 0, 10)
	if len(evs) != 1 || evs[0].Seq != rev {
		t.Fatalf("%+v", evs)
	}
	e := evs[0]
	if e.Type != "resource.changed" || e.ActorKind != "ai_agent" || e.OnBehalfOf != "usr_1" || e.OperationID != "op_1" || e.NodeID != "local" {
		t.Fatalf("envelope %+v", e)
	}
	var p map[string]any
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p["revision"] != fmt.Sprint(rev) || p["kind"] != "update" || p["operation_id"] != "op_1" {
		t.Fatalf("payload %v", p)
	}
	if a := p["actor"].(map[string]any); a["kind"] != "ai_agent" || a["on_behalf_of"] != "usr_1" {
		t.Fatalf("actor %v", a)
	}
}

func TestChangedDefaultsAndLimits(t *testing.T) {
	db := open(t, Options{})
	ctx := context.Background()
	many := make([]string, MaxChangedPointers+3)
	for i := range many {
		many[i] = fmt.Sprintf("/x/%d", i)
	}
	err := db.Update(ctx, func(tx *Tx) error {
		if _, err := tx.Changed(ctx, Change{Subject: "nodes/local", Kind: Created}); err != nil {
			return err
		}
		if _, err := tx.Changed(ctx, Change{Subject: "nodes/local", Kind: Updated, Pointers: many}); err != nil {
			return err
		}
		if _, err := tx.Changed(ctx, Change{Subject: "nodes/local", Kind: "rename"}); err == nil {
			t.Error("unknown kind accepted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	evs, _ := db.EventsAfter(ctx, 0, 10)
	var first, second map[string]any
	json.Unmarshal(evs[0].Payload, &first)
	json.Unmarshal(evs[1].Payload, &second)
	if first["actor"].(map[string]any)["kind"] != "system" || len(first["changed_pointers"].([]any)) != 0 {
		t.Fatalf("defaults %v", first)
	}
	if len(second["changed_pointers"].([]any)) != MaxChangedPointers || second["changed_pointers_truncated"] != true {
		t.Fatalf("truncation %v", second["changed_pointers_truncated"])
	}
}
