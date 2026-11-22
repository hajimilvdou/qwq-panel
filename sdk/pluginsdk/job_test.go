// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"errors"
	"io"
	"testing"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func runJob(t *testing.T, env *testEnv, id, opID, operation string, payload []byte, pre ...*platformv1.Precondition) []*platformv1.JobProgress {
	t.Helper()
	stream, err := env.client.RunJob(testContext(t), &platformv1.RunJobRequest{
		Context: operationContext(id, opID, "en"), Operation: operation, ApiVersion: "v1",
		PayloadJson: payload, Preconditions: pre, Attempt: 1,
	})
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	var out []*platformv1.JobProgress
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		out = append(out, resp.GetProgress())
	}
}

func TestRunJobStepsAndTerminal(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)

	messages := runJob(t, env, "a", "op-job", "test.wait", mustJSON(waitRequest{Steps: 3}))
	if len(messages) != 4 {
		t.Fatalf("%d messages, want 3 progress + 1 terminal: %v", len(messages), messages)
	}
	steps := []string{"s1", "s2", "s3"}
	for idx := 0; idx < 3; idx++ {
		p := messages[idx]
		if p.GetCompleted() || p.GetError() != nil || p.GetStep() != steps[idx] ||
			p.GetStepIndex() != uint32(idx+1) || p.GetStepCount() != 3 || p.GetMessage() == "" {
			t.Fatalf("progress %d = %v", idx, p)
		}
		if idx > 0 && p.GetPercent() <= messages[idx-1].GetPercent() {
			t.Fatalf("percent not increasing: %v", messages)
		}
	}
	last := messages[3]
	if !last.GetCompleted() || last.GetPercent() != 100 || last.GetError() != nil ||
		string(last.GetResultJson()) != `{"steps":3}` {
		t.Fatalf("terminal message = %v", last)
	}
}

func TestRunJobUnknownOperation(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	messages := runJob(t, env, "a", "op-unknown", "test.nope", []byte(`{}`))
	if len(messages) != 1 || messages[0].GetError().GetCode() != "UNKNOWN_OPERATION" || messages[0].GetCompleted() {
		t.Fatalf("messages = %v", messages)
	}
}

func TestRunJobFailingHandler(t *testing.T) {
	p := newTestPlugin()
	p.applyErr = errTest
	env := newTestEnv(t, p)
	env.active("a", nil)

	messages := runJob(t, env, "a", "op-fail", "test.apply", mustJSON(applyRequest{Users: []string{"alice"}}))
	if len(messages) != 2 {
		t.Fatalf("%d messages, want 1 progress + 1 terminal", len(messages))
	}
	if messages[0].GetCompleted() || len(messages[0].GetChanges()) != 1 {
		t.Fatalf("progress = %v", messages[0])
	}
	last := messages[1]
	if last.GetCompleted() || last.GetError().GetCode() != "INTERNAL" {
		t.Fatalf("terminal = %v", last)
	}
	if env.logContains(last.GetError().GetMessage()) || !env.logContains("test failure") {
		t.Fatalf("terminal error leaked or was not logged: %v / %s", last.GetError(), env.lastLog())
	}
}

func TestRunJobProgressChanges(t *testing.T) {
	env := newTestEnv(t, newTestPlugin())
	env.active("a", nil)
	messages := runJob(t, env, "a", "op-apply", "test.apply", mustJSON(applyRequest{Users: []string{"alice", "bob"}}))
	if len(messages) != 3 {
		t.Fatalf("%d messages, want 2 progress + 1 terminal", len(messages))
	}
	wantSubjects := []string{"config", "runtime"}
	for idx, want := range wantSubjects {
		changes := messages[idx].GetChanges()
		if len(changes) != 1 || changes[0].GetSubject() != want || changes[0].GetRevision() == "" {
			t.Fatalf("progress %d changes = %v", idx, changes)
		}
	}
	last := messages[2]
	if !last.GetCompleted() || string(last.GetResultJson()) != `{"applied_revision":"2","users":2}` {
		t.Fatalf("terminal = %v", last)
	}
}

func TestRunJobCancelStopsHandler(t *testing.T) {
	p := newTestPlugin()
	p.holdStep = 1
	env := newTestEnv(t, p)
	env.active("a", nil)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream, err := env.client.RunJob(ctx, &platformv1.RunJobRequest{
		Context: operationContext("a", "op-cancel", "en"), Operation: "test.wait", ApiVersion: "v1",
		PayloadJson: mustJSON(waitRequest{Steps: 3}), Attempt: 1,
	})
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	first, err := stream.Recv()
	if err != nil || first.GetProgress().GetStep() != "s1" {
		t.Fatalf("first message = %v, %v", first, err)
	}
	cancel()
	recv(t, p.exited, "the job handler to return")

	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		if resp.GetProgress().GetCompleted() {
			t.Fatalf("a terminal completed message arrived after cancel: %v", resp.GetProgress())
		}
	}
}

func TestRunJobInvalidProgress(t *testing.T) {
	p := newTestPlugin()
	p.badPercent = 101
	env := newTestEnv(t, p)
	env.active("a", nil)

	messages := runJob(t, env, "a", "op-bad", "test.wait", mustJSON(waitRequest{Steps: 3}))
	if len(messages) != 1 || messages[0].GetError().GetCode() != "PROTOCOL_ERROR" {
		t.Fatalf("messages = %v", messages)
	}
}
