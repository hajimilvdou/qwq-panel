// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestFakeCLICommandAndModes covers the adapter contract's process shape and the
// ADR-0010 §2.1 mode mapping.
func TestFakeCLICommandAndModes(t *testing.T) {
	cli := &FakeCLI{}
	path, args, env, err := cli.Command(CLIConfig{
		Command: "/usr/local/bin/claude", Args: []string{"--print"}, Env: []string{"NO_COLOR=1"},
	})
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	if path != "/usr/local/bin/claude" || len(args) != 1 || args[0] != "--print" || len(env) != 1 {
		t.Fatalf("command = %q %v %v", path, args, env)
	}
	if cli.Cfg.Command != path {
		t.Fatalf("recorded config = %+v", cli.Cfg)
	}
	if _, _, _, err := (&FakeCLI{}).Command(CLIConfig{}); err == nil {
		t.Fatal("empty command accepted")
	}

	want := map[operations.PermissionMode]string{
		operations.PermissionReadOnly: "plan",
		operations.PermissionSafe:     "default",
		operations.PermissionFull:     "bypassPermissions",
		operations.PermissionCustom:   "custom",
	}
	for mode, flag := range want {
		got, err := cli.MapMode(mode)
		if err != nil {
			t.Fatalf("MapMode(%s): %v", mode, err)
		}
		if len(got) != 2 || got[0] != "--permission-mode" || got[1] != flag {
			t.Fatalf("MapMode(%s) = %v", mode, got)
		}
	}
	if _, err := cli.MapMode(operations.PermissionMode("yolo")); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

// TestFakeCLIEncodeDecode covers the stdin/stdout codec and the event stream.
func TestFakeCLIEncodeDecode(t *testing.T) {
	cli := &FakeCLI{}
	turn := Turn{
		SessionID:      "sess_1",
		PermissionMode: operations.PermissionReadOnly,
		Messages:       []Message{{Seq: 1, MessageID: "msg_1", Role: RoleUser, Content: "hi"}},
		Tools:          testTools()[:1],
		Config:         json.RawMessage(`{"base_url":"https://model.test"}`),
	}
	raw, err := cli.Encode(turn)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var out cliTurn
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode stdin: %v", err)
	}
	if out.SessionID != turn.SessionID || out.PermissionMode != operations.PermissionReadOnly || len(out.Messages) != 1 {
		t.Fatalf("encoded turn = %+v", out)
	}
	if cli.Stdin == nil {
		t.Fatal("Encode did not record the stdin")
	}

	cli.Output = `{"type":"message.delta","seq":2,"delta":"hello"}` + "\n" +
		`{"type":"turn.completed","seq":3,"status":"idle"}` + "\n"
	var events []Event
	if err := cli.Decode(nil, func(e Event) error {
		events = append(events, e)
		return nil
	}); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(events) != 2 || events[0].Delta != "hello" || events[1].Status != string(StatusIdle) {
		t.Fatalf("events = %+v", events)
	}

	// An invalid line, an event without a type and a callback error all stop it.
	bad := &FakeCLI{Output: "not json\n"}
	if err := bad.Decode(nil, func(Event) error { return nil }); !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("invalid line = %v", err)
	}
	noType := &FakeCLI{Output: `{"seq":1}` + "\n"}
	if err := noType.Decode(nil, func(Event) error { return nil }); !problem.HasCode(err, problem.PluginError) {
		t.Fatalf("untyped event = %v", err)
	}
	stop := &FakeCLI{Output: `{"type":"message.delta","delta":"x"}` + "\n"}
	if err := stop.Decode(nil, func(Event) error { return errTest }); err == nil {
		t.Fatal("emit error was ignored")
	}
}

// TestFakeCLIRefusesPlaintextSecrets checks that a session config with a
// plaintext credential never reaches a CLI.
func TestFakeCLIRefusesPlaintextSecrets(t *testing.T) {
	cli := &FakeCLI{}
	_, err := cli.Encode(Turn{Config: json.RawMessage(`{"api_key":"sk-live"}`)})
	if !problem.HasCode(err, problem.ValidationFailed) {
		t.Fatalf("Encode with a plaintext key = %v", err)
	}
	if !strings.Contains(problem.From(err).Detail, "secret") {
		t.Fatalf("detail = %q", problem.From(err).Detail)
	}
	// A secret reference is fine.
	if _, err := cli.Encode(Turn{Config: json.RawMessage(`{"api_key_secret":{"$secret":"sec_x"}}`)}); err != nil {
		t.Fatalf("Encode with a reference: %v", err)
	}
}

// TestCLIAdapterFakeIsDeterministic guards the compile-time interface check by
// using the fake through the interface.
func TestCLIAdapterFakeIsDeterministic(t *testing.T) {
	var adapter CLIAdapter = &FakeCLI{Output: `{"type":"message.completed","seq":1}` + "\n"}
	var seen []string
	if err := adapter.Decode(nil, func(e Event) error {
		seen = append(seen, e.Type)
		return nil
	}); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(seen) != 1 || seen[0] != EventMessageCompleted {
		t.Fatalf("seen = %v", seen)
	}
	// The fake never starts a process; Command only validates and records.
	if _, _, _, err := adapter.Command(CLIConfig{Command: "/bin/true"}); err != nil {
		t.Fatalf("Command: %v", err)
	}
}
