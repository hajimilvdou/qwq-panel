// SPDX-License-Identifier: AGPL-3.0-only

// External CLI cores are a P6 feature (A3): the host launches a controlled
// process and speaks to it over a pipe, and every tool call it proposes comes
// back through the host's operation path. This file defines only the adapter
// contract and a fake used by the tests; no process is started here, and the
// host never hands a credential or a token to an adapter.
package agentsession

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// CLIConfig is the configured command of one external core. It carries no
// secret: an environment value that is sensitive is a secret reference resolved
// by the host, never a plaintext value in the session config.
type CLIConfig struct {
	Command string        `json:"command"`
	Args    []string      `json:"args,omitempty"`
	Env     []string      `json:"env,omitempty"`
	WorkDir string        `json:"work_dir,omitempty"`
	Timeout time.Duration `json:"-"`
}

// CLIAdapter is the contract of an external agent core (ADR-0010 §2.1, design
// §7). Command and MapMode are used once per process; Encode writes the turn to
// the process and Decode turns its output back into session events. The host's
// operations decision is authoritative: whatever mode the CLI reports, the
// session's mode is the one operations enforces.
type CLIAdapter interface {
	Command(cfg CLIConfig) (path string, args []string, env []string, err error)
	MapMode(mode operations.PermissionMode) ([]string, error)
	Encode(turn Turn) (stdin []byte, err error)
	Decode(r io.Reader, emit Emit) error
}

// ModeMapping is the ADR-0010 §2.1 table for the CLI adapters that shipped:
// the unified mode maps to the CLI's own permission flags. It is a log hint
// only; the host still decides every operation.
type ModeMapping map[operations.PermissionMode][]string

// DefaultModeMapping returns the documented mapping of the first release.
func DefaultModeMapping() ModeMapping {
	return ModeMapping{
		operations.PermissionReadOnly: {"--permission-mode", "plan"},
		operations.PermissionSafe:     {"--permission-mode", "default"},
		operations.PermissionFull:     {"--permission-mode", "bypassPermissions"},
		operations.PermissionCustom:   {"--permission-mode", "custom"},
	}
}

// cliTurn is the JSON document Encode writes. It contains the permission mode
// so a CLI can pick its local flags, but a CLI cannot change it.
type cliTurn struct {
	SessionID      string                    `json:"session_id"`
	PermissionMode operations.PermissionMode `json:"permission_mode"`
	Messages       []Message                 `json:"messages"`
	Tools          []ToolSpec                `json:"tools,omitempty"`
	Config         json.RawMessage           `json:"config,omitempty"`
}

// maxCLILine bounds one decoded line; a CLI is untrusted.
const maxCLILine = 1 << 20

// FakeCLI is a CLIAdapter test double: it validates the command, records the
// stdin and replays queued events. It never launches a process, so it proves the
// contract without giving a child host credentials.
type FakeCLI struct {
	// Cfg is returned by Command (so a test can assert what would run).
	Cfg CLIConfig
	// Modes overrides DefaultModeMapping.
	Modes ModeMapping
	// Output is the JSON-lines document Decode reads. The default is empty,
	// which produces no events.
	Output string
	// Fail makes Command, MapMode, Encode or Decode return this error.
	Fail error
	// Stdin records the last Encode result.
	Stdin []byte
}

// Command implements CLIAdapter.
func (f *FakeCLI) Command(cfg CLIConfig) (string, []string, []string, error) {
	if f.Fail != nil {
		return "", nil, nil, f.Fail
	}
	if cfg.Command == "" {
		return "", nil, nil, errors.New("fake cli: empty command")
	}
	f.Cfg = cfg
	return cfg.Command, append([]string(nil), cfg.Args...), append([]string(nil), cfg.Env...), nil
}

// MapMode implements CLIAdapter.
func (f *FakeCLI) MapMode(mode operations.PermissionMode) ([]string, error) {
	if f.Fail != nil {
		return nil, f.Fail
	}
	mapping := f.Modes
	if mapping == nil {
		mapping = DefaultModeMapping()
	}
	args, ok := mapping[mode]
	if !ok {
		return nil, fmt.Errorf("fake cli: unsupported permission mode %q", mode)
	}
	return append([]string(nil), args...), nil
}

// Encode implements CLIAdapter. A turn carrying a plaintext secret is refused:
// the adapter contract forbids credentials in the session config.
func (f *FakeCLI) Encode(turn Turn) ([]byte, error) {
	if f.Fail != nil {
		return nil, f.Fail
	}
	if err := refusePlaintextSecrets(turn.Config); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(cliTurn{
		SessionID: turn.SessionID, PermissionMode: turn.PermissionMode,
		Messages: turn.Messages, Tools: turn.Tools, Config: turn.Config,
	})
	if err != nil {
		return nil, problem.Wrap(err)
	}
	f.Stdin = raw
	return raw, nil
}

// Decode implements CLIAdapter.
func (f *FakeCLI) Decode(r io.Reader, emit Emit) error {
	if f.Fail != nil {
		return f.Fail
	}
	src := r
	if src == nil {
		src = strings.NewReader(f.Output)
	}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64<<10), maxCLILine)
	events := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return problem.New(problem.PluginError, "The CLI core wrote a line that is not a session event.")
		}
		if e.Type == "" {
			return problem.New(problem.PluginError, "The CLI core wrote an event without a type.")
		}
		if events++; events > 1000 {
			return problem.New(problem.PluginError, "The CLI core wrote too many events in one turn.")
		}
		if err := emit(e); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return problem.New(problem.Unavailable, "The CLI core stream could not be read.")
	}
	return nil
}

// refusePlaintextSecrets rejects the obvious credential keys of a session config
// before it reaches an external process.
func refusePlaintextSecrets(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	for _, key := range []string{"api_key", "apiKey", "token", "password", "secret"} {
		if _, ok := obj[key]; ok {
			return problem.New(problem.ValidationFailed,
				"A session config must not carry a plaintext secret; use a secret reference.")
		}
	}
	return nil
}

// compile-time check.
var _ CLIAdapter = (*FakeCLI)(nil)
