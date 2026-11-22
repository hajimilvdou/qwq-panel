// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"os/exec"
	"strings"
)

// Runner runs one external command and returns its combined standard output
// and standard error, trimmed. Installer and ExecSystemctl accept a Runner so
// tests can exercise both without systemd, shadow tools or root.
//
// A non-zero exit status is reported as an error together with whatever the
// command wrote, because systemctl and groupadd explain failures on either
// stream.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (output string, err error)
}

// ExecRunner is the production Runner.
type ExecRunner struct{}

// Run implements Runner with os/exec. ExecRunner is stateless and safe for
// concurrent use.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// runnerOr returns r, or ExecRunner when r is nil so that a zero Installer is
// usable. Tests always pass a fake.
func runnerOr(r Runner) Runner {
	if r == nil {
		return ExecRunner{}
	}
	return r
}
