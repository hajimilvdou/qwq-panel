// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultSystemctlTimeout bounds one systemctl invocation. The caller's
// context still wins when it expires first.
const DefaultSystemctlTimeout = 30 * time.Second

// unitNamePattern is the set of unit names this client accepts. It rules out
// argument injection (a leading "-" would be parsed as an option) and anything
// that is not a systemd unit name.
var unitNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]*\.(service|socket|target|slice)$`)

// CheckUnitName rejects unit names that systemctl would read as options or
// that are not unit names at all.
func CheckUnitName(unit string) error {
	if !unitNamePattern.MatchString(unit) {
		return fmt.Errorf("sandbox: %q is not a valid unit name", unit)
	}
	return nil
}

// UnitStatus is the systemd view of one unit. MainPID 0 means the unit has no
// process (inactive, failed or waiting for socket activation).
type UnitStatus struct {
	MainPID      int
	ControlGroup string
	ActiveState  string
	SubState     string
	FragmentPath string
	// StartTime is systemd's ExecMainStartTimestamp: when the unit's main
	// process started. Zero means systemd reported an empty or "n/a" value,
	// or a timestamp this parser does not understand; the supervisor then
	// identifies the process generation by MainPID alone, which is weaker
	// against PID reuse (P2-T1 section 5).
	StartTime time.Time
	// ExecStart is the executable path of the loaded ExecStart= line. The
	// unit is version-pinned (<version dir>/<entrypoint>), so it identifies
	// the version a process runs when the plugin reports no descriptor.
	// Empty when systemd did not report it.
	ExecStart string
}

// Systemctl is the narrow systemd client the supervisor uses. Every method
// takes a context; ExecSystemctl additionally applies a timeout.
//
// MainPID must never be cached by the caller: P2-T1 showed that an
// out-of-band restart makes a cached value wrong, and every plugin report is
// then rejected. Show always asks systemd.
type Systemctl interface {
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
	Kill(ctx context.Context, unit string) error
	Show(ctx context.Context, unit string) (UnitStatus, error)
}

// ExecSystemctl implements Systemctl with the systemctl binary. The agent
// calls it as the unprivileged qwq user; polkit decides whether the action is
// allowed (deployments/polkit/qwq-plugin.rules).
type ExecSystemctl struct {
	// Runner defaults to ExecRunner.
	Runner Runner
	// Timeout defaults to DefaultSystemctlTimeout.
	Timeout time.Duration
}

// NewExecSystemctl returns an ExecSystemctl using r.
func NewExecSystemctl(r Runner) *ExecSystemctl {
	return &ExecSystemctl{Runner: r}
}

// Start starts unit.
func (s *ExecSystemctl) Start(ctx context.Context, unit string) error {
	if err := CheckUnitName(unit); err != nil {
		return err
	}
	_, err := s.run(ctx, "start", unit)
	return err
}

// Stop stops unit. With KillMode=control-group in the unit, systemd cleans the
// whole cgroup.
func (s *ExecSystemctl) Stop(ctx context.Context, unit string) error {
	if err := CheckUnitName(unit); err != nil {
		return err
	}
	_, err := s.run(ctx, "stop", unit)
	return err
}

// Kill sends SIGKILL to the main process. --kill-whom=main is deliberate:
// --kill-whom=all returns "Invalid argument" on systemd 255 for socket
// activated services, and KillMode=control-group already clears the cgroup
// (P2-T1 acceptance 4).
func (s *ExecSystemctl) Kill(ctx context.Context, unit string) error {
	if err := CheckUnitName(unit); err != nil {
		return err
	}
	_, err := s.run(ctx, "kill", "--kill-whom=main", "-s", "SIGKILL", unit)
	return err
}

// Show reads the unit properties the supervisor compares with the kernel's
// view. It never consults a cache.
func (s *ExecSystemctl) Show(ctx context.Context, unit string) (UnitStatus, error) {
	if err := CheckUnitName(unit); err != nil {
		return UnitStatus{}, err
	}
	out, err := s.run(ctx, "show",
		"-p", "MainPID",
		"-p", "ControlGroup",
		"-p", "ActiveState",
		"-p", "SubState",
		"-p", "FragmentPath",
		"-p", "ExecMainStartTimestamp",
		"-p", "ExecStart",
		unit,
	)
	if err != nil {
		return UnitStatus{}, err
	}
	return parseUnitStatus(out)
}

// run executes one systemctl command with the configured timeout.
func (s *ExecSystemctl) run(ctx context.Context, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultSystemctlTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := runnerOr(s.Runner).Run(ctx, "systemctl", args...)
	if err == nil {
		return out, nil
	}
	cmd := "systemctl " + strings.Join(args, " ")
	if ctx.Err() != nil {
		return out, fmt.Errorf("%s: %w", cmd, ctx.Err())
	}
	if out == "" {
		return out, fmt.Errorf("%s: %w%s", cmd, err, authorizationHint(out, err))
	}
	return out, fmt.Errorf("%s: %w: %s%s", cmd, err, out, authorizationHint(out, err))
}

// authorizationDeniedPattern matches systemd's replies when the caller is not
// authorized for the action. The raw message ("Interactive authentication
// required", "Access denied") otherwise sends operators looking for a unit
// fault.
var authorizationDeniedPattern = regexp.MustCompile(`(?i)(interactive authentication required|authentication is required|access denied|not authorized)`)

// authorizationHint explains a refusal that names an authorization decision
// rather than a unit fault, and is empty for every other failure. Ubuntu 22.04
// (polkit 0.105) and a host without polkit deny every unit action of the qwq
// user this way; an enforcing SELinux policy can answer the same (PRIV-06).
func authorizationHint(out string, err error) string {
	msg := out
	if err != nil {
		msg += " " + err.Error()
	}
	if !authorizationDeniedPattern.MatchString(msg) {
		return ""
	}
	return "; the host did not authorize this user to manage plugin units (polkit, or SELinux on an enforcing host); " +
		"run `qwq doctor` and check sandbox-polkit and selinux"
}

// parseUnitStatus parses `systemctl show -p ...` output. The five core
// properties must be present, even when their value is empty: a truncated
// output would otherwise look like a unit with no MainPID. The start timestamp
// is optional because older systemd versions and never-started units omit it.
func parseUnitStatus(out string) (UnitStatus, error) {
	var st UnitStatus
	seen := make(map[string]bool, 5)
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok {
			continue
		}
		switch key {
		case "MainPID":
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 {
				return UnitStatus{}, fmt.Errorf("sandbox: systemctl show returned MainPID=%q", val)
			}
			st.MainPID = n
			seen[key] = true
		case "ControlGroup":
			st.ControlGroup = val
			seen[key] = true
		case "ActiveState":
			st.ActiveState = val
			seen[key] = true
		case "SubState":
			st.SubState = val
			seen[key] = true
		case "FragmentPath":
			st.FragmentPath = val
			seen[key] = true
		case "ExecMainStartTimestamp":
			st.StartTime = parseStartTimestamp(val)
		case "ExecStart":
			st.ExecStart = parseExecStartPath(val)
		}
	}
	for _, key := range []string{"MainPID", "ControlGroup", "ActiveState", "SubState", "FragmentPath"} {
		if !seen[key] {
			return UnitStatus{}, fmt.Errorf("sandbox: systemctl show output has no %s property", key)
		}
	}
	return st, nil
}

// parseExecStartPath extracts path= from systemd's ExecStart property,
// "{ path=/x/y ; argv[]=/x/y ... ; ... }". Anything else yields "".
func parseExecStartPath(v string) string {
	_, rest, ok := strings.Cut(v, "path=")
	if !ok {
		return ""
	}
	path, _, _ := strings.Cut(rest, " ;")
	return strings.TrimSpace(path)
}

// parseStartTimestamp parses systemd's ExecMainStartTimestamp,
// "Mon 2026-11-01 20:42:59 CST", in the host's local time zone (systemd
// formats the timestamp in local time; the time zone abbreviation is dropped
// because time.Parse would treat an unknown abbreviation as UTC).
//
// Any unparseable value yields the zero time instead of an error: losing the
// timestamp weakens PID-reuse detection but must not make the unit
// unobservable, and systemd has no machine-readable variant of this property.
func parseStartTimestamp(v string) time.Time {
	fields := strings.Fields(v)
	if len(fields) < 3 {
		return time.Time{}
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", fields[1]+" "+fields[2], time.Local)
	if err != nil {
		return time.Time{}
	}
	return t
}
