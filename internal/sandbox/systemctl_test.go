// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSystemctlCommands(t *testing.T) {
	ctx := context.Background()
	fr := &fakeRunner{}
	s := NewExecSystemctl(fr)
	const unit = "qwq-plugin@alpha.service"
	if err := s.Start(ctx, unit); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !fr.has("systemctl", "start", unit) {
		t.Errorf("Start did not call systemctl start: %v", fr.calls)
	}
	if err := s.Stop(ctx, unit); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !fr.has("systemctl", "stop", unit) {
		t.Errorf("Stop did not call systemctl stop: %v", fr.calls)
	}
	if err := s.Kill(ctx, unit); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if !fr.has("systemctl", "kill", "--kill-whom=main", "-s", "SIGKILL", unit) {
		t.Errorf("Kill did not use --kill-whom=main -s SIGKILL: %v", fr.calls)
	}
}

func TestSystemctlShowParses(t *testing.T) {
	const out = "MainPID=4242\nControlGroup=/system.slice/qwq-plugin@alpha.service\n" +
		"ActiveState=active\nSubState=running\nFragmentPath=/etc/systemd/system/qwq-plugin@alpha.service\n" +
		"ExecMainStartTimestamp=Sun 2026-11-01 20:42:59 CST\n" +
		"ExecStart={ path=/var/lib/qwq-plugins/alpha/1.0.0/bin/plugin ; argv[]=/var/lib/qwq-plugins/alpha/1.0.0/bin/plugin ; ignore_errors=no ; pid=0 }\n"
	fr := &fakeRunner{reply: func(string, []string) (string, error) { return out, nil }}
	s := NewExecSystemctl(fr)
	st, err := s.Show(context.Background(), "qwq-plugin@alpha.service")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if st.MainPID != 4242 || st.ControlGroup != "/system.slice/qwq-plugin@alpha.service" ||
		st.ActiveState != "active" || st.SubState != "running" ||
		st.FragmentPath != "/etc/systemd/system/qwq-plugin@alpha.service" {
		t.Errorf("Show = %+v", st)
	}
	want := time.Date(2026, 11, 1, 20, 42, 59, 0, time.Local)
	if !st.StartTime.Equal(want) {
		t.Errorf("StartTime = %v, want %v", st.StartTime, want)
	}
	if st.ExecStart != "/var/lib/qwq-plugins/alpha/1.0.0/bin/plugin" {
		t.Errorf("ExecStart = %q", st.ExecStart)
	}
	if !fr.has("systemctl", "show", "-p", "MainPID", "-p", "ControlGroup", "-p", "ActiveState",
		"-p", "SubState", "-p", "FragmentPath", "-p", "ExecMainStartTimestamp", "-p", "ExecStart", "qwq-plugin@alpha.service") {
		t.Errorf("Show used unexpected arguments: %v", fr.calls)
	}
}

// TestSystemctlShowInactive pins the socket-activation case: a unit with no
// process reports MainPID=0 and empty values, and that must not be an error.
func TestSystemctlShowInactive(t *testing.T) {
	const out = "MainPID=0\nControlGroup=\nActiveState=inactive\nSubState=dead\nFragmentPath=\n" +
		"ExecMainStartTimestamp=\n"
	fr := &fakeRunner{reply: func(string, []string) (string, error) { return out, nil }}
	st, err := NewExecSystemctl(fr).Show(context.Background(), "qwq-plugin@alpha.service")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if st.MainPID != 0 || st.ControlGroup != "" || st.ActiveState != "inactive" ||
		st.SubState != "dead" || st.FragmentPath != "" {
		t.Errorf("Show = %+v", st)
	}
	if !st.StartTime.IsZero() {
		t.Errorf("StartTime = %v, want the zero time", st.StartTime)
	}
}

func TestParseStartTimestamp(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Time
	}{
		{"Sun 2026-11-01 20:42:59 CST", time.Date(2026, 11, 1, 20, 42, 59, 0, time.Local)},
		{"Mon 2026-11-02 01:00:00 BST", time.Date(2026, 11, 2, 1, 0, 0, 0, time.Local)},
		{"", time.Time{}},
		{"n/a", time.Time{}},
		{"garbage", time.Time{}},
		{"Sun 2026-13-01 20:42:59 CST", time.Time{}},
	} {
		if got := parseStartTimestamp(c.in); !got.Equal(c.want) {
			t.Errorf("parseStartTimestamp(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSystemctlShowErrors(t *testing.T) {
	for _, c := range []struct {
		name string
		out  string
		err  error
	}{
		{"missing property", "MainPID=1\nControlGroup=/x\nActiveState=active\nSubState=running\n", nil},
		{"bad main pid", "MainPID=abc\nControlGroup=\nActiveState=active\nSubState=running\nFragmentPath=\n", nil},
		{"negative main pid", "MainPID=-1\nControlGroup=\nActiveState=active\nSubState=running\nFragmentPath=\n", nil},
		{"systemctl fails", "Unit missing.service could not be found.", errors.New("exit status 1")},
	} {
		fr := &fakeRunner{reply: func(string, []string) (string, error) { return c.out, c.err }}
		_, err := NewExecSystemctl(fr).Show(context.Background(), "qwq-plugin@alpha.service")
		if err == nil {
			t.Errorf("%s: Show accepted the output", c.name)
			continue
		}
		if c.err != nil && !strings.Contains(err.Error(), "could not be found") {
			t.Errorf("%s: error does not carry systemctl output: %v", c.name, err)
		}
	}
}

func TestSystemctlRejectsUnitNames(t *testing.T) {
	fr := &fakeRunner{}
	s := NewExecSystemctl(fr)
	for _, unit := range []string{
		"", "--help", "-s", "qwq-plugin@alpha", "qwq-plugin@alpha.service; rm -rf /",
		"../qwq-plugin@alpha.service", "qwq-plugin@alpha.exe", "a b.service",
	} {
		if err := s.Start(context.Background(), unit); err == nil {
			t.Errorf("Start accepted unit %q", unit)
		}
		if _, err := s.Show(context.Background(), unit); err == nil {
			t.Errorf("Show accepted unit %q", unit)
		}
	}
	if fr.count() != 0 {
		t.Errorf("invalid unit names reached systemctl: %v", fr.calls)
	}
	if err := CheckUnitName("qwq-plugin@security.scan.socket"); err != nil {
		t.Errorf("CheckUnitName rejected a valid unit: %v", err)
	}
}

// A polkit refusal must read as an authorization problem, not as a unit fault:
// on Ubuntu 22.04 (polkit 0.105) every systemctl call from the qwq user is
// denied with "Interactive authentication required" (PRIV-06).
func TestSystemctlAuthorizationHint(t *testing.T) {
	fr := &fakeRunner{reply: func(string, []string) (string, error) {
		return "Failed to start qwq-plugin@alpha.service: Interactive authentication required.", errors.New("exit status 1")
	}}
	err := NewExecSystemctl(fr).Start(context.Background(), "qwq-plugin@alpha.service")
	if err == nil || !strings.Contains(err.Error(), "polkit") || !strings.Contains(err.Error(), "qwq doctor") {
		t.Fatalf("Start error = %v", err)
	}
	// An ordinary unit fault keeps its message free of the hint.
	fr = &fakeRunner{reply: func(string, []string) (string, error) {
		return "Failed to start qwq-plugin@alpha.service: Unit not found.", errors.New("exit status 1")
	}}
	err = NewExecSystemctl(fr).Start(context.Background(), "qwq-plugin@alpha.service")
	if err == nil || strings.Contains(err.Error(), "polkit") {
		t.Fatalf("Start error = %v", err)
	}
}

// blockingRunner waits for its context, so the timeout test measures the
// client's own deadline rather than the fake's cooperation.
type blockingRunner struct{}

func (blockingRunner) Run(ctx context.Context, _ string, _ ...string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func TestSystemctlTimeout(t *testing.T) {
	s := &ExecSystemctl{Runner: blockingRunner{}, Timeout: 20 * time.Millisecond}
	start := time.Now()
	err := s.Start(context.Background(), "qwq-plugin@alpha.service")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Start took %v, the timeout is 20ms", elapsed)
	}
}

func TestSystemctlHonoursCallerContext(t *testing.T) {
	s := NewExecSystemctl(blockingRunner{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := s.Show(ctx, "qwq-plugin@alpha.service")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Show error = %v, want context.DeadlineExceeded", err)
	}
}
