// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/buildinfo"
)

// asRoot makes geteuid report 0 for the duration of the test. The test process
// itself stays unprivileged; only paths that need real root are avoided.
func asRoot(t *testing.T) {
	t.Helper()
	old := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = old })
}

// asUnprivileged makes geteuid report a normal user.
func asUnprivileged(t *testing.T) {
	t.Helper()
	old := geteuid
	geteuid = func() int { return 1000 }
	t.Cleanup(func() { geteuid = old })
}

// runForTest runs the command with no systemd environment and a discard logger.
func runForTest(t *testing.T, args []string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	logger := slog.New(slog.DiscardHandler)
	code = run(context.Background(), args, &out, &errb, func(string) string { return "" }, logger)
	return code, out.String(), errb.String()
}

func TestActivatedFDCount(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	const pid = 4242
	tests := []struct {
		name    string
		env     map[string]string
		want    int
		wantErr bool
	}{
		{name: "no systemd environment", env: nil, want: 0},
		{name: "one descriptor", env: map[string]string{"LISTEN_FDS": "1", "LISTEN_PID": "4242"}, want: 1},
		{name: "one descriptor without pid", env: map[string]string{"LISTEN_FDS": "1"}, want: 1},
		{name: "zero descriptors", env: map[string]string{"LISTEN_FDS": "0", "LISTEN_PID": "4242"}, want: 0},
		{name: "two descriptors", env: map[string]string{"LISTEN_FDS": "2", "LISTEN_PID": "4242"}, wantErr: true},
		{name: "not a number", env: map[string]string{"LISTEN_FDS": "one"}, wantErr: true},
		{name: "negative", env: map[string]string{"LISTEN_FDS": "-1"}, wantErr: true},
		{name: "foreign pid", env: map[string]string{"LISTEN_FDS": "1", "LISTEN_PID": "1"}, wantErr: true},
		{name: "pid not a number", env: map[string]string{"LISTEN_FDS": "1", "LISTEN_PID": "x"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := activatedFDCount(env(tc.env), pid)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("activatedFDCount(%v) = %d, want an error", tc.env, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("activatedFDCount(%v) = %d, %v; want %d, nil", tc.env, got, err, tc.want)
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	code, _, stderr := runForTest(t, []string{"-h"})
	if code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stderr, "usage: qwq-privileged") {
		t.Errorf("help does not print the usage:\n%s", stderr)
	}
}

func TestRunRefusesNonRoot(t *testing.T) {
	asUnprivileged(t)
	code, _, stderr := runForTest(t, nil)
	if code != 1 || !strings.Contains(stderr, "must run as root") {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
}

func TestRunRejectsUnexpectedArgument(t *testing.T) {
	asRoot(t)
	code, _, stderr := runForTest(t, []string{"install"})
	if code != 2 || !strings.Contains(stderr, `unexpected argument "install"`) {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
}

func TestRunRejectsRelativeSocket(t *testing.T) {
	asRoot(t)
	code, _, stderr := runForTest(t, []string{"--socket", "relative.sock"})
	if code != 1 || !strings.Contains(stderr, "not absolute") {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	asRoot(t)
	code, _, _ := runForTest(t, []string{"--bogus"})
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

// TestPingReportsBuildVersion: the helper reports the release version injected
// into buildinfo, the same one `qwq version` shows (DEP-03), not a private one.
func TestPingReportsBuildVersion(t *testing.T) {
	old := buildinfo.Version
	buildinfo.Version = "v9.8.7"
	t.Cleanup(func() { buildinfo.Version = old })
	if got := defaultHelperConfig().Version; got != "v9.8.7" {
		t.Fatalf("ping version = %q, want the buildinfo version v9.8.7", got)
	}
}
