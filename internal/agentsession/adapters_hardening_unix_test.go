// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package agentsession

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRealCLIProcessIsolationNoHostHomeOrSentinel proves OSProcessLauncher:
//  1. Never exposes host HOME / XDG_* / CODEX_HOME / CLAUDE_CONFIG_DIR / QWQ_MASTER_KEY;
//  2. When running as root (euid==0), automatically drops to an unprivileged
//     UID/GID by default so an external CLI CANNOT read a 0600 root-owned host
//     sentinel file EVEN BY EXACT ABSOLUTE PATH;
//  3. Allows the child to use its own private 0700 HOME and deletes it on Close.
func TestRealCLIProcessIsolationNoHostHomeOrSentinel(t *testing.T) {
	hostFakeHome := t.TempDir()
	// Make parent dir traversable (0755) while keeping sentinel strictly 0600
	// so the test proves UID isolation (not accidental dir traversal block).
	_ = os.Chmod(hostFakeHome, 0o755)
	sentinel := filepath.Join(hostFakeHome, "sentinel.secret")
	if err := os.WriteFile(sentinel, []byte("HOST_0600_SENTINEL_DATA"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	t.Setenv("HOME", hostFakeHome)
	t.Setenv("XDG_CONFIG_HOME", hostFakeHome)
	t.Setenv("CODEX_HOME", hostFakeHome)
	t.Setenv("CLAUDE_CONFIG_DIR", hostFakeHome)
	t.Setenv("QWQ_MASTER_KEY", "SUPER_SECRET_HOST_KEY")

	launcher := OSProcessLauncher{DisableConcurrencyGate: true}
	script := `
printf "EUID=%s\n" "$(id -u)"
printf "HOME=%s\nXDG=%s\nCODEX=%s\nCLAUDE=%s\nMASTER=%s\n" "$HOME" "$XDG_CONFIG_HOME" "$CODEX_HOME" "$CLAUDE_CONFIG_DIR" "${QWQ_MASTER_KEY:-EMPTY}"
printf "HOME_READ=%s\n" "$(cat "$HOME/sentinel.secret" 2>/dev/null || echo BLOCKED)"
printf "ABS_READ=%s\n" "$(cat "$1" 2>/dev/null || echo ABS_BLOCKED)"
echo "private-ok" > "$HOME/work.tmp" && printf "PRIVATE_WRITE=%s\n" "$(cat "$HOME/work.tmp")"
`
	proc, err := launcher.Start(context.Background(), "/bin/sh", []string{"-c", script, "sh", sentinel}, nil, "")
	if err != nil {
		t.Fatalf("launcher.Start: %v", err)
	}
	isoHome := proc.IsolatedHome()
	outBytes, _ := io.ReadAll(proc.Stdout())
	_ = proc.Close(500 * time.Millisecond)

	out := string(outBytes)
	if strings.Contains(out, hostFakeHome) {
		t.Fatalf("child inherited host home path %q:\n%s", hostFakeHome, out)
	}
	if strings.Contains(out, "HOST_0600_SENTINEL_DATA") || strings.Contains(out, "SUPER_SECRET_HOST_KEY") {
		t.Fatalf("child saw host secret:\n%s", out)
	}
	if !strings.Contains(out, "HOME_READ=BLOCKED") || !strings.Contains(out, "MASTER=EMPTY") || !strings.Contains(out, "PRIVATE_WRITE=private-ok") {
		t.Fatalf("unexpected isolation output:\n%s", out)
	}
	if os.Geteuid() == 0 {
		if strings.Contains(out, "EUID=0\n") {
			t.Fatalf("expected default privilege drop from root (euid!=0):\n%s", out)
		}
		if !strings.Contains(out, "ABS_READ=ABS_BLOCKED") {
			t.Fatalf("root-dropped child unexpectedly read 0600 absolute sentinel:\n%s", out)
		}
	}
	if isoHome == "" {
		t.Fatal("expected non-empty IsolatedHome")
	}
	if _, err := os.Stat(isoHome); !os.IsNotExist(err) {
		t.Fatalf("isolated home %q was not removed after Close (err=%v)", isoHome, err)
	}
}

// TestRealCLIProcessGroupReapsTermIgnoringDescendantAndInheritedPipe proves:
//  1. Explicit Close & ctx cancel kill a SIGTERM-ignoring parent + forked descendant holding stderr;
//  2. Even when the main parent PID exits cleanly FIRST while leaving a
//     SIGTERM-ignoring descendant holding stderr open, Close() kills and reaps
//     the descendant BEFORE returning, removing isolatedHome, or releasing quota.
func TestRealCLIProcessGroupReapsTermIgnoringDescendantAndInheritedPipe(t *testing.T) {
	runCase := func(t *testing.T, mode string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		launcher := OSProcessLauncher{
			GracePeriod:            120 * time.Millisecond,
			DisableConcurrencyGate: true,
		}
		var script string
		if mode == "parent_exits_first" {
			// Fork a SIGTERM-ignoring descendant holding stderr open, print its PID,
			// and let the main parent shell exit 0 immediately!
			script = `/bin/sh -c 'trap "" TERM; while true; do sleep 1; done' </dev/null >/dev/null & child=$!; echo "CHILD_PID=$child"; exit 0`
		} else {
			script = `trap '' TERM; sleep 60 & child=$!; echo "CHILD_PID=$child"; while true; do sleep 1; done`
		}

		proc, err := launcher.Start(ctx, "/bin/sh", []string{"-c", script}, nil, "")
		if err != nil {
			t.Fatalf("launcher.Start: %v", err)
		}
		isoHome := proc.IsolatedHome()

		sc := bufio.NewScanner(proc.Stdout())
		if !sc.Scan() {
			_ = proc.Close(100 * time.Millisecond)
			t.Fatalf("failed to read child PID line: %v", sc.Err())
		}
		pidStr := strings.TrimPrefix(strings.TrimSpace(sc.Text()), "CHILD_PID=")
		childPID, err := strconv.Atoi(pidStr)
		if err != nil || childPID <= 0 {
			_ = proc.Close(100 * time.Millisecond)
			t.Fatalf("invalid child PID line %q", sc.Text())
		}

		if mode == "parent_exits_first" {
			// Give parent time to exit cleanly while descendant stays alive.
			time.Sleep(100 * time.Millisecond)
			if err := syscall.Kill(childPID, 0); err != nil {
				t.Fatalf("expected descendant %d still alive before Close, got err=%v", childPID, err)
			}
		}

		start := time.Now()
		if mode == "ctx_cancel" {
			cancel()
			time.Sleep(300 * time.Millisecond)
			_ = proc.Close(120 * time.Millisecond)
		} else {
			_ = proc.Close(120 * time.Millisecond)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("reap took too long: %v", elapsed)
		}

		// Close() must not return until the process group is confirmed dead.
		if err := syscall.Kill(childPID, 0); err != syscall.ESRCH {
			_ = syscall.Kill(childPID, syscall.SIGKILL)
			t.Fatalf("descendant PID %d survived Close (kill -0 err=%v)", childPID, err)
		}
		if _, err := os.Stat(isoHome); !os.IsNotExist(err) {
			t.Fatalf("isolated home %q still exists after close", isoHome)
		}
	}

	t.Run("explicit Close", func(t *testing.T) { runCase(t, "explicit") })
	t.Run("context cancel", func(t *testing.T) { runCase(t, "ctx_cancel") })
	t.Run("parent exits first with surviving descendant", func(t *testing.T) { runCase(t, "parent_exits_first") })
}
