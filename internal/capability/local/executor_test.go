// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCapabilityToolChild(t *testing.T) {
	if len(os.Args) == 0 || !strings.HasPrefix(os.Args[len(os.Args)-1], "--capability-test-child=") {
		return
	}
	kind := strings.TrimPrefix(os.Args[len(os.Args)-1], "--capability-test-child=")
	switch kind {
	case "output":
		for i := 0; i < maxToolOutput/1024+100; i++ {
			fmt.Fprint(os.Stdout, strings.Repeat("x", 1024))
		}
	case "wait":
		time.Sleep(10 * time.Second)
	case "stdin":
		raw, _ := io.ReadAll(io.LimitReader(os.Stdin, 8192))
		fmt.Fprint(os.Stdout, len(raw))
		clear(raw)
	}
	os.Exit(0)
}

func childProgram(t *testing.T, kind string) (string, []string) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path, []string{"-test.run=^TestCapabilityToolChild$", "--", "--capability-test-child=" + kind}
}

func TestToolLimitsAndStdin(t *testing.T) {
	program, args := childProgram(t, "output")
	result, err := runTool(t.Context(), program, args, nil)
	if err == nil || len(result.Output) != 0 {
		t.Fatal("unbounded tool output was accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	program, args = childProgram(t, "wait")
	if _, err := runTool(ctx, program, args, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled tool was executed")
	}
	ctx, cancel = context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	if _, err := runTool(ctx, program, args, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("running tool did not stop on deadline")
	}
	program, args = childProgram(t, "stdin")
	result, err = runTool(t.Context(), program, args, []byte("TEST-ONLY-stdin-material"))
	if err != nil || result.ExitCode != 0 || string(result.Output) != "24" {
		t.Fatalf("stdin tool failed: %v", err)
	}
	if _, err := toolPath(Tool("sh")); err == nil {
		t.Fatal("arbitrary program accepted")
	}
}
