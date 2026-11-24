// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/config"
)

// runRecover implements the root-only `qwq recover` command (ARCH §4.1.1):
// reset an administrator's password, disable their second factor, revoke their
// sessions and delegations, and record the action in the audit log. It opens
// only the services it needs and never starts the HTTP listener.
func runRecover(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	username := fs.String("username", "", "administrator login name")
	passwordStdin := fs.Bool("password-stdin", false, "read the new password from the first line of stdin")
	reason := fs.String("reason", "qwq recover on the console", "reason recorded in the audit log")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "qwq recover: 不接受多余位置参数 %q\n", strings.Join(fs.Args(), " "))
		return 2
	}
	interactive := isTerminalReader(stdin)
	var (
		targetUser = strings.TrimSpace(*username)
		password   string
		err        error
	)
	if interactive && *passwordStdin {
		fmt.Fprintln(stderr, "qwq recover: --password-stdin 仅适用于管道/重定向输入；交互式终端请省略 --password-stdin")
		return 2
	}
	if !interactive {
		if targetUser == "" || !*passwordStdin {
			fmt.Fprintln(stderr, "qwq recover: --username and --password-stdin are required")
			return 2
		}
		password, err = readPassword(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "qwq recover: %v\n", err)
			return 2
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq recover: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	logger = logger.With("service", "recover")

	local, closeDB, err := openLocalDatabase(ctx, cfg, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq recover: %v\n", err)
		return 1
	}
	defer closeDB()

	if interactive {
		reader := bufio.NewReader(stdin)
		if targetUser == "" {
			fmt.Fprint(stdout, "请输入要恢复的管理员用户名 [默认 admin]: ")
			line, rerr := reader.ReadString('\n')
			if rerr != nil && len(line) == 0 {
				fmt.Fprintf(stderr, "qwq recover: 未读取到用户名输入\n")
				return 2
			}
			targetUser = strings.TrimSpace(line)
			if targetUser == "" {
				targetUser = "admin"
			}
		}
		password, err = readInteractivePassword(reader, stdout)
		if err != nil {
			fmt.Fprintf(stderr, "qwq recover: %v\n", err)
			return 2
		}
	}
	id := local.Identity
	az, err := authz.New(authz.Options{DB: local.DB, Clock: local.Clock, Logger: logger, Principals: id})
	if err != nil {
		fmt.Fprintf(stderr, "qwq recover: authz: %v\n", err)
		return 1
	}

	user, err := id.ResetAdmin(ctx, identity.ResetAdminInput{
		Username: targetUser,
		Password: password,
		Reason:   *reason,
	})
	if err != nil {
		fmt.Fprintf(stderr, "qwq recover: %v\n", err)
		return 1
	}
	revoked, err := az.RevokeDelegationsOf(ctx, user.ID)
	if err != nil {
		fmt.Fprintf(stderr, "qwq recover: administrator reset, but revoking delegations failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "administrator %s reset; second factor disabled; sessions revoked; %d delegation(s) revoked\n", user.Username, revoked)
	return 0
}

func isTerminalReader(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func readInteractivePassword(br *bufio.Reader, out io.Writer) (string, error) {
	restoreEcho := disableTerminalEcho()
	defer restoreEcho()
	fmt.Fprint(out, "请输入新密码（至少 12 位，不回显）: ")
	p1, err := br.ReadString('\n')
	fmt.Fprintln(out)
	if err != nil && len(p1) == 0 {
		return "", fmt.Errorf("read password: %w", err)
	}
	p1 = strings.TrimRight(p1, "\r\n")
	if p1 == "" {
		return "", fmt.Errorf("empty password")
	}
	fmt.Fprint(out, "请再次输入新密码确认: ")
	p2, err := br.ReadString('\n')
	fmt.Fprintln(out)
	if err != nil && len(p2) == 0 {
		return "", fmt.Errorf("read password confirmation: %w", err)
	}
	if p1 != strings.TrimRight(p2, "\r\n") {
		return "", fmt.Errorf("两次输入的密码不一致")
	}
	return p1, nil
}

func disableTerminalEcho() func() {
	if runtime.GOOS == "windows" {
		return func() {}
	}
	cmd := exec.Command("stty", "-echo")
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return func() {}
	}
	var once sync.Once
	restoreNow := func() {
		once.Do(func() {
			restore := exec.Command("stty", "echo")
			restore.Stdin = os.Stdin
			_ = restore.Run()
		})
	}
	sigCh := make(chan os.Signal, 2)
	doneCh := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			restoreNow()
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-doneCh:
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(doneCh)
		restoreNow()
	}
}

// readPassword reads one line without echoing. The command expects the caller
// to feed it over a pipe (SSH console, password manager) so the secret never
// appears in argv or the process list.
func readPassword(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return "", fmt.Errorf("empty password")
	}
	if strings.ContainsAny(s, "\r\n") {
		return "", fmt.Errorf("password must be one line")
	}
	return s, nil
}
