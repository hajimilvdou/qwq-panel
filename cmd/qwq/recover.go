// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
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
	if *username == "" || !*passwordStdin {
		fmt.Fprintln(stderr, "qwq recover: --username and --password-stdin are required")
		return 2
	}
	password, err := readPassword(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "qwq recover: %v\n", err)
		return 2
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
	id := local.Identity
	az, err := authz.New(authz.Options{DB: local.DB, Clock: local.Clock, Logger: logger, Principals: id})
	if err != nil {
		fmt.Fprintf(stderr, "qwq recover: authz: %v\n", err)
		return 1
	}

	user, err := id.ResetAdmin(ctx, identity.ResetAdminInput{
		Username: *username,
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
