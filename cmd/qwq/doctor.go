// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/doctor"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
)

// doctorDBCommand is the hidden subcommand that checks the database as the
// data directory's owner, so a root `qwq doctor` never creates root-owned
// -wal/-shm files.
const doctorDBCommand = "__doctor-db"

// doctorOptions are the parsed `qwq doctor` flags.
type doctorOptions struct {
	ConfigPath string
	DataDir    string
	Sandbox    bool
	Preinstall bool
}

// runDoctor prints the checks. Exit status: 0 ok, 1 warnings, 2 usage,
// 3 failures (doctor.ExitCode).
func runDoctor(args []string, env doctor.Env, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	var o doctorOptions
	fs.StringVar(&o.ConfigPath, "config", config.DefaultPath, "bootstrap configuration file")
	fs.StringVar(&o.DataDir, "data-dir", "", "data directory (default: data_dir from the configuration)")
	fs.BoolVar(&o.Sandbox, "sandbox", true, "include the plugin sandbox checks")
	fs.BoolVar(&o.Preinstall, "preinstall", false, "only the platform and port checks the installer runs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rs := collectDoctor(context.Background(), env, o)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rs)
	} else {
		printDoctor(stdout, rs)
	}
	return doctor.ExitCode(rs)
}

// collectDoctor runs the checks selected by o; support-bundle reuses it.
func collectDoctor(ctx context.Context, env doctor.Env, o doctorOptions) []doctor.Result {
	cfg, err := config.Load(o.ConfigPath)
	if err != nil {
		cfg = config.Default()
	}
	if o.DataDir == "" {
		o.DataDir = cfg.DataDir
	}
	rs := doctor.Run(ctx, env, doctor.Options{DataDir: o.DataDir})
	if o.Preinstall {
		return append(rs, doctor.CheckPorts(ctx, env, cfg.HTTP.Listen))
	}
	rs = append(rs, doctor.InstallChecks(ctx, env, doctor.InstallOptions{
		ConfigPath: o.ConfigPath,
		PingHelper: func(ctx context.Context) error {
			_, err := sandbox.NewHelperClient("/run/qwq/privileged.sock").Ping(ctx)
			return err
		},
		CheckDB: checkDatabase,
	})...)
	if o.Sandbox {
		rs = append(rs, doctor.SandboxChecks(env, doctor.SandboxOptions{RuntimeDir: cfg.RunDir, Unit: scoredUnit(env)})...)
	}
	return rs
}

func printDoctor(w io.Writer, rs []doctor.Result) {
	for _, r := range rs {
		fmt.Fprintf(w, "%-5s %-15s %s\n", r.Status, r.ID, r.Detail)
		if r.Fix != "" && r.Status != doctor.OK {
			fmt.Fprintf(w, "      %-15s -> %s\n", "", r.Fix)
		}
	}
}

// scoredUnit picks an installed plugin instance for `systemd-analyze
// security`; the template itself cannot be scored. Empty uses the default.
func scoredUnit(env doctor.Env) string {
	if env.Glob == nil {
		return ""
	}
	units, _ := env.Glob("/etc/systemd/system/qwq-plugin@?*.service")
	if len(units) == 0 {
		return ""
	}
	return filepath.Base(units[0])
}

// checkDatabase checks dataDir/qwq.db as the directory owner: in-process when
// we already are the owner, otherwise in a child process with its uid/gid.
func checkDatabase(ctx context.Context, dataDir string) doctor.Result {
	dbPath := filepath.Join(dataDir, "qwq.db")
	if _, err := os.Stat(dbPath); err != nil {
		return doctor.Result{ID: "database", Status: doctor.Fail, Detail: dbPath + " is missing",
			Fix: "systemctl start qwq-controller creates it on the first start"}
	}
	fi, err := os.Stat(dataDir)
	if err != nil {
		return doctor.Result{ID: "database", Status: doctor.Fail, Detail: err.Error()}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) == os.Geteuid() {
		return databaseResult(ctx, dbPath)
	}
	self, err := os.Executable()
	if err != nil {
		return doctor.Result{ID: "database", Status: doctor.Warn, Detail: "cannot locate the qwq binary: " + err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, doctorDBCommand, "--data-dir", dataDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: st.Uid, Gid: st.Gid}}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return doctor.Result{ID: "database", Status: doctor.Warn, Detail: "database check as the data owner failed: " + err.Error()}
	}
	var r doctor.Result
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return doctor.Result{ID: "database", Status: doctor.Warn, Detail: "unreadable database check output"}
	}
	return r
}

// runDoctorDB is the child half of checkDatabase.
func runDoctorDB(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(doctorDBCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "", "data directory")
	if err := fs.Parse(args); err != nil || *dataDir == "" {
		return 2
	}
	_ = json.NewEncoder(stdout).Encode(databaseResult(context.Background(), filepath.Join(*dataDir, "qwq.db")))
	return 0
}

// databaseResult opens the database without migrating it, then runs
// quick_check and reads the schema version.
func databaseResult(ctx context.Context, dbPath string) doctor.Result {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	db, err := storage.Open(ctx, storage.Options{Path: dbPath, ReadConns: 1, NoMigrate: true})
	if errors.Is(err, storage.ErrPendingMigrations) {
		return doctor.Result{ID: "database", Status: doctor.Warn, Detail: err.Error(),
			Fix: "systemctl restart qwq-controller applies the migrations of the installed version"}
	}
	if err != nil {
		return doctor.Result{ID: "database", Status: doctor.Fail, Detail: err.Error(),
			Fix: "restore the latest backup; see docs/operations"}
	}
	defer db.Close()
	if err := db.QuickCheck(ctx); err != nil {
		return doctor.Result{ID: "database", Status: doctor.Fail, Detail: err.Error(),
			Fix: "stop qwq-controller and restore the latest backup"}
	}
	v, err := db.SchemaVersion(ctx)
	if err != nil {
		return doctor.Result{ID: "database", Status: doctor.Warn, Detail: "schema version: " + err.Error()}
	}
	return doctor.Result{ID: "database", Status: doctor.OK, Detail: fmt.Sprintf("quick_check ok, schema version %d", v)}
}

// sandboxPreflight gates third-party plugin installs on the doctor sandbox
// checks (ARCH §10.2): any failed check refuses the install.
func sandboxPreflight(runDir string) func(ctx context.Context) error {
	return func(context.Context) error {
		rs := doctor.SandboxChecks(doctor.System(), doctor.SandboxOptions{RuntimeDir: runDir})
		if failed := preflightFailures(rs, os.Geteuid() == 0); len(failed) > 0 {
			// Not every failed check is about isolation: an unusable polkit
			// means the units could never be started at all (PRIV-06).
			return problem.New(problem.PreconditionFailed,
				"This host does not meet the plugin sandbox requirements (%s); run `qwq doctor` for fixes.", strings.Join(failed, "; "))
		}
		return nil
	}
}

// preflightFailures lists the failed sandbox checks that apply to this
// controller. polkit only decides for an unprivileged controller; a root one
// (development, tests) manages units directly and is not held to it.
func preflightFailures(rs []doctor.Result, root bool) []string {
	var failed []string
	for _, r := range rs {
		if r.Status != doctor.Fail || (root && r.ID == doctor.SandboxPolkitID) {
			continue
		}
		failed = append(failed, r.ID+": "+r.Detail)
	}
	return failed
}
