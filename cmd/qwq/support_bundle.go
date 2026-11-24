// SPDX-License-Identifier: AGPL-3.0-only

package main

// =============================================================================
//  qwq support-bundle —— 收集排障信息（DEP-05）
// -----------------------------------------------------------------------------
//  内容：doctor.json、最近 1 小时 qwq* 日志、qwq unit 文件、脱敏后的
//  qwq.json、buildinfo。日志与配置按 logging 的敏感键表及 URL/前缀脱敏；归档 0600。
// =============================================================================

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/doctor"
	"github.com/qwq-panel/qwq/internal/hostbackup"
	"github.com/qwq-panel/qwq/internal/panelaccess"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/storage"
)

// bundleSources are what a bundle collects; tests replace them.
type bundleSources struct {
	Doctor     func(ctx context.Context) []doctor.Result
	Journal    func(ctx context.Context) (string, error)
	ConfigPath string
	// EntryPath optionally provides the live secret entry path to redact from logs.
	EntryPath string
	// UnitGlobs list the unit files and drop-ins to include.
	UnitGlobs []string
}

func runSupportBundle(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("support-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output file (.tar.gz, created 0600; must not exist)")
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "qwq support-bundle: --out is required")
		return 2
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "qwq support-bundle: must run as root (use sudo)")
		return 1
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "qwq support-bundle: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	liveEntryPath := ""
	if cfg, cerr := config.Load(*configPath); cerr == nil {
		dbPath := filepath.Join(cfg.DataDir, hostbackup.BackupDBName)
		if _, serr := os.Stat(dbPath); serr == nil {
			if db, oerr := storage.Open(ctx, storage.Options{Path: dbPath, NoMigrate: true}); oerr == nil {
				_, _, rawEP, _, _ := panelaccess.ReadEffectiveFromDB(ctx, db, cfg.HTTP)
				liveEntryPath = rawEP
				_ = db.Close()
			}
		}
	}
	src := bundleSources{
		Doctor: func(ctx context.Context) []doctor.Result {
			return collectDoctor(ctx, doctor.System(), doctorOptions{ConfigPath: *configPath, Sandbox: true})
		},
		Journal: func(ctx context.Context) (string, error) {
			out, err := exec.CommandContext(ctx, "journalctl", "-u", "qwq*", "--since", "-1h", "-n", "5000", "--no-pager", "-o", "short-iso").Output()
			return string(out), err
		},
		ConfigPath: *configPath,
		EntryPath:  liveEntryPath,
		UnitGlobs: []string{
			"/etc/systemd/system/qwq-*.service", "/etc/systemd/system/qwq-*.socket",
			"/etc/systemd/system/qwq-*.service.d/*.conf", "/etc/tmpfiles.d/qwq-plugin-*.conf",
		},
	}
	werr := writeSupportBundle(ctx, f, src)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(*out)
		fmt.Fprintf(stderr, "qwq support-bundle: %v\n", werr)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s\n", *out)
	return 0
}

// writeSupportBundle writes the gzip-compressed tar to w. A source that fails
// is recorded in errors.txt instead of aborting the bundle.
func writeSupportBundle(ctx context.Context, w io.Writer, src bundleSources) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now()
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	var problems []string

	entryPath := strings.Trim(strings.TrimSpace(src.EntryPath), "/")
	rawCfg, cfgErr := os.ReadFile(src.ConfigPath)
	if cfgErr == nil && entryPath == "" {
		entryPath = hostbackup.ExtractEntryPathFromConfig(rawCfg)
	}

	rs, err := json.MarshalIndent(src.Doctor(ctx), "", "  ")
	if err != nil {
		return err
	}
	if err := add("doctor.json", rs); err != nil {
		return err
	}
	journal, err := src.Journal(ctx)
	if err != nil {
		problems = append(problems, "journal: "+err.Error())
	}
	if err := add("journal.txt", []byte(hostbackup.RedactLog(journal, entryPath))); err != nil {
		return err
	}
	if cfgErr != nil {
		problems = append(problems, "config: "+cfgErr.Error())
	} else if err := add("qwq.json", hostbackup.RedactJSONDocument(rawCfg, entryPath)); err != nil {
		return err
	}
	for _, pattern := range src.UnitGlobs {
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				problems = append(problems, f+": "+err.Error())
				continue
			}
			if err := add("units/"+strings.TrimPrefix(f, "/"), []byte(hostbackup.RedactLog(string(b), entryPath))); err != nil {
				return err
			}
		}
	}
	if err := add("buildinfo.txt", []byte(buildinfo.Read().String()+"\n")); err != nil {
		return err
	}
	if len(problems) > 0 {
		if err := add("errors.txt", []byte(strings.Join(problems, "\n")+"\n")); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
