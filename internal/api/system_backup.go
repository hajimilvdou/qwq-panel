// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/hostbackup"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
)

type systemBackupListDTO struct {
	Items []hostbackup.BackupEntry `json:"items"`
}

func (a *api) backupDir() string {
	return storage.BackupDir(filepath.Join(a.d.Config.DataDir, hostbackup.BackupDBName))
}

func (a *api) configFilePath() string {
	if strings.TrimSpace(a.d.ConfigPath) != "" {
		return a.d.ConfigPath
	}
	return config.DefaultPath
}

func (a *api) privilegedSocketPath() string {
	if strings.TrimSpace(a.d.PrivilegedSocket) != "" {
		return a.d.PrivilegedSocket
	}
	return sandbox.DefaultPrivilegedSocket
}

// listSystemBackups implements GET /api/v1/system/backups (administrators only).
func (a *api) listSystemBackups(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	items, err := hostbackup.ListBackups(a.backupDir())
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	a.writeResource(w, r, http.StatusOK, systemBackupListDTO{Items: items}, nil)
}

// createSystemBackup implements POST /api/v1/system/backups (administrators only).
func (a *api) createSystemBackup(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	a.backupMu.Lock()
	defer a.backupMu.Unlock()

	rawCfg, err := os.ReadFile(a.configFilePath())
	if err != nil {
		// Tests or ephemeral hosts without a config file on disk fall back to
		// the loaded runtime Config JSON.
		rawCfg, err = json.MarshalIndent(a.d.Config, "", "  ")
		if err != nil {
			a.fail(w, r, problem.Wrap(err))
			return
		}
	}
	dir := a.backupDir()
	bctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	entry, _, err := hostbackup.CreateBackup(bctx, hostbackup.CreateOptions{
		DataDir:      a.d.Config.DataDir,
		RawConfig:    rawCfg,
		OutDir:       dir,
		Now:          a.d.Clock.Now(),
		HelperSocket: a.privilegedSocketPath(),
	})
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	if perr := storage.PruneBackups(dir, hostbackup.BackupGlob, hostbackup.DefaultKeepBackups); perr != nil {
		a.d.Logger.WarnContext(r.Context(), "api: prune old backups failed", "error", perr)
	}
	details, _ := json.Marshal(map[string]any{
		"filename":   entry.Filename,
		"size_bytes": entry.SizeBytes,
	})
	_ = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor:     act,
			Action:    "system.backup.create",
			Subject:   "system/backups",
			Outcome:   operations.AuditSuccess,
			Details:   details,
			NodeID:    a.d.NodeID,
			TraceID:   gateway.TraceID(r.Context()),
			RequestID: requestID(r),
		})
	})
	a.writeResource(w, r, http.StatusCreated, entry, nil)
}

// downloadSystemBackup implements GET /api/v1/system/backups/{filename} (administrators only).
func (a *api) downloadSystemBackup(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	filename := strings.TrimSpace(r.PathValue("filename"))
	if !hostbackup.IsValidBackupFilename(filename) {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/filename",
			Code:    "INVALID_FORMAT",
			Message: "Backup filename must match qwq-<timestamp>.tar.gz.",
		}))
		return
	}
	root, err := os.OpenRoot(a.backupDir())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			a.fail(w, r, problem.New(problem.NotFound, "Backup archive %q was not found.", filename))
			return
		}
		a.fail(w, r, problem.Wrap(err))
		return
	}
	defer func() { _ = root.Close() }()
	lfi, err := root.Lstat(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			a.fail(w, r, problem.New(problem.NotFound, "Backup archive %q was not found.", filename))
			return
		}
		a.fail(w, r, problem.Wrap(err))
		return
	}
	if !lfi.Mode().IsRegular() || lfi.Mode()&fs.ModeSymlink != 0 {
		a.fail(w, r, problem.New(problem.NotFound, "Backup archive %q is not a regular file.", filename))
		return
	}
	f, err := root.Open(filename)
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	defer func() { _ = f.Close() }()

	dlDetails, _ := json.Marshal(map[string]any{
		"filename":   filename,
		"size_bytes": lfi.Size(),
	})
	_ = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor:     act,
			Action:    "system.backup.download",
			Subject:   "system/backups/" + filename,
			Outcome:   operations.AuditSuccess,
			Details:   dlDetails,
			NodeID:    a.d.NodeID,
			TraceID:   gateway.TraceID(r.Context()),
			RequestID: requestID(r),
		})
	})

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	w.Header().Set("Content-Length", strconv.FormatInt(lfi.Size(), 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

const maxSupportBundleJournalBytes = 4 << 20

// createSystemSupportBundle implements POST /api/v1/system/support-bundle (administrators only).
func (a *api) createSystemSupportBundle(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.requireAdmin(r.Context(), act); err != nil {
		a.fail(w, r, err)
		return
	}
	now := a.d.Clock.Now().UTC()
	entryPath := ""
	if a.d.Access != nil {
		entryPath = strings.Trim(strings.TrimSpace(a.d.Access.Snapshot().EntryPath), "/")
	}
	rawCfg, cfgErr := os.ReadFile(a.configFilePath())
	if cfgErr != nil {
		rawCfg, cfgErr = json.MarshalIndent(a.d.Config, "", "  ")
	}
	if cfgErr == nil && entryPath == "" {
		entryPath = hostbackup.ExtractEntryPathFromConfig(rawCfg)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Name:    name,
			Mode:    0o600,
			Size:    int64(len(data)),
			ModTime: now,
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	var problems []string
	info := buildinfo.Read()
	if err := add("buildinfo.txt", []byte(info.String()+"\n")); err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}

	sysSummary := map[string]any{
		"version":         info.Version,
		"commit":          info.Revision,
		"role":            a.d.Config.Role,
		"started_at":      ts(a.startedAt),
		"exported_at":     ts(now),
		"tls_mode":        a.d.Config.HTTP.TLS.Mode,
		"plugins_enabled": a.pluginsEnabled(r),
	}
	if a.d.TLS != nil {
		st := a.d.TLS.Status(r.Context())
		sysSummary["tls_ready"] = st.Ready
		sysSummary["tls_not_after"] = ts(st.NotAfter)
	}
	if rawSys, merr := json.MarshalIndent(sysSummary, "", "  "); merr == nil {
		if err := add("system.json", append(rawSys, '\n')); err != nil {
			a.fail(w, r, problem.Wrap(err))
			return
		}
	}

	if cfgErr != nil {
		problems = append(problems, "config: "+cfgErr.Error())
	} else if err := add("qwq.json", hostbackup.RedactJSONDocument(rawCfg, entryPath)); err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}

	jctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	jOut, jErr := runBoundedJournalctl(jctx, maxSupportBundleJournalBytes)
	cancel()
	if jErr != nil {
		problems = append(problems, "journal: "+jErr.Error())
	}
	if err := add("journal.txt", []byte(hostbackup.RedactLog(jOut, entryPath))); err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}

	if len(problems) > 0 {
		if err := add("errors.txt", []byte(strings.Join(problems, "\n")+"\n")); err != nil {
			a.fail(w, r, problem.Wrap(err))
			return
		}
	}
	if err := errors.Join(tw.Close(), gz.Close()); err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}

	_ = a.d.DB.Update(r.Context(), func(tx *storage.Tx) error {
		return operations.Audit(r.Context(), tx, operations.AuditRecord{
			Actor:     act,
			Action:    "system.support_bundle.export",
			Subject:   "system/support-bundle",
			Outcome:   operations.AuditSuccess,
			NodeID:    a.d.NodeID,
			TraceID:   gateway.TraceID(r.Context()),
			RequestID: requestID(r),
		})
	})

	filename := "qwq-support-" + now.Format("20060102T150405Z") + ".tar.gz"
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func runBoundedJournalctl(ctx context.Context, limit int64) (string, error) {
	cmd := exec.CommandContext(ctx, "journalctl", "-u", "qwq*", "--since", "-1h", "-n", "5000", "--no-pager", "-o", "short-iso")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	data, rerr := io.ReadAll(io.LimitReader(stdout, limit))
	_ = stdout.Close()
	werr := cmd.Wait()
	if rerr != nil {
		return string(data), rerr
	}
	return string(data), werr
}
