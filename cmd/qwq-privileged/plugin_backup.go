// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
)

const (
	pluginBackupStagePrefix  = ".plugin-backup-"
	maxPluginBackupSpecs     = 64
	maxPluginBackupPaths     = 32
	pluginBackupTimeout      = 170 * time.Second
	maxSingleBackupFileBytes = 512 << 20 // 512 MiB per plugin file
	maxTotalBackupStageBytes = 1 << 30   // 1 GiB total plugin private data budget
	staleBackupStageTTL      = time.Hour
)

// ValidateSafeRelativeBackupPath ensures a plugin manifest backup_paths entry
// stays strictly inside the plugin's default state directory without SQLite URI
// query/fragment injection characters.
func ValidateSafeRelativeBackupPath(rel string) (string, error) {
	raw := strings.TrimSpace(rel)
	if raw == "" || strings.ContainsAny(raw, "\\\x00?#") {
		return "", fmt.Errorf("sandbox: invalid plugin backup relative path %q", rel)
	}
	clean := filepath.Clean(raw)
	if clean == "" || clean == "." || filepath.IsAbs(clean) ||
		clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("sandbox: invalid plugin backup relative path %q", rel)
	}
	return clean, nil
}

func validateBackupStageName(stageName string) error {
	if !strings.HasPrefix(stageName, pluginBackupStagePrefix) ||
		len(stageName) <= len(pluginBackupStagePrefix) ||
		len(stageName) > 128 ||
		strings.ContainsAny(stageName, `/\`) ||
		strings.Contains(stageName, "..") ||
		!versionPattern.MatchString(strings.TrimPrefix(stageName, ".")) {
		return errors.New("invalid plugin backup stage directory name")
	}
	return nil
}

// openBackupStageRoot ensures the root-owned backup staging root exists with
// mode 0750 root:<agentGroup> (read+traverse only for qwq, never writable by
// qwq) and opens a pinned *os.Root verified against s.cfg.Trust.
func (s *helperServer) openBackupStageRoot(agentGID int) (*os.Root, error) {
	stageRoot := filepath.Clean(s.cfg.BackupStageRoot)
	parent := filepath.Dir(stageRoot)
	base := filepath.Base(stageRoot)

	parentRoot, err := s.cfg.Trust.Open(parent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = parentRoot.Close() }()

	// Ensure parent (/var/lib/qwq-privileged) allows group traverse (0710 root:qwq)
	// when running as root so qwq can read backup-stage without listing creds/.
	if os.Geteuid() == 0 && agentGID > 0 {
		if pfi, perr := parentRoot.Stat("."); perr == nil && pfi.Mode().Perm() == 0o700 {
			_ = os.Chown(parent, 0, agentGID)
			_ = os.Chmod(parent, 0o710)
		}
	}
	if _, lerr := parentRoot.Lstat(base); errors.Is(lerr, fs.ErrNotExist) {
		if merr := parentRoot.Mkdir(base, 0o750); merr != nil && !errors.Is(merr, fs.ErrExist) {
			return nil, merr
		}
	}
	if os.Geteuid() == 0 && agentGID > 0 {
		_ = parentRoot.Lchown(base, 0, agentGID)
	}
	_ = parentRoot.Chmod(base, 0o750)
	return s.cfg.Trust.Open(stageRoot)
}

func pruneStaleBackupStages(stageRoot *os.Root, now time.Time) {
	entries, err := fs.ReadDir(stageRoot.FS(), ".")
	if err != nil {
		return
	}
	for _, de := range entries {
		name := de.Name()
		if !strings.HasPrefix(name, pluginBackupStagePrefix) {
			continue
		}
		fi, err := stageRoot.Lstat(name)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if now.Sub(fi.ModTime()) > staleBackupStageTTL {
			_ = stageRoot.RemoveAll(name)
		}
	}
}

// backupPluginData handles HelperOpBackupPluginData: snapshots DynamicUser
// private plugin data trees into a root-owned, qwq-readable staging directory
// (<BackupStageRoot>/<stageName>, 0750 root:qwq) so qwq never owns or writes
// into root's staging tree.
func (s *helperServer) backupPluginData(ctx context.Context, req sandbox.HelperRequest) sandbox.HelperResponse {
	stageName := strings.TrimSpace(req.BackupStageName)
	if err := validateBackupStageName(stageName); err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	if len(req.BackupSpecs) > maxPluginBackupSpecs {
		return helperFailure(problem.ValidationFailed, "Too many plugin backup specs.")
	}
	for _, spec := range req.BackupSpecs {
		if err := sandbox.ValidateID(spec.PluginID); err != nil {
			return helperFailure(problem.ValidationFailed, err.Error())
		}
		if len(spec.BackupPaths) > maxPluginBackupPaths {
			return helperFailure(problem.ValidationFailed, "Too many backup paths for plugin "+spec.PluginID)
		}
	}

	_, gid, err := lookupUserIDs(s.cfg.AgentUser)
	if err != nil {
		s.logger.Error("plugin backup could not resolve agent user", "user", s.cfg.AgentUser, "err", err)
		return helperFailure(problem.Unavailable, "The backup target group could not be resolved.")
	}
	stageRoot, err := s.openBackupStageRoot(gid)
	if err != nil {
		s.logger.Error("plugin backup stage root unavailable", "root", s.cfg.BackupStageRoot, "err", err)
		return helperFailure(problem.Unavailable, "The plugin backup staging root is not available.")
	}
	defer func() { _ = stageRoot.Close() }()
	pruneStaleBackupStages(stageRoot, time.Now())

	if _, lerr := stageRoot.Lstat(stageName); lerr == nil {
		return helperFailure(problem.PreconditionFailed, "The plugin backup stage directory already exists.")
	} else if !errors.Is(lerr, fs.ErrNotExist) {
		return helperFailure(problem.Internal, "Could not inspect plugin backup stage directory.")
	}
	if err := stageRoot.Mkdir(stageName, 0o750); err != nil {
		return helperFailure(problem.Internal, "Could not create plugin backup stage directory.")
	}
	if os.Geteuid() == 0 {
		_ = stageRoot.Lchown(stageName, 0, gid)
	}
	_ = stageRoot.Chmod(stageName, 0o750)

	stageHandle, err := stageRoot.OpenRoot(stageName)
	if err != nil {
		_ = stageRoot.RemoveAll(stageName)
		return helperFailure(problem.Internal, "Could not open plugin backup stage directory.")
	}
	defer func() { _ = stageHandle.Close() }()

	stageDir := filepath.Join(s.cfg.BackupStageRoot, stageName)
	var staged []string
	var totalCopiedBytes int64
	for _, spec := range req.BackupSpecs {
		if err := ctx.Err(); err != nil {
			_ = stageRoot.RemoveAll(stageName)
			return helperFailure(problem.Timeout, "Plugin backup timed out.")
		}
		if err := stageHandle.Mkdir(spec.PluginID, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			s.logger.Warn("plugin backup stage mkdir failed", "plugin_id", spec.PluginID, "err", err)
			continue
		}
		if os.Geteuid() == 0 {
			_ = stageHandle.Lchown(spec.PluginID, 0, gid)
		}
		_ = stageHandle.Chmod(spec.PluginID, 0o750)
		pluginDest, perr := stageHandle.OpenRoot(spec.PluginID)
		if perr != nil {
			_ = stageHandle.RemoveAll(spec.PluginID)
			continue
		}
		copied, bytesCopied, serr := stagePluginBackupTreePinned(
			ctx, s.cfg.Trust, s.cfg.PrivateDataRoot, spec, pluginDest, gid,
			maxTotalBackupStageBytes-totalCopiedBytes, storage.BackupFile,
		)
		_ = pluginDest.Close()
		if serr != nil {
			s.logger.Warn("plugin backup stage skipped plugin due to error",
				"plugin_id", spec.PluginID, "err", serr)
			_ = stageHandle.RemoveAll(spec.PluginID)
			continue
		}
		totalCopiedBytes += bytesCopied
		if copied > 0 {
			staged = append(staged, spec.PluginID)
		} else {
			_ = stageHandle.RemoveAll(spec.PluginID)
		}
	}
	return sandbox.HelperResponse{
		OK:  true,
		UID: os.Geteuid(),
		PluginBackup: &sandbox.PluginBackupResult{
			StageDir:      stageDir,
			StagedPlugins: staged,
		},
	}
}

// cleanupPluginBackup handles HelperOpBackupPluginCleanup: removes a single
// root-owned stage directory inside BackupStageRoot.
func (s *helperServer) cleanupPluginBackup(_ context.Context, req sandbox.HelperRequest) sandbox.HelperResponse {
	stageName := strings.TrimSpace(req.BackupStageName)
	if err := validateBackupStageName(stageName); err != nil {
		return helperFailure(problem.ValidationFailed, err.Error())
	}
	stageRoot, err := s.cfg.Trust.Open(filepath.Clean(s.cfg.BackupStageRoot))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return sandbox.HelperResponse{OK: true, UID: os.Geteuid()}
		}
		return helperFailure(problem.Unavailable, "The plugin backup staging root is not available.")
	}
	defer func() { _ = stageRoot.Close() }()
	fi, err := stageRoot.Lstat(stageName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return sandbox.HelperResponse{OK: true, UID: os.Geteuid()}
		}
		return helperFailure(problem.Internal, "Could not inspect plugin backup stage directory.")
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return helperFailure(problem.PreconditionFailed, "Plugin backup stage target is not a directory.")
	}
	if err := stageRoot.RemoveAll(stageName); err != nil {
		return helperFailure(problem.Internal, "Could not remove plugin backup stage directory.")
	}
	return sandbox.HelperResponse{OK: true, UID: os.Geteuid()}
}

// StagePluginBackupTree safely locks <privateRootBase>/<spec.PluginID>/default
// via *os.Root, snapshots *.db files via an isolated root-owned work copy so
// root never creates root-owned -wal/-shm files inside a DynamicUser directory,
// and copies regular files without following symlinks or hard links.
func StagePluginBackupTree(
	ctx context.Context,
	privateRootBase string,
	spec sandbox.PluginBackupSpec,
	destPluginStageDir string,
	_ int,
	qwqGID int,
	snapshotSQLite func(ctx context.Context, srcDB, dstDB string) error,
) (int, error) {
	if err := os.MkdirAll(destPluginStageDir, 0o750); err != nil {
		return 0, err
	}
	destRoot, err := os.OpenRoot(destPluginStageDir)
	if err != nil {
		return 0, err
	}
	defer func() { _ = destRoot.Close() }()
	copied, _, err := stagePluginBackupTreePinned(
		ctx, sandbox.TrustPolicy{UID: os.Geteuid(), StopAt: filepath.Clean(privateRootBase)}, privateRootBase, spec, destRoot, qwqGID,
		maxTotalBackupStageBytes, snapshotSQLite,
	)
	return copied, err
}

func stagePluginBackupTreePinned(
	ctx context.Context,
	trust sandbox.TrustPolicy,
	privateRootBase string,
	spec sandbox.PluginBackupSpec,
	destRoot *os.Root,
	agentGID int,
	budgetBytes int64,
	snapshotSQLite func(ctx context.Context, srcDB, dstDB string) error,
) (int, int64, error) {
	if err := sandbox.ValidateID(spec.PluginID); err != nil {
		return 0, 0, err
	}
	baseRoot, err := trust.Open(filepath.Clean(privateRootBase))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	defer func() { _ = baseRoot.Close() }()

	pluginLfi, err := baseRoot.Lstat(spec.PluginID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	if !pluginLfi.IsDir() || pluginLfi.Mode()&os.ModeSymlink != 0 {
		return 0, 0, fmt.Errorf("plugin state parent is not a real directory: %s", spec.PluginID)
	}
	pluginRoot, err := baseRoot.OpenRoot(spec.PluginID)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pluginRoot.Close() }()
	if pfi, err := pluginRoot.Stat("."); err != nil || !os.SameFile(pfi, pluginLfi) {
		return 0, 0, fmt.Errorf("plugin state parent changed while opening: %s", spec.PluginID)
	}

	defLfi, err := pluginRoot.Lstat("default")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	if !defLfi.IsDir() || defLfi.Mode()&os.ModeSymlink != 0 {
		return 0, 0, fmt.Errorf("plugin state dir is not a real directory: %s/default", spec.PluginID)
	}
	rootHandle, err := pluginRoot.OpenRoot("default")
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = rootHandle.Close() }()
	if dfi, err := rootHandle.Stat("."); err != nil || !os.SameFile(dfi, defLfi) {
		return 0, 0, fmt.Errorf("plugin state dir changed while opening: %s/default", spec.PluginID)
	}

	paths := append([]string(nil), spec.BackupPaths...)
	paths = append(paths, "tls")

	seen := make(map[string]bool, len(paths))
	copied := 0
	var totalBytes int64
	for _, rawRel := range paths {
		if err := ctx.Err(); err != nil {
			return copied, totalBytes, err
		}
		rel, verr := ValidateSafeRelativeBackupPath(rawRel)
		if verr != nil || seen[rel] {
			continue
		}
		seen[rel] = true

		st, lerr := rootHandle.Lstat(rel)
		if lerr != nil || st.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if st.Mode().IsRegular() {
			n, serr := stageSingleRegularFile(ctx, rootHandle, rel, destRoot, agentGID, budgetBytes-totalBytes, snapshotSQLite)
			if serr != nil {
				return copied, totalBytes, serr
			}
			if n >= 0 {
				totalBytes += n
				copied++
			}
			continue
		}
		if st.IsDir() {
			c, n, derr := stageSubdirTree(ctx, rootHandle, rel, destRoot, agentGID, budgetBytes-totalBytes, snapshotSQLite)
			if derr != nil {
				return copied, totalBytes, derr
			}
			copied += c
			totalBytes += n
		}
	}
	return copied, totalBytes, nil
}

func mkdirAllRootOwned(dst *os.Root, relDir string, agentGID int) error {
	clean := filepath.ToSlash(filepath.Clean(relDir))
	if clean == "." || clean == "" {
		return nil
	}
	parts := strings.Split(clean, "/")
	cur := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if cur == "" {
			cur = part
		} else {
			cur = cur + "/" + part
		}
		if _, err := dst.Lstat(cur); errors.Is(err, fs.ErrNotExist) {
			if merr := dst.Mkdir(cur, 0o750); merr != nil && !errors.Is(merr, fs.ErrExist) {
				return merr
			}
			if os.Geteuid() == 0 && agentGID > 0 {
				_ = dst.Lchown(cur, 0, agentGID)
			}
			_ = dst.Chmod(cur, 0o750)
		}
	}
	return nil
}

func openSafeBackupFile(r *os.Root, rel string, maxBytes int64) (*os.File, fs.FileInfo, error) {
	f, err := r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	nlink, _, ok := sandbox.FileLinks(fi)
	switch {
	case !fi.Mode().IsRegular():
		err = fmt.Errorf("sandbox: backup source %q is not a regular file", rel)
	case ok && nlink != 1:
		err = fmt.Errorf("sandbox: backup source %q has %d hard links", rel, nlink)
	case fi.Size() > maxSingleBackupFileBytes || (maxBytes > 0 && fi.Size() > maxBytes):
		err = fmt.Errorf("sandbox: backup source %q exceeds size budget", rel)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

func stageSingleRegularFile(
	ctx context.Context,
	rootHandle *os.Root,
	rel string,
	destRoot *os.Root,
	agentGID int,
	remainingBudget int64,
	snapshotSQLite func(ctx context.Context, srcDB, dstDB string) error,
) (int64, error) {
	if remainingBudget <= 0 {
		return -1, errors.New("sandbox: plugin backup total size budget exceeded")
	}
	lower := strings.ToLower(rel)
	// Skip live SQLite WAL/SHM sidecar files; snapshotting .db copies them atomically into temp work dir.
	if strings.HasSuffix(lower, ".db-wal") || strings.HasSuffix(lower, ".db-shm") {
		return -1, nil
	}
	relSlash := filepath.ToSlash(rel)
	if err := mkdirAllRootOwned(destRoot, filepath.ToSlash(filepath.Dir(rel)), agentGID); err != nil {
		return -1, err
	}
	if strings.HasSuffix(lower, ".db") && snapshotSQLite != nil {
		return stageSQLiteCopySafe(ctx, rootHandle, relSlash, destRoot, agentGID, remainingBudget, snapshotSQLite)
	}
	return copyRegularBetweenRoots(rootHandle, relSlash, destRoot, relSlash, agentGID, remainingBudget)
}

// stageSQLiteCopySafe copies <rel>, <rel>-wal, and <rel>-shm through the pinned
// *os.Root into a private root-only work directory and runs snapshotSQLite on
// that copy, so root never opens a DynamicUser-owned DB directly or leaves
// root-owned WAL/SHM files inside the plugin's private state directory.
func stageSQLiteCopySafe(
	ctx context.Context,
	srcRoot *os.Root,
	rel string,
	destRoot *os.Root,
	agentGID int,
	remainingBudget int64,
	snapshotSQLite func(ctx context.Context, srcDB, dstDB string) error,
) (int64, error) {
	workDir, err := os.MkdirTemp("", "qwq-plugin-db-*")
	if err != nil {
		return -1, err
	}
	defer func() { _ = os.RemoveAll(workDir) }()
	workRoot, err := os.OpenRoot(workDir)
	if err != nil {
		return -1, err
	}
	defer func() { _ = workRoot.Close() }()

	if _, err := copyRegularBetweenRoots(srcRoot, rel, workRoot, "src.db", 0, remainingBudget); err != nil {
		return -1, err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := copyRegularBetweenRoots(srcRoot, rel+suffix, workRoot, "src.db"+suffix, 0, remainingBudget); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return -1, err
		}
	}
	srcCopy := filepath.Join(workDir, "src.db")
	dstSnap := filepath.Join(workDir, "snap.db")
	if err := snapshotSQLite(ctx, srcCopy, dstSnap); err != nil {
		return -1, err
	}
	return copyRegularBetweenRoots(workRoot, "snap.db", destRoot, rel, agentGID, remainingBudget)
}

func stageSubdirTree(
	ctx context.Context,
	rootHandle *os.Root,
	relDir string,
	destRoot *os.Root,
	agentGID int,
	remainingBudget int64,
	snapshotSQLite func(ctx context.Context, srcDB, dstDB string) error,
) (int, int64, error) {
	copied := 0
	var totalBytes int64
	walkRoot := filepath.ToSlash(relDir)
	err := fs.WalkDir(rootHandle.FS(), walkRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		n, serr := stageSingleRegularFile(ctx, rootHandle, p, destRoot, agentGID, remainingBudget-totalBytes, snapshotSQLite)
		if serr != nil {
			return serr
		}
		if n >= 0 {
			totalBytes += n
			copied++
		}
		return nil
	})
	return copied, totalBytes, err
}

func copyRegularBetweenRoots(src *os.Root, srcRel string, dst *os.Root, dstRel string, agentGID int, maxBytes int64) (int64, error) {
	limit := maxSingleBackupFileBytes
	if maxBytes > 0 && maxBytes < int64(limit) {
		limit = int(maxBytes)
	}
	in, _, err := openSafeBackupFile(src, srcRel, int64(limit))
	if err != nil {
		return 0, err
	}
	defer func() { _ = in.Close() }()

	out, err := dst.OpenFile(dstRel, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return 0, err
	}
	n, cerr := io.Copy(out, io.LimitReader(in, int64(limit)+1))
	if cerr == nil && n > int64(limit) {
		cerr = fmt.Errorf("sandbox: backup file %q exceeded size limit while copying", srcRel)
	}
	serr := out.Sync()
	clerr := out.Close()
	if err := errors.Join(cerr, serr, clerr); err != nil {
		_ = dst.Remove(dstRel)
		return 0, err
	}
	if os.Geteuid() == 0 && agentGID > 0 {
		_ = dst.Lchown(dstRel, 0, agentGID)
	}
	mode := fs.FileMode(0o600)
	if agentGID > 0 {
		mode = 0o640
	}
	_ = dst.Chmod(dstRel, mode)
	return n, nil
}

func lookupUserIDs(name string) (uid, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}
