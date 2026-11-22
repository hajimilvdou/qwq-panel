// SPDX-License-Identifier: AGPL-3.0-only

// Package install stages and publishes verified plugin packages
// (docs/ARCHITECTURE.md §5.1, §6.2).
//
// Installation never unpacks into the version directory. Extract verifies the
// package with sdk/pkgfile - signature first, then the strict manifest, then
// every content digest - and writes it into a private staging directory below
// the staging root, confining every filesystem operation with os.Root. Commit
// publishes the result with a single rename to
// <plugins_root>/<id>/<version>.
//
// The published tree is immutable: files are 0444 (0555 when they carry an
// executable bit), directories are 0555, each file is fsynced before it is
// closed, the containing directory is fsynced after the rename, and Commit
// refuses to replace an existing version directory. The directories belong to
// root when the installer runs as root; verifyTreeOwner asserts that and is
// skipped for unprivileged runs, which is why the tests run without root.
//
// A crash can leave a .staging-* directory behind. CleanupStale removes those
// at startup and touches nothing else in the staging root.
//
// Extract only proves that the package is authentic and intact. The caller
// still checks target, ABI, dependencies and capabilities (ARCH §6.2) against
// Staged.Manifest before it commits; doing so while the package is staged
// keeps a rejected install out of the plugins root.
package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

const (
	// StagingPrefix marks the private directories Extract creates. It is a
	// dot name so an operator listing the plugins root sees them last, and
	// CleanupStale only ever removes entries that carry it.
	StagingPrefix = ".staging-"

	// FileMode, ExecMode and DirMode are the modes of a published version
	// directory (ARCH §6.2: the package directory belongs to root and is
	// read-only).
	FileMode fs.FileMode = 0o444
	ExecMode fs.FileMode = 0o555
	DirMode  fs.FileMode = 0o555

	// stagingDirMode keeps the staging tree writable until it is published.
	stagingDirMode fs.FileMode = 0o700
	// stagingRootMode is the mode of the staging root Extract creates.
	stagingRootMode fs.FileMode = 0o700
)

// Errors reported by Staged.Commit.
var (
	// ErrTargetExists means the version directory is already published.
	// Version directories are immutable, so a second install of the same
	// version is an error, not an overwrite.
	ErrTargetExists = errors.New("install: version directory already exists")
	// ErrTargetMismatch means the target path is not
	// <plugins_root>/<id>/<version> for the staged manifest.
	ErrTargetMismatch = errors.New("install: target does not match the manifest id and version")
	// ErrStagedClosed means Commit or Discard already ran.
	ErrStagedClosed = errors.New("install: staged package was already committed or discarded")
)

// VersionDir returns the only path Commit accepts for a plugin version.
func VersionDir(pluginsRoot, id, version string) string {
	return filepath.Join(pluginsRoot, id, version)
}

// Staged is a verified package waiting to be published. It owns a staging
// directory and an os.Root handle; Commit and Discard release both, and
// exactly one of them must be called.
type Staged struct {
	dir       string
	root      *os.Root
	pkg       *pkgfile.Package
	committed bool
	discarded bool
}

// Extract verifies pkgPath, unpacks it into a new staging directory below
// stagingRoot and returns the staged package.
//
// The package is read exactly once: sdk/pkgfile verifies the signature and
// the manifest before it hands over any other byte, and checks every digest
// while the content is written, so nothing unverified reaches the disk. On
// error the staging directory is removed and the returned error is the one
// pkgfile produced.
//
// stagingRoot must be on the same filesystem as the plugin root, because
// Commit publishes with a rename. Extract creates it with mode 0700 when it
// does not exist.
func Extract(ctx context.Context, pkgPath string, trust manifest.TrustStore, stagingRoot string) (*Staged, error) {
	if trust == nil {
		return nil, errors.New("install: a trust store is required to install a package")
	}
	if stagingRoot == "" {
		return nil, errors.New("install: empty staging root")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	f, err := os.Open(pkgPath)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read only
	if err := os.MkdirAll(stagingRoot, stagingRootMode); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(stagingRoot, StagingPrefix)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		_ = removeTree(dir)
		return nil, err
	}
	ex := &extractor{ctx: ctx, root: root}
	pkg, rerr := pkgfile.Read(f, trust, pkgfile.ReadOptions{Sink: ex})
	if rerr != nil {
		_ = root.Close()
		_ = removeTree(dir)
		return nil, rerr
	}
	// manifest 是签名覆盖的包头，pkgfile 不把它送入内容 Sink。
	// 保存已验证的原始字节，供包内驱动核对二进制摘要，避免重编码破坏签名语义。
	if merr := ex.keepManifest(pkg.ManifestBytes); merr != nil {
		_ = root.Close()
		_ = removeTree(dir)
		return nil, merr
	}
	if ferr := ex.finalize(dir); ferr != nil {
		_ = root.Close()
		_ = removeTree(dir)
		return nil, ferr
	}
	// An authentic package can still violate a host policy; refusing it while
	// it is staged keeps the plugins root free of content the host will not
	// serve (ARCH §5.1, ui/ carries no runtime remote scripts).
	if perr := checkUIAssets(root, pkg.Manifest); perr != nil {
		_ = root.Close()
		_ = removeTree(dir)
		return nil, perr
	}
	return &Staged{dir: dir, root: root, pkg: pkg}, nil
}

// Manifest returns the verified manifest.
func (s *Staged) Manifest() *manifest.Manifest { return s.pkg.Manifest }

// Package returns everything pkgfile verified: manifest, signature and files.
func (s *Staged) Package() *pkgfile.Package { return s.pkg }

// Dir returns the staging directory before Commit and the published version
// directory afterwards.
func (s *Staged) Dir() string { return s.dir }

// Commit publishes the staged package at finalDir, which must be
// VersionDir(pluginsRoot, id, version) for the staged manifest.
//
// Publication is one rename, so the version directory either appears
// complete or not at all. An existing finalDir is never replaced
// (ErrTargetExists): a published version directory is immutable. The parent
// directory is created if needed and fsynced afterwards.
//
// Concurrent installs of the same version must be serialized by the caller:
// the agent holds the per-plugin install lock (ARCH §6.3). An error returned
// after the rename means the version directory exists but its durability or
// ownership could not be confirmed.
func (s *Staged) Commit(finalDir string) error {
	if s.committed || s.discarded {
		return ErrStagedClosed
	}
	if s.pkg == nil || s.pkg.Manifest == nil {
		return errors.New("install: staged package has no manifest")
	}
	if err := checkTarget(finalDir, s.pkg.Manifest); err != nil {
		return err
	}
	// Close the handle before the rename: a directory that is still open
	// cannot be renamed on some platforms, and nothing below needs it.
	if err := s.closeRoot(); err != nil {
		return err
	}
	parent := filepath.Dir(finalDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	if _, err := os.Lstat(finalDir); err == nil {
		return fmt.Errorf("%w: %s", ErrTargetExists, finalDir)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Moving a read-only (0555) directory across parents updates its ".." entry,
	// which requires write permission on the moved directory for non-root users
	// (e.g. unprivileged unit tests). Production runs as root in qwq-privileged.
	relaxedForRename := false
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if err := os.Chmod(s.dir, 0o755); err == nil {
			relaxedForRename = true
		}
	}
	if err := os.Rename(s.dir, finalDir); err != nil {
		if relaxedForRename {
			_ = os.Chmod(s.dir, DirMode)
		}
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrTargetExists, finalDir)
		}
		return fmt.Errorf("install: publishing %s: %w", finalDir, err)
	}
	if relaxedForRename {
		if err := os.Chmod(finalDir, DirMode); err != nil {
			return fmt.Errorf("install: restoring mode on %s: %w", finalDir, err)
		}
	}
	s.committed = true
	s.dir = finalDir
	if err := syncPath(parent); err != nil {
		return err
	}
	if err := verifyTreeOwner(finalDir); err != nil {
		return err
	}
	return nil
}

// Discard removes the staging directory. It is idempotent: after a successful
// Commit it is a no-op (a published version directory is never deleted by the
// installer), and calling it twice is harmless.
func (s *Staged) Discard() error {
	if s.discarded {
		return nil
	}
	s.discarded = true
	if err := s.closeRoot(); err != nil {
		return err
	}
	if s.committed {
		return nil
	}
	return removeTree(s.dir)
}

func (s *Staged) closeRoot() error {
	if s.root == nil {
		return nil
	}
	err := s.root.Close()
	s.root = nil
	return err
}

// checkTarget refuses anything but <abs>/<id>/<version>.
func checkTarget(finalDir string, m *manifest.Manifest) error {
	if finalDir == "" || !filepath.IsAbs(finalDir) {
		return fmt.Errorf("%w: %q must be an absolute path", ErrTargetMismatch, finalDir)
	}
	if clean := filepath.Clean(finalDir); clean != finalDir {
		return fmt.Errorf("%w: %q is not a clean path", ErrTargetMismatch, finalDir)
	}
	if filepath.Base(finalDir) != m.Version || filepath.Base(filepath.Dir(finalDir)) != m.ID {
		return fmt.Errorf("%w: %q must end in %s/%s", ErrTargetMismatch, finalDir, m.ID, m.Version)
	}
	return nil
}

// extractor implements pkgfile.Sink on top of an os.Root.
type extractor struct {
	ctx  context.Context
	root *os.Root
}

// CreateDir creates one directory of the package.
func (x *extractor) CreateDir(path string) error {
	if err := x.ctx.Err(); err != nil {
		return err
	}
	return x.root.MkdirAll(path, stagingDirMode)
}

// CreateFile creates one file of the package and returns its writer. Parent
// directories are created when the archive did not carry them explicitly.
func (x *extractor) CreateFile(path string, size int64, mode fs.FileMode) (io.WriteCloser, error) {
	if err := x.ctx.Err(); err != nil {
		return nil, err
	}
	if parent := parentDir(path); parent != "" {
		if err := x.root.MkdirAll(parent, stagingDirMode); err != nil {
			return nil, err
		}
	}
	final := finalFileMode(mode)
	f, err := x.root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, final)
	if err != nil {
		return nil, err
	}
	return &fileWriter{f: f, mode: final}, nil
}

func (x *extractor) keepManifest(raw []byte) error {
	w, err := x.CreateFile(pkgfile.ManifestPath, int64(len(raw)), pkgfile.ModeFile)
	if err != nil {
		return err
	}
	n, writeErr := w.Write(raw)
	if n != len(raw) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, w.Close())
}

// finalize turns the writable staging tree into the published form: every
// directory becomes 0555 and every directory is fsynced. Files were already
// chmodded and fsynced by fileWriter.Close.
func (x *extractor) finalize(rootDir string) error {
	dirs, err := collectDirs(rootDir)
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if cerr := x.root.Chmod(d, DirMode); cerr != nil {
			return cerr
		}
	}
	if err := os.Chmod(rootDir, DirMode); err != nil {
		return err
	}
	for _, d := range dirs {
		if serr := syncRootDir(x.root, d); serr != nil {
			return serr
		}
	}
	return syncPath(rootDir)
}

// collectDirs lists the directories below rootDir as slash paths.
func collectDirs(rootDir string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(rootDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if !d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(rootDir, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		dirs = append(dirs, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dirs, nil
}

// fileWriter publishes one file: the content is written through it, and Close
// applies the final mode and fsyncs before closing the descriptor.
type fileWriter struct {
	f    *os.File
	mode fs.FileMode
	done bool
}

func (w *fileWriter) Write(p []byte) (int, error) { return w.f.Write(p) }

// Close applies the mode, fsyncs and closes. It is safe to call twice.
func (w *fileWriter) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	// Chmod before the fsync so the metadata it flushes is the published one.
	if err := w.f.Chmod(w.mode); err != nil {
		_ = w.f.Close()
		return err
	}
	if err := w.f.Sync(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}

// finalFileMode maps a package entry mode to the published mode: the
// executable bit survives, every write bit is dropped.
func finalFileMode(mode fs.FileMode) fs.FileMode {
	if mode&0o111 != 0 {
		return ExecMode
	}
	return FileMode
}

// parentDir returns the slash-separated parent of a package path.
func parentDir(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return ""
}

// CleanupStale removes staging directories left behind by a crash.
//
// Only entries whose name starts with StagingPrefix are considered, and those
// younger than minAge are left alone so a concurrent install is never
// disturbed; pass 0 to remove every stale entry regardless of age. The
// recommended call at startup is CleanupStale(root, time.Hour) for an agent
// that installs one plugin at a time (ARCH §6.3).
func CleanupStale(stagingRoot string, minAge time.Duration) ([]string, error) {
	entries, err := os.ReadDir(stagingRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var removed []string
	for _, de := range entries {
		if !strings.HasPrefix(de.Name(), StagingPrefix) {
			continue
		}
		info, ierr := de.Info()
		if ierr != nil {
			return removed, ierr
		}
		if minAge > 0 && now.Sub(info.ModTime()) < minAge {
			continue
		}
		path := filepath.Join(stagingRoot, de.Name())
		if rerr := removeTree(path); rerr != nil {
			return removed, rerr
		}
		removed = append(removed, path)
	}
	return removed, nil
}

// removeTree deletes a tree that may be read-only, making it writable first.
// Every error is reported by the RemoveAll call at the end.
func removeTree(dir string) error {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil //nolint:nilerr // best effort, RemoveAll reports the failure
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(p, 0o700)
		} else {
			_ = os.Chmod(p, 0o600)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

// syncPath fsyncs a directory. Windows does not support it, and the production
// installer only runs on Linux.
func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if runtime.GOOS == "windows" {
			return nil
		}
		return err
	}
	defer f.Close() //nolint:errcheck // read only
	if serr := f.Sync(); serr != nil && runtime.GOOS != "windows" {
		return serr
	}
	return nil
}

// syncRootDir fsyncs one directory of the staging tree.
func syncRootDir(root *os.Root, path string) error {
	f, err := root.Open(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read only
	if serr := f.Sync(); serr != nil && runtime.GOOS != "windows" {
		return serr
	}
	return nil
}
