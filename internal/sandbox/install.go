// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

// Installation paths and modes. The privileged helper owns these files; every
// one of them is written atomically and owned by root.
const (
	// DefaultUnitDir is where systemd reads the rendered units.
	DefaultUnitDir = "/etc/systemd/system"
	// DefaultTmpfilesDir is where the per-plugin runtime directories are
	// declared for the next boot.
	DefaultTmpfilesDir = "/etc/tmpfiles.d"

	// UnitFileMode, TmpfilesFileMode and CredentialFileMode are the modes of
	// the files the helper writes. systemd reads them as root; nothing else
	// may change them.
	UnitFileMode       fs.FileMode = 0o644
	TmpfilesFileMode   fs.FileMode = 0o644
	CredentialFileMode fs.FileMode = 0o600

	// CredentialDirMode keeps the token directory root-only.
	CredentialDirMode fs.FileMode = 0o700
	// RuntimeDirMode is the mode of /run/qwq/plugin/<id> and /run/qwq/link:
	// traversable (systemd needs the listener path, the plugin needs the bind
	// target) but not listable.
	RuntimeDirMode fs.FileMode = 0o711

	// TokenSuffix is appended to the plugin id for the credential file.
	TokenSuffix = ".token"
	// MinTokenLen and MaxTokenLen bound a plugin token. The P2-T1 spike used
	// 64 hex characters.
	MinTokenLen = 32
	MaxTokenLen = 512
)

// Installer performs the privileged half of plugin installation. It is the
// only writer of /etc/systemd/system/qwq-plugin@<id>.*,
// /etc/tmpfiles.d/qwq-plugin-<id>.conf, /run/qwq/{plugin,link,host/<id>} and
// /var/lib/qwq-privileged/creds/<id>.token.
//
// It does not start, stop or enable anything: the agent drives systemd through
// polkit (deployments/polkit/qwq-plugin.rules), and unit-file enablement is an
// administrator decision that the current polkit rule deliberately does not
// grant.
type Installer struct {
	// UnitDir defaults to DefaultUnitDir.
	UnitDir string
	// TmpfilesDir defaults to DefaultTmpfilesDir.
	TmpfilesDir string
	// RuntimeBase defaults to DefaultRuntimeBase.
	RuntimeBase string
	// CredDir defaults to DefaultCredDir. The rendered unit always loads the
	// token from DefaultCredDir; a different value is for tests only.
	CredDir string
	// AgentUser defaults to DefaultAgentUser.
	AgentUser string
	// Runner defaults to ExecRunner.
	Runner Runner
	// Trust is the ancestry policy for the runtime tree. The zero value is the
	// production policy (root-owned up to "/"); only tests relax it.
	Trust TrustPolicy
	// LookupIDs resolves the agent user and the plugin group to the owner of
	// /run/qwq/host/<id>. Nil uses the system user and group databases.
	LookupIDs func(user, group string) (uid, gid int, err error)
}

// DefaultInstaller returns an Installer configured for production paths.
func DefaultInstaller(r Runner) Installer {
	return Installer{
		UnitDir:     DefaultUnitDir,
		TmpfilesDir: DefaultTmpfilesDir,
		RuntimeBase: DefaultRuntimeBase,
		AgentUser:   DefaultAgentUser,
		Runner:      r,
	}
}

func (in Installer) withDefaults() (Installer, error) {
	if in.UnitDir == "" {
		in.UnitDir = DefaultUnitDir
	}
	if in.TmpfilesDir == "" {
		in.TmpfilesDir = DefaultTmpfilesDir
	}
	if in.RuntimeBase == "" {
		in.RuntimeBase = DefaultRuntimeBase
	}
	if in.AgentUser == "" {
		in.AgentUser = DefaultAgentUser
	}
	if in.CredDir == "" {
		in.CredDir = DefaultCredDir
	}
	for _, p := range []struct{ field, path string }{
		{"unit dir", in.UnitDir},
		{"tmpfiles dir", in.TmpfilesDir},
		{"runtime base", in.RuntimeBase},
		{"credential dir", in.CredDir},
	} {
		if _, err := checkDirPath(p.field, p.path); err != nil {
			return Installer{}, err
		}
	}
	if !userPattern.MatchString(in.AgentUser) {
		return Installer{}, fmt.Errorf("sandbox: agent user %q is not a valid user name", in.AgentUser)
	}
	in.Runner = runnerOr(in.Runner)
	if in.LookupIDs == nil {
		in.LookupIDs = lookupIDs
	}
	return in, nil
}

// InstallResult reports what Install created. Paths are absolute.
type InstallResult struct {
	ID         string   `json:"id"`
	Group      string   `json:"group"`
	UnitFiles  []string `json:"unit_files,omitempty"`
	Dirs       []string `json:"dirs,omitempty"`
	Tmpfiles   string   `json:"tmpfiles,omitempty"`
	Credential string   `json:"credential,omitempty"`
	// Warnings reports a non-fatal step the privileged helper could not
	// complete, for example a plugin socket unit that was not enabled. The
	// in-process installer never sets it.
	Warnings []string `json:"warnings,omitempty"`
}

// RemoveResult reports what Remove deleted. It lists a path only when it
// existed, so a second Remove succeeds and reports nothing.
type RemoveResult struct {
	ID        string   `json:"id"`
	Group     string   `json:"group"`
	UnitFiles []string `json:"unit_files,omitempty"`
	Removed   []string `json:"removed,omitempty"`
	// Warnings reports a non-fatal step the privileged helper could not
	// complete, for example a plugin socket unit that could not be disabled.
	// The in-process installer never sets it.
	Warnings []string `json:"warnings,omitempty"`
}

// Install renders and writes everything one plugin needs to be startable by
// systemd, and creates its private group. credential may be nil; the unit then
// fails closed at start because LoadCredential= cannot read its source.
//
// Install is idempotent: re-running it replaces the units and the drop-in and
// tolerates an existing group. The caller must still stop a running instance
// before replacing its units (the agent does that through systemctl).
func (in Installer) Install(ctx context.Context, spec UnitSpec, credential []byte) (InstallResult, error) {
	var res InstallResult
	if ctx == nil {
		ctx = context.Background()
	}
	var err error
	if in, err = in.withDefaults(); err != nil {
		return res, err
	}
	if spec.RuntimeBase == "" {
		spec.RuntimeBase = in.RuntimeBase
	}
	if spec.AgentUser == "" {
		spec.AgentUser = in.AgentUser
	}
	p, err := spec.prepare()
	if err != nil {
		return res, err
	}
	if credential != nil {
		if err := checkToken(credential); err != nil {
			return res, err
		}
	}
	res.ID, res.Group = p.id, p.group

	// Every runtime write goes through one handle whose ancestry is root-owned
	// and not group/world writable (PRIV-01): a qwq-writable parent could
	// otherwise swap plugin/, link/ or creds/ for a symlink to /etc.
	rt, err := in.Trust.Open(p.paths.Runtime)
	if err != nil {
		return res, fmt.Errorf("sandbox: runtime directory %s is not a trusted directory (%w); install deployments/tmpfiles/qwq.conf and run systemd-tmpfiles --create first", p.paths.Runtime, err)
	}
	defer func() { _ = rt.Close() }()
	if res.Dirs, err = ensureRuntimeDirs(rt, p.paths); err != nil {
		return res, err
	}
	if err := CreatePluginGroup(ctx, in.Runner, p.group); err != nil {
		return res, err
	}
	// The host channel directory needs the group that was just created.
	uid, gid, err := in.LookupIDs(p.agentUser, p.group)
	if err != nil {
		return res, fmt.Errorf("sandbox: resolving %s:%s: %w", p.agentUser, p.group, err)
	}
	if err := ensureHostDir(rt, p.id, uid, gid); err != nil {
		return res, err
	}
	res.Dirs = append(res.Dirs, p.paths.HostDir)
	if credential != nil {
		creds, err := in.Trust.Open(in.CredDir)
		if err != nil {
			return res, fmt.Errorf("sandbox: credential dir %s is not a trusted directory (%w); install deployments/tmpfiles/qwq.conf and run systemd-tmpfiles --create first", in.CredDir, err)
		}
		name, err := WriteCredential(creds, p.id, credential)
		_ = creds.Close()
		if err != nil {
			return res, err
		}
		res.Credential = filepath.Join(in.CredDir, name)
	}
	if res.UnitFiles, err = InstallUnit(ctx, spec, in.UnitDir); err != nil {
		return res, err
	}
	tmpfiles, err := RenderTmpfiles(spec)
	if err != nil {
		return res, err
	}
	name, err := TmpfilesName(p.id)
	if err != nil {
		return res, err
	}
	res.Tmpfiles = filepath.Join(in.TmpfilesDir, name)
	if err := WriteFileAtomic(res.Tmpfiles, tmpfiles, TmpfilesFileMode); err != nil {
		return res, err
	}
	return res, nil
}

const UserResourceDropinName = "20-user-resources.conf"

// UpdateResources writes (or removes when reset=true) the user override drop-in
// (20-user-resources.conf) inside qwq-plugin@<id>.service.d/.
func (in Installer) UpdateResources(id string, limits Limits, reset bool) (string, error) {
	var err error
	if in, err = in.withDefaults(); err != nil {
		return "", err
	}
	service, _, err := UnitNames(id)
	if err != nil {
		return "", err
	}
	dropinPath := filepath.Join(in.UnitDir, service+".d", UserResourceDropinName)
	if reset {
		if err := os.Remove(dropinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("sandbox: removing user resource override %s: %w", dropinPath, err)
		}
		return dropinPath, nil
	}
	data, err := RenderResources(limits)
	if err != nil {
		return "", err
	}
	if err := WriteFileAtomic(dropinPath, data, UnitFileMode); err != nil {
		return "", err
	}
	return dropinPath, nil
}

// Remove deletes everything Install created. The plugin must already be
// stopped: removing a unit file does not stop a running service, and systemd
// keeps the cgroup until the unit is stopped or killed.
func (in Installer) Remove(ctx context.Context, id string) (RemoveResult, error) {
	var res RemoveResult
	if ctx == nil {
		ctx = context.Background()
	}
	var err error
	if in, err = in.withDefaults(); err != nil {
		return res, err
	}
	p, err := PathsFor(in.RuntimeBase, id)
	if err != nil {
		return res, err
	}
	group, err := GroupName(id)
	if err != nil {
		return res, err
	}
	res.ID, res.Group = id, group

	if res.UnitFiles, err = RemoveUnit(id, in.UnitDir); err != nil {
		return res, err
	}
	name, err := TmpfilesName(id)
	if err != nil {
		return res, err
	}
	tmpfiles := filepath.Join(in.TmpfilesDir, name)
	ok, err := removeIfExists(tmpfiles)
	if err != nil {
		return res, err
	}
	if ok {
		res.Removed = append(res.Removed, tmpfiles)
	}
	token, err := in.removeCredential(id)
	if err != nil {
		return res, err
	}
	if token != "" {
		res.Removed = append(res.Removed, token)
	}
	// The runtime tree is removed through the trusted handle only; a missing
	// runtime directory simply has nothing left to remove.
	rt, err := in.Trust.Open(p.Runtime)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return res, fmt.Errorf("sandbox: runtime directory %s is not a trusted directory: %w", p.Runtime, err)
	default:
		defer func() { _ = rt.Close() }()
		for _, path := range []string{p.PluginDir} {
			ok, rerr := RemoveAllIn(rt, relTo(p.Runtime, path))
			if rerr != nil {
				return res, fmt.Errorf("sandbox: removing %s: %w", path, rerr)
			}
			if ok {
				res.Removed = append(res.Removed, path)
			}
		}
		// host/ is qwq-writable, so its entries are removed through a handle
		// rooted at host/ itself: a planted link can never reach ../plugin.
		ok, rerr := removeHostDir(rt, id)
		if rerr != nil {
			return res, fmt.Errorf("sandbox: removing %s: %w", p.HostDir, rerr)
		}
		if ok {
			res.Removed = append(res.Removed, p.HostDir)
		}
	}
	// The private group is ancillary: if shadow's two-file update fails (for
	// example a lock conflict with a concurrent version removal), removing the
	// unit and the version tree is still the correct, idempotent outcome. The
	// caller reports the warning; an empty group is harmless and a later
	// uninstall can retry it. The shipped helper unit must keep shadow's
	// fchown() allowed in its seccomp filter (see
	// deployments/systemd/qwq-privileged.service); otherwise every group
	// update fails and this warning becomes the normal path.
	if err := RemovePluginGroup(ctx, in.Runner, group); err != nil {
		res.Warnings = append(res.Warnings, err.Error())
	}
	return res, nil
}

// InstallUnit renders the spec and writes the unit files below destDir. It
// returns the absolute paths it wrote. Files are 0644 and replaced by rename,
// so systemd never reads a half-written unit.
func InstallUnit(ctx context.Context, spec UnitSpec, destDir string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := checkDirPath("unit dir", destDir); err != nil {
		return nil, err
	}
	files, err := RenderUnit(spec)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	written := make([]string, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		path := filepath.Join(destDir, filepath.FromSlash(name))
		if err := WriteFileAtomic(path, files[name], UnitFileMode); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// RemoveUnit deletes the concrete service, socket and resource drop-in
// directory for id below destDir. Missing files are not an error, so it is
// safe to call on a partially installed plugin. It returns the paths that
// existed.
func RemoveUnit(id, destDir string) ([]string, error) {
	service, socket, err := UnitNames(id)
	if err != nil {
		return nil, err
	}
	if _, err := checkDirPath("unit dir", destDir); err != nil {
		return nil, err
	}
	var removed []string
	for _, name := range []string{service, socket, service + ".d"} {
		path := filepath.Join(destDir, name)
		fi, lerr := os.Lstat(path)
		if errors.Is(lerr, fs.ErrNotExist) {
			continue
		}
		if lerr != nil {
			return removed, lerr
		}
		if fi.IsDir() {
			err = os.RemoveAll(path)
		} else {
			err = os.Remove(path)
		}
		if err != nil {
			return removed, fmt.Errorf("sandbox: removing %s: %w", path, err)
		}
		removed = append(removed, path)
	}
	return removed, nil
}

// VerifyEntrypoint checks that versionDir/entrypoint is a regular file with
// the expected digest. It reuses sdk/pkgfile, which opens the file below
// versionDir so a relative path cannot escape it, and only accepts a regular
// file.
//
// The unit runs this as ExecStartPre before every start (ADR-0003 decision 3);
// the helper also exposes it as `qwq privileged verify-entrypoint`.
func VerifyEntrypoint(versionDir, entrypoint, digest string) error {
	dir, err := checkDirPath("version dir", versionDir)
	if err != nil {
		return err
	}
	if !entrypointPattern.MatchString(entrypoint) {
		return fmt.Errorf("sandbox: entrypoint %q must match %s", entrypoint, entrypointPattern)
	}
	if !digestPattern.MatchString(digest) {
		return fmt.Errorf("sandbox: digest %q must be \"sha256:\" plus 64 lower-case hex digits", digest)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("sandbox: version directory: %w", err)
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("sandbox: version directory %s is not a real directory", dir)
	}
	if err := pkgfile.VerifyFile(dir, entrypoint, digest); err != nil {
		return fmt.Errorf("sandbox: entrypoint digest check failed: %w", err)
	}
	return nil
}

// WriteCredential writes the plugin token as <id>.token with mode 0600 into
// the credential directory handle and returns the file name. The directory is
// chmodded 0700 through the same handle, so a symlink cannot redirect it.
//
// The token must be printable ASCII without spaces so that it cannot be
// mangled by a unit file, a journal line or a JSON result.
func WriteCredential(dir *os.Root, id string, token []byte) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	if err := checkToken(token); err != nil {
		return "", err
	}
	if err := dir.Chmod(".", CredentialDirMode); err != nil {
		return "", fmt.Errorf("sandbox: credential dir mode: %w", err)
	}
	name := id + TokenSuffix
	if err := WriteFileAtomicIn(dir, name, token, CredentialFileMode); err != nil {
		return "", err
	}
	return name, nil
}

// CreatePluginGroup creates the private group qwq-p-<id>. It uses
// `groupadd --system --force`, so an existing group is not an error.
func CreatePluginGroup(ctx context.Context, r Runner, name string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := checkGroupName(name); err != nil {
		return err
	}
	out, err := runnerOr(r).Run(ctx, "groupadd", "--system", "--force", name)
	if err != nil {
		return fmt.Errorf("sandbox: groupadd %s: %w: %s", name, err, out)
	}
	return nil
}

// RemovePluginGroup deletes the private group, tolerating a group that is
// already gone.
func RemovePluginGroup(ctx context.Context, r Runner, name string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := checkGroupName(name); err != nil {
		return err
	}
	// groupdel writes /etc/group and /etc/gshadow in two steps. A concurrent
	// uninstall of another version (or a shadow lock) can make one step fail
	// even though the group is already gone; retry briefly and treat "the
	// group does not exist" as success.
	var out string
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		out, err = runnerOr(r).Run(ctx, "groupdel", name)
		if err == nil {
			return nil
		}
		if _, qerr := runnerOr(r).Run(ctx, "getent", "group", name); qerr != nil {
			return nil
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return fmt.Errorf("sandbox: groupdel %s: %w: %s", name, err, out)
}

// WriteFileAtomic writes data to path with mode, replacing an existing file by
// rename so a reader never sees a partial unit. Parent directories are created
// 0755; path must be absolute and clean.
func WriteFileAtomic(path string, data []byte, mode fs.FileMode) error {
	if err := checkText("path", path); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("sandbox: path %q is not absolute", path)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("sandbox: path %q is not clean", path)
	}
	if mode.Perm() == 0 {
		return fmt.Errorf("sandbox: mode for %s is empty", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("sandbox: creating %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".qwq-tmp-")
	if err != nil {
		return fmt.Errorf("sandbox: creating temporary file in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(mode.Perm()); err != nil {
		_ = f.Close()
		return fmt.Errorf("sandbox: mode of %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("sandbox: writing %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sandbox: syncing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("sandbox: closing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("sandbox: publishing %s: %w", path, err)
	}
	return syncDir(dir)
}

// ensureRuntimeDirs creates the runtime directories the units refer to, all
// relative to the trusted runtime handle.
func ensureRuntimeDirs(rt *os.Root, p Paths) ([]string, error) {
	dirs := make([]string, 0, 4)
	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{
		{p.PluginRoot, RuntimeDirMode},
		{p.PluginDir, RuntimeDirMode},
		{p.Link, RuntimeDirMode},
	} {
		if err := MkdirAllIn(rt, relTo(p.Runtime, d.path), d.mode); err != nil {
			return dirs, fmt.Errorf("sandbox: creating %s: %w", d.path, err)
		}
		dirs = append(dirs, d.path)
	}
	return dirs, nil
}

// removeCredential deletes <CredDir>/<id>.token through the trusted handle
// and returns its path when it existed.
func (in Installer) removeCredential(id string) (string, error) {
	creds, err := in.Trust.Open(in.CredDir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("sandbox: credential dir %s is not a trusted directory: %w", in.CredDir, err)
	}
	defer func() { _ = creds.Close() }()
	name := id + TokenSuffix
	ok, err := RemoveAllIn(creds, name)
	if err != nil || !ok {
		return "", err
	}
	return filepath.Join(in.CredDir, name), nil
}

// removeHostDir deletes host/<id> relative to a handle opened on host/.
func removeHostDir(rt *os.Root, id string) (bool, error) {
	host, err := rt.OpenRoot(hostDirName)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = host.Close() }()
	return RemoveAllIn(host, id)
}

// lookupIDs resolves a user and a group through os/user.
func lookupIDs(userName, groupName string) (int, int, error) {
	u, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, err
	}
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("gid %q: %w", g.Gid, err)
	}
	return uid, gid, nil
}

// relTo returns path relative to base. Both come from PathsFor, so path is
// always strictly below base.
func relTo(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		panic(fmt.Sprintf("sandbox: %s is not below %s", path, base))
	}
	return rel
}

// ======================== 原子IO单源接缝：仅测试注入故障，生产仍按同一顺序同步发布 ========================

type atomicFileOperations struct {
	write         func(*os.File, []byte) (int, error)
	syncFile      func(*os.File) error
	syncDirectory func(*os.Root, string) error
}

func defaultAtomicFileOperations() atomicFileOperations {
	return atomicFileOperations{write: (*os.File).Write, syncFile: (*os.File).Sync, syncDirectory: SyncIn}
}

// WriteFileAtomicIn is WriteFileAtomic relative to a directory handle: the
// temporary file, the rename and the directory fsync all stay inside r.
func WriteFileAtomicIn(r *os.Root, name string, data []byte, mode fs.FileMode) error {
	return writeFileAtomicInWithOps(r, name, data, mode, defaultAtomicFileOperations())
}

func writeFileAtomicInWithOps(r *os.Root, name string, data []byte, mode fs.FileMode, operations atomicFileOperations) error {
	if mode.Perm() == 0 {
		return fmt.Errorf("sandbox: mode for %s is empty", name)
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(name), ".qwq-tmp-"+hex.EncodeToString(rnd[:]))
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("sandbox: creating temporary file for %s: %w", name, err)
	}
	defer func() { _ = r.Remove(tmp) }()
	if err := f.Chmod(mode.Perm()); err != nil {
		_ = f.Close()
		return fmt.Errorf("sandbox: mode of %s: %w", tmp, err)
	}
	if written, err := operations.write(f, data); err != nil {
		_ = f.Close()
		return fmt.Errorf("sandbox: writing %s: %w", tmp, err)
	} else if written != len(data) {
		_ = f.Close()
		return fmt.Errorf("sandbox: writing %s: %w", tmp, io.ErrShortWrite)
	}
	if err := operations.syncFile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("sandbox: syncing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("sandbox: closing %s: %w", tmp, err)
	}
	if err := r.Rename(tmp, name); err != nil {
		return fmt.Errorf("sandbox: publishing %s: %w", name, err)
	}
	return operations.syncDirectory(r, filepath.Dir(name))
}

// SyncIn fsyncs the directory rel inside r so a rename survives a crash.
func SyncIn(r *os.Root, rel string) error {
	f, err := r.Open(rel)
	if err != nil {
		return fmt.Errorf("sandbox: opening %s: %w", rel, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("sandbox: syncing %s: %w", rel, err)
	}
	return nil
}

// removeIfExists removes a file and reports whether it existed.
func removeIfExists(path string) (bool, error) {
	err := os.Remove(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("sandbox: removing %s: %w", path, err)
	}
}

// syncDir fsyncs a directory so a rename survives a crash.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sandbox: opening %s: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sandbox: syncing %s: %w", dir, err)
	}
	return nil
}

// checkToken validates a plugin token.
func checkToken(token []byte) error {
	if len(token) < MinTokenLen || len(token) > MaxTokenLen {
		return fmt.Errorf("sandbox: credential is %d bytes, want %d..%d", len(token), MinTokenLen, MaxTokenLen)
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return errors.New("sandbox: credential must be printable ASCII without spaces")
		}
	}
	return nil
}

// checkGroupName validates a Linux group name and the 32-character limit of
// the shadow tools.
func checkGroupName(name string) error {
	if len(name) > 32 {
		return fmt.Errorf("sandbox: group name %q is %d characters, the limit is 32", name, len(name))
	}
	if !groupPattern.MatchString(name) {
		return fmt.Errorf("sandbox: group name %q must match %s", name, groupPattern)
	}
	return nil
}
