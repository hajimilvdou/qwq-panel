// SPDX-License-Identifier: AGPL-3.0-only

package main

// =============================================================================
//  qwq backup / qwq restore —— 数据目录的一致性备份与恢复（DEP-04）
// -----------------------------------------------------------------------------
//  归档是 0600 的 tar.gz：
//    data/qwq.db              VACUUM INTO 快照（不是在线库文件的拷贝）
//    data/keys|tls|acme|plugin-state/...   主密钥、证书、ACME 账户、插件 KV
//    config/qwq.json          引导配置
//    manifest.json            最后写入：格式、schema_version、buildinfo、时间、
//                             每个文件的 sha256（边写边算，活文件也不会自相矛盾）
//
//  master.key 与数据库同生共死：只恢复数据库而换了主密钥，全部 secret 永久
//  不可解，所以二者总在同一个归档里。
//
//  恢复要求 controller 已停。先把归档完整解到 <DataDir>/.restore-tmp，逐项
//  核对 sha256、quick_check 与 schema 版本，全部通过后才动数据目录：被替换
//  的条目先挪进 .restore-old，再把新条目逐个 rename 进来，成功后删除旧的。
// =============================================================================

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/storage"
)

const (
	backupFormat      = 1
	backupDBName      = "qwq.db"
	backupGlob        = "qwq-*.tar.gz"
	backupStamp       = "20060102T150405.000Z"
	archiveManifest   = "manifest.json"
	archiveConfig     = "config/qwq.json"
	archiveDataPrefix = "data/"
	maxManifestBytes  = 4 << 20
	maxRestoreBytes   = 4 << 30 // 4 GiB total decompressed archive budget
	restoreStaging    = ".restore-tmp"
	restoreOld        = ".restore-old"
)

// backupItems 是数据目录中纳入备份、恢复时整体替换的条目。backups/ 与
// staging/ 不在其列：前者是备份本身，后者是安装过程的暂存。
var backupItems = []string{backupDBName, "keys", "tls", "acme", "cluster", "trust", "plugin-state", "qwq-cn-rules.bundle"}

// backupManifest 是归档内 manifest.json 的内容。
type backupManifest struct {
	Format        int          `json:"format"`
	SchemaVersion int          `json:"schema_version"`
	Build         string       `json:"build"`
	CreatedAt     string       `json:"created_at"`
	Files         []backupFile `json:"files"`
}

type backupFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// controllerActive 报告 qwq-controller 是否在运行；测试中替换。
var controllerActive = func() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "qwq-controller.service").Run() == nil
}

// ── qwq backup ──────────────────────────────────────────────────────────────

func runBackup(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: qwq backup [--config FILE] [--out DIR] [--keep N]

Writes a consistent backup (database snapshot, master key, certificates,
plugin state, configuration) to DIR/qwq-<time>.tar.gz, mode 0600, and prints
its path. Run as root it drops to the owner of the data directory, which must
be able to write DIR. Copy backups off the machine: they contain the master key.

`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	out := fs.String("out", "", "output directory (default <data_dir>/backups)")
	keep := fs.Int("keep", 0, "keep only the newest N backups in the output directory (0 keeps all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *keep < 0 {
		fs.Usage()
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq backup: %v\n", err)
		return 2
	}
	rawConfig, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq backup: %v\n", err)
		return 1
	}
	// 以数据目录属主身份读写：root 打开库会留下 root 属主的 WAL/SHM。
	if geteuid() == 0 {
		if err := dropToOwner(cfg.DataDir); err != nil {
			fmt.Fprintf(stderr, "qwq backup: %v\n", err)
			return 1
		}
	}
	dir := *out
	if dir == "" {
		dir = storage.BackupDir(filepath.Join(cfg.DataDir, backupDBName))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	p, err := writeBackup(ctx, cfg.DataDir, rawConfig, dir, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "qwq backup: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, p)
	if err := storage.PruneBackups(dir, backupGlob, *keep); err != nil {
		fmt.Fprintf(stderr, "qwq backup: written, but pruning old backups failed: %v\n", err)
		return 1
	}
	return 0
}

// writeBackup 在 outDir 写出归档并返回其路径。归档先写成 .partial，
// 落盘后再 rename，所以 outDir 里的 qwq-*.tar.gz 总是完整的。
func writeBackup(ctx context.Context, dataDir string, rawConfig []byte, outDir string, now time.Time) (string, error) {
	db := filepath.Join(dataDir, backupDBName)
	if _, err := os.Stat(db); err != nil {
		return "", fmt.Errorf("%w (start qwq-controller once to initialize the data directory)", err)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", err
	}
	stamp := now.UTC().Format(backupStamp)
	final := filepath.Join(outDir, "qwq-"+stamp+".tar.gz")
	snap := filepath.Join(outDir, ".qwq-"+stamp+".db")
	if err := storage.BackupFile(ctx, db, snap); err != nil {
		return "", err
	}
	defer os.Remove(snap)
	version, err := storage.InspectFile(ctx, snap)
	if err != nil {
		return "", err
	}

	tmp := final + ".partial"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	werr := func() error {
		a := newArchiveWriter(f, now)
		if err := a.addFile(archiveDataPrefix+backupDBName, snap); err != nil {
			return err
		}
		for _, item := range backupItems[1:] {
			full := filepath.Join(dataDir, item)
			fi, serr := os.Lstat(full)
			if errors.Is(serr, fs.ErrNotExist) {
				continue
			}
			if serr != nil {
				return serr
			}
			if fi.Mode().IsRegular() {
				if err := a.addFile(archiveDataPrefix+item, full); err != nil {
					return err
				}
				continue
			}
			if fi.IsDir() {
				if err := a.addTree(archiveDataPrefix+item, full); err != nil {
					return err
				}
			}
		}
		if err := a.add(archiveConfig, 0o640, int64(len(rawConfig)), bytes.NewReader(rawConfig)); err != nil {
			return err
		}
		m, err := json.MarshalIndent(backupManifest{
			Format:        backupFormat,
			SchemaVersion: version,
			Build:         buildinfo.Read().String(),
			CreatedAt:     now.UTC().Format(time.RFC3339),
			Files:         a.files,
		}, "", "  ")
		if err != nil {
			return err
		}
		if err := a.entry(archiveManifest, 0o600, int64(len(m)), bytes.NewReader(m)); err != nil {
			return err
		}
		if err := a.close(); err != nil {
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", werr
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	return final, syncDirectory(outDir)
}

// archiveWriter 写 tar.gz，并为每个数据条目记下 sha256 供 manifest 使用。
type archiveWriter struct {
	gz    *gzip.Writer
	tw    *tar.Writer
	mtime time.Time
	files []backupFile
}

func newArchiveWriter(w io.Writer, mtime time.Time) *archiveWriter {
	gz := gzip.NewWriter(w)
	return &archiveWriter{gz: gz, tw: tar.NewWriter(gz), mtime: mtime}
}

// entry 写一个普通文件条目（不记入 manifest）。文件在读取过程中变短时
// tar 会在下一个条目报错，不会悄悄写出残缺归档。
func (a *archiveWriter) entry(name string, mode fs.FileMode, size int64, r io.Reader) error {
	if err := a.tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: name, Mode: int64(mode.Perm()), Size: size, ModTime: a.mtime,
	}); err != nil {
		return err
	}
	_, err := io.Copy(a.tw, io.LimitReader(r, size))
	return err
}

// add 写一个数据条目并记入 manifest。
func (a *archiveWriter) add(name string, mode fs.FileMode, size int64, r io.Reader) error {
	h := sha256.New()
	if err := a.entry(name, mode, size, io.TeeReader(r, h)); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	a.files = append(a.files, backupFile{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
	return nil
}

func (a *archiveWriter) addFile(name, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return a.add(name, fi.Mode(), fi.Size(), f)
}

// addTree 加入 root 下的全部普通文件。root 不存在时什么也不做（例如从未
// 申请过 ACME 证书）；遍历中途被原子替换掉的文件同样跳过。符号链接等
// 特殊文件不属于 qwq 的数据，跳过。
func (a *archiveWriter) addTree(prefix, root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			var rel string
			if rel, err = filepath.Rel(root, p); err == nil {
				err = a.addFile(prefix+"/"+filepath.ToSlash(rel), p)
			}
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	})
}

func (a *archiveWriter) close() error {
	return errors.Join(a.tw.Close(), a.gz.Close())
}

// ── qwq restore ─────────────────────────────────────────────────────────────

func runRestore(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: sudo qwq restore [--config FILE] BACKUP.tar.gz

Replaces the database, master key, certificates, plugin state and
configuration with the contents of a "qwq backup" archive. qwq-controller
must be stopped. The archive is verified completely before anything changes.

`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "qwq restore: must run as root (use sudo)")
		return 1
	}
	if controllerActive() {
		fmt.Fprintln(stderr, "qwq restore: qwq-controller is running; stop it first: systemctl stop qwq-controller")
		return 1
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq restore: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	m, err := restoreBackup(ctx, fs.Arg(0), cfg.DataDir, *configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq restore: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "restored backup of %s (schema %d, %s); start the panel: systemctl start qwq-controller\n",
		m.CreatedAt, m.SchemaVersion, m.Build)
	return 0
}

// restoreBackup 校验并恢复归档，见文件头的流程说明。
//
// 数据目录属于 qwq：root 在其中的每一步都经 os.Root 限定在目录之内，以
// qwq 身份运行的进程即使把暂存目录换成符号链接，也无法把 root 的写入
// 引到目录外。
func restoreBackup(ctx context.Context, archive, dataDir, configPath string) (backupManifest, error) {
	var m backupManifest
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return m, fmt.Errorf("data directory: %w (install qwq first)", err)
	}
	defer root.Close()
	fi, err := root.Stat(".")
	if err != nil {
		return m, err
	}
	uid, gid, ok := ownerOf(fi)
	if !ok {
		return m, fmt.Errorf("data directory %s: owner unavailable", dataDir)
	}

	if err := root.RemoveAll(restoreStaging); err != nil {
		return m, err
	}
	if err := root.Mkdir(restoreStaging, 0o700); err != nil {
		return m, err
	}
	defer root.RemoveAll(restoreStaging)
	staging, err := root.OpenRoot(restoreStaging)
	if err != nil {
		return m, err
	}
	defer staging.Close()

	if m, err = extractBackup(archive, staging); err != nil {
		return m, err
	}
	version, err := storage.InspectFile(ctx, filepath.Join(dataDir, restoreStaging, filepath.FromSlash(archiveDataPrefix+backupDBName)))
	if err != nil {
		return m, err
	}
	if version != m.SchemaVersion {
		return m, fmt.Errorf("database schema %d does not match the manifest (%d)", version, m.SchemaVersion)
	}
	if latest := storage.LatestSchemaVersion(); version > latest {
		return m, fmt.Errorf("backup schema version %d is newer than this binary (%d); install the release that wrote it (%s)", version, latest, m.Build)
	}
	if _, err := staging.Lstat(archiveDataPrefix + "keys/master.key"); err != nil {
		return m, errors.New("backup has no keys/master.key; its secrets could never be decrypted")
	}
	rawConfig, err := staging.ReadFile(archiveConfig)
	if err != nil {
		return m, err
	}
	bc, err := config.Parse(rawConfig)
	if err != nil {
		return m, fmt.Errorf("configuration in backup: %w", err)
	}
	if filepath.Clean(bc.DataDir) != filepath.Clean(dataDir) {
		return m, fmt.Errorf("backup was taken with data_dir %s, this installation uses %s", bc.DataDir, dataDir)
	}
	data := strings.TrimSuffix(archiveDataPrefix, "/")
	if err := fs.WalkDir(staging.FS(), data, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return staging.Lchown(p, uid, gid)
	}); err != nil {
		return m, err
	}

	// ── 校验全部通过，开始替换 ──
	if err := root.RemoveAll(restoreOld); err != nil {
		return m, err
	}
	if err := root.Mkdir(restoreOld, 0o700); err != nil {
		return m, err
	}
	// 旧库的 WAL/SHM 若留下，会被套到恢复回来的库上。
	for _, item := range append([]string{backupDBName + "-wal", backupDBName + "-shm"}, backupItems...) {
		if err := root.Rename(item, restoreOld+"/"+item); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return m, fmt.Errorf("move %s aside: %w (replaced files are kept in %s)", item, err, restoreOld)
		}
		src := restoreStaging + "/" + data + "/" + item
		if _, err := root.Lstat(src); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := root.Rename(src, item); err != nil {
			return m, fmt.Errorf("restore %s: %w (replaced files are kept in %s)", item, err, restoreOld)
		}
	}
	if err := replaceConfig(rawConfig, configPath, gid); err != nil {
		return m, fmt.Errorf("configuration: %w (data directory already restored)", err)
	}
	d, err := root.Open(".")
	if err != nil {
		return m, err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return m, err
	}
	return m, root.RemoveAll(restoreOld)
}

// extractBackup 把归档解到 staging，并核对 manifest：条目一一对应、
// sha256 全部相符。只接受 backupItems 与 config/qwq.json 下的普通文件。
func extractBackup(archive string, staging *os.Root) (backupManifest, error) {
	var m backupManifest
	f, err := os.Open(archive)
	if err != nil {
		return m, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return m, fmt.Errorf("%s: %w", archive, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	got := map[string]string{}
	haveManifest := false
	var totalBytes int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("%s: %w", archive, err)
		}
		if hdr.Name == archiveManifest && !haveManifest {
			if err := json.NewDecoder(io.LimitReader(tr, maxManifestBytes)).Decode(&m); err != nil {
				return m, fmt.Errorf("manifest: %w", err)
			}
			haveManifest = true
			continue
		}
		if hdr.Typeflag != tar.TypeReg || !validArchivePath(hdr.Name) {
			return m, fmt.Errorf("unexpected archive entry %q", hdr.Name)
		}
		if _, dup := got[hdr.Name]; dup {
			return m, fmt.Errorf("duplicate archive entry %q", hdr.Name)
		}
		remaining := maxRestoreBytes - totalBytes
		if remaining < 0 || hdr.Size < 0 || hdr.Size > remaining {
			return m, fmt.Errorf("backup archive exceeds maximum extraction size (%d bytes)", maxRestoreBytes)
		}
		sum, n, err := extractFile(staging, hdr.Name, tr, fs.FileMode(hdr.Mode).Perm()&0o700, remaining)
		if err != nil {
			return m, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		totalBytes += n
		got[hdr.Name] = sum
	}
	switch {
	case !haveManifest:
		return m, errors.New("not a qwq backup: manifest.json missing")
	case m.Format != backupFormat:
		return m, fmt.Errorf("unsupported backup format %d", m.Format)
	case len(m.Files) != len(got):
		return m, fmt.Errorf("archive has %d files, manifest lists %d", len(got), len(m.Files))
	}
	for _, bf := range m.Files {
		if got[bf.Path] != bf.SHA256 {
			return m, fmt.Errorf("checksum mismatch for %s; the backup is damaged", bf.Path)
		}
	}
	if _, ok := got[archiveDataPrefix+backupDBName]; !ok {
		return m, errors.New("backup has no database")
	}
	if _, ok := got[archiveConfig]; !ok {
		return m, errors.New("backup has no configuration")
	}
	return m, nil
}

// validArchivePath 只认 config/qwq.json、data/qwq.db 与 data/<目录条目>/...。
func validArchivePath(name string) bool {
	if name == archiveConfig {
		return true
	}
	rest, ok := strings.CutPrefix(name, archiveDataPrefix)
	if !ok || !fs.ValidPath(rest) {
		return false
	}
	item, sub, nested := strings.Cut(rest, "/")
	if item == backupDBName || item == "qwq-cn-rules.bundle" {
		return !nested
	}
	return nested && sub != "" && slices.Contains(backupItems[1:], item)
}

// extractFile 把 r 写成 staging 下的新文件 name（不覆盖已有文件），返回其 sha256 与写入字节数。
func extractFile(staging *os.Root, name string, r io.Reader, mode fs.FileMode, maxBytes int64) (string, int64, error) {
	mode = mode.Perm() & 0o700
	if mode&0o600 == 0 {
		mode |= 0o600
	}
	if err := staging.MkdirAll(path.Dir(name), 0o700); err != nil {
		return "", 0, err
	}
	out, err := staging.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, maxBytes+1))
	if err == nil && n > maxBytes {
		err = fmt.Errorf("backup archive exceeds maximum extraction size (%d bytes)", maxRestoreBytes)
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = staging.Chmod(name, mode)
	}
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// replaceConfig 原子替换配置文件，保留现有文件的属主与权限；不存在时
// 按 install.sh 的约定建成 root:<数据目录属组> 0640。配置目录属 root，
// 这里的路径操作不受 qwq 影响。
func replaceConfig(raw []byte, dst string, gid int) error {
	mode, uid := fs.FileMode(0o640), 0
	if fi, err := os.Stat(dst); err == nil {
		mode = fi.Mode().Perm()
		if u, g, ok := ownerOf(fi); ok {
			uid, gid = u, g
		}
	}
	tmp := dst + ".restore-tmp"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chown(tmp, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// ownerOf 返回文件的属主与属组。
func ownerOf(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
