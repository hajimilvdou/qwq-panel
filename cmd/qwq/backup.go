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
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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

	"github.com/qwq-panel/qwq/internal/hostbackup"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
)

const (
	backupFormat            = hostbackup.BackupFormat
	backupDBName            = hostbackup.BackupDBName
	backupGlob              = hostbackup.BackupGlob
	backupStamp             = hostbackup.BackupStamp
	archiveManifest         = hostbackup.ArchiveManifest
	archiveConfig           = hostbackup.ArchiveConfig
	archiveDataPrefix       = hostbackup.ArchiveDataPrefix
	archivePluginDataPrefix = hostbackup.ArchivePluginDataPrefix
	maxManifestBytes        = 4 << 20
	maxRestoreBytes         = 4 << 30 // 4 GiB total decompressed archive budget
	restoreStaging          = ".restore-tmp"
	restoreOld              = ".restore-old"
)

// backupItems 是数据目录中纳入备份、恢复时整体替换的条目。backups/ 与
// staging/ 不在其列：前者是备份本身，后者是安装过程的暂存。
var backupItems = append([]string(nil), hostbackup.BackupItems...)

// Test seams for backup/restore of DynamicUser plugin private data & credentials.
var (
	backupHelperSocket    = sandbox.DefaultPrivilegedSocket
	privatePluginDataRoot = sandbox.DefaultPrivatePluginDataRoot
	pluginCredDir         = sandbox.DefaultCredDir
)

// backupManifest 是归档内 manifest.json 的内容。
type backupManifest = hostbackup.BackupManifest

// controllerActive 报告 qwq-controller 是否在运行；测试中替换。
var controllerActive = func() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "qwq-controller.service").Run() == nil
}

// activePluginUnits 返回当前正在运行的 qwq-plugin@*.service 单元列表；测试中可替换。
var activePluginUnits = func() []string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--plain", "qwq-plugin@*.service").Output()
	if err != nil {
		return nil
	}
	var units []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "qwq-plugin@") {
			units = append(units, fields[0])
		}
	}
	return units
}

// ── qwq backup ──────────────────────────────────────────────────────────────

func runBackup(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: qwq backup [create] [--config FILE] [--out DIR] [--keep N]

Writes a consistent backup (database snapshot, master key, certificates,
plugin state, configuration) to DIR/qwq-<time>.tar.gz, mode 0600, and prints
its path. Run as root it drops to the owner of the data directory, which must
be able to write DIR. Copy backups off the machine: they contain the master key.

`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	out := fs.String("out", "", "output directory (default <data_dir>/backups)")
	keep := fs.Int("keep", hostbackup.DefaultKeepBackups, "keep only the newest N backups in the output directory (0 keeps all)")
	if len(args) > 0 && strings.EqualFold(strings.TrimSpace(args[0]), "create") {
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := parseBackupPositionalArgs(fs.Args()); err != nil || *keep < 0 {
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

// parseBackupPositionalArgs accepts either no positional args (`qwq backup`)
// or the documented `create` subcommand (`qwq backup create`).
func parseBackupPositionalArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	if len(args) == 1 && strings.EqualFold(strings.TrimSpace(args[0]), "create") {
		return nil
	}
	return errors.New("unexpected positional arguments")
}

// writeBackup 在 outDir 写出归档并返回其路径。归档先写成 .partial，
// 落盘后再 rename，所以 outDir 里的 qwq-*.tar.gz 总是完整的。
func writeBackup(ctx context.Context, dataDir string, rawConfig []byte, outDir string, now time.Time) (string, error) {
	_, final, err := hostbackup.CreateBackup(ctx, hostbackup.CreateOptions{
		DataDir:      dataDir,
		RawConfig:    rawConfig,
		OutDir:       outDir,
		Now:          now,
		HelperSocket: backupHelperSocket,
	})
	return final, err
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
	if units := activePluginUnits(); len(units) > 0 {
		fmt.Fprintf(stderr, "qwq restore: plugin services are still running (%s); stop them first: systemctl stop 'qwq-plugin@*.service'\n",
			strings.Join(units, ", "))
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
	if err := restorePluginPrivateData(staging, privatePluginDataRoot); err != nil {
		return m, fmt.Errorf("plugin private data: %w (controller data already restored)", err)
	}
	if err := resyncRestoredPluginCredentials(ctx, filepath.Join(dataDir, backupDBName), pluginCredDir, uid, gid); err != nil {
		return m, fmt.Errorf("resync plugin credentials: %w", err)
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

// mkdirAllOwned creates every missing directory component under root for slash-
// separated relDir and applies Lchown(dstUID, dstGID) to newly created segments
// when preserveOwner is true so DynamicUser plugins can traverse nested state dirs.
func mkdirAllOwned(root *os.Root, relDir string, preserveOwner bool, dstUID, dstGID int) error {
	clean := path.Clean(relDir)
	if clean == "." || clean == "" {
		return nil
	}
	cur := ""
	for _, seg := range strings.Split(clean, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if cur == "" {
			cur = seg
		} else {
			cur = cur + "/" + seg
		}
		fi, err := root.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			if merr := root.Mkdir(cur, 0o700); merr != nil {
				return merr
			}
			if preserveOwner {
				_ = root.Lchown(cur, dstUID, dstGID)
			}
			continue
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("refusing to restore through non-directory path %q", cur)
		}
	}
	return nil
}

// restorePluginPrivateData restores archived plugin-data/<id>/... trees back
// into <privateRoot>/<id>/default using pinned *os.Root handles and streaming
// copies, preserving existing DynamicUser ownership (including nested parent
// directories) and clearing stale SQLite WAL/SHM sidecar files next to *.db.
func restorePluginPrivateData(staging *os.Root, privateRoot string) error {
	pRootName := strings.TrimSuffix(archivePluginDataPrefix, "/")
	if _, err := staging.Lstat(pRootName); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if strings.TrimSpace(privateRoot) == "" {
		return nil
	}
	entries, err := fs.ReadDir(staging.FS(), pRootName)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(privateRoot); errors.Is(err, fs.ErrNotExist) {
		if merr := os.MkdirAll(privateRoot, 0o700); merr != nil {
			return merr
		}
	}
	privRoot, err := backupTrustPolicy(privateRoot).Open(privateRoot)
	if err != nil {
		return fmt.Errorf("open private plugin data root %s: %w", privateRoot, err)
	}
	defer func() { _ = privRoot.Close() }()

	for _, de := range entries {
		if !de.IsDir() || sandbox.ValidateID(de.Name()) != nil {
			continue
		}
		pluginID := de.Name()
		if fi, serr := privRoot.Lstat(pluginID); errors.Is(serr, fs.ErrNotExist) {
			if merr := privRoot.Mkdir(pluginID, 0o700); merr != nil {
				return merr
			}
		} else if serr != nil {
			return serr
		} else if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("plugin private data entry %q is not a regular directory", pluginID)
		}

		defaultRel := pluginID + "/default"
		dstUID, dstGID, preserveOwner := 0, 0, false
		if fi, serr := privRoot.Lstat(defaultRel); errors.Is(serr, fs.ErrNotExist) {
			if merr := privRoot.Mkdir(defaultRel, 0o700); merr != nil {
				return merr
			}
		} else if serr != nil {
			return serr
		} else if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("plugin private state dir %q is not a regular directory", defaultRel)
		} else if u, g, ok := ownerOf(fi); ok {
			dstUID, dstGID, preserveOwner = u, g, true
		}

		dstRoot, err := privRoot.OpenRoot(defaultRel)
		if err != nil {
			return err
		}
		srcBase := pRootName + "/" + pluginID
		walkErr := fs.WalkDir(staging.FS(), srcBase, func(p string, d fs.DirEntry, wErr error) error {
			if wErr != nil {
				return wErr
			}
			if p == srcBase || d.IsDir() {
				return nil
			}
			rel := strings.TrimPrefix(p, srcBase+"/")
			if !fs.ValidPath(rel) {
				return fmt.Errorf("invalid plugin data path %q", rel)
			}
			if err := mkdirAllOwned(dstRoot, path.Dir(rel), preserveOwner, dstUID, dstGID); err != nil {
				return err
			}
			if strings.HasSuffix(strings.ToLower(rel), ".db") {
				_ = dstRoot.Remove(rel + "-wal")
				_ = dstRoot.Remove(rel + "-shm")
			}
			srcFile, rerr := staging.Open(p)
			if rerr != nil {
				return rerr
			}
			defer func() { _ = srcFile.Close() }()

			tmp := rel + ".restore-tmp"
			_ = dstRoot.Remove(tmp)
			out, oerr := dstRoot.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
			if oerr != nil {
				return oerr
			}
			_, copyErr := io.Copy(out, srcFile)
			if copyErr == nil {
				copyErr = out.Sync()
			}
			if cerr := out.Close(); copyErr == nil {
				copyErr = cerr
			}
			if copyErr != nil {
				_ = dstRoot.Remove(tmp)
				return copyErr
			}
			if preserveOwner {
				_ = dstRoot.Lchown(tmp, dstUID, dstGID)
			}
			if err := dstRoot.Rename(tmp, rel); err != nil {
				_ = dstRoot.Remove(tmp)
				return err
			}
			return nil
		})
		_ = dstRoot.Close()
		if walkErr != nil {
			return walkErr
		}
	}
	return nil
}

func backupTrustPolicy(rootPath string) sandbox.TrustPolicy {
	if uid := geteuid(); uid != 0 {
		return sandbox.TrustPolicy{UID: uid, StopAt: filepath.Clean(rootPath)}
	}
	return sandbox.TrustPolicy{}
}

// resyncRestoredPluginCredentials rotates and aligns every plugin's on-disk
// /var/lib/qwq-privileged/creds/<id>.token with the restored qwq.db
// plugin_credentials digest so restored or migrated nodes start plugins cleanly.
func resyncRestoredPluginCredentials(ctx context.Context, dbPath, credDir string, dbUID, dbGID int) error {
	if strings.TrimSpace(credDir) == "" {
		return nil
	}
	if _, err := os.Stat(credDir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	credRoot, err := backupTrustPolicy(credDir).Open(credDir)
	if err != nil {
		return fmt.Errorf("open plugin credentials dir %s: %w", credDir, err)
	}
	defer func() { _ = credRoot.Close() }()

	dsn := "file:" + filepath.ToSlash(dbPath) + "?_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
		_ = db.Close()
		for _, suffix := range []string{"", "-wal", "-shm"} {
			_ = os.Lchown(dbPath+suffix, dbUID, dbGID)
		}
	}()
	rows, err := db.QueryContext(ctx, `SELECT plugin_id FROM plugin_credentials`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			// Older backups without plugin_credentials table skip cleanly.
			return nil
		}
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			_ = rows.Close()
			return scanErr
		}
		if sandbox.ValidateID(id) == nil {
			ids = append(ids, id)
		}
	}
	if rerr := rows.Err(); rerr != nil {
		_ = rows.Close()
		return rerr
	}
	_ = rows.Close()
	if len(ids) == 0 {
		return nil
	}

	hasPrevCol := false
	colRows, err := db.QueryContext(ctx, `PRAGMA table_info(plugin_credentials)`)
	if err != nil {
		return err
	}
	for colRows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dflt sql.NullString
		var pk int
		if colRows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk) == nil && name == "prev_token_sha256" {
			hasPrevCol = true
		}
	}
	_ = colRows.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	type pendingCred struct {
		name string
		tmp  string
		tok  []byte
		sum  string
	}
	var pending []pendingCred
	cleanupPending := func() {
		for i := range pending {
			clear(pending[i].tok)
			_ = credRoot.Remove(pending[i].tmp)
		}
	}

	nowStr := storage.FormatTime(time.Now().UTC())
	for _, id := range ids {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			cleanupPending()
			return err
		}
		tok := []byte(base64.RawURLEncoding.EncodeToString(raw))
		clear(raw)
		sum := sha256.Sum256(tok)
		sumHex := hex.EncodeToString(sum[:])

		credName := id + ".token"
		tmp := credName + ".restore-tmp"
		_ = credRoot.Remove(tmp)
		out, oerr := credRoot.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if oerr != nil {
			clear(tok)
			cleanupPending()
			return oerr
		}
		_, werr := out.Write(tok)
		if werr == nil {
			werr = out.Sync()
		}
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			clear(tok)
			_ = credRoot.Remove(tmp)
			cleanupPending()
			return werr
		}
		if geteuid() == 0 {
			_ = credRoot.Lchown(tmp, 0, 0)
		}
		pending = append(pending, pendingCred{name: credName, tmp: tmp, tok: tok, sum: sumHex})

		var uerr error
		if hasPrevCol {
			_, uerr = tx.ExecContext(ctx,
				`UPDATE plugin_credentials SET token_sha256 = ?, prev_token_sha256 = '', issued_at = ? WHERE plugin_id = ?`,
				sumHex, nowStr, id)
		} else {
			_, uerr = tx.ExecContext(ctx,
				`UPDATE plugin_credentials SET token_sha256 = ?, issued_at = ? WHERE plugin_id = ?`,
				sumHex, nowStr, id)
		}
		if uerr != nil {
			cleanupPending()
			return uerr
		}
	}
	if err := tx.Commit(); err != nil {
		cleanupPending()
		return err
	}
	for i := range pending {
		clear(pending[i].tok)
		if err := credRoot.Rename(pending[i].tmp, pending[i].name); err != nil {
			_ = credRoot.Remove(pending[i].tmp)
			return err
		}
	}
	return nil
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
	seenManifest := make(map[string]struct{}, len(m.Files))
	for _, bf := range m.Files {
		if _, dup := seenManifest[bf.Path]; dup {
			return m, fmt.Errorf("duplicate manifest entry %q", bf.Path)
		}
		seenManifest[bf.Path] = struct{}{}
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

// validArchivePath 只认 config/qwq.json、data/qwq.db、data/<目录条目>/... 与 plugin-data/<plugin_id>/...。
func validArchivePath(name string) bool {
	if name == archiveConfig {
		return true
	}
	if rest, ok := strings.CutPrefix(name, archivePluginDataPrefix); ok {
		if !fs.ValidPath(rest) {
			return false
		}
		pluginID, sub, nested := strings.Cut(rest, "/")
		return nested && sub != "" && sandbox.ValidateID(pluginID) == nil
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
