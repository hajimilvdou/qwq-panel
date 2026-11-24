// SPDX-License-Identifier: AGPL-3.0-only

// Package hostbackup provides consistent archive creation, listing, safe
// filename validation, and support-bundle log/JSON redaction shared by the
// `qwq backup` / `qwq support-bundle` CLI commands and the admin Web API.
package hostbackup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/storage"
)

const (
	BackupFormat            = 1
	BackupDBName            = "qwq.db"
	BackupGlob              = "qwq-*.tar.gz"
	BackupStamp             = "20060102T150405.000Z"
	ArchiveManifest         = "manifest.json"
	ArchiveConfig           = "config/qwq.json"
	ArchiveDataPrefix       = "data/"
	ArchivePluginDataPrefix = "plugin-data/"
	DefaultKeepBackups      = 7
	maxListBackups          = 200
)

// BackupItems are the top-level entries inside DataDir included in backups and
// replaced atomically on restore. backups/ and staging/ are excluded.
var BackupItems = []string{
	BackupDBName,
	"keys",
	"tls",
	"acme",
	"cluster",
	"trust",
	"plugin-state",
	"agent-workspace",
	"agent-homes",
	"qwq-cn-rules.bundle",
}

var backupFilenameRe = regexp.MustCompile(`^qwq-[0-9]{8}T[0-9]{6}(?:\.[0-9]{3})?Z\.tar\.gz$`)

// IsValidBackupFilename validates a single backup archive basename without any
// path separators or traversal characters.
func IsValidBackupFilename(name string) bool {
	return backupFilenameRe.MatchString(name)
}

// BackupEntry describes one backup archive stored in <DataDir>/backups.
type BackupEntry struct {
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

// BackupManifest is the manifest.json stored inside each backup archive.
type BackupManifest struct {
	Format        int          `json:"format"`
	SchemaVersion int          `json:"schema_version"`
	Build         string       `json:"build"`
	CreatedAt     string       `json:"created_at"`
	Files         []BackupFile `json:"files"`
}

// BackupFile records one archived file's size and SHA-256 digest.
type BackupFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// CreateOptions configures CreateBackup.
type CreateOptions struct {
	DataDir      string
	RawConfig    []byte
	OutDir       string
	Now          time.Time
	HelperSocket string
}

// ListBackups enumerates backup archives in dir, newest first.
func ListBackups(dir string) ([]BackupEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []BackupEntry{}, nil
		}
		return nil, err
	}
	type item struct {
		entry BackupEntry
		mod   time.Time
	}
	var list []item
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !IsValidBackupFilename(name) {
			continue
		}
		fi, serr := de.Info()
		if serr != nil || !fi.Mode().IsRegular() {
			continue
		}
		created := fi.ModTime().UTC()
		if tsStr := strings.TrimSuffix(strings.TrimPrefix(name, "qwq-"), ".tar.gz"); tsStr != "" {
			if parsed, perr := time.Parse(BackupStamp, tsStr); perr == nil {
				created = parsed.UTC()
			} else if parsed, perr := time.Parse("20060102T150405Z", tsStr); perr == nil {
				created = parsed.UTC()
			}
		}
		list = append(list, item{
			entry: BackupEntry{
				Filename:  name,
				SizeBytes: fi.Size(),
				CreatedAt: created.Format(time.RFC3339),
			},
			mod: created,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		if !list[i].mod.Equal(list[j].mod) {
			return list[i].mod.After(list[j].mod)
		}
		return list[i].entry.Filename > list[j].entry.Filename
	})
	if len(list) > maxListBackups {
		list = list[:maxListBackups]
	}
	out := make([]BackupEntry, len(list))
	for i := range list {
		out[i] = list[i].entry
	}
	return out, nil
}

func randomNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// CreateBackup writes a consistent 0600 backup archive into opts.OutDir and
// returns its metadata and absolute path. When opts.HelperSocket is set and
// reachable, DynamicUser plugin private data trees are also snapshotted via
// qwq-privileged into plugin-data/<plugin_id>/... inside the archive.
func CreateBackup(ctx context.Context, opts CreateOptions) (BackupEntry, string, error) {
	var zero BackupEntry
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	db := filepath.Join(opts.DataDir, BackupDBName)
	if _, err := os.Stat(db); err != nil {
		return zero, "", fmt.Errorf("%w (start qwq-controller once to initialize the data directory)", err)
	}
	if err := os.MkdirAll(opts.OutDir, 0o700); err != nil {
		return zero, "", err
	}
	stamp := opts.Now.UTC().Format(BackupStamp)
	nonce := randomNonce()
	filename := "qwq-" + stamp + ".tar.gz"
	final := filepath.Join(opts.OutDir, filename)
	snap := filepath.Join(opts.OutDir, ".qwq-"+stamp+"-"+nonce+".db")
	if err := storage.BackupFile(ctx, db, snap); err != nil {
		return zero, "", err
	}
	defer func() { _ = os.Remove(snap) }()
	version, err := storage.InspectFile(ctx, snap)
	if err != nil {
		return zero, "", err
	}

	// Snapshot DynamicUser plugin private state directories via qwq-privileged
	// when running on a systemd host with a reachable privileged socket.
	var pluginStageDir string
	if specs := readActivePluginBackupSpecs(ctx, snap); len(specs) > 0 && strings.TrimSpace(opts.HelperSocket) != "" {
		if fi, serr := os.Stat(opts.HelperSocket); serr == nil && fi.Mode()&os.ModeSocket != 0 {
			stageName := ".plugin-backup-" + strings.ReplaceAll(stamp, ".", "-") + "-" + nonce
			helper := sandbox.NewHelperClient(opts.HelperSocket)
			res, berr := helper.BackupPluginData(ctx, stageName, specs)
			if berr != nil {
				return zero, "", fmt.Errorf("snapshot plugin private data: %w", berr)
			}
			if res.StageDir != "" {
				pluginStageDir = res.StageDir
				defer func() {
					cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					_ = helper.BackupPluginCleanup(cleanCtx, stageName)
				}()
			}
		}
	}

	tmp := final + "." + nonce + ".partial"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return zero, "", err
	}
	defer func() { _ = os.Remove(tmp) }()
	werr := func() error {
		a := newArchiveWriter(f, opts.Now)
		if err := a.addFile(ArchiveDataPrefix+BackupDBName, snap); err != nil {
			return err
		}
		for _, item := range BackupItems[1:] {
			full := filepath.Join(opts.DataDir, item)
			fi, serr := os.Lstat(full)
			if errors.Is(serr, fs.ErrNotExist) {
				continue
			}
			if serr != nil {
				return serr
			}
			if fi.Mode().IsRegular() {
				if err := a.addFile(ArchiveDataPrefix+item, full); err != nil {
					return err
				}
				continue
			}
			if fi.IsDir() {
				if err := a.addTree(ArchiveDataPrefix+item, full); err != nil {
					return err
				}
			}
		}
		if pluginStageDir != "" {
			entries, rerr := os.ReadDir(pluginStageDir)
			if rerr != nil {
				return fmt.Errorf("read plugin backup stage %s: %w", pluginStageDir, rerr)
			}
			for _, de := range entries {
				if !de.IsDir() || sandbox.ValidateID(de.Name()) != nil {
					continue
				}
				if err := a.addTree(ArchivePluginDataPrefix+de.Name(), filepath.Join(pluginStageDir, de.Name())); err != nil {
					return err
				}
			}
		}
		if err := a.add(ArchiveConfig, 0o640, int64(len(opts.RawConfig)), bytes.NewReader(opts.RawConfig)); err != nil {
			return err
		}
		m, err := json.MarshalIndent(BackupManifest{
			Format:        BackupFormat,
			SchemaVersion: version,
			Build:         buildinfo.Read().String(),
			CreatedAt:     opts.Now.UTC().Format(time.RFC3339),
			Files:         a.files,
		}, "", "  ")
		if err != nil {
			return err
		}
		if err := a.entry(ArchiveManifest, 0o600, int64(len(m)), bytes.NewReader(m)); err != nil {
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
		return zero, "", werr
	}
	if err := os.Rename(tmp, final); err != nil {
		return zero, "", err
	}
	_ = syncDirectory(opts.OutDir)
	fi, serr := os.Stat(final)
	if serr != nil {
		return zero, final, serr
	}
	return BackupEntry{
		Filename:  filename,
		SizeBytes: fi.Size(),
		CreatedAt: opts.Now.UTC().Format(time.RFC3339),
	}, final, nil
}

func readActivePluginBackupSpecs(ctx context.Context, snapDBPath string) []sandbox.PluginBackupSpec {
	dsn := "file:" + filepath.ToSlash(snapDBPath) + "?_pragma=query_only(1)&_pragma=busy_timeout(3000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(ctx, `SELECT plugin_id, manifest_json FROM plugin_versions WHERE active = 1 ORDER BY plugin_id`)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var specs []sandbox.PluginBackupSpec
	for rows.Next() {
		var pluginID, rawManifest string
		if err := rows.Scan(&pluginID, &rawManifest); err != nil {
			continue
		}
		if sandbox.ValidateID(pluginID) != nil {
			continue
		}
		var doc struct {
			State struct {
				BackupPaths []string `json:"backup_paths"`
			} `json:"state"`
		}
		if err := json.Unmarshal([]byte(rawManifest), &doc); err != nil {
			continue
		}
		if len(doc.State.BackupPaths) == 0 {
			continue
		}
		specs = append(specs, sandbox.PluginBackupSpec{
			PluginID:    pluginID,
			BackupPaths: doc.State.BackupPaths,
		})
	}
	return specs
}

type archiveWriter struct {
	gz    *gzip.Writer
	tw    *tar.Writer
	mtime time.Time
	files []BackupFile
}

func newArchiveWriter(w io.Writer, mtime time.Time) *archiveWriter {
	gz := gzip.NewWriter(w)
	return &archiveWriter{gz: gz, tw: tar.NewWriter(gz), mtime: mtime}
}

func (a *archiveWriter) entry(name string, mode fs.FileMode, size int64, r io.Reader) error {
	if err := a.tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: name, Mode: int64(mode.Perm()), Size: size, ModTime: a.mtime,
	}); err != nil {
		return err
	}
	_, err := io.Copy(a.tw, io.LimitReader(r, size))
	return err
}

func (a *archiveWriter) add(name string, mode fs.FileMode, size int64, r io.Reader) error {
	h := sha256.New()
	if err := a.entry(name, mode, size, io.TeeReader(r, h)); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	a.files = append(a.files, BackupFile{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
	return nil
}

func (a *archiveWriter) addFile(name, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return a.add(name, fi.Mode(), fi.Size(), f)
}

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

func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
