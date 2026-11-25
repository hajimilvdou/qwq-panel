// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Interactive Agent File Exchange Folder ("交互文件夹"):
// Located at <DataDir>/agent-workspace/exchange/.
// Provides a dedicated, safe, structured folder for exchanging files between
// the panel user and AI agents (uploading source inputs into task-specific
// subfolders, letting the agent read/process them alongside server state, and
// letting the agent write reports/artifacts back for the user to preview and
// download).

const (
	maxExchangeUploadBytes  int64 = 50 << 20  // 50 MiB per uploaded file
	maxExchangePreviewBytes int64 = 512 << 10 // 512 KiB inline preview/edit
	maxExchangeZipBytes     int64 = 128 << 20 // 128 MiB per folder archive download
	maxExchangeZipFiles           = 2000
	maxExchangeListEntries        = 1000
	maxExchangeRelPathBytes       = 320
)

// ExchangeEntry describes one file or subfolder inside the interactive exchange folder.
type ExchangeEntry struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"is_dir"`
	Size       int64  `json:"size"`
	ChildCount int    `json:"child_count,omitempty"`
	IsText     bool   `json:"is_text"`
	IsImage    bool   `json:"is_image"`
	MimeType   string `json:"mime_type,omitempty"`
	UpdatedAt  string `json:"updated_at"`
}

// ExchangeListResult is returned by GET /api/v1/agent-exchange/entries.
type ExchangeListResult struct {
	Path       string          `json:"path"`
	ParentPath string          `json:"parent_path"`
	RootHint   string          `json:"root_hint"`
	Entries    []ExchangeEntry `json:"entries"`
	TotalDirs  int             `json:"total_dirs"`
	TotalFiles int             `json:"total_files"`
	TotalBytes int64           `json:"total_bytes"`
}

// ExchangePreview is returned by GET /api/v1/agent-exchange/preview.
type ExchangePreview struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	IsText    bool   `json:"is_text"`
	IsImage   bool   `json:"is_image"`
	MimeType  string `json:"mime_type,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Content   string `json:"content,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

// ExchangeManager manages <DataDir>/agent-workspace/exchange/.
type ExchangeManager struct {
	rootDir string
}

// NewExchangeManager constructs an ExchangeManager under <dataDir>/agent-workspace/exchange.
func NewExchangeManager(dataDir string) *ExchangeManager {
	root := ""
	if strings.TrimSpace(dataDir) != "" {
		root = filepath.Join(dataDir, "agent-workspace", "exchange")
	}
	return &ExchangeManager{rootDir: root}
}

// RootDir returns the absolute exchange directory path (empty if unconfigured).
func (m *ExchangeManager) RootDir() string {
	if m == nil {
		return ""
	}
	return m.rootDir
}

func (m *ExchangeManager) ensureRoot() (string, error) {
	if m == nil || m.rootDir == "" {
		return "", problem.New(problem.Unavailable, "Agent interactive exchange folder is not configured on this host.")
	}
	if err := os.MkdirAll(m.rootDir, 0o700); err != nil {
		return "", problem.New(problem.Internal, "Failed to prepare exchange folder.")
	}
	realRoot, err := filepath.EvalSymlinks(m.rootDir)
	if err != nil {
		return m.rootDir, nil
	}
	return realRoot, nil
}

// CleanExchangeRelPath validates and normalizes a relative path inside the
// exchange folder. Empty string is allowed when allowRoot is true.
func CleanExchangeRelPath(raw string, allowRoot bool, pointer string) (string, error) {
	if pointer == "" {
		pointer = "/path"
	}
	p := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	p = strings.TrimLeft(p, "/")
	p = strings.TrimRight(p, "/")
	if p == "" || p == "." {
		if allowRoot {
			return "", nil
		}
		return "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "REQUIRED", Message: "A relative path is required.",
		})
	}
	if len(p) > maxExchangeRelPathBytes {
		return "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "too_long", Message: "Path is at most 320 bytes.",
		})
	}
	for _, r := range p {
		if unicode.IsControl(r) || r == 0 {
			return "", problem.Validation(problem.Violation{
				Pointer: pointer, Code: "INVALID", Message: "Path contains control characters.",
			})
		}
	}
	// Reject Windows drive letters or colon-prefixed paths.
	if strings.Contains(p, ":") {
		return "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "INVALID", Message: "Path contains disallowed characters.",
		})
	}
	cleaned := path.Clean(p)
	if cleaned == "." {
		if allowRoot {
			return "", nil
		}
		return "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "REQUIRED", Message: "A relative path is required.",
		})
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "INVALID", Message: "Path must stay inside the exchange folder.",
		})
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, ".tmp-") {
			return "", problem.Validation(problem.Violation{
				Pointer: pointer, Code: "INVALID", Message: "Path contains a disallowed segment.",
			})
		}
	}
	return cleaned, nil
}

func (m *ExchangeManager) resolve(relPath string, allowRoot bool, pointer string) (root, full, cleaned string, err error) {
	root, err = m.ensureRoot()
	if err != nil {
		return "", "", "", err
	}
	cleaned, err = CleanExchangeRelPath(relPath, allowRoot, pointer)
	if err != nil {
		return "", "", "", err
	}
	if cleaned == "" {
		return root, root, "", nil
	}
	full = filepath.Join(root, filepath.FromSlash(cleaned))
	rel, err := filepath.Rel(root, full)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", "", "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "INVALID", Message: "Path escapes the exchange folder.",
		})
	}
	// Verify every existing ancestor stays inside root (blocks symlink escapes).
	cur := root
	for _, seg := range strings.Split(cleaned, "/") {
		cur = filepath.Join(cur, seg)
		fi, lerr := os.Lstat(cur)
		if lerr != nil {
			if os.IsNotExist(lerr) {
				break
			}
			return "", "", "", problem.Wrap(lerr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", "", "", problem.Validation(problem.Violation{
				Pointer: pointer, Code: "INVALID", Message: "Symlinks are not allowed inside the exchange folder.",
			})
		}
	}
	return root, full, cleaned, nil
}

// List returns the files and subfolders in one directory of the exchange folder.
func (m *ExchangeManager) List(relDir string) (ExchangeListResult, error) {
	root, full, cleaned, err := m.resolve(relDir, true, "/path")
	if err != nil {
		return ExchangeListResult{}, err
	}
	info, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return ExchangeListResult{}, problem.New(problem.NotFound, "Exchange directory %q not found.", cleaned)
		}
		return ExchangeListResult{}, problem.Wrap(err)
	}
	if !info.IsDir() {
		return ExchangeListResult{}, problem.New(problem.ValidationFailed, "Path %q is not a directory.", cleaned)
	}
	dirEntries, err := os.ReadDir(full)
	if err != nil {
		return ExchangeListResult{}, problem.Wrap(err)
	}
	entries := make([]ExchangeEntry, 0, len(dirEntries))
	var totalDirs, totalFiles int
	var totalBytes int64
	for _, de := range dirEntries {
		if len(entries) >= maxExchangeListEntries {
			break
		}
		name := de.Name()
		if strings.HasPrefix(name, ".tmp-") || de.Type()&os.ModeSymlink != 0 {
			continue
		}
		fi, err := de.Info()
		if err != nil {
			continue
		}
		entryPath := name
		if cleaned != "" {
			entryPath = cleaned + "/" + name
		}
		ent := ExchangeEntry{
			Name:      name,
			Path:      entryPath,
			IsDir:     fi.IsDir(),
			Size:      fi.Size(),
			UpdatedAt: fi.ModTime().UTC().Format(time.RFC3339),
		}
		if fi.IsDir() {
			totalDirs++
			ent.Size = 0
			if sub, serr := os.ReadDir(filepath.Join(full, name)); serr == nil {
				count := 0
				for _, s := range sub {
					if !strings.HasPrefix(s.Name(), ".tmp-") {
						count++
					}
				}
				ent.ChildCount = count
			}
		} else {
			totalFiles++
			totalBytes += fi.Size()
			ent.IsText = isExchangeTextFile(name)
			ent.IsImage = isExchangeImageFile(name)
			ent.MimeType = exchangeMimeType(name)
		}
		entries = append(entries, ent)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	parentPath := ""
	if cleaned != "" {
		if p := path.Dir(cleaned); p != "." {
			parentPath = p
		}
	}
	return ExchangeListResult{
		Path:       cleaned,
		ParentPath: parentPath,
		RootHint:   filepath.ToSlash(root),
		Entries:    entries,
		TotalDirs:  totalDirs,
		TotalFiles: totalFiles,
		TotalBytes: totalBytes,
	}, nil
}

// Mkdir creates a subfolder (including any intermediate parent folders).
func (m *ExchangeManager) Mkdir(relPath string) (ExchangeEntry, error) {
	_, full, cleaned, err := m.resolve(relPath, false, "/path")
	if err != nil {
		return ExchangeEntry{}, err
	}
	if fi, serr := os.Lstat(full); serr == nil {
		if !fi.IsDir() {
			return ExchangeEntry{}, problem.New(problem.StateConflict, "A file already exists at %q.", cleaned)
		}
		return ExchangeEntry{
			Name:      path.Base(cleaned),
			Path:      cleaned,
			IsDir:     true,
			UpdatedAt: fi.ModTime().UTC().Format(time.RFC3339),
		}, nil
	}
	if err := os.MkdirAll(full, 0o700); err != nil {
		return ExchangeEntry{}, problem.New(problem.Internal, "Failed to create folder: %v", err)
	}
	fi, _ := os.Stat(full)
	mod := time.Now().UTC().Format(time.RFC3339)
	if fi != nil {
		mod = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return ExchangeEntry{
		Name:      path.Base(cleaned),
		Path:      cleaned,
		IsDir:     true,
		UpdatedAt: mod,
	}, nil
}

// SaveStream atomically saves an uploaded stream into relPath, enforcing a size bound.
func (m *ExchangeManager) SaveStream(relPath string, r io.Reader, maxBytes int64) (ExchangeEntry, error) {
	if maxBytes <= 0 || maxBytes > maxExchangeUploadBytes {
		maxBytes = maxExchangeUploadBytes
	}
	_, full, cleaned, err := m.resolve(relPath, false, "/path")
	if err != nil {
		return ExchangeEntry{}, err
	}
	if fi, serr := os.Lstat(full); serr == nil && fi.IsDir() {
		return ExchangeEntry{}, problem.New(problem.StateConflict, "Cannot overwrite directory %q with a file.", cleaned)
	}
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ExchangeEntry{}, problem.New(problem.Internal, "Failed to create parent folder.")
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return ExchangeEntry{}, problem.New(problem.Internal, "Failed to create temporary upload file.")
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return ExchangeEntry{}, problem.Wrap(err)
	}
	written, err := io.Copy(tmp, io.LimitReader(r, maxBytes+1))
	if err != nil {
		cleanup()
		return ExchangeEntry{}, problem.New(problem.Internal, "Failed to store uploaded file.")
	}
	if written > maxBytes {
		cleanup()
		return ExchangeEntry{}, problem.New(problem.PayloadTooLarge, "Uploaded file exceeds the %d MiB limit.", maxBytes/(1<<20))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return ExchangeEntry{}, problem.Wrap(err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		_ = os.Remove(tmpName)
		return ExchangeEntry{}, problem.Wrap(err)
	}
	fi, _ := os.Stat(full)
	mod := time.Now().UTC().Format(time.RFC3339)
	if fi != nil {
		mod = fi.ModTime().UTC().Format(time.RFC3339)
	}
	name := path.Base(cleaned)
	return ExchangeEntry{
		Name:      name,
		Path:      cleaned,
		IsDir:     false,
		Size:      written,
		IsText:    isExchangeTextFile(name),
		IsImage:   isExchangeImageFile(name),
		MimeType:  exchangeMimeType(name),
		UpdatedAt: mod,
	}, nil
}

// WriteText atomically writes UTF-8 text into relPath inside the exchange folder.
func (m *ExchangeManager) WriteText(relPath, content string) (ExchangeEntry, error) {
	return m.SaveStream(relPath, strings.NewReader(content), maxExchangeUploadBytes)
}

// Preview returns bounded inline text content or metadata for a file.
func (m *ExchangeManager) Preview(relPath string) (ExchangePreview, error) {
	_, full, cleaned, err := m.resolve(relPath, false, "/path")
	if err != nil {
		return ExchangePreview{}, err
	}
	fi, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return ExchangePreview{}, problem.New(problem.NotFound, "Exchange file %q not found.", cleaned)
		}
		return ExchangePreview{}, problem.Wrap(err)
	}
	if fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return ExchangePreview{}, problem.New(problem.ValidationFailed, "Path %q is not a regular file.", cleaned)
	}
	name := path.Base(cleaned)
	out := ExchangePreview{
		Path:      cleaned,
		Name:      name,
		Size:      fi.Size(),
		IsImage:   isExchangeImageFile(name),
		MimeType:  exchangeMimeType(name),
		UpdatedAt: fi.ModTime().UTC().Format(time.RFC3339),
	}
	f, err := os.Open(full)
	if err != nil {
		return ExchangePreview{}, problem.Wrap(err)
	}
	defer f.Close()

	sampleLimit := maxExchangePreviewBytes + 1
	buf, err := io.ReadAll(io.LimitReader(f, sampleLimit))
	if err != nil {
		return ExchangePreview{}, problem.Wrap(err)
	}
	if out.MimeType == "" && len(buf) > 0 {
		out.MimeType = http.DetectContentType(buf)
	}
	isText := isExchangeTextFile(name) || isProbableUTF8Text(buf)
	out.IsText = isText && !out.IsImage
	if out.IsText {
		if int64(len(buf)) > maxExchangePreviewBytes {
			buf = buf[:maxExchangePreviewBytes]
			// Trim to valid UTF-8 boundary.
			for len(buf) > 0 && !utf8.Valid(buf) {
				buf = buf[:len(buf)-1]
			}
			out.Truncated = true
		}
		out.Content = string(buf)
	}
	return out, nil
}

// ResolveDownload verifies relPath for file or directory download.
func (m *ExchangeManager) ResolveDownload(relPath string) (full string, info os.FileInfo, cleaned string, err error) {
	_, full, cleaned, err = m.resolve(relPath, true, "/path")
	if err != nil {
		return "", nil, "", err
	}
	info, err = os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, "", problem.New(problem.NotFound, "Exchange path %q not found.", cleaned)
		}
		return "", nil, "", problem.Wrap(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, "", problem.New(problem.ValidationFailed, "Symlinks cannot be downloaded.")
	}
	return full, info, cleaned, nil
}

// WriteZipArchive streams a zip archive of dirFull into w with strict size/count bounds.
func (m *ExchangeManager) WriteZipArchive(w io.Writer, dirFull string) error {
	zw := zip.NewWriter(w)
	var totalBytes int64
	var fileCount int
	err := filepath.WalkDir(dirFull, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if p == dirFull {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".tmp-") || d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dirFull, p)
		if err != nil {
			return nil
		}
		zipPath := filepath.ToSlash(rel)
		if d.IsDir() {
			_, err := zw.Create(zipPath + "/")
			return err
		}
		fileCount++
		if fileCount > maxExchangeZipFiles {
			return problem.New(problem.PayloadTooLarge, "Folder archive exceeds maximum file count (%d).", maxExchangeZipFiles)
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		totalBytes += fi.Size()
		if totalBytes > maxExchangeZipBytes {
			return problem.New(problem.PayloadTooLarge, "Folder archive exceeds maximum size (%d MiB).", maxExchangeZipBytes/(1<<20))
		}
		hdr, err := zip.FileInfoHeader(fi)
		if err != nil {
			return err
		}
		hdr.Name = zipPath
		hdr.Method = zip.Deflate
		dst, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(dst, io.LimitReader(src, fi.Size()))
		return err
	})
	closeErr := zw.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Rename moves or renames a file or subfolder inside the exchange folder.
func (m *ExchangeManager) Rename(fromPath, toPath string) (ExchangeEntry, error) {
	_, srcFull, srcClean, err := m.resolve(fromPath, false, "/from")
	if err != nil {
		return ExchangeEntry{}, err
	}
	_, dstFull, dstClean, err := m.resolve(toPath, false, "/to")
	if err != nil {
		return ExchangeEntry{}, err
	}
	if srcClean == dstClean {
		fi, serr := os.Lstat(srcFull)
		if serr != nil {
			if os.IsNotExist(serr) {
				return ExchangeEntry{}, problem.New(problem.NotFound, "Source path %q not found.", srcClean)
			}
			return ExchangeEntry{}, problem.Wrap(serr)
		}
		return entryFromFileInfo(dstClean, fi), nil
	}
	if strings.HasPrefix(dstClean+"/", srcClean+"/") {
		return ExchangeEntry{}, problem.New(problem.ValidationFailed, "Cannot move a folder into itself.")
	}
	if _, err := os.Lstat(srcFull); err != nil {
		if os.IsNotExist(err) {
			return ExchangeEntry{}, problem.New(problem.NotFound, "Source path %q not found.", srcClean)
		}
		return ExchangeEntry{}, problem.Wrap(err)
	}
	if _, err := os.Lstat(dstFull); err == nil {
		return ExchangeEntry{}, problem.New(problem.StateConflict, "Destination path %q already exists.", dstClean)
	}
	if err := os.MkdirAll(filepath.Dir(dstFull), 0o700); err != nil {
		return ExchangeEntry{}, problem.Wrap(err)
	}
	if err := os.Rename(srcFull, dstFull); err != nil {
		return ExchangeEntry{}, problem.Wrap(err)
	}
	fi, err := os.Lstat(dstFull)
	if err != nil {
		return ExchangeEntry{}, problem.Wrap(err)
	}
	return entryFromFileInfo(dstClean, fi), nil
}

// Delete removes a file or folder recursively inside the exchange folder.
func (m *ExchangeManager) Delete(relPath string) error {
	_, full, cleaned, err := m.resolve(relPath, false, "/path")
	if err != nil {
		return err
	}
	fi, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return problem.New(problem.NotFound, "Exchange path %q not found.", cleaned)
		}
		return problem.Wrap(err)
	}
	if fi.IsDir() {
		if err := os.RemoveAll(full); err != nil {
			return problem.Wrap(err)
		}
		return nil
	}
	if err := os.Remove(full); err != nil {
		return problem.Wrap(err)
	}
	return nil
}

func entryFromFileInfo(cleaned string, fi os.FileInfo) ExchangeEntry {
	name := path.Base(cleaned)
	ent := ExchangeEntry{
		Name:      name,
		Path:      cleaned,
		IsDir:     fi.IsDir(),
		Size:      fi.Size(),
		UpdatedAt: fi.ModTime().UTC().Format(time.RFC3339),
	}
	if fi.IsDir() {
		ent.Size = 0
	} else {
		ent.IsText = isExchangeTextFile(name)
		ent.IsImage = isExchangeImageFile(name)
		ent.MimeType = exchangeMimeType(name)
	}
	return ent
}

func isExchangeTextFile(name string) bool {
	if isLikelyTextFilename(name) {
		return true
	}
	ext := strings.ToLower(path.Ext(name))
	switch ext {
	case ".log", ".go", ".rs", ".java", ".c", ".h", ".cpp", ".hpp", ".css", ".html", ".htm", ".svelte", ".vue", ".jsx", ".tsx", ".sql", ".service", ".socket", ".timer", ".nginx", ".caddy", ".diff", ".patch", ".svg":
		return true
	}
	return false
}

func isExchangeImageFile(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".avif":
		return true
	}
	return false
}

func exchangeMimeType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ext == ".md" || ext == ".markdown" {
		return "text/markdown; charset=utf-8"
	}
	if ext == ".yaml" || ext == ".yml" || ext == ".toml" || ext == ".conf" || ext == ".ini" || ext == ".log" {
		return "text/plain; charset=utf-8"
	}
	if mt := mime.TypeByExtension(ext); mt != "" {
		return mt
	}
	return ""
}

func isProbableUTF8Text(sample []byte) bool {
	if len(sample) == 0 {
		return true
	}
	check := sample
	if len(check) > 4096 {
		check = check[:4096]
	}
	for _, b := range check {
		if b == 0 {
			return false
		}
	}
	return utf8.Valid(check)
}

// SanitizeUploadFilename strips any directory components and dangerous characters
// from an uploaded file's base name while preserving UTF-8 names (including Chinese).
func SanitizeUploadFilename(raw string) string {
	name := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	name = path.Base(name)
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		if unicode.IsControl(r) || r == 0 || r == '/' || r == '\\' || r == ':' {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if out == "" || out == "." || out == ".." || strings.HasPrefix(out, ".tmp-") {
		return fmt.Sprintf("upload-%d.bin", time.Now().Unix())
	}
	return out
}
