// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// PackOptions controls Pack.
type PackOptions struct {
	// SigningKey, when non-nil, adds signatures/manifest.sig and requires
	// manifest.publisher.key_id to be this key's id. When nil the package is
	// written unsigned; a host rejects it at install time.
	SigningKey ed25519.PrivateKey
	// Limits bounds the archive that is written (zero value: DefaultLimits).
	// Pack refuses a source tree that would produce a package Read rejects.
	Limits Limits
}

// Pack writes a canonical package built from srcDir to w.
//
// srcDir must contain manifest.json; every other regular file and directory
// below it (except the signatures/ subtree, which the package format owns) is
// added to manifest.files with its content digest. The manifest is rewritten
// with the computed files map and re-encoded with sorted keys and two-space
// indentation, so the bytes that are signed are exactly the bytes the archive
// carries. Everything else in the manifest is preserved verbatim, including
// the value of every number, because Pack decodes into json.Number and never
// reinterprets other fields; the key order does change, which is harmless for
// a JSON document and is what makes the output deterministic.
//
// The manifest is validated with manifest.Parse after the rewrite, so Pack
// rejects a package the host would refuse (unknown fields, a reference to a
// file that does not exist, an entrypoint outside files/, ...). When
// SigningKey is set the publisher key id must match it, because the host
// checks that after verification.
//
// On error the archive written so far is incomplete and must be discarded by
// the caller; nothing is ever written to disk by this package.
func Pack(srcDir string, w io.Writer, opts PackOptions) (*Package, error) {
	if w == nil {
		return nil, errors.New("pkgfile: nil writer")
	}
	limits := opts.Limits.withDefaults()
	priv := opts.SigningKey
	if len(priv) != 0 && len(priv) != ed25519.PrivateKeySize {
		return nil, single("", CodeKeyInvalid, fmt.Sprintf("signing key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize))
	}
	info, err := os.Stat(srcDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pkgfile: %s is not a directory", srcDir)
	}
	manPath := filepath.Join(srcDir, ManifestPath)
	manInfo, merr := os.Lstat(manPath)
	if errors.Is(merr, fs.ErrNotExist) {
		return nil, single(ManifestPath, CodeSourceInvalid, "source tree has no manifest.json")
	}
	if merr != nil {
		return nil, merr
	}
	if !manInfo.Mode().IsRegular() {
		return nil, single(ManifestPath, CodeSourceInvalid, "manifest.json must be a regular file")
	}
	rawManifest, err := os.ReadFile(manPath)
	if err != nil {
		return nil, err
	}
	if len(rawManifest) > MaxManifestBytes {
		return nil, single(ManifestPath, CodeManifestTooLarge,
			fmt.Sprintf("manifest.json is %d bytes, more than %d", len(rawManifest), MaxManifestBytes))
	}
	entries, err := collectSource(srcDir, limits)
	if err != nil {
		return nil, err
	}

	// Hash every file before writing anything: manifest.files must be the
	// first entry, so all digests have to be known up front.
	digests := make(map[string]string, len(entries))
	for i := range entries {
		if entries[i].dir {
			continue
		}
		d, n, herr := hashFile(filepath.Join(srcDir, filepath.FromSlash(entries[i].path)))
		if herr != nil {
			return nil, herr
		}
		entries[i].size = n
		digests[entries[i].path] = d
	}
	var total int64
	for _, e := range entries {
		total += e.size
	}
	if total > limits.TotalBytes {
		return nil, single("", CodeTotalTooLarge, fmt.Sprintf("source tree holds %d bytes, more than %d", total, limits.TotalBytes))
	}

	manifestBytes, err := rewriteManifest(rawManifest, digests)
	if err != nil {
		return nil, err
	}
	m, err := manifest.Parse(manifestBytes)
	if err != nil {
		return nil, err
	}
	// The entrypoint's mode follows the manifest, not the source filesystem:
	// Windows has no executable bit to read (ADR-0007 appendix).
	for i := range entries {
		if entries[i].path == m.Entrypoint {
			entries[i].mode = ModeExec
		}
	}
	var sig *manifest.Signature
	if len(priv) != 0 {
		want := manifest.KeyID(priv.Public().(ed25519.PublicKey))
		if m.Publisher.KeyID != want {
			return nil, single(ManifestPath, CodePublisherMismatch,
				"manifest publisher.key_id is not the signing key "+want)
		}
		sig = signatureFor(manifestBytes, priv)
	}

	// Write the archive.
	aw, err := newArchiveWriter(w)
	if err != nil {
		return nil, err
	}
	if werr := aw.writeBytes(ManifestPath, manifestBytes); werr != nil {
		return nil, werr
	}
	if sig != nil {
		if werr := aw.writeBytes(SignaturePath, sig.Encode()); werr != nil {
			return nil, werr
		}
	}
	for _, e := range entries {
		if e.dir {
			if werr := aw.writeDir(e.path); werr != nil {
				return nil, werr
			}
			continue
		}
		if werr := copySourceFile(aw, srcDir, e, digests[e.path]); werr != nil {
			return nil, werr
		}
	}
	if err := aw.close(); err != nil {
		return nil, err
	}

	pkg := &Package{
		Manifest:      m,
		ManifestBytes: manifestBytes,
		Signature:     sig,
		Size:          total,
		Entries:       len(entries) + 1, // manifest.json
	}
	if sig != nil {
		pkg.Entries++
	}
	for _, e := range entries {
		if e.dir {
			continue
		}
		pkg.Files = append(pkg.Files, FileInfo{Path: e.path, Size: e.size, Digest: digests[e.path]})
	}
	sort.Slice(pkg.Files, func(i, j int) bool { return pkg.Files[i].Path < pkg.Files[j].Path })
	return pkg, nil
}

// copySourceFile re-reads one source file into the archive, checking that it
// still has the digest computed before the manifest was written. A file that
// changes during a pack is an error, not a package whose manifest lies.
func copySourceFile(aw *archiveWriter, srcDir string, e sourceEntry, want string) error {
	f, err := os.Open(filepath.Join(srcDir, filepath.FromSlash(e.path)))
	if err != nil {
		return err
	}
	defer f.Close()
	fw, err := aw.writeFile(e.path, e.size, e.mode)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(fw, h), f)
	if err != nil {
		return err
	}
	if n != e.size {
		return single(e.path, CodeSourceChanged, fmt.Sprintf("file shrank from %d to %d bytes while packing", e.size, n))
	}
	if got := digestString(h.Sum(nil)); got != want {
		return single(e.path, CodeSourceChanged, "file content changed while packing")
	}
	return nil
}

// sourceEntry is one entry of the source tree.
type sourceEntry struct {
	path string
	dir  bool
	mode fs.FileMode
	size int64
}

// collectSource walks srcDir and returns its entries sorted by path. It
// rejects anything the package format cannot represent, so Pack fails with a
// coded error instead of writing an archive Read would refuse.
func collectSource(srcDir string, limits Limits) ([]sourceEntry, error) {
	var (
		entries []sourceEntry
		seen    = make(map[string]string)
		total   int64
		hasMan  bool
	)
	err := filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(srcDir, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		switch {
		case rel == ManifestPath:
			if !d.Type().IsRegular() {
				return single(rel, CodeSourceInvalid, "manifest.json must be a regular file")
			}
			hasMan = true
			return nil
		case rel == "signatures":
			if !d.IsDir() {
				return single(rel, CodeSourceInvalid, "signatures must be a directory")
			}
			return nil
		case strings.HasPrefix(rel, "signatures/"):
			// The container owns signatures/; only the signature Pack writes
			// itself may appear there.
			if rel != SignaturePath {
				return single(rel, CodePathConflict, "only "+SignaturePath+" may appear under signatures/")
			}
			return nil
		}
		clean, perr := checkPath(rel, limits)
		if perr != nil {
			return perr
		}
		folded := strings.ToLower(clean)
		switch {
		case folded == ManifestPath || folded == "signatures":
			return single(clean, CodePathConflict, "path is reserved by the package container")
		case strings.HasPrefix(folded, "signatures/"):
			return single(clean, CodePathConflict, "only signatures/manifest.sig may appear under signatures/")
		}
		if prev, dup := seen[folded]; dup {
			return single(clean, CodePathDuplicate, "path collides with "+excerpt(prev)+" after case folding")
		}
		seen[folded] = clean
		if d.IsDir() {
			entries = append(entries, sourceEntry{path: clean, dir: true, mode: ModeDir})
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return single(clean, CodeSourceInvalid, "symbolic links cannot be packed")
		}
		if !d.Type().IsRegular() {
			return single(clean, CodeSourceInvalid, "only regular files and directories can be packed")
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if fi.Size() > limits.FileBytes {
			return single(clean, CodeFileTooLarge, fmt.Sprintf("file is %d bytes, more than %d", fi.Size(), limits.FileBytes))
		}
		total += fi.Size()
		if total > limits.TotalBytes {
			return single(clean, CodeTotalTooLarge, fmt.Sprintf("source tree is larger than %d bytes", limits.TotalBytes))
		}
		entries = append(entries, sourceEntry{path: clean, mode: sourceMode(fi.Mode()), size: fi.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !hasMan {
		return nil, single(ManifestPath, CodeSourceInvalid, "source tree has no manifest.json")
	}
	// manifest.json and the signature are not in entries, so the entry count
	// is two less than the archive's.
	if len(entries)+2 > limits.Entries {
		return nil, single("", CodeEntryLimit, fmt.Sprintf("source tree has %d entries, more than %d", len(entries)+2, limits.Entries))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	return entries, nil
}

// sourceMode normalises a source file permission to the only two modes the
// format keeps: the executable bit, and nothing else.
func sourceMode(m fs.FileMode) fs.FileMode {
	if m&0o111 != 0 {
		return ModeExec
	}
	return ModeFile
}

// hashFile returns the digest and byte count of a regular file.
func hashFile(name string) (string, int64, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, single("", CodeSourceInvalid, "only regular files can be packed")
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return digestString(h.Sum(nil)), n, nil
}

// rewriteManifest sets files on the source manifest and re-encodes it
// deterministically. Pack chooses to rewrite rather than splice the raw bytes:
// a byte-preserving edit would need offsets from a second JSON parser, while
// re-encoding keeps exactly one parser (the strict one below), keeps every
// value (json.Number is encoded verbatim), sorts keys and indents with two
// spaces - all of which makes the signature cover a stable byte sequence.
func rewriteManifest(raw []byte, files map[string]string) ([]byte, error) {
	obj, err := decodeManifestObject(raw)
	if err != nil {
		return nil, err
	}
	obj["files"] = files
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(obj); err != nil {
		return nil, fmt.Errorf("pkgfile: re-encoding manifest.json: %w", err)
	}
	if buf.Len() > MaxManifestBytes {
		return nil, single(ManifestPath, CodeManifestTooLarge,
			fmt.Sprintf("rewritten manifest.json is %d bytes, more than %d", buf.Len(), MaxManifestBytes))
	}
	return buf.Bytes(), nil
}

// decodeManifestObject decodes the source manifest into a JSON value tree.
// Numbers stay json.Number so they are written back verbatim, and duplicate
// keys are rejected: silently keeping the last one would let a package ship a
// different manifest than the author wrote.
func decodeManifestObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeJSONValue(dec)
	if err != nil {
		return nil, single(ManifestPath, CodeManifestInvalid, "invalid JSON: "+excerpt(err.Error()))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, single(ManifestPath, CodeManifestInvalid, "trailing data after the top-level value")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, single(ManifestPath, CodeManifestInvalid, "top-level value must be an object")
	}
	return obj, nil
}

// decodeJSONValue decodes one JSON value from dec, rejecting duplicate object
// keys at any depth.
func decodeJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool or nil
	}
	switch delim {
	case '{':
		obj := make(map[string]any)
		for dec.More() {
			kt, kerr := dec.Token()
			if kerr != nil {
				return nil, kerr
			}
			key, kok := kt.(string)
			if !kok {
				return nil, errors.New("object key is not a string")
			}
			if _, dup := obj[key]; dup {
				return nil, errors.New("duplicate key " + excerpt(key))
			}
			val, verr := decodeJSONValue(dec)
			if verr != nil {
				return nil, verr
			}
			obj[key] = val
		}
		if _, cerr := dec.Token(); cerr != nil { // closing '}'
			return nil, cerr
		}
		return obj, nil
	case '[':
		arr := make([]any, 0, 8)
		for dec.More() {
			val, verr := decodeJSONValue(dec)
			if verr != nil {
				return nil, verr
			}
			arr = append(arr, val)
		}
		if _, cerr := dec.Token(); cerr != nil { // closing ']'
			return nil, cerr
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unexpected %q", delim.String())
}

// digestString formats a SHA-256 sum the way manifest.files expects it.
func digestString(sum []byte) string {
	return "sha256:" + hex.EncodeToString(sum)
}

// archiveWriter writes the canonical tar+gzip container.
type archiveWriter struct {
	gz   *gzip.Writer
	tw   *tar.Writer
	done bool
}

func newArchiveWriter(w io.Writer) (*archiveWriter, error) {
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	// Zero ModTime means "no timestamp"; the OS byte and the empty name keep
	// the header independent of the machine that produced the package.
	gz.Header.ModTime = epoch
	gz.Header.OS = 255
	return &archiveWriter{gz: gz, tw: tar.NewWriter(gz)}, nil
}

func (a *archiveWriter) writeDir(path string) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeDir,
		Name:     path + "/",
		Mode:     int64(ModeDir.Perm()),
		ModTime:  epoch,
		Format:   tar.FormatUSTAR,
	}
	if err := a.tw.WriteHeader(hdr); err != nil {
		return headerError(path, err)
	}
	return nil
}

func (a *archiveWriter) writeFile(path string, size int64, mode fs.FileMode) (io.Writer, error) {
	if size < 0 {
		return nil, fmt.Errorf("pkgfile: negative size for %s", path)
	}
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     path,
		Mode:     int64(mode.Perm()),
		Size:     size,
		ModTime:  epoch,
		Format:   tar.FormatUSTAR,
	}
	if err := a.tw.WriteHeader(hdr); err != nil {
		return nil, headerError(path, err)
	}
	return a.tw, nil
}

func (a *archiveWriter) writeBytes(path string, data []byte) error {
	w, err := a.writeFile(path, int64(len(data)), ModeFile)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func (a *archiveWriter) close() error {
	if a.done {
		return nil
	}
	a.done = true
	if err := a.tw.Close(); err != nil {
		return err
	}
	return a.gz.Close()
}

// headerError reports a tar header that cannot be encoded. The only header
// field that can fail here is the name, which must fit the 100-byte USTAR
// name plus the 155-byte prefix field.
func headerError(path string, err error) error {
	return single(path, CodeEntryHeader, "cannot encode the entry header: "+excerpt(err.Error()))
}
