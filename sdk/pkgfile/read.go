// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Read verifies a signed package from r and returns its contents.
//
// Verification order follows ARCH §6.2: container size, first entry
// manifest.json, second entry signatures/manifest.sig, then
// manifest.VerifyAndParse over their raw bytes (which checks the envelope,
// the trust store, the Ed25519 signature, strict parsing and the publisher
// binding). Only after that are the remaining entries read; each one must be
// a regular file or a directory, inside the limits, with a path
// manifest.files lists, and with a matching digest. Errors are an *Error for
// container problems and the *manifest.Error from sdk/manifest for signature
// or manifest problems.
func Read(r io.Reader, ts manifest.TrustStore, opts ReadOptions) (*Package, error) {
	if ts == nil {
		return nil, errors.New("pkgfile: Read requires a trust store (ReadUnverified is only for tooling that re-signs)")
	}
	return readPackage(r, ts, opts, true, nil)
}

// ReadUnverified validates the container and every content digest but does
// not check the signature, so it accepts an unsigned package. Two uses:
// tools that are about to re-sign a package (qwqctl sign), and the read-only
// pre-install inspection, which must describe a package the trust root
// refuses instead of failing. An installer must call Read.
func ReadUnverified(r io.Reader, opts ReadOptions) (*Package, error) {
	return readPackage(r, nil, opts, false, nil)
}

// Header loop phases; entries are read strictly in this order so the manifest
// and the signature are verified before anything else is trusted.
const (
	phaseManifest = iota
	phaseSignature
	phaseContent
)

// reader holds the state of one package read.
type reader struct {
	limits     Limits
	sink       Sink
	compressed *countingReader // bytes read from the input (still compressed)
	raw        *countingReader // bytes produced by gzip (tar stream)
	produced   int64           // uncompressed entry bytes seen so far
	buf        []byte

	// lenientSignature downgrades a malformed signature envelope to "absent"
	// in an unverified read (ReadOptions.LenientSignature).
	lenientSignature bool

	manifest *manifest.Manifest
	sig      *manifest.Signature

	folded map[string]string // case-folded path -> path
	dirs   map[string]bool
	sizes  map[string]int64
}

func readPackage(r io.Reader, ts manifest.TrustStore, opts ReadOptions, requireSig bool,
	onManifest func(raw []byte, sig *manifest.Signature) error) (*Package, error) {

	if r == nil {
		return nil, errors.New("pkgfile: nil reader")
	}
	limits := opts.Limits.withDefaults()
	st := &reader{
		limits:           limits,
		sink:             opts.Sink,
		lenientSignature: !requireSig && opts.LenientSignature,
		compressed:       &countingReader{r: io.LimitReader(r, limits.CompressedBytes+1)},
		buf:              make([]byte, 32<<10),
		folded:           make(map[string]string),
		dirs:             make(map[string]bool),
		sizes:            make(map[string]int64),
	}
	zr, err := gzip.NewReader(st.compressed)
	if err != nil {
		return nil, st.streamError(err)
	}
	defer zr.Close() //nolint:errcheck // reading is complete by then
	st.raw = &countingReader{r: zr}
	tr := tar.NewReader(st.raw)

	var (
		phase     = phaseManifest
		index     int
		rawMan    []byte
		rawSig    []byte
		manParsed bool
	)
	// finishManifest parses and verifies the manifest once both fixed entries
	// are known, then hands them to onManifest (Resign writes them out).
	finishManifest := func() error {
		if manParsed {
			return nil
		}
		manParsed = true
		var (
			m   *manifest.Manifest
			err error
		)
		if requireSig {
			m, err = manifest.VerifyAndParse(rawMan, rawSig, ts)
		} else {
			m, err = manifest.Parse(rawMan)
		}
		if err != nil {
			return err
		}
		st.manifest = m
		if onManifest != nil {
			if err := onManifest(rawMan, st.sig); err != nil {
				return err
			}
		}
		return nil
	}

	for {
		hdr, herr := tr.Next()
		if errors.Is(herr, io.EOF) {
			break
		}
		if herr != nil {
			return nil, st.streamError(herr)
		}
		index++
		if index > limits.Entries {
			return nil, single("", CodeEntryLimit,
				fmt.Sprintf("package has more than %d entries", limits.Entries))
		}
		switch phase {
		case phaseManifest:
			if hdr.Name != ManifestPath {
				return nil, single(excerpt(hdr.Name), CodeMissingManifest,
					"the first entry must be "+ManifestPath)
			}
			if !regular(hdr) {
				return nil, single(ManifestPath, CodeEntryType, ManifestPath+" must be a regular file")
			}
			raw, rerr := st.readEntry(tr, hdr, MaxManifestBytes, CodeManifestTooLarge, ManifestPath)
			if rerr != nil {
				return nil, rerr
			}
			rawMan = raw
			st.folded[ManifestPath] = ManifestPath
			phase = phaseSignature
			if berr := st.checkBudget(); berr != nil {
				return nil, berr
			}
			continue
		case phaseSignature:
			if hdr.Name == SignaturePath {
				if !regular(hdr) {
					return nil, single(SignaturePath, CodeEntryType, SignaturePath+" must be a regular file")
				}
				raw, rerr := st.readEntry(tr, hdr, MaxSignatureBytes, CodeSignatureTooLarge, "signature")
				if rerr != nil {
					return nil, rerr
				}
				rawSig = raw
				sig, perr := manifest.ParseSignature(rawSig)
				if perr != nil {
					if !st.lenientSignature {
						return nil, perr
					}
					// Lenient inspection: the envelope does not parse, so the
					// package is treated as unsigned (st.sig stays nil) and the
					// manifest is still checked.
					sig = nil
				}
				st.sig = sig
				st.folded[SignaturePath] = SignaturePath
				if ferr := finishManifest(); ferr != nil {
					return nil, ferr
				}
				phase = phaseContent
				if berr := st.checkBudget(); berr != nil {
					return nil, berr
				}
				continue
			}
			if requireSig {
				return nil, single("", CodeMissingSignature, "package has no "+SignaturePath)
			}
			// Unsigned package: the manifest stands alone, so this entry is
			// ordinary content.
			if ferr := finishManifest(); ferr != nil {
				return nil, ferr
			}
			phase = phaseContent
		}
		// phase is phaseContent here: the entry is part of the payload.
		if hdr.Name == ManifestPath || hdr.Name == SignaturePath {
			return nil, single(hdr.Name, CodeEntryOrder,
				ManifestPath+" must be the first entry and the signature the second")
		}
		if cerr := st.content(tr, hdr); cerr != nil {
			return nil, cerr
		}
		if berr := st.checkBudget(); berr != nil {
			return nil, berr
		}
	}
	if phase == phaseManifest {
		return nil, single("", CodeMissingManifest, "package has no "+ManifestPath)
	}
	if err := finishManifest(); err != nil {
		return nil, err
	}

	// Every file the manifest lists must have been present, with its digest
	// already checked while it was read.
	var vs []Violation
	names := make([]string, 0, len(st.manifest.Files))
	for name := range st.manifest.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	pkg := &Package{
		Manifest:      st.manifest,
		ManifestBytes: rawMan,
		Signature:     st.sig,
		Entries:       index,
		Files:         make([]FileInfo, 0, len(names)),
	}
	for _, name := range names {
		size, seen := st.sizes[name]
		if !seen {
			if len(vs) >= MaxViolations {
				break
			}
			vs = append(vs, Violation{Path: name, Code: CodeFileMissing,
				Message: "listed in manifest.files but missing from the package"})
			continue
		}
		pkg.Files = append(pkg.Files, FileInfo{Path: name, Size: size, Digest: st.manifest.Files[name]})
		pkg.Size += size
	}
	if e := newError(vs); e != nil {
		return nil, e
	}
	return pkg, nil
}

// content validates and consumes one entry after the manifest and signature.
func (st *reader) content(tr *tar.Reader, hdr *tar.Header) error {
	path, isDir, err := st.checkHeader(hdr)
	if err != nil {
		return err
	}
	if isDir {
		if st.sink != nil {
			if serr := st.sink.CreateDir(path); serr != nil {
				return fmt.Errorf("pkgfile: creating directory %s: %w", excerpt(path), serr)
			}
		}
		return nil
	}
	want, listed := st.manifest.Files[path]
	if !listed {
		return single(path, CodeFileUnlisted, "file is not listed in manifest.files")
	}
	if hdr.Size > st.limits.FileBytes {
		return single(path, CodeFileTooLarge,
			fmt.Sprintf("file is %d bytes, more than %d", hdr.Size, st.limits.FileBytes))
	}

	h := sha256.New()
	writers := []io.Writer{h}
	var sinkFile io.WriteCloser
	if st.sink != nil {
		w, serr := st.sink.CreateFile(path, hdr.Size, st.contentMode(path, hdr.Mode))
		if serr != nil {
			return fmt.Errorf("pkgfile: creating file %s: %w", excerpt(path), serr)
		}
		sinkFile = w
		writers = append(writers, w)
	}
	n, cerr := st.copyEntry(tr, writers)
	if sinkFile != nil {
		if clerr := sinkFile.Close(); clerr != nil && cerr == nil {
			cerr = fmt.Errorf("pkgfile: writing file %s: %w", excerpt(path), clerr)
		}
	}
	if cerr != nil {
		return cerr
	}
	if n != hdr.Size {
		return single(path, CodeCorrupt,
			fmt.Sprintf("entry declares %d bytes but holds %d", hdr.Size, n))
	}
	if got := digestString(h.Sum(nil)); got != want {
		return single(path, CodeDigestMismatch, "content does not match the digest in manifest.files")
	}
	st.sizes[path] = n
	return nil
}

// checkHeader validates one entry's name, type and mode, and records it for
// duplicate and file/directory conflict detection.
func (st *reader) checkHeader(hdr *tar.Header) (string, bool, error) {
	path, perr := checkPath(hdr.Name, st.limits)
	if perr != nil {
		return "", false, perr
	}
	isDir := hdr.Typeflag == tar.TypeDir
	if hdr.Typeflag != tar.TypeDir && !regular(hdr) {
		return "", false, single(path, CodeEntryType, entryTypeMessage(hdr))
	}
	if hdr.Mode&0o7000 != 0 {
		return "", false, single(path, CodeEntryMode, "setuid, setgid and sticky bits are not allowed")
	}
	if isDir {
		if hdr.Size != 0 {
			return "", false, single(path, CodeEntryType, "directory entry declares content")
		}
		if _, listed := st.manifest.Files[path]; listed {
			return "", false, single(path, CodePathConflict,
				"path is a file in manifest.files but a directory in the package")
		}
	} else if st.dirs[path] {
		return "", false, single(path, CodePathConflict,
			"path is a directory in the package but a file in manifest.files")
	}
	folded := strings.ToLower(path)
	if prev, dup := st.folded[folded]; dup {
		return "", false, single(path, CodePathDuplicate, "path collides with "+excerpt(prev)+" after case folding")
	}
	st.folded[folded] = path
	if isDir {
		st.dirs[path] = true
	}
	return path, isDir, nil
}

// copyEntry copies one entry's content to every writer while enforcing the
// byte and compression-ratio budgets.
func (st *reader) copyEntry(tr *tar.Reader, dst []io.Writer) (int64, error) {
	var n int64
	for {
		k, rerr := tr.Read(st.buf)
		if k > 0 {
			for _, w := range dst {
				if _, werr := w.Write(st.buf[:k]); werr != nil {
					return n, fmt.Errorf("pkgfile: writing entry content: %w", werr)
				}
			}
			n += int64(k)
			st.produced += int64(k)
			if berr := st.checkBudget(); berr != nil {
				return n, berr
			}
		}
		if errors.Is(rerr, io.EOF) {
			return n, nil
		}
		if rerr != nil {
			return n, st.streamError(rerr)
		}
	}
}

// readEntry reads one of the two fixed entries, bounded by max.
func (st *reader) readEntry(tr *tar.Reader, hdr *tar.Header, max int64, code, what string) ([]byte, error) {
	if hdr.Size > max {
		return nil, single(hdr.Name, code, fmt.Sprintf("%s is %d bytes, more than %d", what, hdr.Size, max))
	}
	b, err := io.ReadAll(io.LimitReader(tr, max+1))
	if err != nil {
		return nil, st.streamError(err)
	}
	if int64(len(b)) > max {
		return nil, single(hdr.Name, code, fmt.Sprintf("%s is larger than %d bytes", what, max))
	}
	st.produced += int64(len(b))
	return b, nil
}

// checkBudget enforces the total-size and compression-ratio limits.
func (st *reader) checkBudget() error {
	if st.produced > st.limits.TotalBytes {
		return single("", CodeTotalTooLarge,
			fmt.Sprintf("package expands to more than %d bytes", st.limits.TotalBytes))
	}
	consumed := st.compressed.n
	if consumed <= 0 || st.produced <= st.limits.RatioFloorBytes {
		return nil
	}
	if st.produced/consumed > st.limits.CompressionRatio {
		return single("", CodeCompressionRatio,
			fmt.Sprintf("%d bytes expand from %d compressed bytes, more than %dx",
				st.produced, consumed, st.limits.CompressionRatio))
	}
	return nil
}

// streamError classifies a failure of the gzip or tar stream.
func (st *reader) streamError(err error) error {
	if st.compressed != nil && st.compressed.n > st.limits.CompressedBytes {
		return single("", CodeTooLarge,
			fmt.Sprintf("package is larger than %d compressed bytes", st.limits.CompressedBytes))
	}
	return single("", CodeCorrupt, "malformed or truncated package: "+excerpt(err.Error()))
}

// checkPath validates a package entry name and returns it without the
// directory marker. Only relative, slash-separated, UTF-8 paths without empty,
// "." or ".." components are accepted.
func checkPath(name string, limits Limits) (string, error) {
	if name == "" {
		return "", single("", CodePathInvalid, "empty entry name")
	}
	if !utf8.ValidString(name) {
		return "", single(excerpt(name), CodePathInvalidUTF8, "entry name is not valid UTF-8")
	}
	if strings.ContainsRune(name, '\\') {
		return "", single(excerpt(name), CodePathInvalid, "entry name contains a backslash")
	}
	if strings.HasPrefix(name, "/") {
		return "", single(excerpt(name), CodePathAbsolute, "entry name is absolute")
	}
	clean := strings.TrimSuffix(name, "/")
	if clean == "" || strings.HasSuffix(clean, "/") {
		return "", single(excerpt(name), CodePathInvalid, "entry name has an empty path component")
	}
	for i := 0; i < len(clean); i++ {
		if clean[i] < 0x20 || clean[i] == 0x7f {
			return "", single(excerpt(name), CodePathInvalid, "entry name contains a control character")
		}
	}
	parts := strings.Split(clean, "/")
	for _, p := range parts {
		switch p {
		case "":
			return "", single(excerpt(name), CodePathInvalid, "entry name has an empty path component")
		case ".", "..":
			return "", single(excerpt(name), CodePathTraversal, "entry name contains "+strconv.Quote(p))
		}
	}
	if len(clean) > limits.PathBytes {
		return "", single(excerpt(clean), CodePathTooLong,
			fmt.Sprintf("path is %d bytes, more than %d", len(clean), limits.PathBytes))
	}
	if len(parts) > limits.PathDepth {
		return "", single(excerpt(clean), CodePathTooDeep,
			fmt.Sprintf("path has %d components, more than %d", len(parts), limits.PathDepth))
	}
	return clean, nil
}

// regular reports whether hdr is a plain file entry. Typeflag 0 is the
// pre-POSIX regular-file marker; tar.TypeRegA names it but is deprecated, and
// tar.Reader presents both as a regular file.
func regular(hdr *tar.Header) bool {
	return hdr.Typeflag == tar.TypeReg || hdr.Typeflag == 0
}

// entryTypeMessage explains why an entry type is refused.
func entryTypeMessage(hdr *tar.Header) string {
	switch hdr.Typeflag {
	case tar.TypeSymlink:
		return "symbolic links are not allowed"
	case tar.TypeLink:
		return "hard links are not allowed"
	case tar.TypeChar:
		return "character devices are not allowed"
	case tar.TypeBlock:
		return "block devices are not allowed"
	case tar.TypeFifo:
		return "FIFOs are not allowed"
	case tar.TypeGNUSparse:
		return "sparse files are not allowed"
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return "extended headers are not allowed"
	}
	return "unsupported entry type " + strconv.QuoteRune(rune(hdr.Typeflag))
}

// contentMode is the mode a content file is installed with. The signature only
// covers manifest.json, so the header's executable bit is untrusted: the signed
// entrypoint is always executable, and the bit is kept only below bin/.
func (st *reader) contentMode(path string, mode int64) fs.FileMode {
	switch {
	case path == st.manifest.Entrypoint:
		return ModeExec
	case !strings.HasPrefix(path, "bin/"):
		return ModeFile
	}
	return entryMode(mode)
}

// entryMode maps an accepted header mode to the canonical entry mode.
func entryMode(mode int64) fs.FileMode {
	if mode&0o111 != 0 {
		return ModeExec
	}
	return ModeFile
}

// countingReader counts the bytes read through it; the compressed and
// uncompressed counts together give the compression ratio.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n += int64(k)
	return k, err
}
