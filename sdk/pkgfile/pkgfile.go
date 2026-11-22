// SPDX-License-Identifier: Apache-2.0

// Package pkgfile reads, writes and verifies .ppkg plugin packages
// (docs/ARCHITECTURE.md §5.1, §6.2, §10.4).
//
// # Container
//
// A package is a gzip stream (RFC 1952) around a USTAR tar archive, so a
// third-party tool only needs a stock tar reader. The archive holds:
//
//	manifest.json            regular file, must be the first entry
//	signatures/manifest.sig  regular file, must be the second entry when present
//	<all other entries>      regular files and directories, no particular order
//
// manifest.json is the manifest described by
// api/manifest/v1/manifest.schema.json. signatures/manifest.sig is the
// detached Ed25519 signature over the raw manifest.json bytes as a JSON
// envelope {"key_id": "ed25519:<hex>", "signature": "<base64>"}
// (see sdk/manifest). manifest.files lists every archive entry except those
// two paths, mapping each relative path to its "sha256:<lower-case hex>"
// content digest.
//
// # Canonical form
//
// Pack writes one deterministic byte sequence for a given source tree and
// signing key:
//
//   - entries are sorted by path, byte-wise, so a directory precedes its
//     children ("bin" sorts before "bin/plugin");
//   - paths are relative, use "/", contain no empty, "." or ".." component
//     and carry a trailing "/" only on directory entries;
//   - every header has ModTime 1970-01-01T00:00:00Z, Uid 0, Gid 0, empty
//     Uname and Gname, Format USTAR and no extended, sparse or long-name
//     headers;
//   - modes are 0755 for directories, 0755 for executable files and 0644 for
//     every other file - the executable bit is the only permission the
//     format preserves;
//   - the gzip header carries no name or comment, MTIME 0 and OS 255, and the
//     payload uses BestCompression.
//
// Packing identical input twice therefore produces identical bytes, which
// lets a release quote the package digest. The source tree's signatures/
// directory is not copied: the only signature Pack ever writes is the one it
// generates from PackOptions.SigningKey. Resign keeps the entry order of its
// input and rewrites only the signature entry.
//
// # Reading
//
// Read verifies before it trusts anything: the first entry must be
// manifest.json and the second signatures/manifest.sig, their raw bytes are
// handed to manifest.VerifyAndParse (size, envelope, trust store, Ed25519,
// strict parse, publisher binding), and only then are the remaining entries
// read. Every entry must be listed in manifest.files with a matching digest
// and every listed file must appear; an archive that adds or drops a file is
// rejected. Symlinks, hard links, device nodes, FIFOs, setuid/setgid/sticky
// bits, absolute paths, "..", duplicate paths (after case folding) and
// non-UTF-8 names are rejected with a stable code.
//
// ReadUnverified skips exactly the signature check. Use it only in tooling
// that is about to re-sign the package (qwqctl sign); installation must call
// Read (internal/pluginhost/install does).
//
// # Resource limits
//
// Limits bounds the compressed size, the total uncompressed size, a single
// file, the entry count, the compression ratio and path length/depth, so a
// hostile package is rejected before it can exhaust memory or disk
// (decompression bomb, ARCH §10.4). DefaultLimits documents the values and
// why each one was chosen.
package pkgfile

import (
	"io"
	"io/fs"
	"time"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// Package layout (ARCH §5.1).
const (
	// Extension is the file name suffix of a plugin package, conventionally
	// "<plugin-id>_<version>_<os>-<arch>.ppkg".
	Extension = ".ppkg"
	// ManifestPath is the first entry of every package.
	ManifestPath = "manifest.json"
	// SignaturePath is the second entry of a signed package.
	SignaturePath = manifest.SignaturePath
	// MaxManifestBytes bounds the manifest entry (same limit as the parser).
	MaxManifestBytes = manifest.MaxSize
	// MaxSignatureBytes bounds the signature envelope.
	MaxSignatureBytes = manifest.MaxSignatureSize
)

// Canonical entry modes. Directory entries carry ModeDir; Pack picks ModeExec
// for a file with any executable bit and ModeFile otherwise.
const (
	ModeDir  fs.FileMode = 0o755
	ModeFile fs.FileMode = 0o644
	ModeExec fs.FileMode = 0o755
)

// epoch is the modification time stamped on every header Pack writes.
var epoch = time.Unix(0, 0).UTC()

// Limits bounds the resources a package may consume while it is read or
// written. The zero value is usable: every field that is zero or negative
// takes its DefaultLimits value, and no limit can be switched off (set a huge
// value instead, deliberately).
type Limits struct {
	// CompressedBytes is the largest accepted package file. A plugin ships a
	// static binary plus its UI, so this is generous, but it still bounds the
	// bytes a download may write before verification starts.
	CompressedBytes int64
	// TotalBytes is the largest sum of uncompressed entry bytes, including
	// manifest.json and the signature.
	TotalBytes int64
	// FileBytes is the largest single entry.
	FileBytes int64
	// Entries is the largest number of tar entries (files and directories).
	Entries int
	// CompressionRatio is the largest accepted TotalBytes/compressed-bytes
	// ratio and guards against decompression bombs.
	CompressionRatio int64
	// RatioFloorBytes delays the ratio check until this many bytes have been
	// produced. A ratio measured over the first kilobyte is meaningless (gzip
	// reads ahead), and no honest package produces megabytes for a few
	// hundred compressed bytes, so the check is both quiet and early enough.
	RatioFloorBytes int64
	// PathBytes is the largest accepted entry path in bytes. manifest.relpath
	// caps manifest paths at 255, so the archive uses the same number.
	PathBytes int
	// PathDepth is the largest number of path components. A plugin package is
	// at most a handful of levels deep ("ui/assets/app.js" is three), so a
	// deeply nested archive is a red flag even when every path is short.
	PathDepth int
}

// DefaultLimits returns the limits Read and Pack apply when Limits is zero.
//
// The numbers are sized for the largest plausible plugin (a 200 MiB static
// binary plus a UI bundle) with room to spare, and they are small enough for
// a 1 GiB node: a rejected package never writes more than TotalBytes.
func DefaultLimits() Limits {
	return Limits{
		CompressedBytes:  256 << 20, // 256 MiB
		TotalBytes:       768 << 20, // 3x compressed; catches a bomb quickly
		FileBytes:        256 << 20,
		Entries:          8192, // manifest.files is capped at 4096 by schema
		CompressionRatio: 200,
		RatioFloorBytes:  8 << 20,
		PathBytes:        255,
		PathDepth:        16,
	}
}

// withDefaults replaces unset fields with their default, so a partial Limits
// is still safe.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.CompressedBytes <= 0 {
		l.CompressedBytes = d.CompressedBytes
	}
	if l.TotalBytes <= 0 {
		l.TotalBytes = d.TotalBytes
	}
	if l.FileBytes <= 0 {
		l.FileBytes = d.FileBytes
	}
	if l.Entries <= 0 {
		l.Entries = d.Entries
	}
	if l.CompressionRatio <= 0 {
		l.CompressionRatio = d.CompressionRatio
	}
	if l.RatioFloorBytes < 0 {
		l.RatioFloorBytes = 0
	} else if l.RatioFloorBytes == 0 {
		l.RatioFloorBytes = d.RatioFloorBytes
	}
	if l.PathBytes <= 0 {
		l.PathBytes = d.PathBytes
	}
	if l.PathDepth <= 0 {
		l.PathDepth = d.PathDepth
	}
	return l
}

// FileInfo is one verified file of a package.
type FileInfo struct {
	// Path is the package-relative path, as listed in manifest.files.
	Path string
	// Size is the file size in bytes.
	Size int64
	// Digest is "sha256:<lower-case hex>" of the file content.
	Digest string
}

// Package is the verified result of reading a package.
type Package struct {
	// Manifest is the parsed manifest.
	Manifest *manifest.Manifest
	// ManifestBytes are the raw bytes the signature covers.
	ManifestBytes []byte
	// Signature is the verified envelope, or nil for an unsigned package
	// returned by ReadUnverified.
	Signature *manifest.Signature
	// Files are the verified files, sorted by path.
	Files []FileInfo
	// Size is the sum of the file sizes (manifest.json and the signature are
	// not counted).
	Size int64
	// Entries is the number of tar entries, directories included.
	Entries int
}

// Sink receives the content of a package while it is read.
//
// pkgfile validates every path, size and digest before and while the bytes
// reach the sink, so a Sink only has to keep them inside a directory of its
// own (internal/pluginhost/install uses os.Root for that). A failed read may
// leave partial content in the sink; the caller must discard it.
type Sink interface {
	// CreateDir is called for every explicit directory entry, in archive
	// order, before any of its children.
	CreateDir(path string) error
	// CreateFile is called for every regular file before its bytes are read.
	// size is the exact number of bytes that will be written and mode is
	// either ModeFile (0644) or ModeExec (0755). Close is called once after
	// the last byte, or once with an error to abandon the file.
	CreateFile(path string, size int64, mode fs.FileMode) (io.WriteCloser, error)
}

// ReadOptions configures Read and ReadUnverified.
type ReadOptions struct {
	// Limits bounds the resources the package may consume (zero value:
	// DefaultLimits).
	Limits Limits
	// Sink, when not nil, receives the verified content. When nil the package
	// is only verified, which is what qwqctl verify does.
	Sink Sink
	// LenientSignature makes ReadUnverified treat a signature envelope that
	// does not parse as absent instead of failing the read, so the
	// pre-install inspection can still show the manifest of a package whose
	// signature envelope is malformed. It has no effect on Read, which always
	// requires a signature that parses.
	LenientSignature bool
}
