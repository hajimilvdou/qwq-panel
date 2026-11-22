// SPDX-License-Identifier: Apache-2.0

package pkgfile

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Violation is one problem found in a package file. It mirrors
// manifest.Violation: a stable machine readable code plus a message for
// humans that never echoes more than a short excerpt of untrusted input.
type Violation struct {
	// Path is the package-relative entry the problem belongs to, or "" for
	// the archive as a whole.
	Path string `json:"path"`
	// Code is one of the Code* constants.
	Code string `json:"code"`
	// Message is for humans.
	Message string `json:"message"`
}

// Error is returned by pkgfile when a package is rejected. Violations are
// sorted by path, then code, then message, and capped at MaxViolations;
// Omitted counts the ones dropped by the cap.
//
// Signature and manifest validation failures are not wrapped in an Error:
// they are the *manifest.Error from sdk/manifest, returned unchanged so the
// codes and JSON Pointers stay exactly the ones the manifest package
// documents. Use errors.As to tell the two apart.
type Error struct {
	Violations []Violation
	Omitted    int
}

func (e *Error) Error() string {
	n := len(e.Violations) + e.Omitted
	var b strings.Builder
	fmt.Fprintf(&b, "package rejected: %d violation(s)", n)
	for i, v := range e.Violations {
		if i == 3 {
			fmt.Fprintf(&b, "; ... and %d more", n-i)
			break
		}
		p := v.Path
		if p == "" {
			p = "<archive>"
		}
		fmt.Fprintf(&b, "; %s %s: %s", p, v.Code, v.Message)
	}
	return b.String()
}

// Has reports whether the error contains a violation with the given code.
func (e *Error) Has(code string) bool {
	for _, v := range e.Violations {
		if v.Code == code {
			return true
		}
	}
	return false
}

const (
	// MaxViolations caps the violations reported for one package. Unlisted
	// files can produce thousands of them, and no caller does anything with
	// more than a handful.
	MaxViolations = 20
	// maxExcerptBytes caps quoted untrusted input in messages.
	maxExcerptBytes = 64
)

// Container size, stream and budget problems.
const (
	CodeTooLarge          = "PKG_TOO_LARGE"          // compressed size above Limits.CompressedBytes
	CodeCorrupt           = "PKG_CORRUPT"            // not gzip, truncated, or malformed tar
	CodeEntryLimit        = "PKG_ENTRY_LIMIT"        // more entries than Limits.Entries
	CodeTotalTooLarge     = "PKG_TOTAL_TOO_LARGE"    // uncompressed total above Limits.TotalBytes
	CodeFileTooLarge      = "PKG_FILE_TOO_LARGE"     // one entry above Limits.FileBytes
	CodeCompressionRatio  = "PKG_COMPRESSION_RATIO"  // decompression bomb
	CodeMissingManifest   = "PKG_MISSING_MANIFEST"   // manifest.json is not the first entry
	CodeMissingSignature  = "PKG_MISSING_SIGNATURE"  // a signed read found no signatures/manifest.sig
	CodeEntryOrder        = "PKG_ENTRY_ORDER"        // manifest.json or the signature is not where it belongs
	CodeManifestTooLarge  = "PKG_MANIFEST_TOO_LARGE" // manifest.json above MaxManifestBytes
	CodeSignatureTooLarge = "PKG_SIGNATURE_TOO_LARGE"
	CodeEntryType         = "PKG_ENTRY_TYPE"   // symlink, hard link, device, FIFO, sparse, or irregular entry
	CodeEntryMode         = "PKG_ENTRY_MODE"   // setuid, setgid or sticky bit
	CodeEntryHeader       = "PKG_ENTRY_HEADER" // a header that cannot be encoded (over-long USTAR name)
)

// Path problems.
const (
	CodePathInvalidUTF8 = "PKG_PATH_INVALID_UTF8"
	CodePathAbsolute    = "PKG_PATH_ABSOLUTE"
	CodePathTraversal   = "PKG_PATH_TRAVERSAL" // "." or ".." component
	CodePathInvalid     = "PKG_PATH_INVALID"   // empty component, backslash, control character, trailing slash
	CodePathTooLong     = "PKG_PATH_TOO_LONG"
	CodePathTooDeep     = "PKG_PATH_TOO_DEEP"
	CodePathDuplicate   = "PKG_PATH_DUPLICATE" // equal after case folding
	CodePathConflict    = "PKG_PATH_CONFLICT"  // one path is both a file and a directory
)

// Content problems.
const (
	CodeFileMissing     = "PKG_FILE_MISSING"    // listed in manifest.files, absent from the archive
	CodeFileUnlisted    = "PKG_FILE_UNLISTED"   // present in the archive, not listed in manifest.files
	CodeDigestMismatch  = "PKG_DIGEST_MISMATCH" // content digest differs from manifest.files
	CodeDigestMalformed = "PKG_DIGEST_MALFORMED"
)

// Writing problems.
const (
	CodeSourceInvalid     = "PKG_SOURCE_INVALID"   // symlink, device or irregular entry in the source tree
	CodeSourceChanged     = "PKG_SOURCE_CHANGED"   // a source file changed between hashing and writing
	CodeManifestInvalid   = "PKG_MANIFEST_INVALID" // the source manifest is not a usable JSON object
	CodeKeyInvalid        = "PKG_KEY_INVALID"
	CodePublisherMismatch = "PKG_PUBLISHER_MISMATCH" // manifest.publisher.key_id is not the signing key
)

// newError sorts, caps and wraps violations. It returns nil for none.
func newError(vs []Violation) *Error {
	if len(vs) == 0 {
		return nil
	}
	sort.Slice(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Message < b.Message
	})
	e := &Error{Violations: vs}
	if len(vs) > MaxViolations {
		e.Violations = vs[:MaxViolations:MaxViolations]
		e.Omitted = len(vs) - MaxViolations
	}
	return e
}

func single(path, code, msg string) *Error {
	return &Error{Violations: []Violation{{Path: path, Code: code, Message: msg}}}
}

// excerpt quotes a short prefix of untrusted text for a message.
func excerpt(s string) string {
	if len(s) > maxExcerptBytes {
		cut := maxExcerptBytes
		for cut > 0 && s[cut]&0xC0 == 0x80 { // do not split a UTF-8 sequence
			cut--
		}
		return strconv.QuoteToASCII(s[:cut]) + "..."
	}
	return strconv.QuoteToASCII(s)
}
