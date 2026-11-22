// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Violation is one problem found in a manifest. It maps 1:1 onto the
// qwq.platform.v1.FieldViolation message.
type Violation struct {
	// Pointer is an RFC 6901 JSON Pointer to the offending instance location
	// ("" is the whole document).
	Pointer string `json:"pointer"`
	// Code is a stable machine readable identifier, one of the Code* constants.
	Code string `json:"code"`
	// Message is for humans. It never echoes more than a short excerpt of
	// untrusted input.
	Message string `json:"message"`
}

// Error is returned by Parse and VerifyAndParse when a manifest is rejected.
// Violations are sorted by pointer, then code, then message, and capped at
// MaxViolations; Omitted counts the ones dropped by the cap.
type Error struct {
	Violations []Violation
	Omitted    int
}

func (e *Error) Error() string {
	n := len(e.Violations) + e.Omitted
	var b strings.Builder
	fmt.Fprintf(&b, "manifest rejected: %d violation(s)", n)
	for i, v := range e.Violations {
		if i == 3 {
			fmt.Fprintf(&b, "; ... and %d more", n-i)
			break
		}
		ptr := v.Pointer
		if ptr == "" {
			ptr = "/"
		}
		fmt.Fprintf(&b, "; %s %s: %s", ptr, v.Code, v.Message)
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
	// MaxViolations caps the violations reported for one manifest.
	MaxViolations = 100
	// maxPointerBytes caps a reported pointer; longer pointers are cut back to
	// the nearest ancestor that fits (keys of rejected documents can be huge).
	maxPointerBytes = 512
	// maxExcerptBytes caps quoted untrusted input in messages.
	maxExcerptBytes = 64
)

// Decode stage (strict JSON). The first problem stops decoding.
const (
	CodeTooLarge         = "TOO_LARGE"          // more than MaxSize bytes
	CodeInvalidUTF8      = "INVALID_UTF8"       // not well-formed UTF-8
	CodeInvalidJSON      = "INVALID_JSON"       // RFC 8259 syntax error (includes NaN, Infinity, BOM)
	CodeTrailingData     = "TRAILING_DATA"      // non-whitespace after the top-level value
	CodeTooDeep          = "TOO_DEEP"           // nesting deeper than MaxDepth
	CodeDuplicateKey     = "DUPLICATE_KEY"      // same key twice in one object, compared after unescaping
	CodeLoneSurrogate    = "LONE_SURROGATE"     // \uD800-\uDFFF escape not part of a valid pair
	CodeNumberNotInteger = "NUMBER_NOT_INTEGER" // manifest v1 only has integer numbers
	CodeNumberOutOfRange = "NUMBER_OUT_OF_RANGE"
	CodeNotObject        = "NOT_OBJECT" // top-level value is not an object
)

// Schema stage: "SCHEMA_" + the failing JSON Schema keyword in upper snake
// case. Only keywords used by manifest.schema.json are listed.
const (
	CodeSchemaType                 = "SCHEMA_TYPE"
	CodeSchemaConst                = "SCHEMA_CONST"
	CodeSchemaEnum                 = "SCHEMA_ENUM"
	CodeSchemaPattern              = "SCHEMA_PATTERN"
	CodeSchemaMinLength            = "SCHEMA_MIN_LENGTH"
	CodeSchemaMaxLength            = "SCHEMA_MAX_LENGTH"
	CodeSchemaMinimum              = "SCHEMA_MINIMUM"
	CodeSchemaMaximum              = "SCHEMA_MAXIMUM"
	CodeSchemaMinItems             = "SCHEMA_MIN_ITEMS"
	CodeSchemaMaxItems             = "SCHEMA_MAX_ITEMS"
	CodeSchemaUniqueItems          = "SCHEMA_UNIQUE_ITEMS"
	CodeSchemaMinProperties        = "SCHEMA_MIN_PROPERTIES"
	CodeSchemaMaxProperties        = "SCHEMA_MAX_PROPERTIES"
	CodeSchemaRequired             = "SCHEMA_REQUIRED"
	CodeSchemaAdditionalProperties = "SCHEMA_ADDITIONAL_PROPERTIES"
	CodeSchemaPropertyNames        = "SCHEMA_PROPERTY_NAMES"
	// CodeSchemaViolation is used for keywords the schema does not use today.
	CodeSchemaViolation = "SCHEMA_VIOLATION"
)

// Typed decode stage. Unreachable unless Manifest and the schema disagree.
const (
	CodeDecodeFailed = "DECODE_FAILED"
)

// Permission naming rules (ADR-0014).
const (
	CodePluginIDReserved         = "PLUGIN_ID_RESERVED"         // id in a host namespace
	CodePermissionNamespace      = "PERMISSION_NAMESPACE"       // permission resource outside the plugin id
	CodePermissionEffectMismatch = "PERMISSION_EFFECT_MISMATCH" // read-class action on a non-read operation
)

// Installer rules (ARCH §5.3): what JSON Schema cannot express.
const (
	CodeUnsupportedSchemaVersion = "UNSUPPORTED_SCHEMA_VERSION" // schema_version minor above SupportedSchemaMinor
	CodePathNotASCII             = "PATH_NOT_ASCII"             // guard: files key outside ASCII (schema forbids it today)
	CodePathCaseCollision        = "PATH_CASE_COLLISION"        // files keys equal after case folding
	CodePathReserved             = "PATH_RESERVED"              // files lists manifest.json or signatures/...
	CodePathFileDirConflict      = "PATH_FILE_DIR_CONFLICT"     // a files key is also a directory of another key
	CodeFileNotListed            = "FILE_NOT_LISTED"            // referenced path missing from files
	CodeDuplicateOperation       = "DUPLICATE_OPERATION"
	CodeUndoUnknown              = "UNDO_UNKNOWN"        // undo names no operation of this plugin
	CodeUIRouteUndeclared        = "UI_ROUTE_UNDECLARED" // ui_route missing from ui.routes
	CodeUIRouteDuplicate         = "UI_ROUTE_DUPLICATE"  // same ui.routes path twice
	// operations[i].capabilities[j] is not a top-level capability (same name and scope).
	CodeOperationCapabilityUndeclared = "OPERATION_CAPABILITY_UNDECLARED"
	// Approval metadata (ADR-0010). The schema enforces the same rules; these
	// guards keep them true for a Manifest that did not come through Parse.
	CodeApprovalInvalid            = "APPROVAL_INVALID"             // approval is not auto, confirm or ai_confirm
	CodeApprovalSummaryMissing     = "APPROVAL_SUMMARY_MISSING"     // confirm/ai_confirm without approval_summary
	CodeApprovalSummaryInvalid     = "APPROVAL_SUMMARY_INVALID"     // blank, multi-line, control/bidi or over 200 characters
	CodeApprovalDescriptionInvalid = "APPROVAL_DESCRIPTION_INVALID" // control/bidi or over 2000 characters
	// Schema 1.3 (ADR-0018).
	CodeSchemaVersionTooLow         = "SCHEMA_VERSION_TOO_LOW"         // member of a later minor than schema_version declares
	CodeUIWidgetDuplicate           = "UI_WIDGET_DUPLICATE"            // same ui.widgets id twice
	CodeUIWidgetOperationUnknown    = "UI_WIDGET_OPERATION_UNKNOWN"    // widget names no operation of this plugin
	CodeUIWidgetOperationUnsuitable = "UI_WIDGET_OPERATION_UNSUITABLE" // widget operation is not effect=read, mode=invoke
)

// Detached signature (VerifyAndParse).
const (
	CodeSignatureMalformed      = "SIGNATURE_MALFORMED"
	CodeKeyUnknown              = "KEY_UNKNOWN"
	CodeSignatureInvalid        = "SIGNATURE_INVALID"
	CodeKeyIDMismatch           = "KEY_ID_MISMATCH"           // publisher.key_id differs from the signing key
	CodePublisherMismatch       = "PUBLISHER_MISMATCH"        // key is bound to another publisher.id
	CodePluginNamespaceMismatch = "PLUGIN_NAMESPACE_MISMATCH" // key may not sign for this plugin id
)

// newError sorts, caps and wraps violations. It returns nil for none.
func newError(vs []Violation) *Error {
	if len(vs) == 0 {
		return nil
	}
	sort.Slice(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if a.Pointer != b.Pointer {
			return a.Pointer < b.Pointer
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

func single(pointer, code, msg string) *Error {
	return &Error{Violations: []Violation{{Pointer: pointer, Code: code, Message: msg}}}
}

// escapeToken escapes one RFC 6901 reference token.
func escapeToken(s string) string {
	if !strings.ContainsAny(s, "~/") {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// pointer builds a JSON Pointer from unescaped tokens. If the result exceeds
// maxPointerBytes, trailing tokens are dropped until it fits, so the pointer
// stays valid and names an ancestor of the real location.
func pointer(tokens []string) string {
	var b strings.Builder
	for _, t := range tokens {
		e := escapeToken(t)
		if b.Len()+1+len(e) > maxPointerBytes {
			break
		}
		b.WriteByte('/')
		b.WriteString(e)
	}
	return b.String()
}

func join(base string, tokens ...string) string {
	var b strings.Builder
	b.WriteString(base)
	for _, t := range tokens {
		e := escapeToken(t)
		if b.Len()+1+len(e) > maxPointerBytes {
			break
		}
		b.WriteByte('/')
		b.WriteString(e)
	}
	return b.String()
}

func index(i int) string { return strconv.Itoa(i) }

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
