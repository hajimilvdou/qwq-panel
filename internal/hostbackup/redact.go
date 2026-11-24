// SPDX-License-Identifier: AGPL-3.0-only

package hostbackup

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/logging"
)

const RedactedValue = "[REDACTED]"

var (
	authHeaderRe = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*(?:bearer|basic)\s+|x-api-key\s*[:=]\s*|x-qwq-mfa-code\s*[:=]\s*)([^\s"',}&#\\]+)`)
	cookieHdrRe  = regexp.MustCompile(`(?i)\b((?:set-)?cookie\s*[:=]\s*)([^\r\n"'}\]]+)`)
	urlUserInfo  = regexp.MustCompile(`(https?://)([^\s/@:]+):([^\s/@]+)@`)
	subTokenRe   = regexp.MustCompile(`(/p/proxy\.advanced/sub/)[A-Za-z0-9_-]+`)
	kvPairRe     = regexp.MustCompile(`(\\"|"?)([A-Za-z0-9_.-]+)(\\"|"?)(\s*[=:]\s*)(\\"(?:[^"\\]|\\.)*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|[^\s,}&#]+)`)
)

// SensitiveField reports whether key should be redacted in exported support
// bundles (logging's sensitive key table plus contact email).
func SensitiveField(key string) bool {
	return logging.IsSensitiveKey(key) || strings.EqualFold(strings.TrimSpace(key), "email")
}

// ExtractEntryPathFromConfig returns http.entry_path from raw qwq.json if present.
func ExtractEntryPathFromConfig(raw []byte) string {
	var doc struct {
		HTTP struct {
			EntryPath string `json:"entry_path"`
		} `json:"http"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	return strings.Trim(strings.TrimSpace(doc.HTTP.EntryPath), "/")
}

func scrubEntryPath(s, currentEntryPath string) string {
	ep := strings.Trim(strings.TrimSpace(currentEntryPath), "/")
	if len(ep) < 4 {
		return s
	}
	re := regexp.MustCompile(`(?i)(/` + regexp.QuoteMeta(ep) + `)(/|$|[?#"'\s),}&\\])`)
	return re.ReplaceAllString(s, "/[REDACTED_ENTRY]${2}")
}

func scrubPlainSegment(s, currentEntryPath string) string {
	out := authHeaderRe.ReplaceAllString(s, "${1}"+RedactedValue)
	out = cookieHdrRe.ReplaceAllString(out, "${1}"+RedactedValue)
	out = urlUserInfo.ReplaceAllString(out, "${1}"+RedactedValue+":"+RedactedValue+"@")
	out = subTokenRe.ReplaceAllString(out, "${1}"+RedactedValue)
	out = scrubEntryPath(out, currentEntryPath)
	out = kvPairRe.ReplaceAllStringFunc(out, func(m string) string {
		p := kvPairRe.FindStringSubmatch(m)
		if len(p) < 6 || !SensitiveField(p[2]) {
			return m
		}
		return p[1] + p[2] + p[3] + p[4] + RedactedValue
	})
	return out
}

// RedactJSON recursively redacts sensitive keys and secret URL patterns inside
// a decoded JSON value.
func RedactJSON(v any, currentEntryPath string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if SensitiveField(k) {
				out[k] = RedactedValue
			} else {
				out[k] = RedactJSON(val, currentEntryPath)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = RedactJSON(t[i], currentEntryPath)
		}
		return out
	case string:
		return scrubPlainSegment(t, currentEntryPath)
	default:
		return v
	}
}

// RedactJSONDocument redacts a JSON document; unparsable input is withheld.
func RedactJSONDocument(raw []byte, currentEntryPath string) []byte {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return []byte("[unparsable; withheld]\n")
	}
	out, err := json.MarshalIndent(RedactJSON(v, currentEntryPath), "", "  ")
	if err != nil {
		return []byte("[unencodable; withheld]\n")
	}
	return append(out, '\n')
}

// RedactSupportLogLine redacts one log line completely, including any plain-text
// prefix before '{', trailing text after the JSON object, URL secret entry paths,
// subscription tokens, cookies, URL userinfo, key=value credentials, and nested JSON payloads.
func RedactSupportLogLine(line, currentEntryPath string) string {
	hadNL := strings.HasSuffix(line, "\n")
	trimmed := strings.TrimSuffix(line, "\n")
	var out string
	if idx := strings.IndexByte(trimmed, '{'); idx >= 0 {
		prefix := scrubPlainSegment(trimmed[:idx], currentEntryPath)
		rest := trimmed[idx:]
		var payload map[string]any
		dec := json.NewDecoder(strings.NewReader(rest))
		dec.UseNumber()
		if err := dec.Decode(&payload); err == nil && payload != nil {
			consumed := int(dec.InputOffset())
			var suffix string
			if consumed > 0 && consumed < len(rest) {
				suffix = scrubPlainSegment(rest[consumed:], currentEntryPath)
			}
			if encoded, merr := json.Marshal(RedactJSON(payload, currentEntryPath)); merr == nil {
				out = prefix + string(encoded) + suffix
			} else {
				out = scrubPlainSegment(trimmed, currentEntryPath)
			}
		} else {
			out = scrubPlainSegment(trimmed, currentEntryPath)
		}
	} else {
		out = scrubPlainSegment(trimmed, currentEntryPath)
	}
	if hadNL {
		return out + "\n"
	}
	return out
}

// RedactLog applies RedactSupportLogLine to every line in s.
func RedactLog(s, currentEntryPath string) string {
	var b bytes.Buffer
	b.Grow(len(s))
	for _, line := range strings.SplitAfter(s, "\n") {
		if line == "" {
			continue
		}
		b.WriteString(RedactSupportLogLine(line, currentEntryPath))
	}
	return b.String()
}
