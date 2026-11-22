// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Grammar limits from the platform.proto header and from the ABI state
// section.
const (
	maxSubjectSegment = 128
	maxSubjectLen     = 512
	maxEventTypeLen   = 128
	maxEventTypePart  = 64
	maxSecretRefLen   = 256
	maxActionLen      = 128
	maxAuditSubject   = 512
	maxDetailsJSON    = 64 << 10
	maxSubscription   = 64
	maxPointerLen     = 512
	maxIDFieldLen     = 128
)

// invalidArg returns INVALID_ARGUMENT. Messages never echo the offending value
// in full: it is untrusted and may be huge.
func invalidArg(message string) error {
	return status.Error(codes.InvalidArgument, message)
}

// validateRelativeSubject checks a plugin-supplied relative subject: segments
// of [A-Za-z0-9._~-] with 1-128 bytes each, separated by "/", and never an
// empty, "." or ".." segment (platform.proto, "Subjects"). The host prefixes a
// valid subject with the instance namespace, so a relative path step must not
// survive validation.
func validateRelativeSubject(s string) error {
	if s == "" {
		return invalidArg("a relative subject is required")
	}
	if len(s) > maxSubjectLen {
		return invalidArg("the subject is too long")
	}
	for _, segment := range strings.Split(s, "/") {
		if segment == "" {
			return invalidArg("the subject has an empty segment")
		}
		if segment == "." || segment == ".." {
			return invalidArg("the subject contains a relative path segment")
		}
		if len(segment) > maxSubjectSegment {
			return invalidArg("a subject segment is longer than 128 bytes")
		}
		for i := 0; i < len(segment); i++ {
			if !subjectByte(segment[i]) {
				return invalidArg("the subject contains a character outside [A-Za-z0-9._~-]")
			}
		}
	}
	return nil
}

// subjectByte reports whether b may appear in a relative subject segment.
func subjectByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '.', '_', '~', '-':
		return true
	}
	return false
}

// validateEventType checks a dotted event type such as "security.alert". The
// ABI only says "dotted"; the host additionally bounds the length and rejects
// wildcards so a plugin cannot smuggle a topic pattern into a published type.
func validateEventType(t string) error {
	if t == "" {
		return invalidArg("an event type is required")
	}
	if len(t) > maxEventTypeLen {
		return invalidArg("the event type is too long")
	}
	for _, part := range strings.Split(t, ".") {
		if part == "" {
			return invalidArg("the event type has an empty segment")
		}
		if len(part) > maxEventTypePart {
			return invalidArg("an event type segment is longer than 64 bytes")
		}
		for i := 0; i < len(part); i++ {
			b := part[i]
			if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-' {
				continue
			}
			return invalidArg("the event type contains a character outside [A-Za-z0-9_-]")
		}
	}
	return nil
}

// validateEventTopic checks one SubscribeEvents topic: an exact event type or a
// prefix ending in ".*" (platform.proto, SubscribeEvents).
func validateEventTopic(topic string) error {
	if topic == "" {
		return invalidArg("a topic is required")
	}
	if prefix, ok := strings.CutSuffix(topic, ".*"); ok {
		if prefix == "" {
			return invalidArg("a wildcard topic needs a prefix")
		}
		return validateEventType(prefix)
	}
	if strings.Contains(topic, "*") {
		return invalidArg("\"*\" is only allowed as a trailing \".*\"")
	}
	return validateEventType(topic)
}

// matchTopic reports whether typ matches the subscription topics. An empty
// topic list matches every event (the SDK sends none to follow everything).
func matchTopic(topics []string, typ string) bool {
	if len(topics) == 0 {
		return true
	}
	for _, topic := range topics {
		if prefix, ok := strings.CutSuffix(topic, ".*"); ok {
			if strings.HasPrefix(typ, prefix+".") {
				return true
			}
			continue
		}
		if typ == topic {
			return true
		}
	}
	return false
}

// validStateKey reports whether key is a state key per the ABI: 1-256 bytes of
// [A-Za-z0-9._/-]. Prefixes allow the empty string.
func validStateKey(key string, maxLen int, allowEmpty bool) bool {
	if key == "" {
		return allowEmpty
	}
	if len(key) > maxLen {
		return false
	}
	for i := 0; i < len(key); i++ {
		b := key[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		switch b {
		case '.', '_', '/', '-':
			continue
		}
		return false
	}
	return true
}

// validateSecretRef bounds a secret reference. The opaque value is resolved by
// the SecretRevealer, so the server only rejects empty, oversized and
// non-visible references.
func validateSecretRef(ref string) error {
	if ref == "" {
		return invalidArg("a secret reference is required")
	}
	if len(ref) > maxSecretRefLen {
		return invalidArg("the secret reference is too long")
	}
	for i := 0; i < len(ref); i++ {
		if ref[i] < 0x21 || ref[i] > 0x7e {
			return invalidArg("the secret reference contains a control or space character")
		}
	}
	return nil
}

// validateAuditAction bounds the stable action identifier of an audit record.
func validateAuditAction(action string) error {
	if action == "" {
		return invalidArg("an audit action is required")
	}
	if len(action) > maxActionLen {
		return invalidArg("the audit action is too long")
	}
	for i := 0; i < len(action); i++ {
		b := action[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		switch b {
		case '.', '_', ':', '-':
			continue
		}
		return invalidArg("the audit action contains a character outside [A-Za-z0-9._:-]")
	}
	return nil
}

// validateAuditSubject bounds the subject of an audit record. Audit subjects
// are host-visible text, so the check only enforces valid UTF-8, printable
// characters and a length cap.
func validateAuditSubject(subject string) error {
	if len(subject) > maxAuditSubject {
		return invalidArg("the audit subject is too long")
	}
	if !utf8.ValidString(subject) {
		return invalidArg("the audit subject is not valid UTF-8")
	}
	for _, r := range subject {
		if r < 0x20 || r == 0x7f {
			return invalidArg("the audit subject contains a control character")
		}
	}
	return nil
}

// validateSubscription checks the durable subscription name:
// [a-z0-9_-]{1,64} (platform.proto, SubscribeEvents).
func validateSubscription(subscription string) error {
	if subscription == "" {
		return invalidArg("a subscription name is required")
	}
	if len(subscription) > maxSubscription {
		return invalidArg("the subscription name is longer than 64 bytes")
	}
	for i := 0; i < len(subscription); i++ {
		b := subscription[i]
		if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b == '-' {
			continue
		}
		return invalidArg("the subscription name contains a character outside [a-z0-9_-]")
	}
	return nil
}

// validatePointers checks the RFC 6901 pointers of one ResourceChange. An empty
// pointer means the whole resource; otherwise each pointer starts with "/".
func validatePointers(pointers []string) error {
	for _, p := range pointers {
		if p == "" || p[0] != '/' {
			return invalidArg("a changed pointer must be empty or start with \"/\"")
		}
		if len(p) > maxPointerLen {
			return invalidArg("a changed pointer is too long")
		}
		for i := 0; i < len(p); i++ {
			if p[i] < 0x20 || p[i] == 0x7f {
				return invalidArg("a changed pointer contains a control character")
			}
		}
	}
	return nil
}

// validatePurpose bounds the free-text purpose of a secret reveal. Truncation
// is applied when the audit record is written; a purpose longer than the cap is
// a client bug, not a reason to reveal.
func validatePurpose(purpose string) error {
	if len(purpose) > 1024 {
		return invalidArg("the purpose is longer than 1024 bytes")
	}
	if !utf8.ValidString(purpose) {
		return invalidArg("the purpose is not valid UTF-8")
	}
	return nil
}

// validateDetailsJSON validates plugin-supplied audit details.
func validateDetailsJSON(details []byte) error {
	if len(details) == 0 {
		return nil
	}
	if len(details) > maxDetailsJSON {
		return limitError("audit.details_bytes", maxDetailsJSON)
	}
	if !jsonValid(details) {
		return invalidArg("audit details are not valid JSON")
	}
	return nil
}

// visibleASCII reports whether s is empty or consists of visible ASCII
// characters without spaces. It is used for short opaque tokens such as a
// schema version.
func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validIdentifier reports whether value is 1..maxLen bytes of
// [A-Za-z0-9._-] starting with a letter or digit. It is the grammar of plugin
// and instance ids in this package.
func validIdentifier(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if i == 0 {
			return false
		}
		switch b {
		case '.', '_', '-':
			continue
		}
		return false
	}
	return true
}

// limitError builds a RESOURCE_EXHAUSTED status for a LimitError.
func limitError(name string, max int64) error {
	return status.Error(codes.ResourceExhausted, fmt.Sprintf("%s exceeds the limit of %d", name, max))
}
