// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// maxSubjectSegment is the segment length limit from the platform.proto
// header.
const maxSubjectSegment = 128

// ValidateSubject checks a plugin-supplied relative subject. The grammar is
// "<segment>(/<segment>)*" with each segment matching [A-Za-z0-9._~-]{1,128}
// (platform.proto, "Subjects"). "." and ".." are rejected as well: the grammar
// alone admits them and a host that prefixes the subject must never treat a
// segment as a path step.
//
// The host prefixes valid subjects with the instance namespace, so a plugin
// cannot name the host's or another plugin's resources.
func ValidateSubject(s string) error {
	if s == "" {
		return invalidSubject(s, "empty")
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" {
			return invalidSubject(s, "empty segment")
		}
		if seg == "." || seg == ".." {
			return invalidSubject(s, "relative path segment")
		}
		if len(seg) > maxSubjectSegment {
			return invalidSubject(s, "segment longer than 128 bytes")
		}
		for i := 0; i < len(seg); i++ {
			if !subjectByte(seg[i]) {
				return invalidSubject(s, "character outside [A-Za-z0-9._~-]")
			}
		}
	}
	return nil
}

func subjectByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.', b == '_', b == '~', b == '-':
		return true
	}
	return false
}

// invalidSubject renders at most a short excerpt of the offending subject so a
// malformed call cannot flood the logs.
func invalidSubject(s, why string) *Error {
	shown := s
	if len(shown) > 80 {
		shown = shown[:80] + "…"
	}
	return &Error{Code: "PROTOCOL_ERROR", Message: fmt.Sprintf("invalid relative subject %q: %s", shown, why)}
}

// validateChanges checks every subject of changes before they are sent. It
// returns the first violation as a PROTOCOL_ERROR domain error.
func validateChanges(changes []ResourceChange) error {
	for _, c := range changes {
		if err := ValidateSubject(c.Subject); err != nil {
			return fmt.Errorf("resource change: %w", err)
		}
	}
	return nil
}

// validatePlan checks the subjects of a plan. Planned changes and preconditions
// both use relative subjects (ADR-0007 #2).
func validatePlan(p Plan) error {
	for _, c := range p.Changes {
		if err := ValidateSubject(c.Subject); err != nil {
			return fmt.Errorf("planned change: %w", err)
		}
		if c.Kind == ChangeUnspecified {
			return &Error{Code: "PROTOCOL_ERROR", Message: fmt.Sprintf("planned change for %q has no kind", c.Subject)}
		}
		if utf8.RuneCountInString(c.Description) > 200 {
			return &Error{Code: "PROTOCOL_ERROR", Message: fmt.Sprintf("planned change for %q has a description longer than 200 characters", c.Subject)}
		}
		if len(c.Before) > 0 && !json.Valid(c.Before) {
			return &Error{Code: "PROTOCOL_ERROR", Message: fmt.Sprintf("planned change for %q has an invalid before_json", c.Subject)}
		}
		if len(c.After) > 0 && !json.Valid(c.After) {
			return &Error{Code: "PROTOCOL_ERROR", Message: fmt.Sprintf("planned change for %q has an invalid after_json", c.Subject)}
		}
	}
	for _, pc := range p.Preconditions {
		if err := ValidateSubject(pc.Subject); err != nil {
			return fmt.Errorf("precondition: %w", err)
		}
	}
	return nil
}

// validateEventSubject checks an event draft's relative subject.
func validateEventSubject(s string) error {
	if err := ValidateSubject(s); err != nil {
		return fmt.Errorf("event: %w", err)
	}
	return nil
}
