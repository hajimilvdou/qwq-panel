// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Subject syntax (ADR-0007 #2 and the header of platform.proto):
//
//	A plugin names its own resources with a relative subject
//	"<segment>(/<segment>)*", each segment matching [A-Za-z0-9._~-]{1,128};
//	the host prefixes the instance namespace. Events and the public API use
//	full subjects, which match the OpenAPI Subject schema.
//
// The relative charset is a subset of the full one, so a valid relative subject
// always yields a valid full subject.
var (
	relativeSegment  = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
	fullSubjectRe    = regexp.MustCompile(`^[a-z][a-z0-9_-]*(/[A-Za-z0-9._~:@-]+)*$`)
	maxSubjectLength = 512
	// instancePrefixChars must stay a prefix of the full subject syntax.
	pluginSegment = regexp.MustCompile(`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`)
	nodeSegment   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	nodeIDRe      = nodeSegment
)

// validateRelativeSubject checks a subject a plugin reported. It rejects empty
// segments, "." and "..", invalid characters and overlong values.
func validateRelativeSubject(s string) error {
	if s == "" {
		return errors.New("operations: empty subject")
	}
	if len(s) > maxSubjectLength {
		return errors.New("operations: subject too long")
	}
	if strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return errors.New("operations: subject has an empty segment")
	}
	segments := strings.Split(s, "/")
	if len(segments) > 16 {
		return errors.New("operations: subject has too many segments")
	}
	for _, seg := range segments {
		if seg == "." || seg == ".." {
			return errors.New("operations: subject contains a relative segment")
		}
		if !relativeSegment.MatchString(seg) {
			return fmt.Errorf("operations: subject segment %q is not allowed", seg)
		}
	}
	return nil
}

// validateFullSubject checks a subject that arrived from a client (Target.Subject)
// against the OpenAPI Subject schema.
func validateFullSubject(s string) error {
	if len(s) > maxSubjectLength {
		return errors.New("operations: subject too long")
	}
	if !fullSubjectRe.MatchString(s) {
		return fmt.Errorf("operations: subject %q is not canonical", s)
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("operations: subject %q contains a relative segment", s)
		}
	}
	return nil
}

// prefixPluginSubject validates a relative subject reported by a plugin and
// returns the full subject with the instance namespace (ADR-0007 #2): node
// placement uses nodes/<node>/plugins/<plugin>/instances/<instance>/resources/…,
// controller placement uses plugins/<plugin>/resources/…. The fixed resources
// segment keeps plugin resources apart from the host's own sub-resources.
func prefixPluginSubject(placement, nodeID, pluginID, instanceID, rel string) (string, error) {
	if err := validateRelativeSubject(rel); err != nil {
		return "", err
	}
	var full string
	switch placement {
	case PlacementNode:
		if !nodeIDRe.MatchString(nodeID) {
			return "", fmt.Errorf("operations: invalid node id %q", nodeID)
		}
		if !pluginSegment.MatchString(pluginID) {
			return "", fmt.Errorf("operations: invalid plugin id %q", pluginID)
		}
		if instanceID == "" || strings.ContainsAny(instanceID, "/.") {
			return "", fmt.Errorf("operations: invalid instance id %q", instanceID)
		}
		full = "nodes/" + nodeID + "/plugins/" + pluginID + "/instances/" + instanceID + "/resources/" + rel
	case PlacementController:
		if !pluginSegment.MatchString(pluginID) {
			return "", fmt.Errorf("operations: invalid plugin id %q", pluginID)
		}
		full = "plugins/" + pluginID + "/resources/" + rel
	default:
		return "", fmt.Errorf("operations: invalid placement %q", placement)
	}
	if len(full) > maxSubjectLength {
		return "", errors.New("operations: subject too long")
	}
	return full, nil
}

// operationSubject is the subject of the operation resource itself.
func operationSubject(id string) string { return "operations/" + id }

// approvalSubject is the subject of the approval resource.
func approvalSubject(id string) string { return "approvals/" + id }

// planSubject is the subject of the plan resource.
func planSubject(id string) string { return "plans/" + id }

// canonicalJSONPrefix names the digest algorithm in plans and idempotency keys.
const canonicalJSONPrefix = "sha256:"
