// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"strconv"
	"strings"
)

// DefaultFallbackEffort is used when a model is not in the built-in catalog
// and the user did not specify a custom reasoning_effort.
const DefaultFallbackEffort = "high"

// ModelEffortProfile describes the official reasoning/thinking effort levels
// supported by a mainstream AI model family.
type ModelEffortProfile struct {
	Family        string   `json:"family"`
	Patterns      []string `json:"patterns"`
	Levels        []string `json:"levels"`
	DefaultEffort string   `json:"default_effort"`
	Notes         string   `json:"notes"`
}

// builtinModelEffortProfiles lists mainstream AI models and their official
// reasoning effort tiers, ordered from most-specific to broadest pattern.
var builtinModelEffortProfiles = HardenedBuiltinModelEffortProfiles()

// BuiltinModelEffortProfiles returns a deep copy of the built-in mainstream AI
// model reasoning effort catalog.
func BuiltinModelEffortProfiles() []ModelEffortProfile {
	return HardenedBuiltinModelEffortProfiles()
}

// normalizeModelID strips common gateway/router prefixes (e.g. "openai/",
// "anthropic/", "openrouter/google/") and lowercases the model identifier.
func normalizeModelID(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if idx := strings.LastIndex(m, "/"); idx >= 0 && idx < len(m)-1 {
		m = m[idx+1:]
	}
	return m
}

// MatchModelEffortProfile looks up a model identifier against the built-in
// catalog of mainstream AI models.
func MatchModelEffortProfile(model string) (ModelEffortProfile, bool) {
	norm := normalizeModelID(model)
	if norm == "" {
		return ModelEffortProfile{}, false
	}
	for _, p := range builtinModelEffortProfiles {
		for _, pat := range p.Patterns {
			if matchesModelPattern(norm, pat) {
				return p, true
			}
		}
	}
	return ModelEffortProfile{}, false
}

func matchesModelPattern(norm, pat string) bool {
	if pat == "" {
		return false
	}
	if len(pat) <= 2 {
		// Short identifiers like "o1"/"o3" must appear at token boundaries so
		// unrelated names like "mistral-nemo12b", "pro1", or "evo3" do not match.
		for start := 0; start < len(norm); {
			idx := strings.Index(norm[start:], pat)
			if idx < 0 {
				return false
			}
			pos := start + idx
			end := pos + len(pat)
			leftOK := pos == 0 || isModelBoundaryByte(norm[pos-1])
			rightOK := end == len(norm) || isModelBoundaryByte(norm[end])
			if leftOK && rightOK {
				return true
			}
			start = pos + 1
		}
		return false
	}
	return strings.HasPrefix(norm, pat) || strings.Contains(norm, pat)
}

func isModelBoundaryByte(b byte) bool {
	return b == '-' || b == '_' || b == '.' || b == ':' || b == '/'
}

// ResolveReasoningEffort returns the effective reasoning effort code for a turn:
//  1. If the user explicitly configured a custom effort, return it verbatim.
//  2. Otherwise match the model against the built-in mainstream AI catalog.
//  3. If unmatched and unconfigured, default to "high".
func ResolveReasoningEffort(model, configured string) (effort string, matched bool, profile ModelEffortProfile) {
	profile, matched = MatchModelEffortProfile(model)
	custom := strings.TrimSpace(configured)
	if custom != "" {
		return custom, matched, profile
	}
	if matched && profile.DefaultEffort != "" {
		return profile.DefaultEffort, true, profile
	}
	return DefaultFallbackEffort, false, ModelEffortProfile{}
}

// IsReasoningEffortDisabled reports whether an effort string explicitly turns
// off extended reasoning (used by adapters/APIs that represent off by omitting
// thinking parameters).
func IsReasoningEffortDisabled(effort string) bool {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "", "none", "off", "disabled", "false", "0":
		return true
	default:
		return false
	}
}

// ParseNumericThinkingBudget parses a positive integer token budget if the user
// entered a numeric custom effort (e.g. "8192" or "16384").
func ParseNumericThinkingBudget(effort string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(effort))
	if err != nil || n <= 0 {
		return 0, false
	}
	if n < 1024 {
		n = 1024
	}
	if n > 128000 {
		n = 128000
	}
	return n, true
}
