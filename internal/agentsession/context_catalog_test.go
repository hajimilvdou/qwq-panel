// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import "testing"

func TestResolveContextWindowMainstreamModels(t *testing.T) {
	cases := []struct {
		model   string
		want    int64
		matched bool
	}{
		{"gpt-5.4", 1_000_000, true},
		{"openai/gpt-5.2", 400_000, true},
		{"gpt-5-mini", 400_000, true},
		{"gpt-5-codex", 400_000, true},
		{"gpt-4.1-mini", 1_000_000, true},
		{"o3", 200_000, true},
		{"o4-mini", 200_000, true},
		{"gpt-4o", 128_000, true},
		{"anthropic/claude-opus-4-6", 1_000_000, true},
		{"claude-sonnet-4-6", 1_000_000, true},
		{"claude-sonnet-4-5-20250929", 200_000, true},
		{"claude-sonnet-4-5[1m]", 1_000_000, true},
		{"claude-3-5-sonnet-20241022", 200_000, true},
		{"gemini-2.5-pro", 1_000_000, true},
		{"google/gemini-3.1-pro", 1_000_000, true},
		{"gemini-1.5-pro", 2_000_000, true},
		{"deepseek-reasoner", 128_000, true},
		{"deepseek-v3.2", 128_000, true},
		{"deepseek-v4", 1_000_000, true},
		{"qwen3-coder-plus", 262_144, true},
		{"qwen3-235b", 131_072, true},
		{"qwen-long", 1_000_000, true},
		{"grok-4.20", 2_000_000, true},
		{"grok-4", 256_000, true},
		{"grok-3", 131_072, true},
		{"glm-5", 200_000, true},
		{"glm-4.5", 128_000, true},
		{"kimi-k2.5", 262_144, true},
		{"kimi-k3", 1_000_000, true},
		{"minimax-m2.5", 204_800, true},
		{"minimax-m1", 1_000_000, true},
		{"doubao-seed-2.0", 256_000, true},
		{"meta-llama/llama-4-scout", 10_000_000, true},
		{"llama-4-maverick", 1_000_000, true},
		{"llama-3.3-70b", 128_000, true},
		{"codestral-latest", 256_000, true},
		{"mistral-large-4", 1_000_000, true},
		{"my-custom-local-64k", 64_000, true},
		{"totally-unknown-model", DefaultFallbackContextTokens, false},
	}
	for _, tc := range cases {
		got, matched, _ := ResolveContextWindow(tc.model, 0)
		if got != tc.want || matched != tc.matched {
			t.Errorf("ResolveContextWindow(%q, 0) = (%d, %v), want (%d, %v)", tc.model, got, matched, tc.want, tc.matched)
		}
	}

	// Explicit user override always wins.
	if got, _, _ := ResolveContextWindow("gpt-5.4", 200_000); got != 200_000 {
		t.Fatalf("explicit override = %d, want 200000", got)
	}
	if got := FormatContextTokensLabel(262_144); got != "256K" {
		t.Fatalf("FormatContextTokensLabel(262144) = %q, want 256K", got)
	}
	if got := FormatContextTokensLabel(1_000_000); got != "1M" {
		t.Fatalf("FormatContextTokensLabel(1M) = %q, want 1M", got)
	}
}
