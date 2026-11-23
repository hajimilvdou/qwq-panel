// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const maxNonStreamResponseBytes = 16 << 20 // 16 MiB bounded read to prevent OOM

// RelayJSONResponseBridge relays non-streaming (stream:false) upstream JSON
// responses verbatim while extracting cross-protocol token usage (OpenAI,
// Anthropic, Gemini) with bidirectional input/output floor fallback so billing
// cannot be bypassed.
func RelayJSONResponseBridge(
	startedAt time.Time,
	upBody io.Reader,
	statusCode int,
	contentType string,
	estimatedInputTokens int,
	w http.ResponseWriter,
) (StreamUsage, error) {
	raw, err := io.ReadAll(io.LimitReader(upBody, maxNonStreamResponseBytes+1))
	ttft := time.Since(startedAt).Milliseconds()
	if err != nil {
		return StreamUsage{InputTokens: max(0, estimatedInputTokens), TTFTMs: ttft}, err
	}
	if len(raw) > maxNonStreamResponseBytes {
		return StreamUsage{
			InputTokens:  max(0, estimatedInputTokens),
			OutputTokens: maxNonStreamResponseBytes / 4,
			TTFTMs:       ttft,
		}, errors.New("upstream JSON response exceeded 16 MiB limit")
	}

	usage := ExtractUsageFromJSONPayload(raw, estimatedInputTokens)
	usage.TTFTMs = ttft

	if contentType == "" {
		contentType = "application/json; charset=utf-8"
	}
	if statusCode <= 0 {
		statusCode = http.StatusOK
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(statusCode)
	_, writeErr := w.Write(raw)
	return usage, writeErr
}

// ExtractUsageFromJSONPayload extracts token usage from non-streaming OpenAI,
// Anthropic, or Gemini JSON payloads and applies input/output floor estimates
// when upstream omits usage metadata.
func ExtractUsageFromJSONPayload(raw []byte, estimatedInputTokens int) StreamUsage {
	var doc struct {
		Usage *struct {
			PromptTokens        int `json:"prompt_tokens"`
			CompletionTokens    int `json:"completion_tokens"`
			InputTokens         int `json:"input_tokens"`
			OutputTokens        int `json:"output_tokens"`
			CacheCreationTokens int `json:"cache_creation_input_tokens"`
			CacheReadTokens     int `json:"cache_read_input_tokens"`
			PromptTokensDetails *struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
			InputTokensDetails *struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
		UsageMetadata *struct {
			PromptTokenCount        int `json:"promptTokenCount"`
			CandidatesTokenCount    int `json:"candidatesTokenCount"`
			CachedContentTokenCount int `json:"cachedContentTokenCount"`
		} `json:"usageMetadata"`
	}

	var u StreamUsage
	if err := json.Unmarshal(raw, &doc); err == nil {
		if doc.Usage != nil {
			u.InputTokens = max(doc.Usage.PromptTokens, doc.Usage.InputTokens)
			u.OutputTokens = max(doc.Usage.CompletionTokens, doc.Usage.OutputTokens)
			u.CacheWriteTokens = doc.Usage.CacheCreationTokens
			u.CachedReadTokens = doc.Usage.CacheReadTokens
			if doc.Usage.CacheCreationTokens > 0 || doc.Usage.CacheReadTokens > 0 {
				if doc.Usage.InputTokens > 0 && doc.Usage.PromptTokens == 0 {
					u.InputTokens = doc.Usage.InputTokens + doc.Usage.CacheReadTokens + doc.Usage.CacheCreationTokens
				}
			}
			if doc.Usage.PromptTokensDetails != nil && doc.Usage.PromptTokensDetails.CachedTokens > u.CachedReadTokens {
				u.CachedReadTokens = doc.Usage.PromptTokensDetails.CachedTokens
			}
			if doc.Usage.InputTokensDetails != nil && doc.Usage.InputTokensDetails.CachedTokens > u.CachedReadTokens {
				u.CachedReadTokens = doc.Usage.InputTokensDetails.CachedTokens
			}
		} else if doc.UsageMetadata != nil {
			u.InputTokens = doc.UsageMetadata.PromptTokenCount
			u.OutputTokens = doc.UsageMetadata.CandidatesTokenCount
			u.CachedReadTokens = doc.UsageMetadata.CachedContentTokenCount
		}
	}

	if u.InputTokens <= 0 && estimatedInputTokens > 0 {
		u.InputTokens = estimatedInputTokens
	}
	if u.OutputTokens <= 0 && len(raw) > 0 {
		u.OutputTokens = max(1, len(raw)/6)
	}
	return u
}
