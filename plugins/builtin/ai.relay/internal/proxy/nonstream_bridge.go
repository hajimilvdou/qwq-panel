// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// NormalizeUpstreamBaseURL strips trailing slashes and a trailing /v1 or /v1beta
// segment so appending /v1/... never produces /v1/v1/... 404 URLs.
func NormalizeUpstreamBaseURL(raw string) string {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	base = strings.TrimSuffix(base, "/v1")
	base = strings.TrimSuffix(base, "/v1beta")
	return strings.TrimRight(base, "/")
}

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

// AggregateCanonicalNonStreamResponse consumes a cross-protocol upstream SSE
// stream (upProto) and emits a standard non-streaming application/json payload
// in downProto format when the downstream client requested stream:false.
func AggregateCanonicalNonStreamResponse(
	startedAt time.Time,
	upBody io.Reader,
	upProto, downProto ProtocolKind,
	reqModel string,
	estimatedInputTokens int,
	w http.ResponseWriter,
) (StreamUsage, error) {
	bufPtr := sseLineBufPool.Get().(*[]byte)
	defer sseLineBufPool.Put(bufPtr)

	sc := bufio.NewScanner(io.LimitReader(upBody, maxNonStreamResponseBytes))
	sc.Buffer(*bufPtr, 2<<20)

	var (
		usage     StreamUsage
		textBuf   strings.Builder
		reasonBuf strings.Builder
	)
	for sc.Scan() {
		line := sc.Bytes()
		after, ok := bytes.CutPrefix(line, []byte("data:"))
		if !ok {
			continue
		}
		payload := bytes.TrimSpace(after)
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		textD, reasonD := parseUpstreamDeltaAndUsage(payload, upProto, &usage)
		if (textD != "" || reasonD != "") && usage.TTFTMs == 0 {
			usage.TTFTMs = time.Since(startedAt).Milliseconds()
		}
		if textD != "" && textBuf.Len() < maxNonStreamResponseBytes {
			textBuf.WriteString(textD)
		}
		if reasonD != "" && reasonBuf.Len() < maxNonStreamResponseBytes {
			reasonBuf.WriteString(reasonD)
		}
	}
	if err := sc.Err(); err != nil {
		return usage, err
	}
	if usage.TTFTMs == 0 {
		usage.TTFTMs = time.Since(startedAt).Milliseconds()
	}
	if usage.InputTokens <= 0 && estimatedInputTokens > 0 {
		usage.InputTokens = estimatedInputTokens
	}
	if usage.OutputTokens <= 0 && (textBuf.Len()+reasonBuf.Len()) > 0 {
		usage.OutputTokens = max(1, (textBuf.Len()+reasonBuf.Len())/4)
	}

	text := textBuf.String()
	reasoning := reasonBuf.String()

	var doc any
	switch downProto {
	case ProtoAnthropicMessages:
		blocks := make([]map[string]any, 0, 2)
		if reasoning != "" {
			blocks = append(blocks, map[string]any{"type": "thinking", "thinking": reasoning})
		}
		blocks = append(blocks, map[string]any{"type": "text", "text": text})
		doc = map[string]any{
			"id":          "msg_qwq",
			"type":        "message",
			"role":        "assistant",
			"model":       reqModel,
			"content":     blocks,
			"stop_reason": "end_turn",
			"usage": map[string]any{
				"input_tokens":  usage.InputTokens,
				"output_tokens": usage.OutputTokens,
			},
		}
	case ProtoOpenAIResponses:
		doc = map[string]any{
			"id":          "resp_qwq",
			"object":      "response",
			"status":      "completed",
			"model":       reqModel,
			"output_text": text,
			"output": []map[string]any{{
				"type": "message",
				"role": "assistant",
				"content": []map[string]any{{
					"type": "output_text",
					"text": text,
				}},
			}},
			"usage": map[string]any{
				"input_tokens":  usage.InputTokens,
				"output_tokens": usage.OutputTokens,
				"total_tokens":  usage.InputTokens + usage.OutputTokens,
			},
		}
	case ProtoGeminiNative:
		parts := make([]map[string]any, 0, 2)
		if reasoning != "" {
			parts = append(parts, map[string]any{"text": reasoning, "thought": true})
		}
		parts = append(parts, map[string]any{"text": text})
		doc = map[string]any{
			"candidates": []map[string]any{{
				"content":      map[string]any{"role": "model", "parts": parts},
				"finishReason": "STOP",
			}},
			"usageMetadata": map[string]any{
				"promptTokenCount":     usage.InputTokens,
				"candidatesTokenCount": usage.OutputTokens,
				"totalTokenCount":      usage.InputTokens + usage.OutputTokens,
			},
		}
	default: // ProtoOpenAIChat
		msg := map[string]any{
			"role":    "assistant",
			"content": text,
		}
		if reasoning != "" {
			msg["reasoning_content"] = reasoning
		}
		doc = map[string]any{
			"id":      "chatcmpl-qwq",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   reqModel,
			"choices": []map[string]any{{
				"index":         0,
				"message":       msg,
				"finish_reason": "stop",
			}},
			"usage": map[string]any{
				"prompt_tokens":     usage.InputTokens,
				"completion_tokens": usage.OutputTokens,
				"total_tokens":      usage.InputTokens + usage.OutputTokens,
			},
		}
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		return usage, err
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, writeErr := w.Write(raw)
	return usage, writeErr
}
