// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type anthropicBlockKind int

const (
	blockNone anthropicBlockKind = iota
	blockThinking
	blockText
)

// AnthropicSSEStateMachine 严格符合 Anthropic Messages 规范的多内容块 SSE 发射器：
// 按到达顺序动态开启/关闭 thinking、text、tool_use 独立内容块并递增 index，
// 防止将 thinking_delta 与 text_delta 混发至同一个 index:0 导致 Claude SDK 断流。
type AnthropicSSEStateMachine struct {
	w           io.Writer
	model       string
	startedMsg  bool
	activeKind  anthropicBlockKind
	nextIndex   int
	activeIndex int
	err         error
}

// NewAnthropicSSEStateMachine 构造 Anthropic Messages SSE 状态机。
func NewAnthropicSSEStateMachine(w io.Writer, model string) *AnthropicSSEStateMachine {
	return &AnthropicSSEStateMachine{w: w, model: model}
}

// Err 返回流写出过程中捕获到的首个下游 I/O 错误。
func (m *AnthropicSSEStateMachine) Err() error {
	if m == nil {
		return nil
	}
	return m.err
}

func (m *AnthropicSSEStateMachine) printf(format string, args ...any) {
	if m.err != nil {
		return
	}
	if _, err := fmt.Fprintf(m.w, format, args...); err != nil {
		m.err = err
	}
}

func (m *AnthropicSSEStateMachine) writeString(s string) {
	if m.err != nil {
		return
	}
	if _, err := io.WriteString(m.w, s); err != nil {
		m.err = err
	}
}

// Started 返回是否已发射过 message_start。
func (m *AnthropicSSEStateMachine) Started() bool {
	return m != nil && m.startedMsg
}

func (m *AnthropicSSEStateMachine) ensureMessageStart(inputTokens int) {
	if m.startedMsg || m.err != nil {
		return
	}
	m.startedMsg = true
	m.printf(
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_qwq\",\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":%d,\"output_tokens\":0}}}\n\n",
		m.model,
		max(inputTokens, 0),
	)
}

func (m *AnthropicSSEStateMachine) switchBlock(target anthropicBlockKind) {
	if m.activeKind == target || m.err != nil {
		return
	}
	if m.activeKind != blockNone {
		m.printf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", m.activeIndex)
	}
	if target == blockNone {
		m.activeKind = blockNone
		return
	}
	idx := m.nextIndex
	m.nextIndex++
	m.activeIndex = idx
	m.activeKind = target

	switch target {
	case blockThinking:
		m.printf("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n", idx)
	case blockText:
		m.printf("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n", idx)
	}
}

// EmitDelta 按顺序安全发射思考流与正文流，自动完成块切换与索引递增。
func (m *AnthropicSSEStateMachine) EmitDelta(inputTokens int, reasoningDelta, textDelta string) {
	if (reasoningDelta == "" && textDelta == "") || m.err != nil {
		return
	}
	m.ensureMessageStart(inputTokens)
	if reasoningDelta != "" {
		m.switchBlock(blockThinking)
		chunk, _ := json.Marshal(map[string]any{
			"type":  "content_block_delta",
			"index": m.activeIndex,
			"delta": map[string]string{"type": "thinking_delta", "thinking": reasoningDelta},
		})
		m.printf("event: content_block_delta\ndata: %s\n\n", chunk)
	}
	if textDelta != "" {
		m.switchBlock(blockText)
		chunk, _ := json.Marshal(map[string]any{
			"type":  "content_block_delta",
			"index": m.activeIndex,
			"delta": map[string]string{"type": "text_delta", "text": textDelta},
		})
		m.printf("event: content_block_delta\ndata: %s\n\n", chunk)
	}
}

// EmitToolUseBlock 完整转发跨协议工具调用块。
func (m *AnthropicSSEStateMachine) EmitToolUseBlock(inputTokens int, toolCallID, toolName, argsJSON string) {
	if toolName == "" || m.err != nil {
		return
	}
	m.ensureMessageStart(inputTokens)
	m.switchBlock(blockNone)
	idx := m.nextIndex
	m.nextIndex++
	if toolCallID == "" {
		toolCallID = fmt.Sprintf("toolu_qwq_%d", idx)
	}
	startPayload, _ := json.Marshal(map[string]any{
		"type":  "content_block_start",
		"index": idx,
		"content_block": map[string]any{
			"type":  "tool_use",
			"id":    toolCallID,
			"name":  toolName,
			"input": map[string]any{},
		},
	})
	m.printf("event: content_block_start\ndata: %s\n\n", startPayload)
	if strings.TrimSpace(argsJSON) != "" {
		deltaPayload, _ := json.Marshal(map[string]any{
			"type":  "content_block_delta",
			"index": idx,
			"delta": map[string]string{"type": "input_json_delta", "partial_json": argsJSON},
		})
		m.printf("event: content_block_delta\ndata: %s\n\n", deltaPayload)
	}
	m.printf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", idx)
}

// Finish 关闭活动块并输出 message_delta / message_stop 终止事件。
func (m *AnthropicSSEStateMachine) Finish(inputTokens, outputTokens int, stopReason string) {
	if m.err != nil {
		return
	}
	m.ensureMessageStart(inputTokens)
	if m.activeKind == blockNone && m.nextIndex == 0 {
		m.switchBlock(blockText)
	}
	m.switchBlock(blockNone)
	if stopReason == "" {
		stopReason = "end_turn"
	}
	msgDelta, _ := json.Marshal(map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
		"usage": map[string]int{"output_tokens": max(outputTokens, 0)},
	})
	m.printf("event: message_delta\ndata: %s\n\n", msgDelta)
	m.writeString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}
