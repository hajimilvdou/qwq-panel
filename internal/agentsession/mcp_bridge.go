// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// MCPBridge exposes qwq's host ToolCatalog (backed by internal/agentapi and
// operations.Run) as a standard Model Context Protocol (MCP) tool server.
//
// Security invariant:
//   - Codex, OpenCode and DSH never receive raw root shell privileges to modify
//     the host. Every panel operation runs through MCPBridge -> turn.Runner ->
//     operations.Run under the session's authoritative PermissionMode and RBAC.
//   - Read-only / Plan Mode filters out non-read tools from tools/list AND
//     re-checks on every tools/call (visibility != authorization).
type MCPBridge struct {
	turn     Turn
	planMode bool
	names    toolNames
	emit     Emit
	bridge   ApprovalBridge
}

// MCPToolDef matches the MCP tools/list item schema.
type MCPToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// MCPCallResult matches the MCP tools/call response payload.
type MCPCallResult struct {
	Content []MCPContentBlock `json:"content"`
	IsError bool              `json:"isError,omitempty"`
}

// MCPContentBlock is one text item inside an MCP tool result.
type MCPContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// NewMCPBridge constructs a session-scoped bridge for one external agent turn.
func NewMCPBridge(turn Turn, planMode bool, emit Emit, bridge ApprovalBridge) *MCPBridge {
	return &MCPBridge{
		turn:     turn,
		planMode: planMode,
		names:    newToolNames(turn.Tools),
		emit:     emit,
		bridge:   bridge,
	}
}

// HandleRequest dispatches MCP JSON-RPC methods (`initialize`, `tools/list`,
// `tools/call`) arriving over stdio or UDS from Codex, OpenCode or DSH.
func (m *MCPBridge) HandleRequest(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "qwq-host-mcp-bridge", "version": "1.0.0"},
		}, nil

	case "tools/list":
		return map[string]any{"tools": m.ListTools()}, nil

	case "tools/call":
		var req struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, problem.New(problem.ValidationFailed, "Malformed MCP tools/call params.")
		}
		return m.CallTool(ctx, req.Name, req.Arguments)

	default:
		return nil, problem.New(problem.NotFound, "Unsupported MCP method %q.", method)
	}
}

// ListTools returns the MCP tool definitions allowed under the current mode.
func (m *MCPBridge) ListTools() []MCPToolDef {
	readOnly := m.turn.PermissionMode == operations.PermissionReadOnly || m.planMode
	out := make([]MCPToolDef, 0, len(m.turn.Tools))
	for _, spec := range m.turn.Tools {
		if readOnly && !isReadOnlyTool(spec) {
			continue
		}
		schema := spec.Parameters
		if len(schema) == 0 || !json.Valid(schema) {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		desc := strings.TrimSpace(spec.Summary)
		if spec.Description != "" {
			if desc != "" {
				desc += " — "
			}
			desc += spec.Description
		}
		out = append(out, MCPToolDef{
			Name:        m.names.name(spec.Action),
			Description: desc,
			InputSchema: schema,
		})
	}
	return out
}

// CallTool executes one host action through turn.Runner, publishing standard
// qwq tool_call / approval_required / tool_result events along the way.
func (m *MCPBridge) CallTool(ctx context.Context, toolName string, rawArgs json.RawMessage) (MCPCallResult, error) {
	spec, ok := m.names.byName[toolName]
	if !ok {
		return mcpErrorResult(fmt.Sprintf("Unknown host tool %q.", toolName)), nil
	}
	if m.turn.PermissionMode == operations.PermissionReadOnly || m.planMode {
		if !isReadOnlyTool(spec) {
			return mcpErrorResult(fmt.Sprintf(
				"Denied: session is in read-only/plan mode and cannot invoke %q (effect=%s).",
				spec.Action, spec.Effect,
			)), nil
		}
	}
	if m.turn.Runner == nil {
		return mcpErrorResult("Host tool runner is unavailable."), nil
	}
	if len(rawArgs) == 0 {
		rawArgs = json.RawMessage(`{}`)
	}
	if !json.Valid(rawArgs) {
		return mcpErrorResult("Tool arguments must be valid JSON."), nil
	}

	callID := "mcp_" + toolName
	if m.turn.NextCallID != nil {
		callID = m.turn.NextCallID()
	}

	if m.emit != nil {
		_ = m.emit(Event{
			Type:      EventToolCall,
			SessionID: m.turn.SessionID,
			CallID:    callID,
			Action:    spec.Action,
			Args:      rawArgs,
			Risk:      spec.Risk,
		})
	}

	res, err := m.turn.Runner.RunTool(operations.WithPermissionMode(ctx, m.turn.PermissionMode), ToolCall{
		CallID:         callID,
		SessionID:      m.turn.SessionID,
		PermissionMode: m.turn.PermissionMode,
		Action:         spec.Action,
		Args:           rawArgs,
	})
	if err != nil {
		pe := problem.From(err)
		m.emitResult(callID, spec.Action, ToolFailed, "", "", nil, ErrorOf(pe))
		return mcpErrorResult(pe.Detail), nil
	}

	if res.Status == ToolAwaitingApproval {
		if res.ApprovalID == "" {
			return mcpErrorResult("Host refused to queue approval without an approval_id."), nil
		}
		if m.emit != nil {
			ev := Event{
				Type:        EventApprovalRequired,
				SessionID:   m.turn.SessionID,
				CallID:      callID,
				Action:      spec.Action,
				Args:        rawArgs,
				ApprovalID:  res.ApprovalID,
				OperationID: res.OperationID,
				Risk:        spec.Risk,
				Approval:    spec.Approval,
				Summary:     spec.Summary,
				Description: spec.Description,
			}
			if res.Approval != nil {
				if res.Approval.Summary != "" {
					ev.Summary = res.Approval.Summary
				}
				if res.Approval.Description != "" {
					ev.Description = res.Approval.Description
				}
				ev.Deadline = res.Approval.Deadline
			}
			_ = m.emit(ev)
		}
		if m.bridge == nil {
			// Fail closed if no human approval bridge is wired.
			m.emitResult(callID, spec.Action, ToolRejected, res.OperationID, res.ApprovalID, nil,
				&ErrorInfo{Code: problem.Unavailable, Detail: "Human approval bridge is not available."})
			return mcpErrorResult("Approval required but no approval bridge is wired; action denied."), nil
		}
		dec, waitErr := m.bridge.Wait(ctx, res.ApprovalID)
		if waitErr != nil {
			m.emitResult(callID, spec.Action, ToolCancelled, res.OperationID, res.ApprovalID, nil, ErrorOf(problem.From(waitErr)))
			return mcpErrorResult("Approval wait cancelled or timed out."), nil
		}
		if m.emit != nil {
			_ = m.emit(Event{
				Type:       EventApprovalDecided,
				SessionID:  m.turn.SessionID,
				CallID:     callID,
				ApprovalID: res.ApprovalID,
				Decision:   dec.Decision,
				Comment:    dec.Comment,
			})
		}
		if dec.Decision != DecisionApprove {
			m.emitResult(callID, spec.Action, ToolRejected, res.OperationID, res.ApprovalID, nil,
				&ErrorInfo{Code: problem.PermissionDenied, Detail: "Rejected by administrator: " + dec.Comment})
			return mcpErrorResult("Rejected by administrator."), nil
		}
		res.Status = dec.Status
		if res.Status == "" {
			res.Status = ToolSucceeded
		}
		res.Result = dec.Result
		res.Error = dec.Error
	}

	m.emitResult(callID, spec.Action, res.Status, res.OperationID, res.ApprovalID, res.Result, ErrorOf(res.Error))
	if res.Status != ToolSucceeded {
		msg := "Host tool failed."
		if res.Error != nil && res.Error.Detail != "" {
			msg = res.Error.Detail
		}
		return mcpErrorResult(msg), nil
	}
	text := string(res.Result)
	if text == "" {
		text = `{"ok":true}`
	}
	return MCPCallResult{Content: []MCPContentBlock{{Type: "text", Text: text}}}, nil
}

func (m *MCPBridge) emitResult(callID, action string, status ToolStatus, opID, aprID string, result json.RawMessage, errInfo *ErrorInfo) {
	if m.emit == nil {
		return
	}
	_ = m.emit(Event{
		Type:        EventToolResult,
		SessionID:   m.turn.SessionID,
		CallID:      callID,
		Action:      action,
		Status:      string(status),
		OperationID: opID,
		ApprovalID:  aprID,
		Result:      result,
		Error:       errInfo,
	})
}

func isReadOnlyTool(spec ToolSpec) bool {
	return strings.EqualFold(spec.Effect, "read") && !strings.EqualFold(spec.Risk, "high")
}

func mcpErrorResult(msg string) MCPCallResult {
	return MCPCallResult{
		IsError: true,
		Content: []MCPContentBlock{{Type: "text", Text: msg}},
	}
}

const (
	maxMCPBodyBytes       = 256 << 10 // 256 KiB hard body ceiling (+1 overflow check)
	maxMCPJSONDepth       = 32
	maxMCPConcurrentCalls = 4
	mcpShutdownGrace      = 500 * time.Millisecond
)

// LoopbackMCPServer exposes MCPBridge on an ephemeral 127.0.0.1:0 HTTP JSON-RPC
// endpoint guarded by a per-turn 256-bit random bearer token, strict JSON depth
// & duplicate-key validation, bounded concurrency, and turn-linked cancellation
// so external CLIs (Claude Code, Codex, OpenCode, DSH/ACP) can invoke qwq panel
// actions through Runner and operations.Run without raw host privileges.
type LoopbackMCPServer struct {
	URL       string
	Token     string
	srv       *http.Server
	ln        net.Listener
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// StartLoopbackMCPServer binds 127.0.0.1:0 with a background parent context.
func StartLoopbackMCPServer(bridge *MCPBridge) (*LoopbackMCPServer, error) {
	return StartLoopbackMCPServerWithContext(context.Background(), bridge)
}

// StartLoopbackMCPServerWithContext binds 127.0.0.1:0 and ties every active
// handler context to parentCtx so cancelling the turn or calling Close()
// immediately interrupts in-flight tool calls and reclaims sockets/FDs.
func StartLoopbackMCPServerWithContext(parentCtx context.Context, bridge *MCPBridge) (*LoopbackMCPServer, error) {
	if bridge == nil {
		return nil, problem.New(problem.Internal, "nil MCPBridge")
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	var tokBytes [32]byte
	if _, err := rand.Read(tokBytes[:]); err != nil {
		return nil, problem.Wrap(err)
	}
	token := hex.EncodeToString(tokBytes[:])

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, problem.Wrap(err)
	}

	serverCtx, serverCancel := context.WithCancel(parentCtx)
	sem := make(chan struct{}, maxMCPConcurrentCalls)

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			writeMCPRPCError(w, http.StatusTooManyRequests, nil, -32029, "Too many concurrent MCP calls.")
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPBodyBytes+1))
		if err != nil {
			writeMCPRPCError(w, http.StatusBadRequest, nil, -32700, "Failed to read MCP request body.")
			return
		}
		if len(body) > maxMCPBodyBytes {
			writeMCPRPCError(w, http.StatusRequestEntityTooLarge, nil, -32600, "MCP request body exceeds 256 KiB limit.")
			return
		}
		if err := validateStrictMCPJSON(body, maxMCPJSONDepth); err != nil {
			writeMCPRPCError(w, http.StatusBadRequest, nil, -32600, err.Error())
			return
		}

		var env rpcEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			writeMCPRPCError(w, http.StatusBadRequest, nil, -32700, "Malformed JSON-RPC envelope.")
			return
		}
		// Clear the server's 10s ReadTimeout once the request body is read so
		// long-running human approval waits never disconnect the MCP client.
		_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
		res, callErr := bridge.HandleRequest(r.Context(), env.Method, env.Params)
		w.Header().Set("Content-Type", "application/json")
		resp := rpcEnvelope{JSONRPC: "2.0", ID: env.ID}
		if callErr != nil {
			resp.Error = &rpcError{Code: -32000, Message: callErr.Error()}
		} else {
			resp.Result, _ = json.Marshal(res)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      0, // Approval waits can exceed 30s; per-request ctx bounds handler lifetime.
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return serverCtx },
	}
	go func() { _ = srv.Serve(ln) }()

	s := &LoopbackMCPServer{
		URL:    "http://" + ln.Addr().String() + "/mcp",
		Token:  token,
		srv:    srv,
		ln:     ln,
		cancel: serverCancel,
	}
	go func() {
		<-serverCtx.Done()
		_ = s.Close()
	}()
	return s, nil
}

func writeMCPRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(rpcEnvelope{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	})
}

// validateStrictMCPJSON enforces valid single-document JSON with bounded
// nesting depth and zero duplicate object keys at any nesting level.
func validateStrictMCPJSON(raw []byte, maxDepth int) error {
	if !json.Valid(raw) {
		return errors.New("invalid JSON document")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := validateJSONValue(dec, 0, maxDepth); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

func validateJSONValue(dec *json.Decoder, depth, maxDepth int) error {
	tok, err := dec.Token()
	if err != nil {
		return errors.New("unexpected end of JSON document")
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	nextDepth := depth + 1
	if nextDepth > maxDepth {
		return fmt.Errorf("JSON nesting depth exceeds limit %d", maxDepth)
	}
	switch d {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return errors.New("expected object key")
			}
			key, ok := keyTok.(string)
			if !ok {
				return errors.New("non-string object key")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(dec, nextDepth, maxDepth); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errors.New("unclosed JSON object")
		}
	case '[':
		for dec.More() {
			if err := validateJSONValue(dec, nextDepth, maxDepth); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errors.New("unclosed JSON array")
		}
	}
	return nil
}

// Close cancels every active handler context, attempts a brief graceful
// shutdown, and unconditionally force-closes the server to reclaim sockets/FDs.
func (s *LoopbackMCPServer) Close() error {
	if s == nil || s.srv == nil {
		return nil
	}
	var closeErr error
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		ctx, cancel := context.WithTimeout(context.Background(), mcpShutdownGrace)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
		closeErr = s.srv.Close()
	})
	return closeErr
}
