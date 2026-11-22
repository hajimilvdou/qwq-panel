// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// JSON-RPC 2.0 bidirectional stdio transport shared by:
//   - OpenAI Codex (`codex app-server`)
//   - DeepSeek Harness (`dsh acp`)
//   - OpenCode (`opencode acp`)
//   - Generic ACP agents (`adapter_acp_generic.go`)
//
// Unlike one-way stdin/stdout encoders, modern agents issue server-to-client
// requests mid-turn (e.g., execCommandApproval, applyPatchApproval,
// session/request_permission, mcp/tools/call). JSONRPCConn handles both
// client-initiated requests and server-initiated callbacks concurrently.

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// RPCNotificationHandler handles incoming server-to-client notifications.
type RPCNotificationHandler func(ctx context.Context, method string, params json.RawMessage) error

// RPCRequestHandler handles incoming server-to-client requests (such as
// bidirectional approvals or host MCP tool calls) and returns a JSON-serializable
// result or an error.
type RPCRequestHandler func(ctx context.Context, method string, params json.RawMessage) (any, error)

// JSONRPCConn manages one newline-delimited JSON-RPC 2.0 stream.
type JSONRPCConn struct {
	w        io.Writer
	writeMu  sync.Mutex
	nextID   atomic.Int64
	pendingM sync.Mutex
	pending  map[string]chan rpcEnvelope

	onNotify  RPCNotificationHandler
	onRequest RPCRequestHandler

	done chan struct{}
	err  error
}

// NewJSONRPCConn starts reading NDJSON frames from r and writes frames to w.
func NewJSONRPCConn(ctx context.Context, r io.Reader, w io.Writer, onNotify RPCNotificationHandler, onRequest RPCRequestHandler) *JSONRPCConn {
	c := &JSONRPCConn{
		w:         w,
		pending:   map[string]chan rpcEnvelope{},
		onNotify:  onNotify,
		onRequest: onRequest,
		done:      make(chan struct{}),
	}
	go c.readLoop(ctx, r)
	return c
}

// Call sends a JSON-RPC request and waits for its matching response.
func (c *JSONRPCConn) Call(ctx context.Context, method string, params any, out any) error {
	idNum := c.nextID.Add(1)
	idRaw := json.RawMessage(fmt.Sprintf("%d", idNum))
	idKey := string(idRaw)

	var pRaw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return problem.Wrap(err)
		}
		pRaw = b
	}

	ch := make(chan rpcEnvelope, 1)
	c.pendingM.Lock()
	c.pending[idKey] = ch
	c.pendingM.Unlock()

	defer func() {
		c.pendingM.Lock()
		delete(c.pending, idKey)
		c.pendingM.Unlock()
	}()

	if err := c.writeFrame(rpcEnvelope{
		JSONRPC: "2.0",
		ID:      idRaw,
		Method:  method,
		Params:  pRaw,
	}); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		if c.err != nil {
			return c.err
		}
		return problem.New(problem.Unavailable, "External agent JSON-RPC stream closed unexpectedly.")
	case resp := <-ch:
		if resp.Error != nil {
			return problem.New(problem.PluginError, "%s", resp.Error.Error())
		}
		if out != nil && len(resp.Result) > 0 {
			if err := json.Unmarshal(resp.Result, out); err != nil {
				return problem.New(problem.PluginError, "External agent returned malformed JSON-RPC result: %v", err)
			}
		}
		return nil
	}
}

// Notify sends a one-way JSON-RPC notification (no id, no response).
func (c *JSONRPCConn) Notify(method string, params any) error {
	var pRaw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return problem.Wrap(err)
		}
		pRaw = b
	}
	return c.writeFrame(rpcEnvelope{JSONRPC: "2.0", Method: method, Params: pRaw})
}

// Done closes when the underlying reader reaches EOF or errors.
func (c *JSONRPCConn) Done() <-chan struct{} { return c.done }

// Err returns the reader termination error after Done closes.
func (c *JSONRPCConn) Err() error { return c.err }

func (c *JSONRPCConn) writeFrame(env rpcEnvelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = c.w.Write(raw)
	return err
}

func (c *JSONRPCConn) readLoop(ctx context.Context, r io.Reader) {
	defer close(c.done)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxCLILine)

	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var env rpcEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			// Skip non-JSON banner lines safely rather than crashing on startup logs.
			continue
		}
		hasID := len(bytes.TrimSpace(env.ID)) > 0 && string(bytes.TrimSpace(env.ID)) != "null"

		switch {
		case env.Method != "" && hasID:
			// Server-to-client request (e.g. approval or MCP tool call): handle asynchronously
			// so reading notifications does not deadlock while awaiting human approval.
			reqEnv := env
			go c.handleServerRequest(ctx, reqEnv)

		case env.Method != "":
			if c.onNotify != nil {
				if err := c.onNotify(ctx, env.Method, env.Params); err != nil {
					c.err = err
					return
				}
			}

		case hasID:
			trimmed := bytes.TrimSpace(env.ID)
			c.pendingM.Lock()
			ch, ok := c.pending[string(trimmed)]
			c.pendingM.Unlock()
			if ok {
				select {
				case ch <- env:
				default:
				}
			}
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		c.err = err
	}
}

func (c *JSONRPCConn) handleServerRequest(ctx context.Context, env rpcEnvelope) {
	if c.onRequest == nil {
		_ = c.writeFrame(rpcEnvelope{
			JSONRPC: "2.0",
			ID:      env.ID,
			Error:   &rpcError{Code: -32601, Message: "method not handled by qwq host"},
		})
		return
	}
	res, err := c.onRequest(ctx, env.Method, env.Params)
	if err != nil {
		_ = c.writeFrame(rpcEnvelope{
			JSONRPC: "2.0",
			ID:      env.ID,
			Error:   &rpcError{Code: -32000, Message: err.Error()},
		})
		return
	}
	raw, mErr := json.Marshal(res)
	if mErr != nil {
		raw = json.RawMessage(`{}`)
	}
	_ = c.writeFrame(rpcEnvelope{
		JSONRPC: "2.0",
		ID:      env.ID,
		Result:  raw,
	})
}
