// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
)

// ======================== 本人范围与角色权限两层守卫 ========================
// 网关只允许浏览器会话或服务账号，路由再检查当前角色与服务范围。
// 通过后仍由 Service 校验本人归属，他人会话保留 404；工具另走 operations 授权。

// agentSessionRoute 在读取后端、解析写入内容或启动模型前执行已有 RBAC。
// GET/HEAD 采用 read；其他已注册方法采用 write，避免新增路由漏掉写权限。
func (a *api) agentSessionRoute(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		act, err := a.caller(r)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		permission := "host.agent_sessions:write"
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			permission = "host.agent_sessions:read"
		}
		if err := a.authorize(r.Context(), act, permission, ""); err != nil {
			a.fail(w, r, err)
			return
		}
		next(w, r)
	}
}

// agentSessionDTO is the AgentSession schema.
type agentSessionDTO struct {
	SessionID        string          `json:"session_id"`
	PluginID         string          `json:"plugin_id"`
	Title            string          `json:"title"`
	Core             string          `json:"core"`
	PermissionMode   string          `json:"permission_mode"`
	Status           string          `json:"status"`
	Config           json.RawMessage `json:"config"`
	HasAPIKey        bool            `json:"has_api_key"`
	LastSeq          int64           `json:"last_seq"`
	PendingApprovals int             `json:"pending_approvals"`
	LastMessageAt    string          `json:"last_message_at,omitempty"`
	// LastMessagePreview is the head of the newest transcript entry (gap 6):
	// at most 120 characters of plain text, untrusted (model or plugin output).
	LastMessagePreview string `json:"last_message_preview,omitempty"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	Revision           string `json:"revision"`
}

// newAgentSessionDTO renders one session.
func newAgentSessionDTO(s *agentsession.Session) agentSessionDTO {
	out := agentSessionDTO{
		SessionID: s.ID, PluginID: s.PluginID, Title: s.Title, Core: string(s.Core),
		PermissionMode: string(s.PermissionMode), Status: string(s.Status), Config: s.Config,
		HasAPIKey: s.HasAPIKey(), LastSeq: s.LastSeq, PendingApprovals: s.Pending,
		LastMessagePreview: s.LastMessagePreview,
		CreatedAt:          ts(s.CreatedAt), UpdatedAt: ts(s.UpdatedAt), Revision: s.Revision,
	}
	if s.LastMessageAt != nil {
		out.LastMessageAt = ts(*s.LastMessageAt)
	}
	return out
}

// agentMessageDTO is the AgentSessionMessage schema.
type agentMessageDTO struct {
	Seq         int64           `json:"seq"`
	MessageID   string          `json:"message_id"`
	Role        string          `json:"role"`
	Content     string          `json:"content"`
	ContentJSON json.RawMessage `json:"content_json,omitempty"`
	OperationID string          `json:"operation_id,omitempty"`
	ApprovalID  string          `json:"approval_id,omitempty"`
	CreatedAt   string          `json:"created_at"`
}

func newAgentMessageDTO(m agentsession.Message) agentMessageDTO {
	return agentMessageDTO{
		Seq: m.Seq, MessageID: m.MessageID, Role: m.Role, Content: m.Content,
		ContentJSON: m.ContentJSON, OperationID: m.OperationID, ApprovalID: m.ApprovalID,
		CreatedAt: ts(m.CreatedAt),
	}
}

func newAgentMessageDTOs(in []agentsession.Message) []agentMessageDTO {
	out := make([]agentMessageDTO, 0, len(in))
	for _, m := range in {
		out = append(out, newAgentMessageDTO(m))
	}
	return out
}

// agentApprovalDTO is the AgentSessionApproval schema: the pending calls of a
// session with the plugin author's confirmation text (untrusted, ADR-0010 §4).
type agentApprovalDTO struct {
	CallID      string          `json:"call_id"`
	ApprovalID  string          `json:"approval_id"`
	OperationID string          `json:"operation_id,omitempty"`
	Action      string          `json:"action"`
	Args        json.RawMessage `json:"args,omitempty"`
	Summary     string          `json:"summary,omitempty"`
	Description string          `json:"description,omitempty"`
	Risk        string          `json:"risk,omitempty"`
	Approval    string          `json:"approval,omitempty"`
	Status      string          `json:"status"`
	Deadline    string          `json:"deadline,omitempty"`
	CreatedAt   string          `json:"created_at"`
}

func newAgentApprovalDTOs(in []agentsession.PendingApproval) []agentApprovalDTO {
	out := make([]agentApprovalDTO, 0, len(in))
	for _, a := range in {
		dto := agentApprovalDTO{
			CallID: a.CallID, ApprovalID: a.ApprovalID, OperationID: a.OperationID,
			Action: a.Action, Args: secrets.RedactArguments(a.Args), Summary: a.Summary, Description: a.Description,
			Risk: a.Risk, Approval: a.Approval, Status: string(a.Status), CreatedAt: ts(a.CreatedAt),
		}
		if a.Deadline != nil {
			dto.Deadline = ts(*a.Deadline)
		}
		out = append(out, dto)
	}
	return out
}

// agentSessionDetail is AgentSession plus its recent transcript and pending
// approvals (GET /agent-sessions/{id}).
type agentSessionDetail struct {
	agentSessionDTO
	Messages  []agentMessageDTO  `json:"messages"`
	Approvals []agentApprovalDTO `json:"approvals"`
}

// agentSessionCreateRequest is AgentSessionCreateRequest.
type agentSessionCreateRequest struct {
	Title          string          `json:"title"`
	Core           string          `json:"core"`
	PermissionMode string          `json:"permission_mode"`
	Config         json.RawMessage `json:"config"`
}

// agentSessionUpdateRequest is AgentSessionUpdateRequest.
type agentSessionUpdateRequest struct {
	Title            *string `json:"title"`
	PermissionMode   string  `json:"permission_mode"`
	ExpectedRevision string  `json:"expected_revision"`
}

// agentSessionAPIKeyRequest is AgentSessionAPIKeyRequest.
type agentSessionAPIKeyRequest struct {
	APIKey string `json:"api_key"`
}

// agentSendMessageRequest is AgentSendMessageRequest.
type agentSendMessageRequest struct {
	Content         string `json:"content"`
	ClientMessageID string `json:"client_message_id"`
}

// agentSendMessageResponse is AgentSendMessageResponse: the stored user message
// and the state of the session the turn was started for.
type agentSendMessageResponse struct {
	Session agentSessionDTO `json:"session"`
	Message agentMessageDTO `json:"message"`
}

// agentCancelRequest is AgentSessionCancelRequest (optional body).
type agentCancelRequest struct {
	Reason string `json:"reason"`
}

// agentApprovalList is AgentSessionApprovalList.
type agentApprovalList struct {
	Items []agentApprovalDTO `json:"items"`
}

// agentMessageList is the response of GET /agent-sessions/{id}/messages (gap 6).
type agentMessageList struct {
	Items []agentMessageDTO `json:"items"`
}

// agentSessions returns the service, or UNAVAILABLE if the host has none.
func (a *api) agentSessions() (*agentsession.Service, error) {
	if a.d.AgentSessions == nil {
		return nil, problem.New(problem.Unavailable, "The agent session backend is not available on this host.")
	}
	return a.d.AgentSessions, nil
}

// agentSessionID returns the validated path parameter of a session route.
func agentSessionID(r *http.Request) (string, error) {
	id := r.PathValue("session_id")
	if id == "" || len(id) > 128 {
		return "", problem.New(problem.NotFound, "No such agent session.")
	}
	return id, nil
}

// createAgentSession creates a session owned by the caller.
func (a *api) createAgentSession(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req agentSessionCreateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	mode, err := permissionMode(req.PermissionMode)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	rec, err := svc.Create(r.Context(), act, agentsession.CreateRequest{
		Title:          req.Title,
		Core:           agentsession.CoreName(req.Core),
		PermissionMode: mode,
		Config:         req.Config,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/agent-sessions/"+rec.ID)
	a.writeResource(w, r, http.StatusCreated, newAgentSessionDTO(rec), nil)
}

// listAgentSessions returns the caller's sessions, optionally only the ones
// that need attention (waiting_approval or failed).
func (a *api) listAgentSessions(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	page, err := svc.List(r.Context(), act, agentsession.ListFilter{
		Status:        r.URL.Query().Get("status"),
		SinceRevision: q.SinceRevision,
		Cursor:        q.Cursor,
		Limit:         q.Limit,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items := make([]any, 0, len(page.Items))
	for i := range page.Items {
		items = append(items, newAgentSessionDTO(&page.Items[i]))
	}
	a.writeList(w, r, listResponse{
		Items:      items,
		NextCursor: page.NextCursor,
		Revision:   page.Revision,
		Delta:      page.Delta,
	}, q.Fields)
}

// getAgentSession returns one session with its recent messages and pending
// approvals.
func (a *api) getAgentSession(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	rec, err := svc.Get(r.Context(), act, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	msgs, err := svc.Messages(r.Context(), act, id, 0)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	approvals, err := svc.PendingApprovals(r.Context(), act, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, agentSessionDetail{
		agentSessionDTO: newAgentSessionDTO(rec),
		Messages:        newAgentMessageDTOs(msgs),
		Approvals:       newAgentApprovalDTOs(approvals),
	}, fields)
}

// listAgentMessages returns one page of the session transcript, newest first
// (gap 6): the messages with seq < before_seq, at most limit (default the
// snapshot window, at most 200), oldest first. The owner is the only reader;
// another principal's session answers 404 like every other session route.
func (a *api) listAgentMessages(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	before, err := beforeSeq(r.URL.Query().Get("before_seq"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	q, err := a.g.ListQuery(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	limit := q.Limit
	if r.URL.Query().Get("limit") == "" {
		// Absent limit: the snapshot window of GET /agent-sessions/{id}.
		limit = 0
	}
	msgs, err := svc.MessagesBefore(r.Context(), act, id, before, limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, agentMessageList{Items: newAgentMessageDTOs(msgs)}, nil)
}

// beforeSeq parses the before_seq query parameter of the transcript page.
func beforeSeq(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return 0, problem.Validation(problem.Violation{
			In: "query", Pointer: "/before_seq", Code: "INVALID",
			Message: "before_seq must be a positive message sequence.",
		})
	}
	return n, nil
}

// updateAgentSession changes the title and/or the permission mode. Only the
// caller can change the mode; the agent core has no path to this handler, and a
// delegation token is rejected by the gateway.
func (a *api) updateAgentSession(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req agentSessionUpdateRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := parseExpectedRevision(req.ExpectedRevision); err != nil {
		a.fail(w, r, err)
		return
	}
	mode, err := permissionMode(req.PermissionMode)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	rec, err := svc.Update(r.Context(), act, id, agentsession.UpdateRequest{
		Title:            req.Title,
		PermissionMode:   mode,
		ExpectedRevision: req.ExpectedRevision,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newAgentSessionDTO(rec), fields)
}

// putAgentSessionAPIKey stores the native core's API key of a session
// (AGT-02). The answer is the session, which only shows has_api_key.
func (a *api) putAgentSessionAPIKey(w http.ResponseWriter, r *http.Request) {
	var req agentSessionAPIKeyRequest
	a.writeAgentSessionAPIKey(w, r, func(svc *agentsession.Service, act actor.Actor, id string) (*agentsession.Session, error) {
		if err := a.decodeJSON(r, &req); err != nil {
			return nil, err
		}
		return svc.SetAPIKey(r.Context(), act, id, req.APIKey)
	})
}

// deleteAgentSessionAPIKey removes the API key of a session.
func (a *api) deleteAgentSessionAPIKey(w http.ResponseWriter, r *http.Request) {
	a.writeAgentSessionAPIKey(w, r, func(svc *agentsession.Service, act actor.Actor, id string) (*agentsession.Session, error) {
		return svc.ClearAPIKey(r.Context(), act, id)
	})
}

// writeAgentSessionAPIKey is the shared shape of the api-key routes.
func (a *api) writeAgentSessionAPIKey(w http.ResponseWriter, r *http.Request,
	write func(*agentsession.Service, actor.Actor, string) (*agentsession.Session, error)) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	rec, err := write(svc, act, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newAgentSessionDTO(rec), nil)
}

// deleteAgentSession closes a session and removes its transcript.
func (a *api) deleteAgentSession(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if raw := r.URL.Query().Get("expected_revision"); raw != "" {
		rec, err := svc.Get(r.Context(), act, id)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if raw != rec.Revision {
			a.fail(w, r, problem.Conflict(rec.Revision))
			return
		}
	}
	if err := svc.Delete(r.Context(), act, id); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sendAgentMessage appends a user message and starts the turn that answers it.
func (a *api) sendAgentMessage(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req agentSendMessageRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := svc.Send(r.Context(), act, id, agentsession.SendRequest{
		Content:         req.Content,
		ClientMessageID: req.ClientMessageID,
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	msg := res.Message
	w.Header().Set("Location", "/api/v1/agent-sessions/"+id+"/events")
	a.writeResource(w, r, http.StatusCreated, agentSendMessageResponse{
		Session: newAgentSessionDTO(&res.Session),
		Message: newAgentMessageDTO(msg),
	}, nil)
}

// cancelAgentSession cancels the running turn or a paused approval turn.
func (a *api) cancelAgentSession(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req agentCancelRequest
	if err := a.decodeOptionalJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	rec, err := svc.Cancel(r.Context(), act, id, req.Reason)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, newAgentSessionDTO(rec), fields)
}

// listAgentApprovals returns the pending approvals of one session.
func (a *api) listAgentApprovals(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items, err := svc.PendingApprovals(r.Context(), act, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, agentApprovalList{Items: newAgentApprovalDTOs(items)}, nil)
}

// agentSSE is the session event stream writer. It mirrors the gateway's SSE
// framing: domain events are unnamed frames whose `id` is the session seq, and
// ready/heartbeat/resync are named control frames.
type agentSSE struct {
	w   http.ResponseWriter
	rc  *http.ResponseController
	err error
}

// event writes one session event.
func (s *agentSSE) event(e agentsession.Event) {
	if s.err != nil {
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		s.err = err
		return
	}
	s.err = s.write(fmt.Sprintf("id: %d\ndata: %s\n\n", e.Seq, data))
}

// control writes one named frame.
func (s *agentSSE) control(event string, payload any) {
	if s.err != nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		s.err = err
		return
	}
	s.err = s.write(fmt.Sprintf("event: %s\ndata: %s\n\n", event, data))
}

// ready announces the stream and the reconnect delay.
func (s *agentSSE) ready(payload any) {
	if s.err != nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		s.err = err
		return
	}
	s.err = s.write(fmt.Sprintf("retry: %d\nevent: ready\ndata: %s\n\n", agentSSERetryMS, data))
}

func (s *agentSSE) write(frame string) error {
	if _, err := s.w.Write([]byte(frame)); err != nil {
		return err
	}
	return s.rc.Flush()
}

// SSETiming of the session stream.
const (
	agentSSERetryMS = 3000
)

// agentStreamReady is the `event: ready` payload.
type agentStreamReady struct {
	HeadSequence     int64 `json:"head_sequence"`
	HeartbeatSeconds int   `json:"heartbeat_seconds"`
}

// agentStreamResync is the `event: resync` payload.
type agentStreamResync struct {
	Reason       string `json:"reason"`
	HeadSequence int64  `json:"head_sequence"`
}

// agentStreamHeartbeat is the `event: heartbeat` payload.
type agentStreamHeartbeat struct {
	HeadSequence int64  `json:"head_sequence"`
	ServerTime   string `json:"server_time"`
}

// streamAgentSession serves GET /api/v1/agent-sessions/{id}/events.
func (a *api) streamAgentSession(w http.ResponseWriter, r *http.Request) {
	svc, err := a.agentSessions()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id, err := agentSessionID(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	after, err := agentResumeSeq(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sub, err := svc.Subscribe(r.Context(), act, id, after)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	defer sub.Close()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	rc, done := gateway.PrepareStream(w)
	defer done()
	_ = rc.Flush()
	sw := &agentSSE{w: w, rc: rc}
	head := sub.Head
	heartbeatSeconds := int((svc.Heartbeat() + time.Second - 1) / time.Second)
	if heartbeatSeconds < 1 {
		heartbeatSeconds = 1
	}
	if sub.Resync {
		sw.control("resync", agentStreamResync{Reason: sub.Reason, HeadSequence: head})
	}
	sw.ready(agentStreamReady{HeadSequence: head, HeartbeatSeconds: heartbeatSeconds})
	for _, e := range sub.Replay {
		sw.event(e)
		if e.Seq > head {
			head = e.Seq
		}
	}
	if sw.err != nil {
		return
	}
	heartbeat := time.NewTicker(svc.Heartbeat())
	defer heartbeat.Stop()
	for {
		select {
		case e, ok := <-sub.Events:
			if !ok {
				if sub.Overflowed() {
					sw.control("resync", agentStreamResync{Reason: "buffer_overflow", HeadSequence: head})
				}
				return
			}
			if e.Seq > head {
				head = e.Seq
			}
			sw.event(e)
			if sw.err != nil {
				return
			}
		case <-heartbeat.C:
			sw.control("heartbeat", agentStreamHeartbeat{
				HeadSequence: head, ServerTime: ts(a.d.Clock.Now()),
			})
			if sw.err != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

// agentResumeSeq parses Last-Event-ID (or last_event_id) of a session stream; -1
// means "start live".
func agentResumeSeq(r *http.Request) (int64, error) {
	raw := r.Header.Get("Last-Event-ID")
	fromQuery := false
	if raw == "" {
		raw = r.URL.Query().Get("last_event_id")
		fromQuery = true
	}
	if raw == "" {
		return -1, nil
	}
	n, ok := gateway.ParseSequence(raw)
	if !ok {
		in := "header"
		pointer := "/Last-Event-ID"
		if fromQuery {
			in, pointer = "query", "/last_event_id"
		}
		return 0, problem.Validation(problem.Violation{
			In: in, Pointer: pointer, Code: "INVALID",
			Message: "The resume position must be a decimal session sequence.",
		})
	}
	return n, nil
}

// permissionMode validates a permission mode from a request body. The empty
// value keeps the session default; an unknown value is a validation error and
// never reaches the session row.
func permissionMode(raw string) (operations.PermissionMode, error) {
	if raw == "" {
		return "", nil
	}
	mode := operations.PermissionMode(raw)
	if !mode.Valid() || mode == "" {
		return "", problem.Validation(problem.Violation{
			Pointer: "/permission_mode", Code: "INVALID",
			Message: "permission_mode must be read_only, safe, full or custom.",
		})
	}
	return mode, nil
}
