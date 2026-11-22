// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · Agent 会话与原生核心脚本（缺口 2 / 6）
 * --------------------------------------------------------------------------
 * native 核心按脚本回放：message.delta → tool_call → (approval_required → 决定)
 *   → tool_result → message.delta → message.completed → turn.completed
 * 消息里提到"防火墙"→ 提议开启防火墙（可达性审批）；提到"用户/账号"→ 创建用户；
 * 其他 → 读一次 CPU 再回答。外部三核心 available=false。
 * 会话状态变化同时发到全局流 agent.session.updated / attention（只给 owner）。
 * ========================================================================== */
import { checkRevision, created, invalid, MockProblem, noContent, notFound, ok, requireString, type Ctx, type RouteSpec, type S } from '../http.ts';
import { MONITOR, SECURITY, AGENT } from '../catalog.ts';
import { changed, later, newId, nowIso, publish, rev, runOperation, type AgentSessionRow, type Db } from '../store.ts';
import { pushSessionEvent, streamSession } from '../events.ts';
import { widgetResult } from '../widgets.ts';

const MODES: S['PermissionMode'][] = ['read_only', 'safe', 'full', 'custom'];

function own(ctx: Ctx): AgentSessionRow {
  const s = ctx.db.agentSessions.get(ctx.params.id!);
  if (!s || s.owner_id !== ctx.user!.user_id) throw notFound('会话');
  return s;
}

const strip = ({ owner_id: _o, turn: _t, ...s }: AgentSessionRow) => s;

/** 绑定到当前一轮的定时回调：取消（turn 变化）后自动失效 */
function step(db: Db, s: AgentSessionRow, ms: number, fn: () => void) {
  const turn = s.turn ?? 0;
  later(db, ms, () => {
    if ((s.turn ?? 0) === turn && db.agentSessions.has(s.session_id)) fn();
  });
}

/** 状态变化：更新行、发 resource.changed + agent.session.updated（+attention） */
function setStatus(db: Db, s: AgentSessionRow, status: S['AgentSessionStatus'], extra: { approval_id?: string; operation_id?: string } = {}) {
  const previous = s.status;
  s.status = status;
  s.updated_at = nowIso();
  s.revision = rev(db);
  const subject = `agent_sessions/${s.session_id}`;
  const actor = { kind: 'ai_agent' as const, id: 'agt_native', on_behalf_of: s.owner_id, display_name: 'AI 助手' };
  changed(db, subject, 'update', actor, { revision: s.revision, ownerId: s.owner_id, pointers: ['/status'] });
  publish(db, 'agent.session.updated', subject, { session_id: s.session_id, status, previous_status: previous, pending_approvals: s.pending_approvals, last_seq: s.last_seq, last_message_at: s.last_message_at, revision: s.revision }, { actor, ownerId: s.owner_id });
  if (status === 'waiting_approval' || status === 'failed') {
    publish(db, 'agent.session.attention', subject, { session_id: s.session_id, status, ...extra, revision: s.revision }, { actor, ownerId: s.owner_id });
  }
}

function addMessage(db: Db, s: AgentSessionRow, m: Omit<S['AgentSessionMessage'], 'seq' | 'created_at'>): S['AgentSessionMessage'] {
  const list = db.agentMessages.get(s.session_id) ?? [];
  db.agentMessages.set(s.session_id, list);
  const msg = { ...m, seq: (list.at(-1)?.seq ?? 0) + 1, created_at: nowIso() };
  list.push(msg);
  s.last_message_at = msg.created_at;
  s.last_message_preview = msg.content.slice(0, 120);
  return msg;
}

/** 把一段文字按 delta 回放，结束后存成完整消息 */
function speak(db: Db, s: AgentSessionRow, text: string, startMs: number): number {
  const id = newId('msg');
  const chunks = text.match(/.{1,6}/gsu) ?? [text];
  chunks.forEach((c, i) => step(db, s, startMs + i * 60, () => pushSessionEvent(db, s.session_id, { type: 'message.delta', message_id: id, delta: c })));
  const end = startMs + chunks.length * 60;
  step(db, s, end, () => {
    addMessage(db, s, { message_id: id, role: 'assistant', content: text });
    pushSessionEvent(db, s.session_id, { type: 'message.completed', message_id: id });
  });
  return end + 50;
}

function finishTurn(db: Db, s: AgentSessionRow, at: number, status: 'completed' | 'cancelled' = 'completed') {
  step(db, s, at, () => {
    pushSessionEvent(db, s.session_id, { type: 'turn.completed', status });
    setStatus(db, s, s.pending_approvals ? 'waiting_approval' : 'idle');
  });
}

function runScript(ctx: Ctx, s: AgentSessionRow, content: string) {
  const db = ctx.db;
  const ai = { kind: 'ai_agent' as const, id: 'agt_native', on_behalf_of: s.owner_id, display_name: 'AI 助手' };
  setStatus(db, s, 'running');
  const wantsFirewall = /防火墙|firewall/i.test(content);
  const wantsUser = /用户|账号|account|user/i.test(content);

  if (!wantsFirewall && !wantsUser) {
    let t = speak(db, s, '我先看一下服务器的当前状态。', 200);
    const call = newId('call');
    step(db, s, t, () => pushSessionEvent(db, s.session_id, { type: 'tool_call', call_id: call, action: `${MONITOR}/overview.cpu`, args: {}, risk: 'low', approval: 'auto' }));
    step(db, s, t + 500, () => {
      const r = widgetResult(db, `${MONITOR}/overview.cpu`) as { value: number };
      pushSessionEvent(db, s.session_id, { type: 'tool_result', call_id: call, status: 'succeeded', result: r });
      addMessage(db, s, { message_id: newId('msg'), role: 'tool', content: `读取 CPU 使用率：${r.value}%`, content_json: { action: `${MONITOR}/overview.cpu`, status: 'succeeded' } });
    });
    t = speak(db, s, 'CPU 和内存都在正常范围内，暂时没有需要处理的问题。需要我盯着某个指标吗？', t + 700);
    finishTurn(db, s, t);
    return;
  }

  const action = wantsFirewall ? `${SECURITY}/firewall.enable` : 'host.users.create';
  const args = wantsFirewall ? { default_policy: 'deny', allow: [22, 443] } : { username: 'frank', role: 'viewer' };
  const t = speak(db, s, wantsFirewall ? '我建议开启防火墙，只放行 SSH（22）和 HTTPS（443）。这一步需要你确认。' : '我会创建一个只读用户 frank。这一步需要你确认。', 200);
  step(db, s, t, () => {
    const call = newId('call');
    pushSessionEvent(db, s.session_id, { type: 'tool_call', call_id: call, action, args, risk: wantsFirewall ? 'high' : 'medium', approval: 'ai_confirm' });
    const res = runOperation(
      { ...ctx, user: db.users.get(s.owner_id) ?? ctx.user },
      {
        action,
        args,
        actor: ai,
        target: wantsFirewall ? { plugin_id: SECURITY, node_id: 'local' } : { subject: 'users' },
        onSettled: (op) => {
          pushSessionEvent(db, s.session_id, { type: 'tool_result', call_id: call, status: op.status === 'SUCCEEDED' ? 'succeeded' : 'failed', operation_id: op.operation_id, result: op.result });
          const end = speak(db, s, op.status === 'SUCCEEDED' ? '已经完成了。' : '没有成功，我把错误记在了操作详情里。', 300);
          finishTurn(db, s, end);
        },
      },
      () => (wantsFirewall ? { enabled: true } : { username: 'frank', enrollment_pending: true }),
    );
    const op = res.body as S['Operation'];
    if (op.status === 'AWAITING_APPROVAL') {
      s.pending_approvals++;
      const summary = db.actions.find((a) => a.id === action)?.approval_summary;
      pushSessionEvent(db, s.session_id, { type: 'approval_required', call_id: call, approval_id: op.approval_id, operation_id: op.operation_id, action, args, summary, deadline: nowIso(Date.now() + 15 * 60_000) });
      addMessage(db, s, { message_id: newId('msg'), role: 'tool', content: '等待你批准', approval_id: op.approval_id, operation_id: op.operation_id, content_json: { action, status: 'awaiting_approval' } });
      setStatus(db, s, 'waiting_approval', { approval_id: op.approval_id, operation_id: op.operation_id });
    }
  });
}

/** 审批被决定后（ops 路由调用）：向关联会话推 approval_decided；拒绝时结束本轮 */
export function afterDecision(db: Db, a: S['Approval']): void {
  for (const s of db.agentSessions.values()) {
    const hit = (db.agentEvents.get(s.session_id) ?? []).some((e) => e.approval_id === a.approval_id) ||
      (db.agentMessages.get(s.session_id) ?? []).some((m) => m.approval_id === a.approval_id);
    if (!hit) continue;
    pushSessionEvent(db, s.session_id, { type: 'approval_decided', approval_id: a.approval_id, decision: a.status === 'APPROVED' ? 'approve' : 'reject', comment: a.comment });
    if (a.status === 'REJECTED') {
      const end = speak(db, s, '好的，我不做这一步了。', 200);
      finishTurn(db, s, end);
    }
  }
}

/* ------------------------------------------------------------------ 路由 */

export const agentRoutes: RouteSpec[] = [
  {
    method: 'GET',
    pattern: '/api/v1/agent-cores',
    handler: () =>
      ok({
        items: [
          { core: 'native', available: true },
          { core: 'claude-code', available: false, reason: '外部核心尚未接入' },
          { core: 'codex', available: false, reason: '外部核心尚未接入' },
          { core: 'opencode', available: false, reason: '外部核心尚未接入' },
        ],
      }),
  },
  {
    method: 'GET',
    pattern: '/api/v1/agent-sessions',
    handler: ({ db, user, query }) => {
      const st = query.get('status');
      const items = [...db.agentSessions.values()]
        .filter((s) => s.owner_id === user!.user_id)
        .filter((s) => !st || (st === 'attention' ? ['waiting_approval', 'attention', 'failed'].includes(s.status) : s.status === st))
        .sort((a, b) => (b.last_message_at ?? b.created_at).localeCompare(a.last_message_at ?? a.created_at))
        .map(strip);
      return ok({ items, revision: `r${db.revCounter}`, delta: false });
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/agent-sessions',
    idempotency: 'none',
    fields: ['title', 'core', 'permission_mode', 'config'],
    handler: (ctx) => {
      const { db, body } = ctx;
      const core = body.core ?? 'native';
      if (core !== 'native') throw new MockProblem(409, 'STATE_CONFLICT', '这个核心暂不可用');
      if (body.permission_mode && !MODES.includes(body.permission_mode)) throw invalid('/permission_mode', '权限模式不对', 'ENUM');
      const config = body.config ?? {};
      if ('api_key_secret' in config) throw new MockProblem(422, 'VALIDATION_FAILED', '不接受 api_key_secret', { violations: [{ in: 'body', pointer: '/config/api_key_secret', message: '请使用 AI 服务或会话 Key 接口', code: 'FORBIDDEN' }] });
      if (config.provider_id && config.base_url) throw invalid('/config/base_url', '使用 AI 服务时不能指定地址', 'CONFLICT');
      const s: AgentSessionRow = {
        session_id: newId('ses'),
        plugin_id: AGENT,
        title: typeof body.title === 'string' && body.title.trim() ? body.title.slice(0, 80) : '新的对话',
        core,
        permission_mode: body.permission_mode ?? 'safe',
        status: 'idle',
        config: { provider_id: config.provider_id ?? 'aip_default', ...(config.model ? { model: config.model } : {}) },
        has_api_key: false,
        last_seq: 0,
        pending_approvals: 0,
        created_at: nowIso(),
        updated_at: nowIso(),
        revision: rev(db),
        owner_id: ctx.user!.user_id,
      };
      db.agentSessions.set(s.session_id, s);
      db.agentMessages.set(s.session_id, []);
      db.agentEvents.set(s.session_id, []);
      changed(db, `agent_sessions/${s.session_id}`, 'create', { kind: 'human', id: s.owner_id }, { revision: s.revision, ownerId: s.owner_id });
      return created(strip(s));
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/agent-sessions/:id',
    handler: (ctx) => {
      const s = own(ctx);
      const messages = (ctx.db.agentMessages.get(s.session_id) ?? []).slice(-40);
      const approvals = [...ctx.db.approvals.values()]
        .filter((a) => a.status === 'PENDING' && messages.some((m) => m.approval_id === a.approval_id))
        .map((a) => ({ call_id: newId('call'), approval_id: a.approval_id, operation_id: a.operation_id, action: a.facts.action.id, args: a.facts.args, summary: a.facts.approval_summary, description: a.facts.approval_description, risk: a.facts.effective_risk, approval: a.facts.action.approval, status: 'awaiting_approval' as const, deadline: a.expires_at, created_at: a.created_at }));
      return ok({ ...strip(s), messages, approvals });
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/agent-sessions/:id/messages',
    handler: (ctx) => {
      const s = own(ctx);
      const beforeRaw = ctx.query.get('before_seq');
      const limitRaw = ctx.query.get('limit');
      const before = beforeRaw === null ? Infinity : Number(beforeRaw);
      if (beforeRaw !== null && (!Number.isInteger(before) || before < 1)) throw invalid('/before_seq', 'before_seq 需为正整数', 'INVALID');
      const limit = limitRaw === null ? 40 : Number(limitRaw);
      if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw invalid('/limit', 'limit 需在 1–200 之间', 'INVALID');
      return ok({ items: (ctx.db.agentMessages.get(s.session_id) ?? []).filter((m) => m.seq < before).slice(-limit) });
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/agent-cores/auth',
    handler: () =>
      ok({
        items: [
          { core: 'claude-code', installed: false, logged_in: false, auth_dir: '/var/lib/qwq/agent-homes/claude-code', hint: '支持官方 OAuth 登录或自定义 Anthropic Key' },
          { core: 'codex', installed: false, logged_in: false, auth_dir: '/var/lib/qwq/agent-homes/codex', hint: '支持官方 Device Code 登录或自定义 OpenAI Key' },
          { core: 'opencode', installed: false, logged_in: false, auth_dir: '/var/lib/qwq/agent-homes/opencode', hint: '支持官方登录或自定义 OpenAI/Anthropic Key' },
        ],
      }),
  },
  {
    method: 'GET',
    pattern: '/api/v1/agent-workspace/files',
    handler: () => ok({ root: '/var/lib/qwq/agent-workspace', items: [] }),
  },
  {
    method: 'GET',
    pattern: '/api/v1/agent-registry',
    handler: () => ok({ items: [], sources: [], live: false }),
  },
  {
    method: 'PATCH',
    pattern: '/api/v1/agent-sessions/:id',
    idempotency: 'none',
    fields: ['title', 'permission_mode', 'config', 'expected_revision'],
    handler: (ctx) => {
      const s = own(ctx);
      checkRevision(s.revision, ctx.body.expected_revision);
      if (ctx.body.title !== undefined) s.title = requireString(ctx.body, 'title', 80);
      if (ctx.body.permission_mode !== undefined) {
        if (!MODES.includes(ctx.body.permission_mode)) throw invalid('/permission_mode', '权限模式不对', 'ENUM');
        s.permission_mode = ctx.body.permission_mode;
      }
      if (ctx.body.config && typeof ctx.body.config === 'object') {
        s.config = { ...(s.config ?? {}), ...ctx.body.config };
      }
      s.revision = rev(ctx.db);
      s.updated_at = nowIso();
      changed(ctx.db, `agent_sessions/${s.session_id}`, 'update', { kind: 'human', id: s.owner_id }, { revision: s.revision, ownerId: s.owner_id });
      return ok(strip(s));
    },
  },
  {
    method: 'DELETE',
    pattern: '/api/v1/agent-sessions/:id',
    idempotency: 'none',
    handler: (ctx) => {
      const s = own(ctx);
      ctx.db.agentSessions.delete(s.session_id);
      ctx.db.agentMessages.delete(s.session_id);
      changed(ctx.db, `agent_sessions/${s.session_id}`, 'delete', { kind: 'human', id: s.owner_id }, { ownerId: s.owner_id });
      return noContent();
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/agent-sessions/:id/messages',
    idempotency: 'none',
    fields: ['content', 'client_message_id'],
    handler: (ctx) => {
      const s = own(ctx);
      const content = requireString(ctx.body, 'content', 32_768);
      const list = ctx.db.agentMessages.get(s.session_id) ?? [];
      const cid = ctx.body.client_message_id;
      const dup = cid ? list.find((m) => m.message_id === `msg_c_${cid}`) : undefined;
      if (dup) return ok({ session: strip(s), message: dup });
      if (s.status === 'running') throw new MockProblem(409, 'STATE_CONFLICT', 'AI 还在处理上一条消息');
      const message = addMessage(ctx.db, s, { message_id: cid ? `msg_c_${cid}` : newId('msg'), role: 'user', content });
      runScript(ctx, s, content);
      return ok({ session: strip(s), message });
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/agent-sessions/:id/cancel',
    idempotency: 'none',
    fields: ['reason'],
    handler: (ctx) => {
      const s = own(ctx);
      s.turn = (s.turn ?? 0) + 1;
      pushSessionEvent(ctx.db, s.session_id, { type: 'turn.completed', status: 'cancelled' });
      setStatus(ctx.db, s, s.pending_approvals ? 'waiting_approval' : 'cancelled');
      return ok(strip(s));
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/agent-sessions/:id/approvals',
    handler: (ctx) => {
      const s = own(ctx);
      const ids = new Set((ctx.db.agentMessages.get(s.session_id) ?? []).map((m) => m.approval_id).filter(Boolean));
      const items = [...ctx.db.approvals.values()]
        .filter((a) => a.status === 'PENDING' && ids.has(a.approval_id))
        .map((a) => ({ call_id: a.operation_id, approval_id: a.approval_id, operation_id: a.operation_id, action: a.facts.action.id, args: a.facts.args, summary: a.facts.approval_summary, status: 'awaiting_approval' as const, created_at: a.created_at }));
      return ok({ items });
    },
  },
  { method: 'GET', pattern: '/api/v1/agent-sessions/:id/events', handler: (ctx) => streamSession(ctx, own(ctx).session_id) },
];
