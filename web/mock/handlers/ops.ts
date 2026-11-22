// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 操作、计划、审批、动作目录（缺口 5）
 * --------------------------------------------------------------------------
 * GET /operations 支持 status / actor_kind / plugin_id / node_id 筛选、cursor 翻页、
 * since_revision 增量（返回 delta=true，只含变化项）。
 * 审批决定：幂等 + expected_revision；已处理 → 409 STATE_CONFLICT；
 * requires_mfa 时 mfa_code 必须为 123456，否则 403 MFA_REQUIRED。
 * ========================================================================== */
import { checkRevision, invalid, MockProblem, notFound, ok, paginate, type RouteSpec, type S } from '../http.ts';
import { actorOf, decideApproval, newId, nowIso, rev, setOpStatus, type Db, type Op } from '../store.ts';
import { MOCK_TOTP } from './auth.ts';
import { afterDecision } from './agent.ts';
import { allowed } from '../server.ts';

const revNum = (r: string) => Number(r.slice(1)) || 0;

function listOps(db: Db, q: URLSearchParams) {
  const status = q.get('status')?.split(',').filter(Boolean);
  const kind = q.get('actor_kind');
  const plugin = q.get('plugin_id');
  const node = q.get('node_id');
  const since = q.get('since_revision');
  let items = [...db.operations.values()]
    .filter((o) => !status || status.includes(o.status))
    .filter((o) => !kind || o.actor.kind === kind)
    .filter((o) => !plugin || o.target.plugin_id === plugin)
    .filter((o) => !node || o.target.node_id === node)
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
  if (since) {
    items = items.filter((o) => revNum(o.revision) > revNum(since));
    return { items, revision: `r${db.revCounter}`, delta: true, deleted_ids: [] };
  }
  const { page, next } = paginate(items, q, 30, 100);
  return { items: page, next_cursor: next, revision: `r${db.revCounter}`, delta: false };
}

export const opsRoutes: RouteSpec[] = [
  /* ---------------------------------------------------------------- operations */
  { method: 'GET', pattern: '/api/v1/operations', perm: 'host.operations:read', handler: ({ db, query }) => ok(listOps(db, query)) },
  {
    method: 'GET',
    pattern: '/api/v1/operations/:id',
    perm: 'host.operations:read',
    handler: ({ db, params }) => ok(db.operations.get(params.id!) ?? (() => { throw notFound('操作'); })()),
  },
  {
    method: 'POST',
    pattern: '/api/v1/operations/:id/cancel',
    perm: 'host.operations:cancel',
    fields: ['reason'],
    handler: (ctx) => {
      const op = ctx.db.operations.get(ctx.params.id!);
      if (!op) throw notFound('操作');
      if (op.status === 'AWAITING_APPROVAL' || op.status === 'PENDING') {
        const a = op.approval_id ? ctx.db.approvals.get(op.approval_id) : undefined;
        if (a && a.status === 'PENDING') {
          a.status = 'CANCELED';
          a.revision = rev(ctx.db);
        }
        ctx.db.pending.delete(op.operation_id);
        setOpStatus(ctx.db, op, 'CANCELED');
      } else if (op.status === 'RUNNING') {
        op.cancel_requested = true;
        setOpStatus(ctx.db, op, 'CANCELED');
      } else {
        throw new MockProblem(409, 'STATE_CONFLICT', '操作已结束，无法取消');
      }
      return ok(op);
    },
  },

  /* ---------------------------------------------------------------- plans */
  {
    method: 'POST',
    pattern: '/api/v1/plans',
    idempotency: 'none',
    fields: ['action', 'args', 'target', 'expected_revision'],
    handler: (ctx) => {
      const meta = ctx.db.actions.find((a) => a.id === ctx.body.action);
      if (!meta) throw invalid('/action', '没有这个操作', 'UNKNOWN_ACTION');
      const plan: S['Plan'] = {
        plan_id: newId('pln'),
        action: meta.id,
        target: ctx.body.target ?? {},
        args: ctx.body.args ?? {},
        args_digest: 'sha256:' + Math.random().toString(16).slice(2),
        plannable: meta.plannable,
        changes: [],
        violations: [],
        warnings: [],
        preconditions: [],
        effective_risk: meta.risk,
        requires_approval: meta.approval !== 'auto',
        requires_mfa: meta.effect === 'destructive',
        executable: true,
        created_at: nowIso(),
        expires_at: nowIso(Date.now() + 10 * 60_000),
      };
      ctx.db.plans.set(plan.plan_id, plan);
      return { status: 201, body: plan };
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/plans/:id',
    handler: ({ db, params }) => ok(db.plans.get(params.id!) ?? (() => { throw notFound('计划'); })()),
  },
  {
    method: 'POST',
    pattern: '/api/v1/plans/:id/execute',
    handler: (ctx) => {
      const plan = ctx.db.plans.get(ctx.params.id!);
      if (!plan) throw notFound('计划');
      if (Date.parse(plan.expires_at) < Date.now()) throw new MockProblem(409, 'PLAN_EXPIRED', '预览已过期');
      if (plan.operation_id) throw new MockProblem(409, 'STATE_CONFLICT', '已经执行过了');
      const op: Op = {
        operation_id: newId('op'),
        action: plan.action,
        status: 'SUCCEEDED',
        target: plan.target,
        actor: actorOf(ctx.user),
        effective_risk: plan.effective_risk,
        plan_id: plan.plan_id,
        attempt: 1,
        created_at: nowIso(),
        updated_at: nowIso(),
        finished_at: nowIso(),
        revision: rev(ctx.db),
        args: plan.args,
      };
      ctx.db.operations.set(op.operation_id, op);
      plan.operation_id = op.operation_id;
      setOpStatus(ctx.db, op, 'SUCCEEDED', { result: { ok: true } });
      return ok({ operation_id: op.operation_id, action: op.action, status: op.status, result: op.result, revision: op.revision });
    },
  },

  /* ---------------------------------------------------------------- approvals */
  {
    method: 'GET',
    pattern: '/api/v1/approvals',
    handler: ({ db, query }) => {
      const status = query.get('status') ?? 'PENDING';
      const opId = query.get('operation_id');
      const items = [...db.approvals.values()]
        .filter((a) => a.status === status && (!opId || a.operation_id === opId))
        .sort((a, b) => a.created_at.localeCompare(b.created_at));
      return ok({ items, revision: `r${db.revCounter}`, delta: false });
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/approvals/:id',
    handler: ({ db, params }) => ok(db.approvals.get(params.id!) ?? (() => { throw notFound('审批'); })()),
  },
  {
    method: 'POST',
    pattern: '/api/v1/approvals/:id/decision',
    fields: ['decision', 'expected_revision', 'comment', 'mfa_code'],
    handler: (ctx) => {
      const a = ctx.db.approvals.get(ctx.params.id!);
      if (!a) throw notFound('审批');
      if (a.status !== 'PENDING') throw new MockProblem(409, 'STATE_CONFLICT', '这条审批已经被处理了');
      if (Date.parse(a.expires_at) < Date.now()) throw new MockProblem(409, 'STATE_CONFLICT', '审批已过期');
      checkRevision(a.revision, ctx.body.expected_revision);
      if (ctx.body.decision !== 'approve' && ctx.body.decision !== 'reject') throw invalid('/decision', '只能是 approve 或 reject', 'ENUM');
      if (a.requires_mfa && ctx.body.decision === 'approve') {
        if (!ctx.user!.mfa_enabled) throw new MockProblem(403, 'MFA_REQUIRED', '需要先开启两步验证');
        if (ctx.body.mfa_code !== MOCK_TOTP) throw new MockProblem(403, 'MFA_REQUIRED', '验证码不对', { violations: [{ in: 'body', pointer: '/mfa_code', message: '验证码不对', code: 'MFA_INVALID' }] });
      }
      decideApproval(ctx.db, a, ctx.body.decision, actorOf(ctx.user), ctx.body.comment);
      afterDecision(ctx.db, a);
      for (const s of ctx.db.agentSessions.values()) {
        if (s.pending_approvals > 0 && (ctx.db.agentMessages.get(s.session_id) ?? []).some((m) => m.approval_id === a.approval_id)) {
          s.pending_approvals--;
          if (!s.pending_approvals && (s.status === 'waiting_approval' || s.status === 'attention')) s.status = 'idle';
          s.revision = rev(ctx.db);
        }
      }
      return ok(a);
    },
  },

  /* ---------------------------------------------------------------- 动作目录（仅人类会话，按 RBAC 过滤） */
  {
    method: 'GET',
    pattern: '/api/v1/actions',
    handler: (ctx) => {
      const { db, query } = ctx;
      const q = (query.get('q') ?? '').trim().toLowerCase();
      const plugin = query.get('plugin_id');
      const effect = query.get('effect');
      const limit = Math.min(50, Number(query.get('limit')) || 20);
      const hits = db.actions
        .filter((a) => db.plugins.has(a.plugin_id ?? '') || a.source === 'host')
        .filter((a) => allowed(ctx.user!.role, a.permission ?? 'host.plugins:read'))
        .filter((a) => !plugin || a.plugin_id === plugin)
        .filter((a) => !effect || a.effect === effect)
        .filter((a) => !q || a.summary.toLowerCase().includes(q) || a.id.toLowerCase().includes(q));
      return ok({ items: hits.slice(0, limit), truncated: hits.length > limit });
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/actions/:id',
    handler: ({ db, params, user }) => {
      const a = db.actions.find((x) => x.id === params.id);
      if (!a || !allowed(user!.role, a.permission ?? 'host.plugins:read')) throw notFound('操作');
      return ok({ ...a, request_schema: { type: 'object', properties: {}, additionalProperties: false } });
    },
  },
];
