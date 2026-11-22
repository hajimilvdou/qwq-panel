// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 用户、委托、节点
 * ========================================================================== */
import { randomBytes } from 'node:crypto';
import { checkRevision, created, invalid, MockProblem, noContent, notFound, ok, paginate, requireString, type RouteSpec, type S } from '../http.ts';
import { actorOf, changed, newId, nowIso, rev, runOperation } from '../store.ts';
import { issueEnrollment, MOCK_TOTP } from './auth.ts';

const ROLES: S['Role'][] = ['admin', 'operator', 'viewer'];
const list = <T>(items: T[], q: URLSearchParams, revision: string) => {
  const { page, next } = paginate(items, q);
  return { items: page, next_cursor: next, revision, delta: false };
};

export const userRoutes: RouteSpec[] = [
  /* ---------------------------------------------------------------- 用户 */
  {
    method: 'GET',
    pattern: '/api/v1/users',
    perm: 'host.users:read',
    handler: ({ db, query }) => ok(list([...db.users.values()], query, `r${db.revCounter}`)),
  },
  {
    method: 'GET',
    pattern: '/api/v1/users/:id',
    perm: 'host.users:read',
    handler: ({ db, params }) => ok(db.users.get(params.id!) ?? (() => { throw notFound('用户'); })()),
  },
  {
    method: 'POST',
    pattern: '/api/v1/users',
    perm: 'host.users:create',
    fields: ['username', 'role', 'display_name'],
    handler: (ctx) => {
      const { db, body } = ctx;
      const username = requireString(body, 'username', 32).toLowerCase();
      if (!/^[a-z][a-z0-9_.-]{1,31}$/.test(username)) throw invalid('/username', '只能用小写字母、数字和 _.-，以字母开头', 'PATTERN');
      if (!ROLES.includes(body.role)) throw invalid('/role', '角色不对', 'ENUM');
      if ([...db.users.values()].some((u) => u.username === username)) throw new MockProblem(409, 'STATE_CONFLICT', '用户名已被使用');
      return runOperation(ctx, { action: 'host.users.create', target: { subject: 'users' }, args: { username, role: body.role } }, () => {
        const u: S['User'] = {
          user_id: newId('usr'),
          username,
          display_name: body.display_name || username,
          role: body.role,
          mfa_enabled: false,
          disabled: false,
          created_at: nowIso(),
          updated_at: nowIso(),
          revision: rev(db),
        };
        db.users.set(u.user_id, u);
        changed(db, `users/${u.user_id}`, 'create', actorOf(ctx.user), { revision: u.revision });
        return { user: u, enrollment_pending: true, enrollment_expires_at: nowIso(Date.now() + 24 * 3600_000) };
      });
    },
  },
  {
    method: 'PATCH',
    pattern: '/api/v1/users/:id',
    perm: 'host.users:update',
    fields: ['expected_revision', 'display_name', 'role', 'disabled'],
    handler: (ctx) => {
      const u = ctx.db.users.get(ctx.params.id!);
      if (!u) throw notFound('用户');
      checkRevision(u.revision, ctx.body.expected_revision);
      if (ctx.body.role !== undefined && !ROLES.includes(ctx.body.role)) throw invalid('/role', '角色不对', 'ENUM');
      if (u.user_id === ctx.user!.user_id && (ctx.body.disabled || (ctx.body.role && ctx.body.role !== 'admin'))) {
        throw new MockProblem(409, 'STATE_CONFLICT', '不能停用或降级自己');
      }
      const { expected_revision: _r, ...patch } = ctx.body;
      return runOperation(ctx, { action: 'host.users.update', target: { subject: `users/${u.user_id}` }, args: patch }, () => {
        Object.assign(u, patch, { updated_at: nowIso(), revision: rev(ctx.db) });
        if (patch.disabled) for (const [sid, s] of ctx.db.sessions) if (s.userId === u.user_id) ctx.db.sessions.delete(sid);
        changed(ctx.db, `users/${u.user_id}`, 'update', actorOf(ctx.user), { revision: u.revision, pointers: Object.keys(patch).map((k) => '/' + k) });
        return u;
      });
    },
  },
  {
    method: 'DELETE',
    pattern: '/api/v1/users/:id',
    perm: 'host.users:delete',
    handler: (ctx) => {
      const u = ctx.db.users.get(ctx.params.id!);
      if (!u) throw notFound('用户');
      checkRevision(u.revision, ctx.query.get('expected_revision'));
      if (u.user_id === ctx.user!.user_id) throw new MockProblem(409, 'STATE_CONFLICT', '不能删除自己');
      return runOperation(ctx, { action: 'host.users.delete', target: { subject: `users/${u.user_id}` }, args: { username: u.username }, approval: false }, () => {
        ctx.db.users.delete(u.user_id);
        changed(ctx.db, `users/${u.user_id}`, 'delete', actorOf(ctx.user));
        return {};
      });
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/users/:id/enrollment-token',
    perm: 'host.users:update',
    fields: ['mfa_code'],
    secretFields: ['enrollment_token'],
    handler: (ctx) => {
      const u = ctx.db.users.get(ctx.params.id!);
      if (!u) throw notFound('用户');
      if (u.disabled || ctx.db.passwords.has(u.user_id)) throw new MockProblem(409, 'STATE_CONFLICT', '该用户已有密码或已停用，不能签发注册链接');
      const s = ctx.session!;
      const fresh = s.mfaVerifiedAt && Date.now() - s.mfaVerifiedAt < 15 * 60_000;
      if (!fresh && ctx.user!.mfa_enabled && ctx.body.mfa_code !== MOCK_TOTP) throw new MockProblem(403, 'MFA_REQUIRED', '需要最近验证过两步验证');
      const t = issueEnrollment(ctx.db, u.user_id);
      return ok({ user_id: u.user_id, enrollment_token: t.enrollment_token, expires_at: t.expires_at });
    },
  },

  /* ---------------------------------------------------------------- 委托 */
  {
    method: 'GET',
    pattern: '/api/v1/delegations',
    perm: 'host.delegations:read',
    handler: ({ db, query, user }) => {
      const all = query.get('owner') === 'all' && user!.role === 'admin';
      return ok(list([...db.delegations.values()].filter((d) => all || d.owner_id === user!.user_id), query, `r${db.revCounter}`));
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/delegations',
    perm: 'host.delegations:create',
    fields: ['label', 'policy', 'ttl_seconds'],
    secretFields: ['token'],
    handler: (ctx) => {
      const label = requireString(ctx.body, 'label', 64);
      const ttl = Number(ctx.body.ttl_seconds) || 30 * 86400;
      const d: S['DelegationCreated'] = {
        delegation_id: newId('dlg'),
        label,
        owner_id: ctx.user!.user_id,
        policy: { auto_approve_max_risk: 'none', on_approval_required: 'queue', requests_per_minute: 60, ...(ctx.body.policy ?? {}) },
        status: 'active',
        token_prefix: 'qwq_dlg_' + randomBytes(2).toString('hex'),
        created_at: nowIso(),
        expires_at: nowIso(Date.now() + ttl * 1000),
        revision: rev(ctx.db),
      };
      const { token: _t, ...stored } = d;
      ctx.db.delegations.set(d.delegation_id, stored);
      changed(ctx.db, `delegations/${d.delegation_id}`, 'create', actorOf(ctx.user), { revision: d.revision });
      return created({ ...d, token: `${d.token_prefix}${randomBytes(18).toString('base64url')}` });
    },
  },
  {
    method: 'PATCH',
    pattern: '/api/v1/delegations/:id',
    perm: 'host.delegations:update',
    fields: ['expected_revision', 'status', 'policy'],
    handler: (ctx) => {
      const d = ctx.db.delegations.get(ctx.params.id!);
      if (!d || d.owner_id !== ctx.user!.user_id) throw notFound('令牌');
      checkRevision(d.revision, ctx.body.expected_revision);
      if (ctx.body.status) d.status = ctx.body.status;
      if (ctx.body.policy) d.policy = { ...d.policy, ...ctx.body.policy };
      d.revision = rev(ctx.db);
      changed(ctx.db, `delegations/${d.delegation_id}`, 'update', actorOf(ctx.user), { revision: d.revision });
      return ok(d);
    },
  },
  {
    method: 'DELETE',
    pattern: '/api/v1/delegations/:id',
    perm: 'host.delegations:delete',
    handler: (ctx) => {
      const d = ctx.db.delegations.get(ctx.params.id!);
      if (!d || d.owner_id !== ctx.user!.user_id) throw notFound('令牌');
      checkRevision(d.revision, ctx.query.get('expected_revision'));
      ctx.db.delegations.delete(d.delegation_id);
      changed(ctx.db, `delegations/${d.delegation_id}`, 'delete', actorOf(ctx.user));
      return noContent();
    },
  },

  /* ---------------------------------------------------------------- 节点 */
  {
    method: 'GET',
    pattern: '/api/v1/nodes',
    perm: 'host.nodes:read',
    handler: ({ db, query }) => ok(list([...db.nodes.values()], query, `r${db.revCounter}`)),
  },
  {
    method: 'GET',
    pattern: '/api/v1/nodes/:id',
    perm: 'host.nodes:read',
    handler: ({ db, params }) => ok(db.nodes.get(params.id!) ?? (() => { throw notFound('节点'); })()),
  },
];
