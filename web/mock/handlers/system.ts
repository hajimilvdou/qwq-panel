// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 系统、健康检查、审计、AI 提供方（缺口 2 / 7）、全局事件流
 * ========================================================================== */
import { checkRevision, invalid, MockProblem, noContent, notFound, ok, paginate, requireString, type Ctx, type RouteSpec } from '../http.ts';
import { actorOf, changed, newId, nowIso, rev, runOperation, writeAudit } from '../store.ts';
import { streamEvents } from '../events.ts';
import type { AiProvider } from '../../shell/src/api/additions.ts';

/** 普通用户看不到 base_url（缺口 2） */
const providerDto = (ctx: Ctx, { api_key: _k, ...p }: AiProvider & { api_key?: string }): Partial<AiProvider> =>
  ctx.user!.role === 'admin' ? p : { provider_id: p.provider_id, name: p.name, model: p.model, is_default: p.is_default, has_api_key: p.has_api_key };

function provider(ctx: Ctx) {
  const p = ctx.db.providers.get(ctx.params.id!);
  if (!p) throw notFound('AI 服务');
  return p;
}

function checkUrl(v: unknown): string {
  if (typeof v !== 'string') throw invalid('/base_url', '必填', 'REQUIRED');
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw invalid('/base_url', '不是合法的地址', 'FORMAT');
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) throw invalid('/base_url', '只接受不带账号、参数的 https 地址', 'FORMAT');
  return v.replace(/\/+$/, '');
}

export const systemRoutes: RouteSpec[] = [
  { method: 'GET', pattern: '/healthz', public: true, handler: () => ok({ status: 'ok' }) },
  { method: 'GET', pattern: '/readyz', public: true, handler: () => ok({ status: 'ok' }) },
  {
    method: 'GET',
    pattern: '/api/v1/system',
    perm: 'host.system:read',
    handler: ({ db, user }) =>
      ok({
        version: '0.6.0-mock',
        commit: '2d14fa1',
        role: 'standalone',
        started_at: nowIso(db.startedAt),
        tls: { mode: 'self_signed', fingerprint: db.setup.tls_fingerprint, not_after: '2027-11-08T00:00:00Z' },
        plugins_enabled: [...db.plugins.values()].some((p) => p.active_version),
        ...(user!.role === 'admin' ? { listen: '0.0.0.0:8443', data_dir: '/var/lib/qwq' } : {}),
      }),
  },
  { method: 'GET', pattern: '/api/v1/events', handler: (ctx) => streamEvents(ctx) },

  /* ---------------------------------------------------------------- 审计（仅 admin） */
  {
    method: 'GET',
    pattern: '/api/v1/audit',
    perm: 'host.audit:read',
    handler: ({ db, query }) => {
      const f = (k: string) => query.get(k);
      const items = db.audit
        .filter((e) => !f('actor') || e.actor.id === f('actor') || e.actor.display_name === f('actor'))
        .filter((e) => !f('action') || e.action.includes(f('action')!))
        .filter((e) => !f('subject') || e.subject.startsWith(f('subject')!))
        .filter((e) => !f('outcome') || e.outcome === f('outcome'))
        .filter((e) => !f('operation_id') || e.operation_id === f('operation_id'))
        .filter((e) => !f('from') || e.at >= f('from')!)
        .filter((e) => !f('to') || e.at <= f('to')!);
      const { page, next } = paginate(items, query, 50, 200);
      return ok({ items: page, meta: { next_cursor: next } });
    },
  },

  /* ---------------------------------------------------------------- AI 提供方 */
  {
    method: 'GET',
    pattern: '/api/v1/ai/providers',
    handler: (ctx) => ok({ items: [...ctx.db.providers.values()].map((p) => providerDto(ctx, p)) }),
  },
  {
    method: 'POST',
    pattern: '/api/v1/ai/providers',
    perm: 'host.ai_providers:create',
    fields: ['name', 'kind', 'base_url', 'model', 'is_default'],
    handler: (ctx) => {
      const name = requireString(ctx.body, 'name', 64);
      const base_url = checkUrl(ctx.body.base_url);
      const model = requireString(ctx.body, 'model', 128);
      return runOperation(ctx, { action: 'host.ai_providers.create', args: { name, base_url, model } }, () => {
        const p: AiProvider = { provider_id: newId('aip'), name, kind: 'openai_compatible', base_url, model, has_api_key: false, is_default: !!ctx.body.is_default, created_at: nowIso(), updated_at: nowIso(), revision: rev(ctx.db) };
        if (p.is_default) for (const x of ctx.db.providers.values()) x.is_default = false;
        ctx.db.providers.set(p.provider_id, p);
        changed(ctx.db, `ai_providers/${p.provider_id}`, 'create', actorOf(ctx.user), { revision: p.revision });
        return p;
      });
    },
  },
  {
    method: 'PATCH',
    pattern: '/api/v1/ai/providers/:id',
    perm: 'host.ai_providers:update',
    fields: ['expected_revision', 'name', 'base_url', 'model', 'is_default'],
    handler: (ctx) => {
      const p = provider(ctx);
      checkRevision(p.revision!, ctx.body.expected_revision);
      const { expected_revision: _r, ...patch } = ctx.body;
      if (patch.base_url !== undefined) patch.base_url = checkUrl(patch.base_url);
      return runOperation(ctx, { action: 'host.ai_providers.update', args: patch }, () => {
        if (patch.is_default) for (const x of ctx.db.providers.values()) x.is_default = false;
        const pointers = Object.keys(patch).map((k) => '/' + k);
        /* 改 base_url 清掉已存 Key，防止换端点把密钥带出去 */
        if (patch.base_url !== undefined && p.has_api_key) {
          delete p.api_key;
          p.has_api_key = false;
          pointers.push('/has_api_key');
        }
        Object.assign(p, patch, { updated_at: nowIso(), revision: rev(ctx.db) });
        changed(ctx.db, `ai_providers/${p.provider_id}`, 'update', actorOf(ctx.user), { revision: p.revision, pointers });
        return providerDto(ctx, p);
      });
    },
  },
  {
    method: 'DELETE',
    pattern: '/api/v1/ai/providers/:id',
    perm: 'host.ai_providers:delete',
    handler: (ctx) => {
      const p = provider(ctx);
      checkRevision(p.revision!, ctx.query.get('expected_revision'));
      if (p.is_default && ctx.db.providers.size > 1) throw new MockProblem(409, 'STATE_CONFLICT', '默认 AI 服务不能删除，请先把别的设为默认');
      return runOperation(ctx, { action: 'host.ai_providers.delete', args: { name: p.name } }, () => {
        ctx.db.providers.delete(p.provider_id);
        changed(ctx.db, `ai_providers/${p.provider_id}`, 'delete', actorOf(ctx.user));
        return {};
      });
    },
  },
  {
    method: 'PUT',
    pattern: '/api/v1/ai/providers/:id/api-key',
    perm: 'host.ai_providers:update',
    fields: ['api_key'],
    handler: (ctx) => {
      const p = provider(ctx);
      p.api_key = requireString(ctx.body, 'api_key', 512);
      p.has_api_key = true;
      p.revision = rev(ctx.db);
      writeAudit(ctx.db, { actor: actorOf(ctx.user), action: 'host.ai_providers.set_key', subject: `ai_providers/${p.provider_id}`, outcome: 'success', request_id: ctx.requestId });
      changed(ctx.db, `ai_providers/${p.provider_id}`, 'update', actorOf(ctx.user), { revision: p.revision, pointers: ['/has_api_key'] });
      return noContent();
    },
  },
  {
    method: 'DELETE',
    pattern: '/api/v1/ai/providers/:id/api-key',
    perm: 'host.ai_providers:update',
    handler: (ctx) => {
      const p = provider(ctx);
      delete p.api_key;
      p.has_api_key = false;
      p.revision = rev(ctx.db);
      changed(ctx.db, `ai_providers/${p.provider_id}`, 'update', actorOf(ctx.user), { revision: p.revision, pointers: ['/has_api_key'] });
      return noContent();
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/ai/providers/:id/test',
    perm: 'host.ai_providers:update',
    handler: (ctx) => {
      const p = provider(ctx);
      return ok(p.has_api_key ? { ok: true, latency_ms: 180 + Math.floor(Math.random() * 120) } : { ok: false, category: 'auth' });
    },
  },
];
