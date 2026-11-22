// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 插件：列表、上传预检、安装/更新/回滚、配置、运维、operation 调用
 * --------------------------------------------------------------------------
 * 上传包按文件名决定预检结果（便于演示向导各分支）：
 *   *monitor*  → 已安装插件的更新（1.5.0）
 *   *bad*      → 签名无效
 *   *huge*     → 内存不足、兼容性问题
 *   其他       → 新插件「域名解析」
 * ========================================================================== */
import { randomBytes } from 'node:crypto';
import { checkRevision, created, invalid, MockProblem, notFound, ok, type Ctx, type RouteSpec, type S } from '../http.ts';
import { ACTIONS, MONITOR } from '../catalog.ts';
import { actorOf, changed, later, newId, nowIso, publish, rev, runOperation, writeAudit, type Db } from '../store.ts';
import { widgetResult } from '../widgets.ts';
import type { Plugin, PluginPackageInspection } from '../../shell/src/api/additions.ts';

const getPlugin = (db: Db, id: string): Plugin => {
  const p = db.plugins.get(id);
  if (!p) throw notFound('应用');
  return p;
};

function touch(ctx: Ctx, p: Plugin, pointers: string[], opId?: string) {
  p.revision = rev(ctx.db);
  changed(ctx.db, `plugins/${p.plugin_id}`, 'update', actorOf(ctx.user), { revision: p.revision, pointers, operationId: opId });
}

/* ------------------------------------------------------------------ 预检 */

function inspect(db: Db, uploadId: string): PluginPackageInspection {
  const u = db.uploads.get(uploadId)!;
  const name = u.manifestOf;
  const isUpdate = name.includes('monitor');
  const huge = name.includes('huge');
  const id = isUpdate ? MONITOR : 'com.qwq.dns';
  const installed = db.plugins.get(id);
  return {
    ...u.upload,
    signature: { valid: !name.includes('bad'), key_id: 'qwq-release-2026', trusted: true, publisher_id: 'qwq' },
    manifest: name.includes('bad')
      ? undefined
      : {
          id,
          version: isUpdate ? '1.5.0' : '0.3.1',
          name: isUpdate ? '系统监控' : '域名解析',
          summary: isUpdate ? '看 CPU、内存、磁盘和网络' : '管理 DNS 记录与动态域名',
          description: isUpdate ? '新增进程列表与温度监控。' : '支持 Cloudflare、阿里云 DNS，自动更新动态 IP。',
          placement: 'node',
          target: 'linux-amd64',
          abi: '1',
          capabilities: [
            { name: 'net.egress', scope: 'api.cloudflare.com', reason: '调用 DNS 服务商接口', sensitive: false },
            { name: 'secret.read', scope: 'dns_token', reason: '读取你保存的 DNS 令牌', sensitive: true },
          ],
          connect_sources: isUpdate ? [] : ['https://api.cloudflare.com'],
          resources: { memory_max_mb: huge ? 2048 : 64, cpu_quota_percent: 20, pids_max: 32, fds_max: 128, disk_max_mb: 64 },
          operations: [
            { name: 'records.list', summary: '列出解析记录', effect: 'read', risk: 'low' },
            { name: 'records.update', summary: '修改解析记录', effect: 'write', risk: 'high', approval: 'ai_confirm', reachability: true },
          ],
          ui_routes: 1,
          widgets: 1,
        },
    compatibility: huge ? { ok: false, problems: [{ in: 'body', pointer: '/abi', message: '需要宿主 ABI 2，当前为 1', code: 'ABI' }] } : { ok: true, problems: [] },
    memory: { required_mb: huge ? 2048 : 64, available_mb: 1630, ok: !huge },
    disk: { required_mb: 64, available_mb: db.flags.degraded ? 1600 : 15000, ok: true },
    installed: installed ? { version: installed.active_version!, revision: installed.revision } : undefined,
  };
}

/** 安装/更新的步骤事件（plugin.install.*），最后切到 running */
function rollout(ctx: Ctx, p: Plugin, version: string, kind: 'install' | 'update' | 'rollback') {
  const steps = ['verify', 'stage', 'start', 'health', 'commit'];
  p.runtime = { state: 'starting', since: nowIso() };
  steps.forEach((step, i) =>
    later(ctx.db, 600 * (i + 1), () => {
      publish(ctx.db, `plugin.${kind}.step`, `plugins/${p.plugin_id}`, { plugin_id: p.plugin_id, version, step, index: i, total: steps.length }, { actor: actorOf(ctx.user) });
      if (i === steps.length - 1) {
        p.runtime = { state: 'running', since: nowIso(), restarts: 0, memory_bytes: 21_000_000, memory_max_bytes: 128 * 1024 * 1024 };
        touch(ctx, p, ['/runtime', '/active_version']);
      }
    }),
  );
}

function versionRow(db: Db, pluginId: string, version: string): S['PluginVersion'] {
  return {
    plugin_id: pluginId,
    version,
    digest: 'sha256:' + randomBytes(16).toString('hex'),
    status: 'ACTIVE',
    install_status: 'INSTALLED',
    active: true,
    installed_at: nowIso(),
    activated_at: nowIso(),
    revision: rev(db),
  };
}

/* ------------------------------------------------------------------ operation 调用（两种路径共用） */

function invoke(ctx: Ctx, pluginId: string, opName: string) {
  const p = getPlugin(ctx.db, pluginId);
  if (p.runtime?.state !== 'running') throw new MockProblem(503, 'PLUGIN_UNAVAILABLE', '应用没有在运行');
  const meta = ACTIONS.find((a) => a.id === `${pluginId}/${opName}`);
  if (!meta) throw notFound('操作');
  const payload = ctx.body?.payload ?? {};
  if (meta.effect === 'read') {
    const out: S['OperationOutcome'] = { operation_id: '', action: meta.id, status: 'SUCCEEDED', result: widgetResult(ctx.db, meta.id) };
    return ok(out);
  }
  if (!ctx.idempotencyKey) throw invalid('/', '写操作需要 Idempotency-Key', 'IDEMPOTENCY_KEY_REQUIRED');
  return runOperation(
    ctx,
    { action: meta.id, target: { plugin_id: pluginId, node_id: p.placement === 'node' ? 'local' : undefined }, args: payload, job: meta.mode === 'job' ? { steps: ['准备', '打包', '上传'] } : undefined },
    () => ({ ok: true }),
  );
}

/* ------------------------------------------------------------------ 路由 */

export const pluginRoutes: RouteSpec[] = [
  {
    method: 'GET',
    pattern: '/api/v1/plugins',
    perm: 'host.plugins:read',
    handler: ({ db }) => ok({ items: [...db.plugins.values()], revision: `r${db.revCounter}`, delta: false }),
  },
  { method: 'GET', pattern: '/api/v1/plugins/:id', perm: 'host.plugins:read', handler: ({ db, params }) => ok(getPlugin(db, params.id!)) },
  {
    method: 'POST',
    pattern: '/api/v1/plugin-packages',
    perm: 'host.plugins:install',
    idempotency: 'none',
    handler: (ctx) => {
      const raw: Buffer = ctx.body;
      const filename = /filename="([^"]*)"/.exec(raw.subarray(0, 2048).toString('latin1'))?.[1] ?? 'package.qwqpkg';
      if (raw.length > 64 * 1024 * 1024) throw new MockProblem(413, 'PAYLOAD_TOO_LARGE', '安装包不能超过 64 MiB');
      const upload: S['PluginPackageUpload'] = {
        upload_id: newId('upl'),
        size: raw.length,
        sha256: randomBytes(32).toString('hex'),
        expires_at: nowIso(Date.now() + 30 * 60_000),
      };
      ctx.db.uploads.set(upload.upload_id, { upload, ownerId: ctx.user!.user_id, manifestOf: filename.toLowerCase() });
      return created(upload);
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/plugin-packages/:id',
    perm: 'host.plugins:install',
    handler: (ctx) => {
      const u = ctx.db.uploads.get(ctx.params.id!);
      if (!u || u.ownerId !== ctx.user!.user_id) throw notFound('安装包');
      return ok(inspect(ctx.db, u.upload.upload_id));
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/plugins',
    perm: 'host.plugins:install',
    fields: ['upload_id', 'accepted_capabilities', 'expected_revision'],
    handler: (ctx) => {
      const u = ctx.db.uploads.get(String(ctx.body.upload_id));
      if (!u || u.ownerId !== ctx.user!.user_id) throw invalid('/upload_id', '安装包已过期，请重新上传', 'EXPIRED');
      const ins = inspect(ctx.db, u.upload.upload_id);
      if (!ins.signature.valid || !ins.manifest) throw new MockProblem(422, 'PRECONDITION_FAILED', '签名无效');
      if (ctx.db.plugins.has(ins.manifest.id)) throw new MockProblem(409, 'STATE_CONFLICT', '已安装，请使用更新');
      const m = ins.manifest;
      const v = versionRow(ctx.db, m.id, m.version);
      const p: Plugin = {
        plugin_id: m.id,
        name: m.name,
        summary: m.summary,
        description: m.description,
        publisher_id: ins.signature.publisher_id,
        placement: m.placement,
        active_version: m.version,
        active_status: 'ACTIVE',
        install_status: 'INSTALLED',
        config_revision: rev(ctx.db),
        versions: [v],
        created_at: nowIso(),
        revision: rev(ctx.db),
        capabilities: m.capabilities,
        dependencies: [],
        resources: m.resources,
        license: 'Apache-2.0',
        ui: { entry_url: `/plugin-ui/${m.id}/${m.version}/index.html`, routes: [{ path: '/', title: m.name, nav: true, permission: 'host.plugins:read' }], widgets: [], connect_sources: m.connect_sources },
      };
      ctx.db.plugins.set(p.plugin_id, p);
      ctx.db.uploads.delete(u.upload.upload_id);
      changed(ctx.db, `plugins/${p.plugin_id}`, 'create', actorOf(ctx.user), { revision: p.revision });
      rollout(ctx, p, m.version, 'install');
      return created(v);
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/plugins/:id/update',
    perm: 'host.plugins:update',
    fields: ['upload_id', 'accepted_capabilities', 'expected_revision'],
    handler: (ctx) => {
      const p = getPlugin(ctx.db, ctx.params.id!);
      if (ctx.body.expected_revision) checkRevision(p.revision, ctx.body.expected_revision);
      const u = ctx.db.uploads.get(String(ctx.body.upload_id));
      if (!u) throw invalid('/upload_id', '安装包已过期，请重新上传', 'EXPIRED');
      const ins = inspect(ctx.db, u.upload.upload_id);
      const from = p.active_version;
      const v = versionRow(ctx.db, p.plugin_id, ins.manifest!.version);
      p.versions = [v, ...p.versions.map((x) => ({ ...x, active: false, status: 'STOPPED' as const }))];
      p.active_version = v.version;
      if (p.ui) p.ui.entry_url = `/plugin-ui/${p.plugin_id}/${v.version}/index.html`;
      touch(ctx, p, ['/active_version', '/versions']);
      rollout(ctx, p, v.version, 'update');
      const res: S['PluginUpdateResult'] = { saga_id: newId('sag'), plugin_id: p.plugin_id, from_version: from, to_version: v.version, strategy: 'overlap', state: 'COMMITTED', restarted: false, version: v };
      return ok(res);
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/plugins/:id/rollback',
    perm: 'host.plugins:update',
    fields: ['expected_revision'],
    handler: (ctx) => {
      const p = getPlugin(ctx.db, ctx.params.id!);
      if (ctx.body.expected_revision) checkRevision(p.revision, ctx.body.expected_revision);
      const prev = p.versions.find((v) => !v.active);
      if (!prev) throw new MockProblem(409, 'STATE_CONFLICT', '没有可回滚的版本');
      const from = p.active_version;
      p.versions = p.versions.map((v) => ({ ...v, active: v.version === prev.version, status: v.version === prev.version ? 'ACTIVE' : 'STOPPED' }));
      p.active_version = prev.version;
      if (p.ui) p.ui.entry_url = `/plugin-ui/${p.plugin_id}/${prev.version}/index.html`;
      touch(ctx, p, ['/active_version', '/versions']);
      rollout(ctx, p, prev.version, 'rollback');
      return ok({ saga_id: newId('sag'), plugin_id: p.plugin_id, from_version: from, to_version: prev.version, strategy: 'restart', state: 'COMMITTED', restarted: true, version: prev });
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/plugins/:id/config',
    perm: 'host.plugins:read',
    handler: ({ db, params }) => ok(db.pluginConfigs.get(params.id!) ?? (() => { throw notFound('配置'); })()),
  },
  {
    method: 'PUT',
    pattern: '/api/v1/plugins/:id/config',
    perm: 'host.plugins:configure',
    fields: ['config', 'expected_revision'],
    handler: (ctx) => {
      const p = getPlugin(ctx.db, ctx.params.id!);
      const cur = ctx.db.pluginConfigs.get(p.plugin_id);
      if (!cur) throw notFound('配置');
      checkRevision(cur.revision, ctx.body.expected_revision);
      if (typeof ctx.body.config !== 'object' || !ctx.body.config) throw invalid('/config', '必须是对象', 'TYPE');
      const next: S['PluginConfig'] = { ...cur, config: ctx.body.config, revision: rev(ctx.db), created_at: nowIso(), applied_at: nowIso() };
      ctx.db.pluginConfigs.set(p.plugin_id, next);
      p.config_revision = next.revision;
      touch(ctx, p, ['/config_revision']);
      return ok(next);
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/plugins/:id/config-schema',
    perm: 'host.plugins:read',
    handler: ({ db, params }) => ok(db.pluginSchemas.get(params.id!) ?? (() => { throw notFound('配置'); })()),
  },
  {
    /* restart 不产生 operation（运行时自身生命周期）；200 返回刷新后的 Plugin，路由写审计 */
    method: 'POST',
    pattern: '/api/v1/plugins/:id/restart',
    perm: 'host.plugins:update',
    fields: ['reason'],
    handler: (ctx) => {
      const p = getPlugin(ctx.db, ctx.params.id!);
      p.runtime = { ...p.runtime, state: 'running', since: nowIso(), restarts: (p.runtime?.restarts ?? 0) + 1 };
      touch(ctx, p, ['/runtime']);
      writeAudit(ctx.db, { actor: actorOf(ctx.user), action: 'host.plugins.restart', subject: `plugins/${p.plugin_id}`, outcome: 'success', request_id: ctx.requestId });
      return ok(p);
    },
  },
  ...(['enable', 'disable'] as const).map(
    (verb): RouteSpec => ({
      method: 'POST',
      pattern: `/api/v1/plugins/:id/${verb}`,
      perm: 'host.plugins:update',
      fields: [],
      handler: (ctx) => {
        const p = getPlugin(ctx.db, ctx.params.id!);
        if (p.builtin && verb === 'disable') throw new MockProblem(409, 'STATE_CONFLICT', '内置应用不能停用');
        return runOperation(ctx, { action: `host.plugins.${verb}`, target: { plugin_id: p.plugin_id }, risk: 'high', job: { steps: [verb === 'enable' ? '启动服务' : '停止服务'] } }, () => {
          p.runtime = verb === 'disable' ? { state: 'stopped', since: nowIso() } : { ...p.runtime, state: 'running', since: nowIso() };
          touch(ctx, p, ['/runtime']);
          return p.runtime;
        });
      },
    }),
  ),
  {
    method: 'DELETE',
    pattern: '/api/v1/plugins/:id',
    perm: 'host.plugins:uninstall',
    handler: (ctx) => {
      const p = getPlugin(ctx.db, ctx.params.id!);
      checkRevision(p.revision, ctx.query.get('expected_revision'));
      if (p.builtin) throw new MockProblem(409, 'STATE_CONFLICT', '内置应用不能卸载');
      const dependents = [...ctx.db.plugins.values()].filter((x) => x.dependencies?.includes(p.plugin_id)).map((x) => x.plugin_id);
      if (dependents.length) throw new MockProblem(409, 'STATE_CONFLICT', '有应用依赖它，需先卸载它们', { dependents: dependents.slice(0, 64) });
      const purge = ctx.query.get('purge_data') === 'true';
      if (purge) {
        const s = ctx.session!;
        if (!s.mfaVerifiedAt || Date.now() - s.mfaVerifiedAt > 15 * 60_000) throw new MockProblem(403, 'MFA_REQUIRED', '删除数据需要最近验证过两步验证');
      }
      return runOperation(ctx, { action: 'host.plugins.uninstall', target: { plugin_id: p.plugin_id }, args: { purge_data: purge }, job: { steps: ['停止服务', '移除文件', purge ? '删除数据' : '保留数据'] } }, () => {
        ctx.db.plugins.delete(p.plugin_id);
        if (purge) ctx.db.pluginConfigs.delete(p.plugin_id);
        changed(ctx.db, `plugins/${p.plugin_id}`, 'delete', actorOf(ctx.user));
        return {};
      });
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/plugins/:id/logs',
    perm: 'host.plugins:logs',
    handler: (ctx) => {
      const p = getPlugin(ctx.db, ctx.params.id!);
      if (ctx.query.get('since_revision')) throw invalid('/since_revision', '日志不支持 since_revision', 'UNSUPPORTED');
      const stream = ctx.query.get('stream');
      if (stream && stream !== 'stdout' && stream !== 'stderr') throw invalid('/stream', '只能是 stdout 或 stderr', 'ENUM');
      const limitRaw = ctx.query.get('limit');
      const limit = limitRaw === null ? 50 : Number(limitRaw);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw invalid('/limit', 'limit 需在 1–100 之间', 'INVALID');
      const all = Array.from({ length: 120 }, (_, i) => ({
        at: nowIso(Date.now() - (120 - i) * 37_000),
        stream: (i % 9 === 0 ? 'stderr' : 'stdout') as 'stdout' | 'stderr',
        line: i % 9 === 0 ? `warn: ${p.name} slow tick ${120 + i}ms` : `info: ${p.plugin_id} tick #${1200 + i} ok`,
      })).filter((l) => !stream || l.stream === stream);
      const offset = Number(Buffer.from(ctx.query.get('cursor') ?? '', 'base64url').toString() || 0) || 0;
      const items = all.slice(offset, offset + limit);
      const more = offset + limit < all.length;
      return ok({ items, next_cursor: more ? Buffer.from(String(offset + limit)).toString('base64url') : undefined, truncated: more });
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/plugins/:id/operations/:op',
    fields: ['payload', 'subject', 'expected_revision', 'plan_id'],
    idempotency: 'none',
    handler: (ctx) => invoke(ctx, ctx.params.id!, ctx.params.op!),
  },
  {
    method: 'POST',
    pattern: '/api/v1/nodes/:node/plugins/:id/instances/:inst/operations/:op',
    fields: ['payload', 'subject', 'expected_revision', 'plan_id'],
    idempotency: 'none',
    handler: (ctx) => invoke(ctx, ctx.params.id!, ctx.params.op!),
  },
];
