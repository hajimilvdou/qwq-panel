// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 请求管线
 * --------------------------------------------------------------------------
 *   场景（?mock= / __mock）→ 离线 / 延迟 / 随机 503 → 路由匹配（404/405）
 *   → 会话（Cookie qwq_session）→ RBAC → 请求体（严格 JSON，未知字段 400）
 *   → CSRF → 幂等（同 key 回放、指纹不同 422、进行中 409）→ 处理器
 * 响应一律带 X-Request-Id 与 Cache-Control: no-store。
 * ========================================================================== */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { compileRoutes, MockProblem, problemBody, type Ctx, type Result } from './http.ts';
import { closeAllStreams } from './events.ts';
import { SCENARIOS } from './scenarios.ts';
import { mockPassword, seed } from './seed.ts';
import { newId, type Db } from './store.ts';
import { pluginAsset, PLUGIN_UI_CSP } from './widgets.ts';
import { authRoutes, cookieOf } from './handlers/auth.ts';
import { userRoutes } from './handlers/users.ts';
import { pluginRoutes } from './handlers/plugins.ts';
import { opsRoutes } from './handlers/ops.ts';
import { agentRoutes } from './handlers/agent.ts';
import { systemRoutes } from './handlers/system.ts';
import type { S } from './http.ts';

/* ------------------------------------------------------------------ RBAC（服务端视角，与真实宿主角色一致） */

const ROLE_PERMS: Record<S['Role'], readonly string[]> = {
  admin: ['*'],
  operator: [
    'host.operations:*',
    'host.account:update',
    'host.plugins:read',
    'host.plugins:update',
    'host.plugins:logs',
    'host.plugins:configure',
    'host.nodes:read',
    'host.delegations:*',
    'host.system:read',
  ],
  viewer: ['host.operations:read', 'host.account:update', 'host.plugins:read', 'host.nodes:read', 'host.system:read'],
};

export function allowed(role: S['Role'], perm: string): boolean {
  const res = perm.split(':')[0];
  return ROLE_PERMS[role].some((p) => p === '*' || p === perm || p === `${res}:*`);
}

/* ------------------------------------------------------------------ 工具 */

const ROUTES = compileRoutes([...authRoutes, ...userRoutes, ...pluginRoutes, ...opsRoutes, ...agentRoutes, ...systemRoutes]);

function send(res: ServerResponse, r: Result, requestId: string): void {
  const headers: Record<string, string> = { 'X-Request-Id': requestId, 'Cache-Control': 'no-store', ...r.headers };
  if (r.body === undefined || r.status === 204) {
    res.writeHead(r.status, headers);
    res.end();
    return;
  }
  const isProblem = r.status >= 400;
  headers['Content-Type'] = isProblem ? 'application/problem+json' : 'application/json; charset=utf-8';
  res.writeHead(r.status, headers);
  res.end(JSON.stringify(r.body));
}

const sendProblem = (res: ServerResponse, p: MockProblem, rid: string, headers: Record<string, string> = {}) =>
  send(res, { status: p.status, body: problemBody(p, rid), headers }, rid);

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ 服务 */

export interface MockServer {
  readonly db: Db;
  handle(req: IncomingMessage, res: ServerResponse, next: () => void): void;
  scenario(name: string): boolean;
  reset(): void;
}

export function createMockServer(password = mockPassword()): MockServer {
  let db = seed(password);

  const swap = (name: string): boolean => {
    const sc = SCENARIOS[name];
    if (!sc) return false;
    const sessions = db.sessions;
    closeAllStreams(db);
    for (const t of db.timers) clearTimeout(t);
    db = seed(password);
    db.scenario = name;
    if (name !== 'fresh') db.sessions = sessions;
    sc.apply(db);
    if (db.flags.sessionTtlMs) for (const s of db.sessions.values()) s.expiresAt = Math.min(s.expiresAt, Date.now() + db.flags.sessionTtlMs);
    return true;
  };

  async function control(req: IncomingMessage, res: ServerResponse, path: string, rid: string) {
    if (req.method === 'GET' && path === '/__mock/state') {
      return send(res, { status: 200, body: { scenario: db.scenario, scenarios: Object.fromEntries(Object.entries(SCENARIOS).map(([k, v]) => [k, v.description])), setup_token: db.setup.token } }, rid);
    }
    if (req.method === 'POST' && path === '/__mock/reset') {
      swap('healthy');
      return send(res, { status: 204 }, rid);
    }
    if (req.method === 'POST' && path === '/__mock/scenario') {
      let name = '';
      try {
        name = JSON.parse((await readBody(req)).toString() || '{}').name;
      } catch {
        /* 下面统一 400 */
      }
      if (!swap(name)) return sendProblem(res, new MockProblem(400, 'VALIDATION_FAILED', `未知场景：${name}`), rid);
      return send(res, { status: 200, body: { scenario: name } }, rid);
    }
    return sendProblem(res, new MockProblem(404, 'NOT_FOUND'), rid);
  }

  async function api(req: IncomingMessage, res: ServerResponse, url: URL, rid: string) {
    const method = (req.method ?? 'GET').toUpperCase();
    const path = url.pathname;
    const f = db.flags;

    if (f.offline) return sendProblem(res, new MockProblem(503, 'UNAVAILABLE', '宿主不可用'), rid, { 'Retry-After': '5' });
    if (f.delayMs) await sleep(f.delayMs);
    if (f.flakyRate && path !== '/api/v1/events' && Math.random() < f.flakyRate) {
      return sendProblem(res, new MockProblem(503, 'UNAVAILABLE', '随机故障（flaky 场景）'), rid, { 'Retry-After': '1' });
    }

    /* 路由匹配：路径命中但方法不对 → 405 */
    let route: (typeof ROUTES)[number] | undefined;
    let params: Record<string, string> = {};
    let pathHit = false;
    for (const r of ROUTES) {
      const m = r.re.exec(path);
      if (!m) continue;
      pathHit = true;
      if (r.method !== method) continue;
      route = r;
      params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1] ?? '')]));
      break;
    }
    if (!route) return sendProblem(res, pathHit ? new MockProblem(405, 'METHOD_NOT_ALLOWED') : new MockProblem(404, 'NOT_FOUND', '没有这个接口'), rid);

    /* 会话 */
    const sid = cookieOf({ req } as Ctx);
    let session = sid ? db.sessions.get(sid) ?? null : null;
    if (session && session.expiresAt < Date.now()) {
      db.sessions.delete(session.sid);
      session = null;
    }
    const user = session ? db.users.get(session.userId) ?? null : null;
    if (session && (!user || user.disabled)) session = null;
    if (!route.public && !session) return sendProblem(res, new MockProblem(401, 'UNAUTHENTICATED', '请先登录'), rid);
    if (route.perm && user && !allowed(user.role, route.perm)) return sendProblem(res, new MockProblem(403, 'PERMISSION_DENIED', '没有权限'), rid);

    /* 请求体 */
    const mutating = method !== 'GET' && method !== 'HEAD';
    let body: any = {};
    const raw = mutating ? await readBody(req) : Buffer.alloc(0);
    const type = req.headers['content-type'] ?? '';
    if (type.startsWith('multipart/form-data')) body = raw;
    else if (raw.length) {
      if (!type.includes('application/json')) return sendProblem(res, new MockProblem(415, 'UNSUPPORTED_MEDIA_TYPE'), rid);
      try {
        body = JSON.parse(raw.toString('utf8'));
      } catch {
        return sendProblem(res, new MockProblem(400, 'VALIDATION_FAILED', '请求体不是合法 JSON'), rid);
      }
      if (route.fields && body && typeof body === 'object') {
        const unknown = Object.keys(body).filter((k) => !route.fields!.includes(k));
        if (unknown.length) {
          return sendProblem(res, new MockProblem(400, 'VALIDATION_FAILED', '包含未知字段', { violations: unknown.map((k) => ({ in: 'body', pointer: `/${k}`, message: '未知字段', code: 'UNKNOWN_FIELD' })) }), rid);
        }
      }
    }

    /* CSRF：带会话的变更请求 */
    if (mutating && session && !route.public && req.headers['x-csrf-token'] !== session.csrf) {
      return sendProblem(res, new MockProblem(403, 'CSRF_FAILED', 'CSRF 令牌无效'), rid);
    }

    /* 幂等 */
    const key = req.headers['idempotency-key'] as string | undefined;
    if (mutating && !key && route.idempotency !== 'none') {
      return sendProblem(res, new MockProblem(400, 'VALIDATION_FAILED', '缺少 Idempotency-Key', { violations: [{ in: 'header', pointer: '/Idempotency-Key', message: '缺少 Idempotency-Key 头', code: 'IDEMPOTENCY_KEY_REQUIRED' }] }), rid);
    }
    const idemId = key ? `${session?.userId ?? 'anon'}:${key}` : '';
    const fingerprint = `${method} ${path}${url.search} ${Buffer.isBuffer(body) ? raw.length : JSON.stringify(body)}`;
    if (mutating && key) {
      const rec = db.idem.get(idemId);
      if (rec) {
        if (rec.fingerprint !== fingerprint) return sendProblem(res, new MockProblem(422, 'IDEMPOTENCY_KEY_REUSED', '同一个 key 用在了不同的请求上'), rid);
        if (!rec.done) return sendProblem(res, new MockProblem(409, 'IDEMPOTENCY_IN_PROGRESS', '上一次请求还在处理'), rid, { 'Retry-After': '1' });
        return send(res, { status: rec.status, body: rec.body, headers: { 'Idempotency-Replayed': 'true' } }, rid);
      }
      db.idem.set(idemId, { fingerprint, status: 0, body: undefined, done: false });
    }

    const ctx: Ctx = { req, res, method, path, params, query: url.searchParams, body, db, session, user, requestId: rid, idempotencyKey: key };
    try {
      const out = await route.handler(ctx);
      if (out === 'stream') return;
      if (mutating && key) {
        /* 机密例外：回放时剔除一次性凭据（不持久化） */
        let stored = out.body;
        if (route.secretFields && stored && typeof stored === 'object') {
          stored = Object.fromEntries(Object.entries(stored).filter(([k]) => !route!.secretFields!.includes(k)));
        }
        db.idem.set(idemId, { fingerprint, status: out.status, body: stored, done: true });
      }
      send(res, out, rid);
    } catch (err) {
      if (mutating && key) db.idem.delete(idemId);
      if (err instanceof MockProblem) return sendProblem(res, err, rid);
      console.error('[mock] handler crashed', err);
      sendProblem(res, new MockProblem(500, 'INTERNAL', '模拟后端出错'), rid);
    }
  }

  function staticAsset(req: IncomingMessage, res: ServerResponse, path: string, rid: string) {
    const m = /^\/plugin-ui\/([^/]+)\/([^/]+)\/(.+)$/.exec(path);
    /* 静态资源 404/405 是纯文本，不是 problem+json（与真实宿主一致） */
    const plain = (status: number, text: string) => {
      res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'X-Request-Id': rid });
      res.end(req.method === 'HEAD' ? undefined : text);
    };
    if (req.method !== 'GET' && req.method !== 'HEAD') return plain(405, 'method not allowed');
    const asset = m ? pluginAsset(db, decodeURIComponent(m[1]!), decodeURIComponent(m[2]!), m[3]!) : null;
    if (!asset) return plain(404, 'not found');
    res.writeHead(200, {
      'Content-Type': asset.type,
      'Content-Security-Policy': PLUGIN_UI_CSP,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'public, max-age=31536000, immutable',
      'X-Request-Id': rid,
    });
    res.end(req.method === 'HEAD' ? undefined : asset.body);
  }

  return {
    get db() {
      return db;
    },
    scenario: swap,
    reset: () => void swap('healthy'),
    handle(req, res, next) {
      const url = new URL(req.url ?? '/', 'http://mock.local');
      const path = url.pathname;
      const rid = newId('req');
      const fail = (err: unknown) => {
        console.error('[mock]', err);
        if (!res.headersSent) sendProblem(res, new MockProblem(500, 'INTERNAL'), rid);
      };
      if (path.startsWith('/__mock/')) return void control(req, res, path, rid).catch(fail);
      if (path.startsWith('/plugin-ui/')) return staticAsset(req, res, path, rid);
      if (path.startsWith('/api/') || path === '/healthz' || path === '/readyz') return void api(req, res, url, rid).catch(fail);
      /* 页面请求带 ?mock=<场景>：先切场景再交给 Vite */
      const want = url.searchParams.get('mock');
      if (want && req.method === 'GET' && want !== db.scenario) swap(want);
      next();
    },
  };
}
