// SPDX-License-Identifier: AGPL-3.0-only
/* 模拟后端关键路径：登录与 CSRF、幂等、未知字段、审批流、事件流续传、场景 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createMockServer, type MockServer } from '../mock/server.ts';

const PW = 'Mock-Password-2026';
let mock: MockServer;
let server: Server;
let base = '';
let cookie = '';
let csrf = '';

async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(base + path, {
    method,
    headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const set = res.headers.get('set-cookie');
  if (set) cookie = set.split(';')[0]!;
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : undefined };
}

async function login(username = 'alice') {
  cookie = '';
  const r = await call('POST', '/api/v1/sessions', { username, password: PW });
  csrf = r.body.csrf_token;
  return r;
}

const write = (method: string, path: string, body: unknown, key = 'k-' + Math.random()) =>
  call(method, path, body, { 'x-csrf-token': csrf, 'idempotency-key': key });

beforeAll(async () => {
  mock = createMockServer(PW);
  server = createServer((req, res) => mock.handle(req, res, () => res.writeHead(404).end()));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => mock.reset());

describe('mock backend', () => {
  it('未登录 401（problem+json，带 request_id 与 no-store）', async () => {
    cookie = '';
    const r = await call('GET', '/api/v1/plugins');
    expect(r.status).toBe(401);
    expect(r.headers.get('content-type')).toContain('application/problem+json');
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(r.body).toMatchObject({ code: 'UNAUTHENTICATED', retryable: false });
    expect(r.body.request_id).toBe(r.headers.get('x-request-id'));
  });

  it('登录：错误口令 401；成功返回会话与 HttpOnly Cookie', async () => {
    expect((await call('POST', '/api/v1/sessions', { username: 'alice', password: 'nope' })).status).toBe(401);
    const r = await login();
    expect(r.status).toBe(200);
    expect(r.body.user.username).toBe('alice');
    expect(cookie).toMatch(/^qwq_session=/);
  });

  it('变更请求校验 CSRF 与 Idempotency-Key', async () => {
    await login();
    const body = { expected_revision: 'r0', display_name: 'A' };
    expect((await call('PATCH', '/api/v1/sessions/current/profile', body, { 'idempotency-key': 'k1' })).body.code).toBe('CSRF_FAILED');
    expect((await call('PATCH', '/api/v1/sessions/current/profile', body, { 'x-csrf-token': csrf })).status).toBe(400);
  });

  it('未知字段 400；expected_revision 不符 409', async () => {
    await login();
    const unknown = await write('PATCH', '/api/v1/sessions/current/profile', { display_name: 'A', expected_revision: 'r1', evil: 1 });
    expect(unknown.status).toBe(400);
    expect(unknown.body.violations[0].pointer).toBe('/evil');
    const stale = await write('PATCH', '/api/v1/sessions/current/profile', { display_name: 'A', expected_revision: 'r-old' });
    expect(stale.body.code).toBe('REVISION_CONFLICT');
  });

  it('幂等：同 key 回放同一结果；同 key 不同请求 422', async () => {
    await login();
    const a = await write('POST', '/api/v1/users', { username: 'zed', role: 'viewer' }, 'same');
    const b = await write('POST', '/api/v1/users', { username: 'zed', role: 'viewer' }, 'same');
    expect(a.status).toBe(200);
    expect(b.body).toEqual(a.body);
    expect(b.headers.get('idempotency-replayed')).toBe('true');
    const c = await write('POST', '/api/v1/users', { username: 'other', role: 'viewer' }, 'same');
    expect(c.body.code).toBe('IDEMPOTENCY_KEY_REUSED');
  });

  it('RBAC：viewer 不能创建用户', async () => {
    await login('carol');
    expect((await write('POST', '/api/v1/users', { username: 'q', role: 'viewer' })).body.code).toBe('PERMISSION_DENIED');
  });

  it('审批流：批准后操作完成，重复决定 409', async () => {
    await login();
    const pending = await call('GET', '/api/v1/approvals?status=PENDING');
    expect(pending.body.items.map((a: { approval_id: string }) => a.approval_id).sort()).toEqual(['apr_create_erin', 'apr_firewall']);
    const a = pending.body.items.find((x: { approval_id: string }) => x.approval_id === 'apr_create_erin');
    const ok = await write('POST', '/api/v1/approvals/apr_create_erin/decision', { decision: 'approve', expected_revision: a.revision });
    expect(ok.body.status).toBe('APPROVED');
    expect((await call('GET', '/api/v1/operations/op_create_erin')).body.status).toBe('SUCCEEDED');
    expect((await call('GET', '/api/v1/users/usr_erin')).status).toBe(200);
    const again = await write('POST', '/api/v1/approvals/apr_create_erin/decision', { decision: 'approve', expected_revision: a.revision });
    expect(again.body.code).toBe('STATE_CONFLICT');
  });

  it('小组件只读调用返回固定形状', async () => {
    await login();
    const r = await call('POST', '/api/v1/nodes/local/plugins/com.qwq.monitor/instances/default/operations/overview.cpu', { payload: {} }, { 'x-csrf-token': csrf });
    expect(r.body.status).toBe('SUCCEEDED');
    expect(r.body.result).toMatchObject({ unit: '%', level: expect.any(String) });
  });

  it('事件流：ready 帧 + 续传写入后的事件', async () => {
    await login();
    const head = mock.db.seq;
    await write('PATCH', '/api/v1/sessions/current/profile', { display_name: 'Alice 2', expected_revision: mock.db.users.get('usr_alice')!.revision });
    const ctrl = new AbortController();
    const res = await fetch(`${base}/api/v1/events?topics=resource.changed`, { headers: { cookie, 'last-event-id': String(head) }, signal: ctrl.signal });
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    const reader = res.body!.getReader();
    let text = '';
    while (!text.includes('users/usr_alice')) text += new TextDecoder().decode((await reader.read()).value);
    ctrl.abort();
    expect(text).toContain('event: ready');
    expect(text).toMatch(/id: \d+\ndata: \{.*"type":"resource.changed"/);
  });

  it('场景：fresh 未初始化、viewer 降权；?mock= 在页面请求时切换', async () => {
    expect(mock.scenario('fresh')).toBe(true);
    expect((await call('GET', '/api/v1/setup')).body.initialized).toBe(false);
    mock.reset();
    await new Promise<void>((resolve) => mock.handle({ url: '/apps?mock=viewer', method: 'GET', headers: {} } as never, {} as never, resolve));
    expect(mock.db.scenario).toBe('viewer');
    expect(mock.db.users.get('usr_alice')!.role).toBe('viewer');
    expect(mock.scenario('nope')).toBe(false);
  });
});
