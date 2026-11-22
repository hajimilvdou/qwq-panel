// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · HTTP 基础：路由表、上下文、problem+json
 * --------------------------------------------------------------------------
 * 与真实宿主保持同构的部分集中在这里：
 *   problem+json（code/retryable/request_id）、X-Request-Id、Cache-Control: no-store、
 *   未知字段 400、expected_revision 冲突 409。
 * CSRF、幂等、会话在 server.ts 的请求管线里处理。
 * ========================================================================== */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Db, MockSession } from './store.ts';
import type { components } from '../shell/src/api/schema.d.ts';

export type S = components['schemas'];
export type ProblemCode = S['ProblemCode'];

/* ------------------------------------------------------------------ 错误 */

export class MockProblem extends Error {
  constructor(
    readonly status: number,
    readonly code: ProblemCode,
    readonly detail?: string,
    readonly extra: Partial<S['Problem']> = {},
  ) {
    super(code);
  }
}

const RETRYABLE = new Set<ProblemCode>([
  'IDEMPOTENCY_IN_PROGRESS',
  'RATE_LIMITED',
  'UNAVAILABLE',
  'NODE_OFFLINE',
  'PLUGIN_UNAVAILABLE',
  'TIMEOUT',
  'INTERNAL',
]);

export function problemBody(p: MockProblem, requestId: string): S['Problem'] {
  return {
    type: `https://qwq.dev/problems/${p.code.toLowerCase().replace(/_/g, '-')}`,
    title: p.code.replace(/_/g, ' ').toLowerCase(),
    status: p.status,
    code: p.code as S['ProblemCode'],
    retryable: RETRYABLE.has(p.code),
    request_id: requestId,
    ...(p.detail ? { detail: p.detail } : {}),
    ...p.extra,
  };
}

export const notFound = (what = '资源') => new MockProblem(404, 'NOT_FOUND', `${what}不存在`);
export const denied = (detail = '没有权限') => new MockProblem(403, 'PERMISSION_DENIED', detail);
export const invalid = (pointer: string, message: string, code = 'INVALID') =>
  new MockProblem(400, 'VALIDATION_FAILED', '请求参数不合法', { violations: [{ in: 'body', pointer, message, code }] });

/* ------------------------------------------------------------------ 路由 */

export interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  method: string;
  path: string;
  params: Record<string, string>;
  query: URLSearchParams;
  body: any;
  db: Db;
  session: MockSession | null;
  /** session 对应的用户（登录路由为 null） */
  user: S['User'] | null;
  requestId: string;
  idempotencyKey: string | undefined;
}

export interface Result {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}

export type Handler = (ctx: Ctx) => Result | Promise<Result> | 'stream';

export interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  pattern: string;
  /** public：匿名可访问；默认需要会话 */
  public?: boolean;
  /** 所需权限（按内置角色映射判定） */
  perm?: string;
  /** 允许的请求体顶层字段；给出即严格校验（未知字段 400） */
  fields?: readonly string[];
  /** 变更是否要求 Idempotency-Key（非 GET 默认 required） */
  idempotency?: 'required' | 'none';
  /** 机密例外：幂等回放时剔除这些响应字段（不持久化一次性凭据） */
  secretFields?: readonly string[];
  handler: Handler;
}

export interface CompiledRoute extends RouteSpec {
  re: RegExp;
  keys: string[];
}

export function compileRoutes(specs: readonly RouteSpec[]): CompiledRoute[] {
  return specs.map((s) => {
    const keys: string[] = [];
    const src = s.pattern
      .split('/')
      .map((seg) => {
        if (seg === '*') {
          keys.push('rest');
          return '(.*)';
        }
        if (seg.startsWith(':')) {
          keys.push(seg.slice(1));
          return '([^/]+)';
        }
        return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      })
      .join('/');
    return { ...s, re: new RegExp(`^${src}$`), keys };
  });
}

export const ok = (body?: unknown, status = 200): Result => ({ status, body });
export const created = (body: unknown): Result => ({ status: 201, body });
export const accepted = (body: unknown): Result => ({ status: 202, body });
export const noContent = (): Result => ({ status: 204 });

/* ------------------------------------------------------------------ 校验小工具 */

/** expected_revision 必填且必须匹配 */
export function checkRevision(current: string, expected: unknown): void {
  if (typeof expected !== 'string' || !expected) throw invalid('/expected_revision', '缺少 expected_revision', 'REQUIRED');
  if (expected !== current) throw new MockProblem(409, 'REVISION_CONFLICT', '资源已被修改');
}

export function requireString(body: any, key: string, max = 256): string {
  const v = body?.[key];
  if (typeof v !== 'string' || !v.trim()) throw invalid(`/${key}`, '必填', 'REQUIRED');
  if (v.length > max) throw invalid(`/${key}`, `不能超过 ${max} 个字符`, 'TOO_LONG');
  return v;
}

/** 列表分页：cursor 为偏移量的不透明编码 */
export function paginate<T>(items: readonly T[], q: URLSearchParams, def = 50, max = 200) {
  const limit = Math.min(max, Math.max(1, Number(q.get('limit')) || def));
  const offset = Number(Buffer.from(q.get('cursor') ?? '', 'base64url').toString() || 0) || 0;
  const page = items.slice(offset, offset + limit);
  const next = offset + limit < items.length ? Buffer.from(String(offset + limit)).toString('base64url') : undefined;
  return { page, next };
}
