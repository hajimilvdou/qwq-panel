// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * HTTP 客户端（ADR-0006 D1 的"手写薄封装"）
 * --------------------------------------------------------------------------
 *   - 非 GET 请求带 X-CSRF-Token（令牌只放内存）
 *   - 变更请求带 Idempotency-Key；同一次用户动作的重试复用同一个 key
 *   - application/problem+json → ApiError（按 code 分支，不看 title）
 *   - 401 交给会话层统一处理（跳登录页并记住回跳地址）
 *   - CSRF_FAILED：经会话层取新令牌，用同一个 Idempotency-Key 重试一次
 *   - GET 与带 key 的变更在网络错误、429、502–504 上有限重试
 *     （等待时间取 problem.retry_after，其次 HTTP Retry-After 头，再次指数退避）
 * ========================================================================== */
import type { FieldViolation, Operation, OperationOutcome, OperationStatus, Problem, ProblemCode } from './types';

/* ------------------------------------------------------------------ 错误 */

export class ApiError extends Error {
  readonly status: number;
  /** 已知码见 ProblemCode；后端新增的码按字符串兜底，非 problem 响应为 HTTP_<status> */
  readonly code: ProblemCode | (string & {});
  readonly problem: Problem | null;
  readonly retryable: boolean;
  readonly retryAfter: number | undefined;

  constructor(status: number, problem: Problem | null, fallback: string, retryAfterHeader?: number) {
    super(problem?.detail || problem?.title || fallback);
    this.name = 'ApiError';
    this.status = status;
    this.problem = problem;
    this.code = problem?.code ?? (status >= 500 ? 'INTERNAL' : 'HTTP_' + status);
    this.retryable = problem?.retryable ?? status >= 500;
    this.retryAfter = problem?.retry_after ?? retryAfterHeader;
  }

  get requestId(): string | undefined {
    return this.problem?.request_id || undefined;
  }

  get violations(): FieldViolation[] {
    return this.problem?.violations ?? [];
  }

  /** 按 JSON Pointer 取字段错误：{ '/password': '至少 12 个字符' } */
  fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const v of this.violations) {
      if (!(v.pointer in out)) out[v.pointer] = v.message;
    }
    return out;
  }
}

/** 请求没有到达服务器（断网、DNS、TLS、被浏览器拦截） */
export class NetworkError extends Error {
  constructor(cause: unknown) {
    super('network');
    this.name = 'NetworkError';
    this.cause = cause;
  }
}

/* ------------------------------------------------------------------ 会话钩子 */

let csrfToken: string | null = null;
let onUnauthenticated: (() => void) | null = null;
let refreshCsrf: (() => Promise<void>) | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}
export function setUnauthenticatedHandler(fn: (() => void) | null): void {
  onUnauthenticated = fn;
}
/** 会话层注册：重新 GET /sessions/current 并 setCsrfToken。CSRF_FAILED 时调用 */
export function setCsrfRefresher(fn: (() => Promise<void>) | null): void {
  refreshCsrf = fn;
}
/** 供 upload.ts 读取当前会话钩子（不泄露给业务层） */
export function getAuthHooks() {
  return { csrfToken, onUnauthenticated, refreshCsrf };
}

/** 这些路由的 401 是正常业务结果（口令错、令牌错），不触发全局登出 */
const SILENT_401: ReadonlySet<string> = new Set([
  '/api/v1/sessions',
  '/api/v1/sessions/mfa',
  '/api/v1/setup',
  '/api/v1/enrollments',
]);

/* ------------------------------------------------------------------ 请求 */

export type QueryValue = string | number | boolean | undefined | null | readonly string[];

export interface RequestOptions {
  query?: Record<string, QueryValue>;
  body?: unknown;
  /** true：生成新 key；字符串：复用调用方保存的 key（重试同一动作） */
  idempotency?: boolean | string;
  signal?: AbortSignal;
  headers?: Record<string, string>;
  /** 重试等待总预算（毫秒）；下一次等待会超出预算时直接抛错。冷启动用它尽快给出离线态 */
  retryBudgetMs?: number;
}

export interface ApiResponse<T> {
  status: number;
  data: T;
  headers: Headers;
}

export function newIdempotencyKey(): string {
  return 'web-' + crypto.randomUUID();
}

export function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  if (!query) return path;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      if (v.length) qs.set(k, v.join(','));
    } else {
      qs.set(k, String(v));
    }
  }
  const s = qs.toString();
  return s ? `${path}?${s}` : path;
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(t);
        reject(signal.reason);
      },
      { once: true },
    );
  });

async function parseProblem(res: Response): Promise<Problem | null> {
  const type = res.headers.get('content-type') ?? '';
  if (!type.includes('json')) return null;
  try {
    return (await res.json()) as Problem;
  } catch {
    return null;
  }
}

/** Retry-After 头：秒数或 HTTP 日期 */
export function parseRetryAfter(value: string | null, now = Date.now()): number | undefined {
  if (!value) return undefined;
  const n = Number(value);
  if (Number.isFinite(n) && n >= 0) return n;
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - now) / 1000));
}

function retryDelay(attempt: number, retryAfter?: number): number {
  if (retryAfter !== undefined) return Math.min(retryAfter, 30) * 1000;
  const base = 400 * 2 ** attempt;
  return base * (0.8 + Math.random() * 0.4);
}

export async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<ApiResponse<T>> {
  const url = buildUrl(path, opts.query);
  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers };
  const mutating = method !== 'GET' && method !== 'HEAD';
  let body: BodyInit | undefined;

  if (opts.body !== undefined) {
    if (opts.body instanceof FormData) {
      body = opts.body;
    } else {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }
  }
  if (mutating && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  if (opts.idempotency) {
    headers['Idempotency-Key'] = typeof opts.idempotency === 'string' ? opts.idempotency : newIdempotencyKey();
  }

  /* 只有可安全重放的请求才自动重试：GET，或带幂等键的变更 */
  const retriable = !mutating || Boolean(opts.idempotency);
  const maxAttempts = retriable ? 3 : 1;

  let csrfRetried = false;
  let budget = opts.retryBudgetMs ?? Infinity;
  /* 还能重试吗：次数与等待预算都够才扣减并返回等待时长，否则 null */
  const nextWait = (attempt: number, retryAfter?: number): number | null => {
    if (attempt + 1 >= maxAttempts) return null;
    const wait = retryDelay(attempt, retryAfter);
    if (wait > budget) return null;
    budget -= wait;
    return wait;
  };

  for (let attempt = 0; ; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers,
        body,
        credentials: 'same-origin',
        cache: 'no-store',
        signal: opts.signal,
      });
    } catch (err) {
      if (opts.signal?.aborted) throw err;
      const wait = nextWait(attempt);
      if (wait !== null) {
        await sleep(wait, opts.signal);
        continue;
      }
      throw new NetworkError(err);
    }

    if (res.ok) {
      let data: unknown = undefined;
      if (res.status !== 204) {
        const type = res.headers.get('content-type') ?? '';
        data = type.includes('json') ? await res.json() : await res.text();
      }
      return { status: res.status, data: data as T, headers: res.headers };
    }

    const problem = await parseProblem(res);
    const error = new ApiError(
      res.status,
      problem,
      res.statusText || 'HTTP ' + res.status,
      parseRetryAfter(res.headers.get('retry-after')),
    );

    if (res.status === 401 && !SILENT_401.has(path)) {
      onUnauthenticated?.();
      throw error;
    }
    /* 令牌过期或被轮换：取新令牌后以同一个 key 重放一次，不计入重试次数 */
    if (error.code === 'CSRF_FAILED' && mutating && refreshCsrf && !csrfRetried) {
      csrfRetried = true;
      await refreshCsrf();
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
      attempt--;
      continue;
    }
    const transient =
      res.status === 429 ||
      res.status === 502 ||
      res.status === 503 ||
      res.status === 504 ||
      error.code === 'IDEMPOTENCY_IN_PROGRESS';
    const wait = retriable && transient ? nextWait(attempt, error.retryAfter) : null;
    if (wait !== null) {
      await sleep(wait, opts.signal);
      continue;
    }
    throw error;
  }
}

export const http = {
  get: <T>(path: string, opts?: Omit<RequestOptions, 'body'>) => request<T>('GET', path, opts),
  post: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('POST', path, { ...opts, body }),
  put: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('PUT', path, { ...opts, body }),
  patch: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('PATCH', path, { ...opts, body }),
  del: <T>(path: string, opts?: RequestOptions) => request<T>('DELETE', path, opts),
};

/* 上传（XHR 进度 + CSRF 重试）见 ./upload.ts，避免进入首屏包 */

/* ------------------------------------------------------------------ Operation 结果归一 */

/**
 * 变更类路由返回 200 + OperationOutcome（已完成）或 202 + Operation（进行中、待审批）。
 * 统一成一个形状，调用方只看 status。
 */
export interface OpResult {
  operationId: string;
  status: OperationStatus;
  approvalId?: string;
  result?: unknown;
  error?: Problem;
  operation?: Operation;
}

export function toOpResult(resp: ApiResponse<Operation | OperationOutcome>): OpResult {
  const d = resp.data;
  return {
    operationId: d.operation_id,
    status: d.status,
    approvalId: d.approval_id,
    result: d.result,
    error: d.error,
    operation: resp.status === 202 ? (d as Operation) : undefined,
  };
}

export const TERMINAL: ReadonlySet<OperationStatus> = new Set([
  'SUCCEEDED',
  'FAILED',
  'CANCELED',
  'REJECTED',
  'EXPIRED',
] as OperationStatus[]);
