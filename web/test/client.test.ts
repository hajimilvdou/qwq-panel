// SPDX-License-Identifier: AGPL-3.0-only
/* API 客户端：重试与幂等键复用、CSRF 刷新重放、401 分流、Retry-After */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  NetworkError,
  buildUrl,
  parseRetryAfter,
  request,
  setCsrfRefresher,
  setCsrfToken,
  setUnauthenticatedHandler,
} from '$api/client';
import { upload } from '$api/upload';

type Call = { url: string; init: RequestInit };
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': status >= 400 ? 'application/problem+json' : 'application/json', ...headers },
  });
const problem = (status: number, code: string, extra: object = {}) =>
  json(status, { type: 'x', title: 'x', status, code, retryable: status >= 500, request_id: 'req_1', ...extra });

let calls: Call[];
function stubFetch(...responses: (Response | Error)[]) {
  calls = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      const r = responses.shift();
      if (!r) throw new Error('no more responses');
      if (r instanceof Error) throw r;
      return r;
    }),
  );
}
const header = (c: Call, k: string) => (c.init.headers as Record<string, string>)[k];

beforeEach(() => {
  vi.useFakeTimers();
  setCsrfToken('tok-1');
  setUnauthenticatedHandler(null);
  setCsrfRefresher(null);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('buildUrl', () => {
  it('跳过空值，数组用逗号', () => {
    expect(buildUrl('/a', { x: 1, y: '', z: undefined, s: ['A', 'B'], e: [] })).toBe('/a?x=1&s=A%2CB');
  });
});

describe('parseRetryAfter', () => {
  it('秒数与 HTTP 日期', () => {
    expect(parseRetryAfter('7')).toBe(7);
    expect(parseRetryAfter(new Date(10_000).toUTCString(), 4_000)).toBe(6);
    expect(parseRetryAfter('garbage')).toBeUndefined();
    expect(parseRetryAfter(null)).toBeUndefined();
  });
});

describe('request', () => {
  it('变更请求带 CSRF 与幂等键；503 重试时复用同一个键', async () => {
    stubFetch(problem(503, 'UNAVAILABLE'), json(200, { ok: 1 }));
    const p = request('POST', '/api/v1/x', { body: {}, idempotency: 'web-k1' });
    await vi.runAllTimersAsync();
    const r = await p;
    expect(r.data).toEqual({ ok: 1 });
    expect(calls).toHaveLength(2);
    expect(header(calls[0]!, 'Idempotency-Key')).toBe('web-k1');
    expect(header(calls[1]!, 'Idempotency-Key')).toBe('web-k1');
    expect(header(calls[0]!, 'X-CSRF-Token')).toBe('tok-1');
  });

  it('不带幂等键的变更不自动重试', async () => {
    stubFetch(problem(503, 'UNAVAILABLE'));
    await expect(request('POST', '/api/v1/x', { body: {} })).rejects.toBeInstanceOf(ApiError);
    expect(calls).toHaveLength(1);
  });

  it('429 读取 HTTP Retry-After 头作为等待时间', async () => {
    stubFetch(new Response('', { status: 429, headers: { 'retry-after': '2' } }), json(200, {}));
    const p = request('GET', '/api/v1/y');
    await vi.advanceTimersByTimeAsync(1900);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(200);
    await p;
    expect(calls).toHaveLength(2);
  });

  it('retryBudgetMs：Retry-After 超出预算时不等待，立即抛错', async () => {
    stubFetch(problem(503, 'UNAVAILABLE', { retry_after: 5 }), json(200, {}));
    await expect(request('GET', '/api/v1/setup', { retryBudgetMs: 1000 })).rejects.toBeInstanceOf(ApiError);
    expect(calls).toHaveLength(1);
  });

  it('CSRF_FAILED：刷新令牌后用同一个键重放一次', async () => {
    stubFetch(problem(403, 'CSRF_FAILED'), json(200, { done: true }));
    setCsrfRefresher(async () => setCsrfToken('tok-2'));
    const r = await request('POST', '/api/v1/z', { body: {}, idempotency: 'web-k2' });
    expect(r.data).toEqual({ done: true });
    expect(header(calls[1]!, 'X-CSRF-Token')).toBe('tok-2');
    expect(header(calls[1]!, 'Idempotency-Key')).toBe('web-k2');
  });

  it('CSRF 重放后仍失败则抛错，不无限循环', async () => {
    stubFetch(problem(403, 'CSRF_FAILED'), problem(403, 'CSRF_FAILED'));
    setCsrfRefresher(async () => {});
    await expect(request('POST', '/api/v1/z', { body: {}, idempotency: 'k' })).rejects.toMatchObject({ code: 'CSRF_FAILED' });
    expect(calls).toHaveLength(2);
  });

  it('401 触发全局处理；登录类路由的 401 不触发', async () => {
    const onUnauth = vi.fn();
    setUnauthenticatedHandler(onUnauth);
    stubFetch(problem(401, 'UNAUTHENTICATED'), problem(401, 'UNAUTHENTICATED'));
    await expect(request('GET', '/api/v1/plugins')).rejects.toBeInstanceOf(ApiError);
    expect(onUnauth).toHaveBeenCalledTimes(1);
    await expect(request('POST', '/api/v1/sessions', { body: {} })).rejects.toBeInstanceOf(ApiError);
    expect(onUnauth).toHaveBeenCalledTimes(1);
  });

  it('网络错误重试耗尽后抛 NetworkError', async () => {
    stubFetch(new TypeError('x'), new TypeError('x'), new TypeError('x'));
    const p = request('GET', '/api/v1/n').catch((e) => e);
    await vi.runAllTimersAsync();
    expect(await p).toBeInstanceOf(NetworkError);
    expect(calls).toHaveLength(3);
  });

  it('problem 字段映射到 ApiError', async () => {
    stubFetch(problem(400, 'VALIDATION_FAILED', { violations: [{ in: 'body', pointer: '/name', code: 'REQUIRED', message: '必填' }] }));
    const err = (await request('POST', '/api/v1/v', { body: {} }).catch((e) => e)) as ApiError;
    expect(err.code).toBe('VALIDATION_FAILED');
    expect(err.fieldErrors()).toEqual({ '/name': '必填' });
    expect(err.requestId).toBe('req_1');
  });
});

describe('upload', () => {
  it('403 CSRF_FAILED 自动刷新 CSRF 令牌并单次重试', async () => {
    const sentTokens: string[] = [];
    let attempt = 0;
    class FakeXHR {
      status = 0;
      statusText = '';
      responseText = '';
      withCredentials = false;
      upload: { onprogress: ((e: ProgressEvent) => void) | null } = { onprogress: null };
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onabort: (() => void) | null = null;
      #headers: Record<string, string> = {};
      open() {}
      setRequestHeader(k: string, v: string) {
        this.#headers[k] = v;
      }
      getResponseHeader(k: string) {
        return k.toLowerCase() === 'content-type' ? 'application/json' : null;
      }
      abort() {}
      send() {
        sentTokens.push(this.#headers['X-CSRF-Token'] ?? '');
        attempt++;
        if (attempt === 1) {
          this.status = 403;
          this.responseText = JSON.stringify({ code: 'CSRF_FAILED', title: 'csrf', status: 403 });
        } else {
          this.status = 201;
          this.responseText = JSON.stringify({ upload_id: 'up_1' });
        }
        queueMicrotask(() => this.onload?.());
      }
    }
    vi.stubGlobal('XMLHttpRequest', FakeXHR);
    setCsrfToken('old-csrf');
    setCsrfRefresher(async () => setCsrfToken('fresh-csrf'));

    const res = await upload<{ upload_id: string }>('/api/v1/plugin-packages', new FormData());
    expect(res.status).toBe(201);
    expect(res.data).toEqual({ upload_id: 'up_1' });
    expect(sentTokens).toEqual(['old-csrf', 'fresh-csrf']);
  });
});
