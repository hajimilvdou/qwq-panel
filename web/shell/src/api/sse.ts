// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * SSE 读取器
 * --------------------------------------------------------------------------
 * 用 fetch + ReadableStream 而不是 EventSource：
 *   - 可以显式带 Last-Event-ID（页面刷新后续传）
 *   - 能拿到 HTTP 状态与 problem+json（401 交给会话层，403/404 不重连）
 *   - 心跳看门狗：默认 45 秒没有任何字节就重连
 *   - 退避：3s 起（服务端 retry: 为下限）指数到 30s，±20% 抖动
 *   - 429：按 problem.retry_after / Retry-After 等待
 *
 * 帧解析单独导出为 createSseParser()，便于测试与复用（会话流同样用它）。
 * 调用方自行记录"最后一个事件 ID"：控制帧（ready/heartbeat/resync）不带 id。
 * ========================================================================== */
import { ApiError, parseRetryAfter } from './client';
import type { Problem } from './types';

export interface SseFrame {
  event?: string;
  id?: string;
  data: string;
}

export type SseState = 'connecting' | 'open' | 'reconnecting' | 'closed';

export interface SseOptions {
  /** 每次（重）连时调用，返回最新 URL */
  url: () => string;
  lastEventId?: () => string | undefined;
  onFrame: (frame: SseFrame) => void;
  /** attempt：连续失败次数（open 后归零）；delayMs：本次重连等待 */
  onState?: (state: SseState, info: { attempt: number; delayMs?: number; status?: number }) => void;
  /** 401：会话失效；403/404：资源不可见。都不再重连 */
  onFatal?: (error: ApiError) => void;
  watchdogMs?: number;
  /** 首次退避基数，默认 3000（ENG §5） */
  baseRetryMs?: number;
  /** 测试注入 */
  fetch?: typeof fetch;
  random?: () => number;
}

export interface SseHandle {
  close(): void;
  /** 立即重连：等待中则跳过等待；已连接则断开后马上重连 */
  reconnectNow(): void;
}

const MAX_DELAY = 30_000;

export function openStream(opts: SseOptions): SseHandle {
  const watchdogMs = opts.watchdogMs ?? 45_000;
  const doFetch = opts.fetch ?? fetch;
  const random = opts.random ?? Math.random;
  let minRetry = opts.baseRetryMs ?? 3000;
  let ctrl: AbortController | null = null;
  let closed = false;
  let attempt = 0;
  let immediate = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let watchdog: ReturnType<typeof setTimeout> | null = null;

  const setState = (s: SseState, extra: { delayMs?: number; status?: number } = {}) =>
    opts.onState?.(s, { attempt, ...extra });

  const kick = () => {
    if (watchdog) clearTimeout(watchdog);
    watchdog = setTimeout(() => ctrl?.abort(new DOMException('watchdog', 'TimeoutError')), watchdogMs);
  };

  /** 计划下一次连接；retryAfterSec 存在时以它为准（429） */
  const schedule = (retryAfterSec?: number, status?: number) => {
    if (closed) return;
    if (immediate) {
      immediate = false;
      attempt = 0;
      timer = setTimeout(connect, 0);
      return;
    }
    attempt++;
    const exp = Math.min(MAX_DELAY, minRetry * 2 ** Math.min(attempt - 1, 6));
    const delay =
      retryAfterSec !== undefined ? Math.min(retryAfterSec * 1000, 5 * 60_000) : exp * (0.8 + random() * 0.4);
    setState('reconnecting', { delayMs: Math.round(delay), status });
    timer = setTimeout(connect, delay);
  };

  async function connect() {
    if (closed) return;
    timer = null;
    ctrl = new AbortController();
    if (attempt === 0) setState('connecting');
    const headers: Record<string, string> = { Accept: 'text/event-stream' };
    const last = opts.lastEventId?.();
    if (last) headers['Last-Event-ID'] = last;

    let res: Response;
    try {
      res = await doFetch(opts.url(), { headers, credentials: 'same-origin', cache: 'no-store', signal: ctrl.signal });
    } catch {
      schedule();
      return;
    }
    const type = res.headers.get('content-type') ?? '';
    if (!res.ok || !res.body || !type.includes('text/event-stream')) {
      let problem: Problem | null = null;
      try {
        problem = (await res.json()) as Problem;
      } catch {
        /* 非 JSON */
      }
      const err = new ApiError(res.status, problem, res.statusText, parseRetryAfter(res.headers.get('retry-after')));
      if (res.status === 401 || res.status === 403 || res.status === 404) {
        closed = true;
        setState('closed', { status: res.status });
        opts.onFatal?.(err);
        return;
      }
      schedule(res.status === 429 ? (err.retryAfter ?? 30) : undefined, res.status);
      return;
    }

    attempt = 0;
    setState('open');
    kick();
    const parser = createSseParser(opts.onFrame, (ms) => {
      minRetry = Math.max(1000, ms);
    });
    try {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        kick();
        parser.feed(decoder.decode(value, { stream: true }));
      }
    } catch {
      /* 中断或看门狗：下面统一重连 */
    }
    if (watchdog) clearTimeout(watchdog);
    if (!closed) schedule();
  }

  void connect();

  return {
    close() {
      closed = true;
      if (timer) clearTimeout(timer);
      if (watchdog) clearTimeout(watchdog);
      ctrl?.abort();
      setState('closed');
    },
    reconnectNow() {
      if (closed) return;
      if (timer) {
        clearTimeout(timer);
        timer = null;
        attempt = 0;
        void connect();
      } else {
        immediate = true;
        ctrl?.abort();
      }
    },
  };
}

/* ------------------------------------------------------------------ 帧解析（WHATWG SSE，增量） */

export interface SseParser {
  /** 喂入任意切分的文本块 */
  feed(chunk: string): void;
}

export function createSseParser(emit: (f: SseFrame) => void, onRetry: (ms: number) => void = () => {}): SseParser {
  let buf = '';
  /** 上一块以 \r 结尾：若下一块以 \n 开头，二者合为一个 CRLF，不能算两次换行 */
  let pendingCR = false;
  let event: string | undefined;
  let id: string | undefined;
  let data: string[] = [];

  const dispatch = () => {
    if (data.length) emit({ event, id, data: data.join('\n') });
    event = undefined;
    id = undefined;
    data = [];
  };

  const line = (l: string) => {
    if (l === '') return dispatch();
    if (l.startsWith(':')) return;
    const colon = l.indexOf(':');
    const field = colon < 0 ? l : l.slice(0, colon);
    let val = colon < 0 ? '' : l.slice(colon + 1);
    if (val.startsWith(' ')) val = val.slice(1);
    switch (field) {
      case 'event':
        event = val;
        break;
      case 'data':
        data.push(val);
        break;
      case 'id':
        if (!val.includes('\0')) id = val;
        break;
      case 'retry':
        if (/^\d+$/.test(val)) onRetry(Number(val));
        break;
    }
  };

  return {
    feed(chunk) {
      if (pendingCR && chunk.startsWith('\n')) chunk = chunk.slice(1);
      pendingCR = false;
      buf += chunk;
      let nl: number;
      while ((nl = buf.search(/[\r\n]/)) >= 0) {
        const isCR = buf[nl] === '\r';
        if (isCR && nl === buf.length - 1) {
          /* 块末尾的 \r：先按换行处理，记下以便吞掉下一块开头的 \n */
          pendingCR = true;
          line(buf.slice(0, nl));
          buf = '';
          break;
        }
        const step = isCR && buf[nl + 1] === '\n' ? 2 : 1;
        line(buf.slice(0, nl));
        buf = buf.slice(nl + step);
      }
    },
  };
}
