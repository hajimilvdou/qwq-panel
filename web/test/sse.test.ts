// SPDX-License-Identifier: AGPL-3.0-only
/* SSE：增量帧解析（跨块 CRLF）与重连状态机（退避、429、致命错误、续传头） */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createSseParser, openStream, type SseFrame } from '$api/sse';

describe('createSseParser', () => {
  it('解析 event / id / 多行 data，忽略注释', () => {
    const out: SseFrame[] = [];
    const p = createSseParser((f) => out.push(f));
    p.feed(': hi\nevent: ready\ndata: {"a":1}\n\nid: 7\ndata: x\ndata: y\n\n');
    expect(out).toEqual([
      { event: 'ready', id: undefined, data: '{"a":1}' },
      { event: undefined, id: '7', data: 'x\ny' },
    ]);
  });

  it('CRLF 跨块到达时不多算一个空行', () => {
    const out: SseFrame[] = [];
    const p = createSseParser((f) => out.push(f));
    p.feed('data: a\r');
    p.feed('\ndata: b\r');
    p.feed('\n\r\n');
    expect(out).toEqual([{ event: undefined, id: undefined, data: 'a\nb' }]);
  });

  it('retry 字段回调', () => {
    const retry = vi.fn();
    createSseParser(() => {}, retry).feed('retry: 5000\n\n');
    expect(retry).toHaveBeenCalledWith(5000);
  });

  it('空 id 心跳帧产出 id: undefined，不会清空断点水位', () => {
    const out: SseFrame[] = [];
    const p = createSseParser((f) => out.push(f));
    p.feed('event: heartbeat\nid:\ndata: {}\n\nid: 12\ndata: {"ok":true}\n\n');
    expect(out[0]).toEqual({ event: 'heartbeat', id: undefined, data: '{}' });
    expect(out[1]).toEqual({ event: undefined, id: '12', data: '{"ok":true}' });
  });
});

/* ------------------------------------------------------------------ 重连 */

function streamResponse(text: string, keepOpen = false): Response {
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(new TextEncoder().encode(text));
      if (!keepOpen) c.close();
    },
  });
  return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

describe('openStream', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('网络错误后按退避重连（3s ±20%），带上 Last-Event-ID', async () => {
    const seen: (string | undefined)[] = [];
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('net'))
      .mockImplementation(async (_u: string, init: RequestInit) => {
        seen.push((init.headers as Record<string, string>)['Last-Event-ID']);
        return streamResponse('id: 9\ndata: {}\n\n', true);
      });
    const states: string[] = [];
    const h = openStream({
      url: () => '/e',
      lastEventId: () => '42',
      onFrame: () => {},
      onState: (s) => states.push(s),
      fetch: fetchMock,
      random: () => 0.5,
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(states).toEqual(['connecting', 'reconnecting']);
    await vi.advanceTimersByTimeAsync(2999);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(seen).toEqual(['42']);
    expect(states.at(-1)).toBe('open');
    h.close();
  });

  it('401 视为致命：回调 onFatal，不再重连', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 401, headers: { 'content-type': 'application/json' } }));
    const onFatal = vi.fn();
    openStream({ url: () => '/e', onFrame: () => {}, onFatal, fetch: fetchMock });
    await vi.advanceTimersByTimeAsync(60_000);
    expect(onFatal).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('429 按 retry_after 等待', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ code: 'RATE_LIMITED', retry_after: 20 }), { status: 429, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValue(streamResponse('', true));
    const info: { delayMs?: number; status?: number }[] = [];
    const h = openStream({ url: () => '/e', onFrame: () => {}, onState: (_s, i) => info.push(i), fetch: fetchMock });
    await vi.advanceTimersByTimeAsync(0);
    expect(info.at(-1)).toMatchObject({ delayMs: 20_000, status: 429 });
    await vi.advanceTimersByTimeAsync(19_999);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    h.close();
  });

  it('看门狗：长时间无字节则断开重连', async () => {
    const fetchMock = vi.fn().mockImplementation(async (_u: string, init: RequestInit) => {
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          init.signal?.addEventListener('abort', () => c.error(new DOMException('aborted', 'AbortError')));
        },
      });
      return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
    });
    const h = openStream({ url: () => '/e', onFrame: () => {}, fetch: fetchMock, watchdogMs: 1000, random: () => 0.5 });
    await vi.advanceTimersByTimeAsync(1001);
    await vi.advanceTimersByTimeAsync(3001);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    h.close();
  });

  it('reconnectNow：已连接时立即重连（不等退避）', async () => {
    const fetchMock = vi.fn().mockImplementation(async (_u: string, init: RequestInit) => {
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          init.signal?.addEventListener('abort', () => c.error(new DOMException('aborted', 'AbortError')));
        },
      });
      return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
    });
    const h = openStream({ url: () => '/e', onFrame: () => {}, fetch: fetchMock });
    await vi.advanceTimersByTimeAsync(10);
    h.reconnectNow();
    await vi.advanceTimersByTimeAsync(10);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    h.close();
  });
});
