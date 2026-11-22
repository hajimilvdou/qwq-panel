// SPDX-License-Identifier: AGPL-3.0-only
/* 事件总线、快照缓存、审批队列的关键逻辑 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventBus, Lru } from '$lib/events.svelte';
import { mergeDelta, resources, Resource } from '$lib/resource.svelte';
import { ApprovalQueue } from '$lib/ai/approvals.svelte';
import type { SseOptions } from '$api/sse';
import type { Approval, Event as DomainEvent } from '$api/types';

/* ------------------------------------------------------------------ 工具 */

function fakeBus() {
  let opts: SseOptions | null = null;
  const bus = new EventBus({
    open: (o) => {
      opts = o;
      return { close: vi.fn(), reconnectNow: vi.fn() };
    },
  });
  bus.start();
  const emit = (type: string, payload: object, id = Math.random().toString(36)) =>
    opts!.onFrame({ id, data: JSON.stringify({ event_id: id, sequence: '1', type, schema_version: '1', subject: (payload as { subject?: string }).subject ?? 'x', occurred_at: '', delivery_class: 'reliable', payload }) });
  return { bus, emit, control: (event: string, data: object) => opts!.onFrame({ event, data: JSON.stringify(data) }), state: (s: Parameters<NonNullable<SseOptions['onState']>>[0], status?: number) => opts!.onState!(s, { attempt: 1, status }) };
}

const approval = (id: string, status: Approval['status'] = 'PENDING', created = '2026-11-09T00:00:00Z') =>
  ({ approval_id: id, operation_id: 'op_' + id, status, created_at: created, revision: 'r1' }) as Approval;

/* ------------------------------------------------------------------ 事件总线 */

describe('EventBus', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('LRU 去重：同一 event_id 只分发一次', () => {
    const { bus, emit } = fakeBus();
    const fn = vi.fn();
    bus.on('operation.updated', fn);
    emit('operation.updated', {}, 'e1');
    emit('operation.updated', {}, 'e1');
    emit('operation.updated', {}, 'e2');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('前缀订阅 agent.session.*', () => {
    const { bus, emit } = fakeBus();
    const fn = vi.fn();
    bus.on('agent.session.*', fn);
    emit('agent.session.attention', {});
    emit('agent.sessionx', {});
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('resync 触发 onResync；buffer_overflow 后立即重连', async () => {
    const { bus, control } = fakeBus();
    const fn = vi.fn();
    bus.onResync(fn);
    const spy = vi.spyOn(bus, 'reconnectNow');
    control('resync', { reason: 'buffer_overflow', head_sequence: '99' });
    await Promise.resolve();
    expect(fn).toHaveBeenCalledOnce();
    expect(spy).toHaveBeenCalledOnce();
    expect(bus.headSequence).toBe('99');
  });

  it('重连后的第二个 ready 也会让订阅方重拉', () => {
    const { bus, control } = fakeBus();
    const fn = vi.fn();
    bus.onResync(fn);
    control('ready', { head_sequence: '1' });
    expect(fn).not.toHaveBeenCalled();
    control('ready', { head_sequence: '5' });
    expect(fn).toHaveBeenCalledOnce();
  });

  it('断线超过 5 秒才显示 offline；429 标记 degraded', () => {
    const { bus, state } = fakeBus();
    state('reconnecting', 429);
    expect(bus.degraded).toBe(true);
    vi.advanceTimersByTime(4999);
    expect(bus.offline).toBe(false);
    vi.advanceTimersByTime(1);
    expect(bus.offline).toBe(true);
    state('open');
    expect(bus.offline).toBe(false);
    expect(bus.degraded).toBe(false);
  });

  it('Lru 容量淘汰最旧项', () => {
    const l = new Lru(2);
    l.seen('a');
    l.seen('b');
    l.seen('c');
    expect(l.seen('a')).toBe(false);
    expect(l.seen('c')).toBe(true);
  });
});

/* ------------------------------------------------------------------ 快照缓存 */

describe('resource cache', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    resources.clear();
    vi.useRealTimers();
  });

  const changedEvt = (subject: string, revision = 'r9') =>
    ({ type: 'resource.changed', subject, payload: { subject, revision } }) as unknown as DomainEvent;

  it('subject 前缀命中后合并刷新，且两次拉取间隔 ≥ 1s', async () => {
    const load = vi.fn().mockResolvedValue([1]);
    const r = resources.get({ key: 'plugins', load, subjects: ['plugins/'] });
    resources.acquire(r);
    await vi.advanceTimersByTimeAsync(0);
    expect(load).toHaveBeenCalledTimes(1);
    expect(r.status).toBe('ready');
    resources.handle(changedEvt('plugins/a'));
    resources.handle(changedEvt('plugins/b'));
    resources.handle(changedEvt('users/x'));
    await vi.advanceTimersByTimeAsync(999);
    expect(load).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('同 revision 的事件跳过', async () => {
    const load = vi.fn().mockResolvedValue({ revision: 'r9' });
    const r = resources.get({ key: 'u1', load, subjects: ['users/u1'], revisionOf: (d: { revision: string }) => d.revision });
    resources.acquire(r);
    await vi.advanceTimersByTimeAsync(0);
    resources.handle(changedEvt('users/u1', 'r9'));
    await vi.advanceTimersByTimeAsync(2000);
    expect(load).toHaveBeenCalledTimes(1);
    resources.handle(changedEvt('users/u1', 'r10'));
    await vi.advanceTimersByTimeAsync(2000);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('刷新失败保留旧数据；无数据时进入 error', async () => {
    const r = new Resource({ key: 'k', load: vi.fn().mockResolvedValueOnce('old').mockRejectedValue(new Error('x')) });
    await r.refresh();
    await r.refresh();
    expect(r.data).toBe('old');
    expect(r.status).toBe('ready');
    expect(r.error).toBeInstanceOf(Error);
    const r2 = new Resource({ key: 'k2', load: vi.fn().mockRejectedValue(new Error('x')) });
    await r2.refresh();
    expect(r2.status).toBe('error');
  });

  it('无引用 60s 后回收', async () => {
    const load = vi.fn().mockResolvedValue(1);
    const opts = { key: 'gc', load };
    const r = resources.get(opts);
    resources.acquire(r);
    resources.release(r);
    await vi.advanceTimersByTimeAsync(60_001);
    expect(resources.get(opts)).not.toBe(r);
  });

  it('mergeDelta：upsert、删除、新项在前；全量直接替换', () => {
    const prev = [{ id: 'a', v: 1 }, { id: 'b', v: 1 }, { id: 'c', v: 1 }];
    const next = mergeDelta(prev, { items: [{ id: 'b', v: 2 }, { id: 'd', v: 1 }], delta: true, deleted_ids: ['c'], revision: 'r2' }, (x) => x.id);
    expect(next.map((x) => `${x.id}${x.v}`)).toEqual(['b2', 'd1', 'a1']);
    expect(mergeDelta(prev, { items: [{ id: 'z', v: 0 }], delta: false, revision: 'r3' }, (x) => x.id)).toEqual([{ id: 'z', v: 0 }]);
  });
});

/* ------------------------------------------------------------------ 审批队列 */

describe('ApprovalQueue', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('快照 + 事件合并、按 id 去重、终态移除、按时间排序', async () => {
    const list = vi.fn().mockResolvedValue({ items: [approval('b', 'PENDING', '2026-11-09T02:00:00Z')], delta: false, revision: 'r1' });
    const one = vi.fn(async (id: string) => approval(id, 'PENDING', '2026-11-09T01:00:00Z'));
    const q = new ApprovalQueue(list, one);
    const { bus, emit } = fakeBus();
    q.connect(bus);
    await vi.advanceTimersByTimeAsync(0);
    expect(q.pending.map((a) => a.approval_id)).toEqual(['b']);

    emit('operation.updated', { operation_id: 'op_a', status: 'AWAITING_APPROVAL', approval_id: 'a' });
    emit('operation.updated', { operation_id: 'op_a', status: 'AWAITING_APPROVAL', approval_id: 'a' });
    await vi.advanceTimersByTimeAsync(0);
    expect(one).toHaveBeenCalledTimes(1);
    expect(q.pending.map((a) => a.approval_id)).toEqual(['a', 'b']);
    expect(q.unseen).toHaveLength(2);
    q.markSeen('a');
    expect(q.unseen.map((a) => a.approval_id)).toEqual(['b']);

    emit('operation.updated', { operation_id: 'op_b', status: 'RUNNING', approval_id: 'b' });
    expect(q.pending.map((a) => a.approval_id)).toEqual(['a']);
    q.disconnect();
  });

  it('断线（offline）时每 30s 兜底轮询', async () => {
    const list = vi.fn().mockResolvedValue({ items: [], delta: false, revision: 'r1' });
    const q = new ApprovalQueue(list, vi.fn());
    const { bus, state } = fakeBus();
    q.connect(bus);
    await vi.advanceTimersByTimeAsync(0);
    expect(list).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(list).toHaveBeenCalledTimes(1);
    state('reconnecting');
    await vi.advanceTimersByTimeAsync(30_000);
    expect(list).toHaveBeenCalledTimes(2);
    q.disconnect();
  });
});
