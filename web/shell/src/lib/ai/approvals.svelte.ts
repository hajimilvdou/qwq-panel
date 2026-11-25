// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 待审批队列（ENG §5 / SPEC §4）
 * --------------------------------------------------------------------------
 * 来源合并，按 approval_id 去重：
 *   GET /approvals?status=PENDING            快照（登录后、resync 后）
 *   operation.updated{AWAITING_APPROVAL}     新增（拉单条）
 *   operation.updated{其他状态, approval_id}  移除
 *   resource.changed approvals/<id>          拉单条，非 PENDING 即移除
 *   agent.session.attention{approval_id}     拉单条（缺口 6）
 * 兜底：事件流断线（offline）或被限流（degraded）时 30s 轮询。
 *
 *   approvals.pending          按创建时间升序（先到先批）
 *   approvals.unseen           尚未在悬浮窗里看过的（驱动 reach 态）
 *   approvals.markSeen(id)
 * ========================================================================== */
import { SvelteMap, SvelteSet } from 'svelte/reactivity';
import { approvals as api } from '$api/endpoints';
import type { Approval, Event as DomainEvent, OperationUpdatedPayload } from '$api/types';
import type { AgentSessionAttentionPayload } from '$api/additions';
import type { EventBus } from '../events.svelte';

const POLL = 30_000;

export class ApprovalQueue {
  #map = new SvelteMap<string, Approval>();
  #seen = new SvelteSet<string>();
  #suppressed = new Set<string>();
  #poll: ReturnType<typeof setInterval> | null = null;
  #offs: (() => void)[] = [];
  #inflight = new Set<string>();

  loaded = $state(false);

  readonly pending = $derived(
    [...this.#map.values()].sort((a, b) => a.created_at.localeCompare(b.created_at)),
  );
  readonly unseen = $derived(this.pending.filter((a) => !this.#seen.has(a.approval_id)));

  constructor(private fetchList = () => api.list('PENDING'), private fetchOne = api.get) {}

  get(id: string): Approval | undefined {
    return this.#map.get(id);
  }

  markSeen(id: string): void {
    this.#seen.add(id);
  }

  suppress(id: string): void {
    this.#suppressed.add(id);
    this.#seen.add(id);
    this.#map.delete(id);
  }

  unsuppress(id: string): void {
    this.#suppressed.delete(id);
  }

  async load(): Promise<void> {
    try {
      const page = await this.fetchList();
      const ids = new Set(page.items.map((a) => a.approval_id));
      for (const id of [...this.#map.keys()]) if (!ids.has(id)) this.#map.delete(id);
      for (const a of page.items) this.#map.set(a.approval_id, a);
      this.loaded = true;
    } catch {
      /* 保留旧数据；断线兜底轮询会再试 */
    }
  }

  /** 拉单条：仍 PENDING 则放入，否则移除；404 视为已不存在。同一 id 并发只拉一次 */
  async refreshOne(id: string): Promise<void> {
    if (this.#suppressed.has(id) || this.#inflight.has(id)) return;
    this.#inflight.add(id);
    try {
      const a = await this.fetchOne(id);
      if (!this.#suppressed.has(id)) this.upsert(a);
    } catch {
      this.#map.delete(id);
    } finally {
      this.#inflight.delete(id);
    }
  }

  /** 决定后由审批卡调用；或事件带来新状态 */
  upsert(a: Approval): void {
    if (a.status === 'PENDING' && !this.#suppressed.has(a.approval_id)) this.#map.set(a.approval_id, a);
    else this.#map.delete(a.approval_id);
  }

  remove(id: string): void {
    this.#map.delete(id);
  }

  /** 接入事件总线与断线兜底；返回取消函数 */
  connect(bus: EventBus): () => void {
    this.#offs = [
      bus.on('operation.updated', (e) => this.#onOperation(e)),
      bus.on('resource.changed', (e) => {
        const subject = (e.payload as { subject?: string }).subject ?? e.subject;
        if (subject.startsWith('approvals/')) void this.refreshOne(subject.slice('approvals/'.length));
      }),
      bus.on('agent.session.attention', (e) => {
        const p = e.payload as unknown as AgentSessionAttentionPayload;
        if (p.approval_id) void this.refreshOne(p.approval_id);
      }),
      bus.onResync(() => void this.load()),
    ];
    const tick = () => {
      if (bus.offline || bus.degraded) void this.load();
    };
    this.#poll = setInterval(tick, POLL);
    void this.load();
    return () => this.disconnect();
  }

  disconnect(): void {
    this.#offs.forEach((f) => f());
    this.#offs = [];
    if (this.#poll) clearInterval(this.#poll);
    this.#poll = null;
    this.#map.clear();
    this.#seen.clear();
    this.loaded = false;
  }

  #onOperation(e: DomainEvent) {
    const p = e.payload as unknown as OperationUpdatedPayload;
    if (!p.approval_id) return;
    if (p.status === 'AWAITING_APPROVAL') {
      if (!this.#map.has(p.approval_id)) void this.refreshOne(p.approval_id);
    } else {
      this.#map.delete(p.approval_id);
    }
  }
}

export const approvals = new ApprovalQueue();
