// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 操作实时缓存：operation.updated → 最新状态/进度
 * --------------------------------------------------------------------------
 *   liveOps.get(id)              最近一次推送的 payload（无则 undefined）
 *   liveOps.watch(id, fn)        到达终态时回调一次；返回取消函数
 *   liveOps.running              进行中的操作（悬浮窗 working 态等用）
 *
 * 只保存事件里带的字段，不替代 GET /operations/{id}；详情页仍以快照为准。
 * ========================================================================== */
import { SvelteMap } from 'svelte/reactivity';
import { TERMINAL } from '$api/client';
import type { Event as DomainEvent, OperationUpdatedPayload } from '$api/types';
import type { EventBus } from './events.svelte';

type Watcher = (p: OperationUpdatedPayload) => void;
const KEEP = 200;

class LiveOperations {
  #map = new SvelteMap<string, OperationUpdatedPayload>();
  #watchers = new Map<string, Set<Watcher>>();

  readonly running = $derived([...this.#map.values()].filter((p) => !TERMINAL.has(p.status)));

  get(id: string): OperationUpdatedPayload | undefined {
    return this.#map.get(id);
  }

  watch(id: string, fn: Watcher): () => void {
    let set = this.#watchers.get(id);
    if (!set) this.#watchers.set(id, (set = new Set()));
    set.add(fn);
    return () => {
      set.delete(fn);
      if (!set.size) this.#watchers.delete(id);
    };
  }

  /** 接入事件总线；返回取消函数 */
  connect(bus: EventBus): () => void {
    return bus.on('operation.updated', (e) => this.apply(e));
  }

  apply(e: DomainEvent): void {
    const p = e.payload as unknown as OperationUpdatedPayload;
    if (!p?.operation_id) return;
    const prev = this.#map.get(p.operation_id);
    /* 乱序到达的旧事件不覆盖新状态（revision 为不透明串，只比较是否终态） */
    if (prev && TERMINAL.has(prev.status) && !TERMINAL.has(p.status)) return;
    this.#map.set(p.operation_id, p);
    if (this.#map.size > KEEP) {
      const oldest = this.#map.keys().next().value;
      if (oldest) this.#map.delete(oldest);
    }
    if (TERMINAL.has(p.status)) {
      const set = this.#watchers.get(p.operation_id);
      this.#watchers.delete(p.operation_id);
      set?.forEach((fn) => fn(p));
    }
  }

  clear(): void {
    this.#map.clear();
    this.#watchers.clear();
  }
}

export const liveOps = new LiveOperations();
