// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 服务端快照缓存（ENG §3）
 * --------------------------------------------------------------------------
 * key → { data, status, error }。由 SSE 失效，组件卸载 60s 后回收。
 *
 *   // 组件 <script> 顶层：
 *   const plugins = useResource({
 *     key: 'plugins',
 *     load: (signal) => api.plugins.list(),
 *     subjects: ['plugins/'],          // resource.changed 的 subject 前缀
 *   });
 *   {#if plugins.status === 'loading'} <Skeleton/> {:else if plugins.error} ... {/if}
 *
 * 失效规则：
 *   - subject 命中（前缀或全等）即标脏；全等且 revisionOf(data) 与事件相同则跳过
 *   - 同一 key 100ms 内合并，且两次拉取间隔 ≥1s（渲染 ≤1 次/秒）
 *   - 页面隐藏时只标脏，可见时再取；resync 时全部失效
 *   - 刷新期间保留旧数据（refreshing=true），不闪烁
 * ========================================================================== */
import type { Event as DomainEvent, ListMeta } from '$api/types';

export type ResourceStatus = 'idle' | 'loading' | 'ready' | 'error';

export interface ResourceOptions<T> {
  key: string;
  load: (signal: AbortSignal) => Promise<T>;
  /** resource.changed 的 subject 前缀（以 / 结尾）或全等 subject */
  subjects?: readonly string[];
  /** 额外的事件类型（如 'operation.updated'），命中即失效 */
  events?: readonly string[];
  /** 单资源的 revision，用于跳过同版本事件 */
  revisionOf?: (data: T) => string | undefined;
}

const GC_AFTER = 60_000;
const COALESCE = 100;
const MIN_INTERVAL = 1000;

export class Resource<T> {
  data = $state<T | undefined>(undefined);
  status = $state<ResourceStatus>('idle');
  error = $state<unknown>(null);
  /** 已有数据时的后台刷新 */
  refreshing = $state(false);

  refs = 0;
  dirty = false;
  #ctrl: AbortController | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #last = 0;
  gcTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(readonly opts: ResourceOptions<T>) {}

  /** 立即重取（用户点"重试"、写操作完成后） */
  refresh = async (): Promise<void> => {
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
    this.#ctrl?.abort();
    const ctrl = (this.#ctrl = new AbortController());
    this.dirty = false;
    this.#last = Date.now();
    if (this.data === undefined) this.status = 'loading';
    else this.refreshing = true;
    try {
      const d = await this.opts.load(ctrl.signal);
      if (ctrl.signal.aborted) return;
      this.data = d;
      this.error = null;
      this.status = 'ready';
    } catch (err) {
      if (ctrl.signal.aborted) return;
      this.error = err;
      /* 有旧数据时保留旧数据，只记录错误 */
      this.status = this.data === undefined ? 'error' : 'ready';
    } finally {
      if (this.#ctrl === ctrl) {
        this.refreshing = false;
        this.#ctrl = null;
      }
    }
  };

  /** 合并与节流后的刷新 */
  schedule(): void {
    if (this.#timer) return;
    if (typeof document !== 'undefined' && document.hidden) {
      this.dirty = true;
      return;
    }
    const wait = Math.max(COALESCE, this.#last + MIN_INTERVAL - Date.now());
    this.#timer = setTimeout(() => {
      this.#timer = null;
      void this.refresh();
    }, wait);
  }

  /** 本地乐观更新（写操作成功后直接替换），不触发拉取 */
  set(data: T): void {
    this.data = data;
    this.status = 'ready';
    this.error = null;
  }

  dispose(): void {
    this.#ctrl?.abort();
    if (this.#timer) clearTimeout(this.#timer);
  }
}

/* ------------------------------------------------------------------ 缓存 */

class ResourceCache {
  #map = new Map<string, Resource<unknown>>();

  get<T>(opts: ResourceOptions<T>): Resource<T> {
    let r = this.#map.get(opts.key) as Resource<T> | undefined;
    if (!r) {
      r = new Resource(opts);
      this.#map.set(opts.key, r as Resource<unknown>);
    }
    return r;
  }

  acquire<T>(r: Resource<T>): void {
    r.refs++;
    if (r.gcTimer) clearTimeout(r.gcTimer);
    r.gcTimer = null;
    if (r.status === 'idle' || r.dirty) void r.refresh();
  }

  release<T>(r: Resource<T>): void {
    r.refs = Math.max(0, r.refs - 1);
    if (r.refs > 0) return;
    r.gcTimer = setTimeout(() => {
      if (r.refs === 0) {
        r.dispose();
        this.#map.delete(r.opts.key);
      }
    }, GC_AFTER);
  }

  /** 按事件失效 */
  handle(e: DomainEvent): void {
    for (const r of this.#map.values()) {
      if (matches(r, e)) {
        if (r.refs > 0) r.schedule();
        else r.dirty = true;
      }
    }
  }

  invalidate(key: string): void {
    const r = this.#map.get(key);
    if (r) r.refs > 0 ? r.schedule() : (r.dirty = true);
  }

  invalidateAll(): void {
    for (const r of this.#map.values()) r.refs > 0 ? r.schedule() : (r.dirty = true);
  }

  /** 页面重新可见：补取期间标脏的 */
  flushDirty(): void {
    for (const r of this.#map.values()) if (r.dirty && r.refs > 0) r.schedule();
  }

  clear(): void {
    for (const r of this.#map.values()) r.dispose();
    this.#map.clear();
  }
}

function matches(r: Resource<unknown>, e: DomainEvent): boolean {
  const o = r.opts;
  if (o.events?.includes(e.type)) return true;
  if (e.type !== 'resource.changed' || !o.subjects) return false;
  const p = e.payload as { subject?: string; revision?: string };
  const subject = p.subject ?? e.subject;
  for (const s of o.subjects) {
    if (s === subject) {
      /* 同版本：本地已是最新 */
      return !(o.revisionOf && r.data !== undefined && o.revisionOf(r.data) === p.revision);
    }
    if (s.endsWith('/') && subject.startsWith(s)) return true;
  }
  return false;
}

export const resources = new ResourceCache();

/**
 * 组件内使用：随组件挂载引用、卸载释放。必须在组件初始化阶段调用。
 * 同 key 的多个组件共享同一份数据。
 */
export function useResource<T>(opts: ResourceOptions<T>): Resource<T> {
  const r = resources.get(opts);
  $effect(() => {
    resources.acquire(r);
    return () => resources.release(r);
  });
  return r;
}

/* ------------------------------------------------------------------ 增量列表合并 */

/**
 * since_revision 增量合并（operations / approvals / agent-sessions）：
 * delta=false 视为全量；delta=true 时按 id upsert、按 deleted_ids 删除，新项在前。
 */
export function mergeDelta<T>(
  prev: readonly T[],
  page: ListMeta & { items: T[] },
  idOf: (x: T) => string,
): T[] {
  if (!page.delta) return page.items.slice();
  const gone = new Set(page.deleted_ids ?? []);
  const fresh = new Map(page.items.map((x) => [idOf(x), x]));
  const kept = prev.filter((x) => !gone.has(idOf(x)) && !fresh.has(idOf(x)));
  return [...page.items.filter((x) => !gone.has(idOf(x))), ...kept];
}
