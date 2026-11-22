// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 全局事件总线（ENG §5）
 * --------------------------------------------------------------------------
 * 单连接 GET /api/v1/events，按 type 分发，event_id LRU 去重（1024）。
 *
 *   events.start() / events.stop()        会话层登入登出时调用
 *   events.on('operation.updated', fn)    订阅；返回取消函数
 *   events.on('resource.changed', fn)     fn(event)，payload 已是对象
 *   events.on('agent.session.*', fn)      末尾 * 前缀匹配
 *   events.onResync(fn)                   ready 之后的 resync：重拉快照
 *   events.state / events.offline         连接状态；断线超过 5s → offline=true
 *   events.degraded                       429（超 8 条连接）：订阅方改轮询
 *
 * 页面隐藏时保持连接（审批提醒要及时）。不做 SharedWorker。
 * ========================================================================== */
import { ApiError } from '$api/client';
import { events as eventsApi } from '$api/endpoints';
import { openStream, type SseFrame, type SseHandle, type SseOptions, type SseState } from '$api/sse';
import type { Event as DomainEvent, StreamReady, StreamResync } from '$api/types';

export const TOPICS = ['resource.changed', 'operation.updated', 'plugin.*', 'agent.session.*'] as const;
const DEDUPE = 1024;
const OFFLINE_AFTER = 5000;

export type EventHandler = (e: DomainEvent) => void;

/** 有界去重集合：插入顺序淘汰 */
export class Lru {
  #set = new Set<string>();
  constructor(private max: number) {}
  /** 已见过返回 true；否则记下并返回 false */
  seen(id: string): boolean {
    if (this.#set.has(id)) return true;
    this.#set.add(id);
    if (this.#set.size > this.max) this.#set.delete(this.#set.values().next().value!);
    return false;
  }
  clear(): void {
    this.#set.clear();
  }
}

export interface EventBusDeps {
  open?: (opts: SseOptions) => SseHandle;
  onUnauthenticated?: () => void;
}

export class EventBus {
  state = $state<SseState>('closed');
  /** 断线超过 5 秒（显示顶栏下细条） */
  offline = $state(false);
  /** 被限流（多标签超出连接上限）：审批等改 30s 轮询 */
  degraded = $state(false);
  headSequence = $state<string | null>(null);

  #handle: SseHandle | null = null;
  #handlers = new Map<string, Set<EventHandler>>();
  #resync = new Set<() => void>();
  #lru = new Lru(DEDUPE);
  #lastId: string | undefined;
  #offlineTimer: ReturnType<typeof setTimeout> | null = null;
  #readySeen = false;

  constructor(private deps: EventBusDeps = {}) {}

  /** 启动前注入依赖（main.ts 里接上会话层的 401 处理） */
  configure(deps: EventBusDeps): void {
    this.deps = { ...this.deps, ...deps };
  }

  start(): void {
    if (this.#handle) return;
    const open = this.deps.open ?? openStream;
    this.#readySeen = false;
    this.#handle = open({
      url: () => eventsApi.url(TOPICS),
      lastEventId: () => this.#lastId,
      onFrame: (f) => this.#frame(f),
      onState: (s, info) => this.#state(s, info.status),
      onFatal: (err: ApiError) => {
        this.#handle = null;
        if (err.status === 401) this.deps.onUnauthenticated?.();
      },
    });
  }

  stop(): void {
    this.#handle?.close();
    this.#handle = null;
    this.#lastId = undefined;
    this.#lru.clear();
    this.#setOffline(false);
    this.degraded = false;
    this.state = 'closed';
  }

  reconnectNow(): void {
    this.#handle?.reconnectNow();
  }

  /** type 精确匹配，或以 '.*' 结尾做前缀匹配 */
  on(type: string, fn: EventHandler): () => void {
    let set = this.#handlers.get(type);
    if (!set) this.#handlers.set(type, (set = new Set()));
    set.add(fn);
    return () => set.delete(fn);
  }

  onResync(fn: () => void): () => void {
    this.#resync.add(fn);
    return () => this.#resync.delete(fn);
  }

  /** 测试与 mock 用：直接注入一帧 */
  dispatchFrame(f: SseFrame): void {
    this.#frame(f);
  }

  #frame(f: SseFrame) {
    switch (f.event) {
      case 'ready': {
        const d = parse<StreamReady>(f.data);
        if (d) this.headSequence = d.head_sequence;
        /* 重连后的 ready：断线期间可能漏事件（lossy 或超出保留），稳妥起见让订阅方重拉 */
        if (this.#readySeen) this.#emitResync();
        this.#readySeen = true;
        return;
      }
      case 'heartbeat':
        return;
      case 'resync': {
        const d = parse<StreamResync>(f.data);
        if (d) {
          this.headSequence = d.head_sequence;
          this.#lastId = d.head_sequence;
        }
        this.#emitResync();
        /* buffer_overflow 后服务端会断流：立即重连，从 head 续传 */
        if (d?.reason === 'buffer_overflow') queueMicrotask(() => this.reconnectNow());
        return;
      }
    }
    if (f.event !== undefined && f.event !== 'message') return;
    const e = parse<DomainEvent>(f.data);
    if (!e || typeof e.type !== 'string') return;
    if (f.id) this.#lastId = f.id;
    if (e.event_id && this.#lru.seen(e.event_id)) return;
    this.#emit(e);
  }

  #emit(e: DomainEvent) {
    const call = (set: Set<EventHandler> | undefined) =>
      set?.forEach((fn) => {
        try {
          fn(e);
        } catch (err) {
          console.error('[events] handler failed', err);
        }
      });
    call(this.#handlers.get(e.type));
    for (const [k, set] of this.#handlers) {
      if (k.endsWith('.*') && e.type.startsWith(k.slice(0, -1))) call(set);
    }
  }

  #emitResync() {
    this.#resync.forEach((fn) => fn());
  }

  #state(s: SseState, status?: number) {
    this.state = s;
    if (s === 'open') {
      this.degraded = false;
      this.#setOffline(false);
    } else if (s === 'reconnecting') {
      if (status === 429) this.degraded = true;
      if (!this.#offlineTimer && !this.offline) {
        this.#offlineTimer = setTimeout(() => {
          this.#offlineTimer = null;
          if (this.state !== 'open') this.offline = true;
        }, OFFLINE_AFTER);
      }
    }
  }

  #setOffline(v: boolean) {
    if (this.#offlineTimer) clearTimeout(this.#offlineTimer);
    this.#offlineTimer = null;
    this.offline = v;
  }
}

function parse<T>(s: string): T | null {
  try {
    return JSON.parse(s) as T;
  } catch {
    return null;
  }
}

export const events = new EventBus();
