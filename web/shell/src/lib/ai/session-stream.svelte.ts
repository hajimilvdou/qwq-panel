// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 单个 Agent 会话的实时视图（快照 + 会话 SSE + 写操作）
 * --------------------------------------------------------------------------
 *   const c = new SessionStream(id);  c.start();  …  c.stop();
 *
 *   c.session     AgentSession（标题、模式、revision）
 *   c.transcript  TranscriptState（条目、seq、status）
 *   c.phase       loading | ready | error | gone
 *   c.link        会话流连接态（断线时界面给细提示）
 *   c.send(text) / c.retry(localId) / c.cancel() / c.setMode(m) / c.rename(t) / c.takeover() / c.remove()
 *
 * 流程（契约 §3.2）：先 GET 快照 → 以快照 seq 为 Last-Event-ID 开流 → 帧交给 reduce。
 * 收到 resync 重拉快照（流不必重开，后续帧 seq 自然接上）。
 * 全局 agent.session.updated 只更新状态与 revision（不含内容，缺口 6）。
 * ========================================================================== */
import { newIdempotencyKey } from '$api/client';
import { agent } from '$api/endpoints';
import { openStream, type SseFrame, type SseHandle, type SseState } from '$api/sse';
import type { AgentSession, AgentSessionEvent, PermissionMode } from '$api/types';
import type { AgentSessionUpdatedPayload } from '$api/additions';
import { events } from '../events.svelte';
import { addLocalUser, fromMessages, reduce, settleLocalUser, type TranscriptState } from './transcript';
import { readMarks } from './agent-sessions.svelte';

/** 快照返回的最近消息条数上限：满额时提示"仅显示最近的消息" */
export const SNAPSHOT_LIMIT = 40;
/** 单条消息上限（字节，契约 §1） */
export const MESSAGE_MAX_BYTES = 32_768;

export type StreamFrame =
  | { kind: 'event'; event: AgentSessionEvent }
  | { kind: 'resync' }
  | { kind: 'ready' }
  | null;

/** 会话流帧 → 语义（纯函数，便于测试）；心跳与坏帧返回 null */
export function parseSessionFrame(f: SseFrame): StreamFrame {
  if (f.event === 'resync') return { kind: 'resync' };
  if (f.event === 'ready') return { kind: 'ready' };
  if (f.event && f.event !== 'message') return null;
  try {
    const ev = JSON.parse(f.data) as AgentSessionEvent;
    if (typeof ev?.type !== 'string' || typeof ev.seq !== 'number') return null;
    return { kind: 'event', event: ev };
  } catch {
    return null;
  }
}

export const byteLength = (s: string): number => new TextEncoder().encode(s).length;

type Phase = 'loading' | 'ready' | 'error' | 'gone';

export class SessionStream {
  session = $state<AgentSession | null>(null);
  transcript = $state<TranscriptState>({ items: [], seq: 0, status: 'idle' });
  phase = $state<Phase>('loading');
  error = $state<unknown>(null);
  link = $state<SseState>('connecting');
  truncated = $state(false);

  readonly busy = $derived(this.transcript.status === 'running' || this.transcript.status === 'waiting_approval');

  #sse: SseHandle | null = null;
  #offs: (() => void)[] = [];
  #stopped = false;
  #loadCtrl: AbortController | null = null;
  /** 本地消息 id → client_message_id（重试复用，服务端去重） */
  #pending = new Map<string, { cid: string; text: string }>();

  constructor(
    readonly id: string,
    private api = agent,
    private open = openStream,
  ) {}

  start(): void {
    this.#stopped = false;
    void this.#load().then(() => {
      if (this.#stopped || this.phase !== 'ready') return;
      this.#sse = this.open({
        url: () => this.api.eventsUrl(this.id),
        lastEventId: () => String(this.transcript.seq),
        onFrame: (f) => this.#onFrame(f),
        onState: (s) => (this.link = s),
        onFatal: () => (this.phase = 'gone'),
      });
    });
    this.#offs = [
      events.on('agent.session.updated', (e) => {
        const p = e.payload as unknown as AgentSessionUpdatedPayload;
        if (p.session_id !== this.id || !this.session) return;
        this.session = { ...this.session, status: p.status, revision: p.revision, last_seq: p.last_seq };
      }),
      events.on('resource.changed', (e) => {
        const p = e.payload as { subject?: string; kind?: string };
        if (p.subject === `agent_sessions/${this.id}` && p.kind === 'delete') this.phase = 'gone';
      }),
    ];
  }

  stop(): void {
    this.#stopped = true;
    this.#loadCtrl?.abort();
    this.#loadCtrl = null;
    this.#sse?.close();
    this.#sse = null;
    this.#offs.forEach((f) => f());
    this.#offs = [];
  }

  /* ---------------------------------------------------------------- 读 */

  async #load(): Promise<void> {
    this.#loadCtrl?.abort();
    const ctrl = new AbortController();
    this.#loadCtrl = ctrl;
    try {
      const d = await this.api.get(this.id);
      if (this.#stopped || ctrl.signal.aborted) return;
      const { messages, approvals: _a, ...s } = d;
      this.session = s;
      const fresh = fromMessages(messages, s.status, s.last_seq);
      /* 保留尚未落库的本地气泡（resync 期间发送中 / 发送失败待重试） */
      const local = this.transcript.items.filter((x) => x.kind === 'user' && x.state);
      this.transcript = { ...fresh, items: [...fresh.items, ...local] };
      this.truncated = messages.length >= SNAPSHOT_LIMIT;
      this.phase = 'ready';
      this.#markRead();
    } catch (err) {
      const status = (err as { status?: number }).status;
      if (status === 404) this.phase = 'gone';
      else if (this.phase !== 'ready') {
        this.error = err;
        this.phase = 'error';
      }
    }
  }

  reload = (): Promise<void> => {
    this.phase = this.phase === 'ready' ? 'ready' : 'loading';
    return this.#load();
  };

  #onFrame(f: SseFrame) {
    const parsed = parseSessionFrame(f);
    if (!parsed) return;
    if (parsed.kind === 'resync') return void this.#load();
    if (parsed.kind === 'ready') return;
    this.transcript = reduce(this.transcript, parsed.event);
    if (this.session) this.session = { ...this.session, status: this.transcript.status, last_seq: this.transcript.seq };
    this.#markRead();
  }

  #markRead() {
    readMarks?.mark(this.id, Math.max(this.transcript.seq, this.session?.last_seq ?? 0));
  }

  /* ---------------------------------------------------------------- 写 */

  /** 发送；失败的气泡保留，可 retry(localId) */
  async send(text: string): Promise<void> {
    const localId = 'local-' + newIdempotencyKey();
    const cid = newIdempotencyKey();
    this.#pending.set(localId, { cid, text });
    this.transcript = addLocalUser(this.transcript, localId, text);
    await this.#deliver(localId);
  }

  async retry(localId: string): Promise<void> {
    if (!this.#pending.has(localId)) return;
    this.transcript = {
      ...this.transcript,
      items: this.transcript.items.map((x) => (x.kind === 'user' && x.id === localId ? { ...x, state: 'sending' } : x)),
    };
    await this.#deliver(localId);
  }

  async #deliver(localId: string): Promise<void> {
    const p = this.#pending.get(localId)!;
    try {
      const r = await this.api.send(this.id, p.text, p.cid);
      this.#pending.delete(localId);
      this.transcript = settleLocalUser(this.transcript, localId, { id: r.message.message_id });
      this.session = r.session;
      if (this.transcript.status !== 'waiting_approval') this.transcript = { ...this.transcript, status: 'running' };
    } catch (err) {
      this.transcript = settleLocalUser(this.transcript, localId, 'failed');
      throw err;
    }
  }

  /** 暂停：取消当前 turn（空闲时后端什么也不做） */
  async cancel(): Promise<void> {
    this.session = await this.api.cancel(this.id, '用户暂停');
  }

  async setMode(mode: PermissionMode): Promise<void> {
    if (!this.session) return;
    this.session = await this.api.update(this.id, { expected_revision: this.session.revision, permission_mode: mode });
  }

  async rename(title: string): Promise<void> {
    if (!this.session) return;
    this.session = await this.api.update(this.id, { expected_revision: this.session.revision, title });
  }

  /** 接管（ADR-0004 D9）：先停手，再降为只读 */
  async takeover(): Promise<void> {
    await this.cancel();
    if (this.session?.permission_mode !== 'read_only') await this.setMode('read_only');
  }

  async remove(): Promise<void> {
    await this.api.remove(this.id);
    readMarks?.forget(this.id);
    this.phase = 'gone';
    this.stop();
  }
}
