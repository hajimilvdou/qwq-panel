// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 悬浮窗里的"当前会话"
 * --------------------------------------------------------------------------
 *   dockSession.id / stream        当前会话（记在 localStorage，跨刷新保留）
 *   dockSession.switchTo(id|null)  切换；null = 下一句话开新对话
 *   dockSession.send(text)         没有会话时先建一个（内置核心、"重要操作先问我"、默认 AI 服务）
 *   dockSession.attach() / detach() 悬浮窗展开或会话运行中才保持会话流
 * ========================================================================== */
import { newIdempotencyKey } from '$api/client';
import { agent } from '$api/endpoints';
import { resources } from '../resource.svelte';
import { lastSession } from './agent-sessions.svelte';
import { SessionStream } from './session-stream.svelte';

class DockSession {
  id = $state<string | null>(null);
  stream = $state<SessionStream | null>(null);
  #attached = false;

  init(): void {
    this.id = lastSession.get();
  }

  attach(): void {
    this.#attached = true;
    this.#ensureStream();
  }

  detach(): void {
    this.#attached = false;
    this.stream?.stop();
    this.stream = null;
  }

  switchTo(id: string | null): void {
    if (id === this.id) return;
    this.stream?.stop();
    this.stream = null;
    this.id = id;
    lastSession.set(id);
    if (this.#attached) this.#ensureStream();
  }

  async send(text: string): Promise<void> {
    if (!this.id) {
      const s = await agent.create({
        title: text.replace(/\s+/g, ' ').slice(0, 40),
        permission_mode: 'safe',
        config: { stream: true, enable_plan_tool: true },
      });
      resources.invalidate('agent-sessions');
      this.switchTo(s.session_id);
      /* 新会话：直接发，switchTo 已建立会话流从 seq 0 完整回放并推流，禁止 reload 清空流式气泡 */
      await agent.send(s.session_id, text, newIdempotencyKey());
      return;
    }
    await this.stream?.send(text);
  }

  /** 会话被删除或不可见：清掉记忆，回到"新对话" */
  forgetIfGone(): void {
    if (this.stream?.phase === 'gone') this.switchTo(null);
  }

  reset(): void {
    this.detach();
    this.id = null;
  }

  #ensureStream() {
    if (!this.id || this.stream) return;
    this.stream = new SessionStream(this.id);
    this.stream.start();
  }
}

export const dockSession = new DockSession();
