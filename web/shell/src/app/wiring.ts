// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 运行时接线：会话 ↔ 事件流 ↔ 缓存 ↔ 审批队列
 * --------------------------------------------------------------------------
 * 登录后：先开 SSE，再由各页面拉快照（先流后快照，ENG §4）。
 * 登出后：关流，清空所有内存态（不留上一个用户的数据）。
 * ========================================================================== */
import { approvals } from '$lib/ai/approvals.svelte';
import { dock } from '$lib/ai/dock.svelte';
import { events } from '$lib/events.svelte';
import { liveOps } from '$lib/operations.svelte';
import { resources } from '$lib/resource.svelte';
import { session } from '$lib/session.svelte';
import { toasts } from '$lib/toast.svelte';

/* 这些事件类型会让订阅了对应 subject / events 的缓存失效 */
const INVALIDATING = ['resource.changed', 'operation.updated', 'plugin.*', 'agent.session.*'];

export function wire(): void {
  events.configure({ onUnauthenticated: () => session.expire() });

  let offs: (() => void)[] = [];

  session.onSignedIn(() => {
    events.start();
    offs = [
      liveOps.connect(events),
      approvals.connect(events),
      ...INVALIDATING.map((t) => events.on(t, (e) => resources.handle(e))),
      events.onResync(() => resources.invalidateAll()),
    ];
  });

  session.onSignedOut(() => {
    offs.forEach((f) => f());
    offs = [];
    events.stop();
    resources.clear();
    liveOps.clear();
    dock.close();
  });

  /* 页面隐藏：保持连接，暂停循环动画；重新可见时补取期间标脏的快照 */
  document.addEventListener('visibilitychange', () => {
    document.documentElement.toggleAttribute('data-hidden', document.hidden);
    if (!document.hidden) resources.flushDirty();
  });

  installCrashReporter();
}

/* ------------------------------------------------------------------ 未捕获错误 */

/** 最近 50 条未捕获错误（内存环），便于排查；不上报任何外部服务 */
export const crashLog: { at: string; message: string }[] = [];

function installCrashReporter() {
  let lastToast = 0;
  const record = (message: string) => {
    crashLog.push({ at: new Date().toISOString(), message });
    if (crashLog.length > 50) crashLog.shift();
    /* 同一时间的连环错误只提示一次 */
    if (Date.now() - lastToast > 5000) {
      lastToast = Date.now();
      toasts.error('页面出了点意外，部分功能可能不正常', undefined, { label: '刷新', run: () => location.reload() });
    }
  };
  addEventListener('error', (e) => record(String(e.message)));
  addEventListener('unhandledrejection', (e) => {
    const r = e.reason as { name?: string } | undefined;
    /* 取消与已由业务处理的 API 错误不算崩溃 */
    if (r?.name === 'AbortError' || r?.name === 'ApiError' || r?.name === 'NetworkError') return;
    record(String((e.reason as Error | undefined)?.message ?? e.reason));
  });
}
