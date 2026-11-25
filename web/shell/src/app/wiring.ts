// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 运行时接线：会话 ↔ 登录后事件流（按需加载） ↔ 崩溃兜底
 * --------------------------------------------------------------------------
 * 未登录或启动阶段不加载 SSE / 审批队列 / 操作流，登录后异步接线。
 * ========================================================================== */
import { resources } from '$lib/resource.svelte';
import { session } from '$lib/session.svelte';
import { toasts } from '$lib/toast.svelte';

export function wire(): void {
  let gen = 0;
  let modPromise: Promise<typeof import('./signed-in-wiring')> | null = null;
  const loadSignedIn = () => (modPromise ??= import('./signed-in-wiring'));

  session.onSignedIn(() => {
    const cur = ++gen;
    void loadSignedIn().then((m) => {
      if (cur === gen) m.startSignedInRuntime();
    });
  });

  session.onSignedOut(() => {
    gen++;
    if (modPromise) {
      void modPromise.then((m) => m.stopSignedInRuntime());
    } else {
      resources.clear();
    }
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
  addEventListener('error', (e) => {
    const msg = String(e.message ?? '');
    /* 浏览器 ResizeObserver 循环节流提示属于无害告警，绝不能弹全局崩溃红条 */
    if (msg.includes('ResizeObserver loop')) return;
    record(msg);
  });
  addEventListener('unhandledrejection', (e) => {
    const r = e.reason as { name?: string } | undefined;
    /* 取消与已由业务处理的 API 错误不算崩溃 */
    if (r?.name === 'AbortError' || r?.name === 'ApiError' || r?.name === 'NetworkError') return;
    record(String((e.reason as Error | undefined)?.message ?? e.reason));
  });
}
