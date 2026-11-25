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

const CRASH_TOAST_TEXT = '页面出了点意外，部分功能可能不正常';
const IGNORED_REJECTION_NAMES = new Set(['AbortError', 'TimeoutError', 'ApiError', 'NetworkError']);

function isBenignBrowserError(message: string, err: unknown): boolean {
  const lower = message.trim().toLowerCase();
  if (!lower && !err) return true;
  if (lower.includes('resizeobserver loop')) return true;
  /* 跨源脚本或浏览器扩展注入的无堆栈泛化提示，并非面板自身崩溃 */
  if ((lower === 'script error.' || lower === 'script error') && !err) return true;
  return false;
}

function installCrashReporter() {
  let lastToast = 0;
  const record = (message: string, detail?: unknown) => {
    const clean = message.trim() || 'Unknown runtime error';
    crashLog.push({ at: new Date().toISOString(), message: clean });
    if (crashLog.length > 50) crashLog.shift();
    if (typeof console !== 'undefined' && typeof console.error === 'function') {
      console.error('[qwq-runtime]', clean, detail ?? '');
    }
    /* 同一时间的连环错误不重复堆叠 */
    const alreadyShowing = toasts.items.some((t) => t.kind === 'error' && t.text === CRASH_TOAST_TEXT);
    if (!alreadyShowing && Date.now() - lastToast > 8000) {
      lastToast = Date.now();
      toasts.error(CRASH_TOAST_TEXT, undefined, { label: '刷新', run: () => location.reload() });
    }
  };
  addEventListener('error', (e) => {
    const msg = String(e.message ?? (e.error as Error | undefined)?.message ?? '');
    if (isBenignBrowserError(msg, e.error)) return;
    record(msg, e.error);
  });
  addEventListener('unhandledrejection', (e) => {
    const r = e.reason as { name?: string; message?: string } | undefined;
    /* 取消、超时与已由业务处理的 API / 网络错误不算崩溃 */
    if (r?.name && IGNORED_REJECTION_NAMES.has(r.name)) return;
    const msg = String(r?.message ?? e.reason ?? '');
    if (isBenignBrowserError(msg, e.reason)) return;
    record(msg, e.reason);
  });
}
