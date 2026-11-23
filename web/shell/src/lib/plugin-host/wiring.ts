// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 宿主侧接线：把 PluginBridge 的抽象依赖接到真实的 api / events / dock / prefs / clipboard
 * --------------------------------------------------------------------------
 *   hostSettings()             当前主题 / 动效 / 密度 / token 白名单 / 可见性 / public_origin
 *   pluginFrameSrc(entry, s)   entry_url + #theme=…&motion=…&density=…&path=…
 *   bridgeDeps(plugin, hooks)  BridgeDeps（invoke 走 endpoints，审批交悬浮窗，复制走宿主剪贴板）
 * ========================================================================== */
import { ApiError, newIdempotencyKey, NetworkError, TERMINAL, type OpResult } from '$api/client';
import { operations as opsApi, plugins as pluginsApi } from '$api/endpoints';
import type { Plugin } from '$api/types';
import { dock } from '../ai/dock.svelte';
import { events } from '../events.svelte';
import { prefs } from '../prefs.svelte';
import { toasts } from '../toast.svelte';
import type { BridgeDeps, BridgeProblem, HostSettings } from './index';

/** 下发给插件的设计 token（只读值，不含任何会话信息） */
export const TOKEN_WHITELIST = [
  '--accent',
  '--accent-strong',
  '--accent-soft',
  '--accent-text',
  '--on-accent',
  '--bg',
  '--surface',
  '--surface-2',
  '--surface-3',
  '--line',
  '--line-input',
  '--text',
  '--text-2',
  '--text-3',
  '--ok',
  '--ok-soft',
  '--ok-text',
  '--warn',
  '--warn-soft',
  '--warn-text',
  '--bad',
  '--bad-soft',
  '--bad-text',
  '--info',
  '--info-soft',
  '--info-text',
  '--r-sm',
  '--r-md',
  '--r-lg',
] as const;

export function hostSettings(): HostSettings {
  const tokens: Record<string, string> = {};
  if (typeof document !== 'undefined') {
    const cs = getComputedStyle(document.documentElement);
    for (const k of TOKEN_WHITELIST) {
      const v = cs.getPropertyValue(k).trim();
      if (v) tokens[k] = v;
    }
  }
  return {
    theme: prefs.resolvedTheme,
    motion: prefs.resolvedMotion,
    density: prefs.density,
    tokens,
    visible: typeof document === 'undefined' || document.visibilityState === 'visible',
    public_origin: typeof window !== 'undefined' ? window.location.origin : '',
  };
}

/** 首帧参数放 fragment：不进服务端日志、不触发重新请求 */
export function pluginFrameSrc(entryUrl: string, s: HostSettings, path: string): string {
  const q = new URLSearchParams({ theme: s.theme, motion: s.motion, density: s.density, path });
  return `${entryUrl.split('#')[0]}#${q.toString()}`;
}

const SAFE_DETAIL_CODES = new Set([
  'PLUGIN_ERROR',
  'VALIDATION_FAILED',
  'INVALID_ARGUMENT',
  'PRECONDITION_FAILED',
  'STATE_CONFLICT',
  'NOT_FOUND',
]);

export function toProblem(err: unknown): BridgeProblem {
  if (err instanceof ApiError) {
    return {
      code: err.code,
      status: err.status,
      detail: SAFE_DETAIL_CODES.has(err.code) ? err.problem?.detail : undefined,
    };
  }
  if (err instanceof NetworkError) return { code: 'UNAVAILABLE', detail: '网络连接不可用' };
  return { code: 'INTERNAL' };
}

function sleepOrSignal(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener('abort', done, { once: true });
  });
}

async function waitForOperation(initial: OpResult, budgetMs: number, signal?: AbortSignal): Promise<OpResult> {
  let cur = initial;
  const opId = cur.operationId;
  if (!opId || TERMINAL.has(cur.status) || cur.status === 'AWAITING_APPROVAL') return cur;

  const deadline = Date.now() + budgetMs;
  let wakeup: (() => void) | null = null;
  const off = events.on('operation.updated', (e) => {
    const p = e.payload as { operation_id?: string } | undefined;
    if (p?.operation_id === opId && wakeup) {
      const fn = wakeup;
      wakeup = null;
      fn();
    }
  });

  try {
    let delayMs = 250;
    while (!TERMINAL.has(cur.status) && cur.status !== 'AWAITING_APPROVAL' && Date.now() < deadline) {
      if (signal?.aborted) break;
      const waitMs = Math.min(delayMs, Math.max(50, deadline - Date.now()));
      await new Promise<void>((resolve) => {
        wakeup = resolve;
        void sleepOrSignal(waitMs, signal).then(() => {
          if (wakeup === resolve) wakeup = null;
          resolve();
        });
      });
      if (signal?.aborted) break;
      const op = await opsApi.get(opId, signal);
      cur = {
        operationId: op.operation_id,
        status: op.status,
        approvalId: op.approval_id,
        result: op.result,
        error: op.error,
        operation: op,
      };
      delayMs = Math.min(1500, Math.round(delayMs * 1.6));
    }
  } finally {
    off();
  }
  return cur;
}

type Hooks = Pick<BridgeDeps, 'onReady' | 'onResize' | 'onToast' | 'onNavigate' | 'onTimeout' | 'onConfirm' | 'onCopy'>;

export function bridgeDeps(plugin: Plugin, hooks: Hooks): BridgeDeps {
  return {
    pluginId: plugin.plugin_id,
    operations: (plugin.operations ?? []).map((o) => ({ id: o.id, effect: o.effect, mode: o.mode, summary: o.summary })),
    routes: plugin.ui?.routes ?? [],
    invoke: async (op, payload, key, meta) => {
      const name = op.id.slice(plugin.plugin_id.length + 1);
      let r = await pluginsApi.invoke(
        { pluginId: plugin.plugin_id, operation: name, placement: plugin.placement },
        payload,
        { key, subject: meta?.subject, expectedRevision: meta?.expectedRevision, signal: meta?.signal },
      );
      /* 需要批准：交给悬浮窗，插件只知道"在等批准"，拿不到批准能力 */
      if (r.status === 'AWAITING_APPROVAL') {
        dock.open({ approvalId: r.approvalId });
      } else if (r.operationId && !TERMINAL.has(r.status)) {
        /* mode="job" 返回 HTTP 202 PENDING/RUNNING 时透明等待终态，直接返回真实业务 result */
        r = await waitForOperation(r, 45_000, meta?.signal);
        if (r.status === 'AWAITING_APPROVAL') dock.open({ approvalId: r.approvalId });
      }
      const errDetail = r.error
        ? SAFE_DETAIL_CODES.has(r.error.code)
          ? r.error.detail || r.error.code
          : r.error.code
        : undefined;
      return { status: r.status, operation_id: r.operationId, approval_id: r.approvalId, result: r.result, error: errDetail };
    },
    toProblem,
    subscribe: (fn) => {
      const relay = (e: { type: string; subject: string; occurred_at: string; payload: Record<string, unknown> }) =>
        fn({ type: e.type, subject: e.subject, occurred_at: e.occurred_at, payload: e.payload });
      const offs = [events.on('resource.changed', relay), events.on('plugin.*', relay)];
      return () => offs.forEach((off) => off());
    },
    newKey: newIdempotencyKey,
    onCopy: async ({ text, label }) => {
      await navigator.clipboard.writeText(text);
      toasts.success(label || '已复制到剪贴板');
    },
    ...hooks,
  };
}
