// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 宿主侧接线：把 PluginBridge 的抽象依赖接到真实的 api / events / dock / prefs
 * --------------------------------------------------------------------------
 *   hostSettings()             当前主题 / 动效 / 密度 / token 白名单 / 可见性
 *   pluginFrameSrc(entry, s)   entry_url + #theme=…&motion=…&density=…&path=…
 *   bridgeDeps(plugin, hooks)  BridgeDeps（invoke 走 endpoints，审批交悬浮窗）
 * ========================================================================== */
import { ApiError, newIdempotencyKey, NetworkError } from '$api/client';
import { plugins as pluginsApi } from '$api/endpoints';
import type { Plugin } from '$api/types';
import { dock } from '../ai/dock.svelte';
import { events } from '../events.svelte';
import { prefs } from '../prefs.svelte';
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
  };
}

/** 首帧参数放 fragment：不进服务端日志、不触发重新请求 */
export function pluginFrameSrc(entryUrl: string, s: HostSettings, path: string): string {
  const q = new URLSearchParams({ theme: s.theme, motion: s.motion, density: s.density, path });
  return `${entryUrl.split('#')[0]}#${q.toString()}`;
}

export function toProblem(err: unknown): BridgeProblem {
  if (err instanceof ApiError) {
    /* 只回 code/status；detail 仅插件自己的 PLUGIN_ERROR 原样回给插件 */
    return { code: err.code, status: err.status, detail: err.code === 'PLUGIN_ERROR' ? err.problem?.detail : undefined };
  }
  if (err instanceof NetworkError) return { code: 'UNAVAILABLE' };
  return { code: 'INTERNAL' };
}

type Hooks = Pick<BridgeDeps, 'onReady' | 'onResize' | 'onToast' | 'onNavigate' | 'onTimeout'>;

export function bridgeDeps(plugin: Plugin, hooks: Hooks): BridgeDeps {
  return {
    pluginId: plugin.plugin_id,
    operations: (plugin.operations ?? []).map((o) => ({ id: o.id, effect: o.effect, mode: o.mode, summary: o.summary })),
    routes: plugin.ui?.routes ?? [],
    invoke: async (op, payload, key, meta) => {
      const name = op.id.slice(plugin.plugin_id.length + 1);
      const r = await pluginsApi.invoke(
        { pluginId: plugin.plugin_id, operation: name, placement: plugin.placement },
        payload,
        { key, subject: meta?.subject, expectedRevision: meta?.expectedRevision },
      );
      /* 需要批准：交给悬浮窗，插件只知道"在等批准"，拿不到批准能力 */
      if (r.status === 'AWAITING_APPROVAL') dock.open({ approvalId: r.approvalId });
      return { status: r.status, operation_id: r.operationId, approval_id: r.approvalId, result: r.result, error: r.error?.code };
    },
    toProblem,
    subscribe: (fn) => {
      const relay = (e: { type: string; subject: string; occurred_at: string; payload: Record<string, unknown> }) =>
        fn({ type: e.type, subject: e.subject, occurred_at: e.occurred_at, payload: e.payload });
      const offs = [events.on('resource.changed', relay), events.on('plugin.*', relay)];
      return () => offs.forEach((off) => off());
    },
    newKey: newIdempotencyKey,
    ...hooks,
  };
}
