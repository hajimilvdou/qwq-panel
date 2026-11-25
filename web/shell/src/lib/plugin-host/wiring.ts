// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 宿主侧接线：把 PluginBridge 的抽象依赖接到真实的 api / events / dock / prefs / clipboard
 * --------------------------------------------------------------------------
 *   hostSettings()             当前主题 / 动效 / 密度 / token 白名单 / 可见性 / public_origin
 *   pluginFrameSrc(entry, s)   entry_url + #theme=…&motion=…&density=…&path=…
 *   bridgeDeps(plugin, hooks)  BridgeDeps（invoke 走 endpoints，审批交悬浮窗，复制走宿主剪贴板）
 * ========================================================================== */
import { ApiError, newIdempotencyKey, NetworkError, TERMINAL, type OpResult } from '$api/client';
import { copyTextWithFallback } from '$ui/clipboard';
import { operations as opsApi, plugins as pluginsApi } from '$api/endpoints';
import { isPluginActiveReady } from '$api/endpoints-plugins';
import type { Plugin } from '$api/types';
import { installOfficialPlugin } from '../../features/apps/official-install';
import { dock } from '../ai/dock.svelte';
import { events } from '../events.svelte';
import { prefs } from '../prefs.svelte';
import { resources } from '../resource.svelte';
import { toasts } from '../toast.svelte';
import {
  isEnsurePluginAllowed,
  type BridgeConfirmRequest,
  type BridgeDeps,
  type BridgeProblem,
  type EnsurePluginsFailure,
  type EnsurePluginsParams,
  type EnsurePluginsResult,
  type HostSettings,
} from './index';

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
  let panelTlsMode = '';
  let panelTlsSha256 = '';
  const sys = resources.peek('system.info');
  if (sys && typeof sys === 'object' && 'tls' in sys) {
    const tls = (sys as { tls?: { mode?: string; fingerprint?: string } }).tls;
    if (typeof tls?.mode === 'string') panelTlsMode = tls.mode;
    if (typeof tls?.fingerprint === 'string') {
      const hex = tls.fingerprint.replace(/:/g, '').replace(/^sha256/i, '').trim().toLowerCase();
      if (/^[0-9a-f]{64}$/.test(hex)) panelTlsSha256 = hex;
    }
  }
  return {
    theme: prefs.resolvedTheme,
    motion: prefs.resolvedMotion,
    density: prefs.density,
    tokens,
    visible: typeof document === 'undefined' || document.visibilityState === 'visible',
    public_origin: typeof window !== 'undefined' ? window.location.origin : '',
    panel_tls_mode: panelTlsMode || undefined,
    panel_tls_sha256: panelTlsSha256 || undefined,
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

export class EnsurePluginsError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    readonly detail?: string,
  ) {
    super(detail || code);
    this.name = 'EnsurePluginsError';
  }
}

export function toProblem(err: unknown): BridgeProblem {
  if (err instanceof EnsurePluginsError) {
    return {
      code: err.code,
      status: err.status,
      detail: err.detail,
    };
  }
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

const ENSURE_PLUGIN_LABELS: Record<string, string> = {
  'web.ingress': '反向代理网关 (web.ingress)',
  'tls.certificates': '自动 HTTPS 证书管理 (tls.certificates)',
  'domain.dns': 'DNS 托管与自动验证 (domain.dns)',
  'core.xray': 'Xray 核心驱动 (core.xray)',
};

function computeBridgeJobWaitMs(declaredTimeoutMs?: number): number {
  const base = declaredTimeoutMs && declaredTimeoutMs > 0 ? declaredTimeoutMs + 15_000 : 90_000;
  return Math.min(Math.max(base, 90_000), 660_000);
}

export interface EnsurePluginsHandlerDeps {
  listPlugins: () => Promise<{ items: Plugin[] }>;
  installPlugin?: (pluginId: string, key: string, autoEnable?: boolean) => Promise<OpResult>;
  enablePlugin: (pluginId: string, key: string) => Promise<OpResult>;
  waitForOp: (initial: OpResult, budgetMs: number, signal?: AbortSignal) => Promise<OpResult>;
  newKey: () => string;
  confirmAction?: (req: BridgeConfirmRequest) => Promise<boolean>;
  onAwaitingApproval?: (approvalId?: string) => void;
  onChanged?: () => void;
}

function opFailureDetail(op: OpResult, fallback: string): string | null {
  if (op.status === 'AWAITING_APPROVAL') return '等待审批确认';
  if (op.error) {
    return SAFE_DETAIL_CODES.has(op.error.code) ? op.error.detail || op.error.code : op.error.code;
  }
  if (op.status === 'FAILED' || op.status === 'REJECTED' || op.status === 'CANCELED' || op.status === 'EXPIRED') {
    return `${fallback} (${op.status})`;
  }
  return null;
}

/**
 * 零信任官方联动组件一键安装/启用处理器：
 *   1. 严格校验白名单（仅允许 web.ingress / tls.certificates / domain.dns，其余直接 PERMISSION_DENIED）；
 *   2. 对缺装或停用组件强制弹出宿主标准确认框；
 *   3. 依次安装缺失组件并启用停用组件，等待 Operation 终态并返回结构化结果。
 */
export function createEnsurePluginsHandler(
  deps: EnsurePluginsHandlerDeps,
): (req: EnsurePluginsParams) => Promise<EnsurePluginsResult> {
  return async (req: EnsurePluginsParams): Promise<EnsurePluginsResult> => {
    const requested = Array.from(new Set((req.plugins ?? []).map((s) => s.trim()).filter(Boolean)));
    if (requested.length === 0) {
      throw new EnsurePluginsError('INVALID_ARGUMENT', 400, '请求的组件列表不能为空');
    }
    const disallowed = requested.filter((id) => !isEnsurePluginAllowed(id));
    if (disallowed.length > 0) {
      throw new EnsurePluginsError(
        'PERMISSION_DENIED',
        403,
        `不允许请求非白名单组件：${disallowed.join(', ')}`,
      );
    }

    const page = await deps.listPlugins();
    const byId = new Map<string, Plugin>();
    for (const item of page.items ?? []) {
      byId.set(item.plugin_id, item);
    }

    const already_ready: string[] = [];
    const missing: string[] = [];
    const disabled: string[] = [];
    for (const id of requested) {
      const existing = byId.get(id);
      if (!existing) {
        missing.push(id);
      } else if (isPluginActiveReady(existing)) {
        already_ready.push(id);
      } else {
        disabled.push(id);
      }
    }

    if (missing.length === 0 && disabled.length === 0) {
      return {
        ready: true,
        installed: [],
        enabled: [],
        already_ready,
      };
    }

    const lines: string[] = [];
    if (req.reason) lines.push(req.reason);
    if (missing.length > 0) {
      lines.push(`将安装并启用：${missing.map((id) => ENSURE_PLUGIN_LABELS[id] ?? id).join('、')}`);
    }
    if (disabled.length > 0) {
      lines.push(`将启动并启用：${disabled.map((id) => ENSURE_PLUGIN_LABELS[id] ?? id).join('、')}`);
    }
    lines.push('是否立即继续？');

    const confirmed = deps.confirmAction
      ? await deps.confirmAction({
          title: '启用官方联动组件',
          body: lines.join('\n'),
          confirmLabel: '立即启用',
          danger: false,
        })
      : false;

    if (!confirmed) {
      return {
        ready: false,
        cancelled: true,
        installed: [],
        enabled: [],
        already_ready,
      };
    }

    const installed: string[] = [];
    const enabled: string[] = [];
    const failed: EnsurePluginsFailure[] = [];

    for (const id of missing) {
      if (!deps.installPlugin) {
        failed.push({ plugin_id: id, detail: `组件 ${id} 尚未安装，请前往应用中心上传安装官方组件包` });
        continue;
      }
      try {
        let op = await deps.installPlugin(id, deps.newKey(), true);
        if (op.status === 'AWAITING_APPROVAL') {
          deps.onAwaitingApproval?.(op.approvalId);
          failed.push({ plugin_id: id, detail: '等待审批确认' });
          continue;
        }
        if (op.operationId && !TERMINAL.has(op.status)) {
          op = await deps.waitForOp(op, 60_000);
        }
        if (op.status === 'AWAITING_APPROVAL') {
          deps.onAwaitingApproval?.(op.approvalId);
          failed.push({ plugin_id: id, detail: '等待审批确认' });
          continue;
        }
        const failDetail = opFailureDetail(op, '安装未完成');
        if (failDetail) {
          failed.push({ plugin_id: id, detail: failDetail });
          continue;
        }
        installed.push(id);
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          failed.push({
            plugin_id: id,
            detail: `当前节点未预置 ${id} 内置安装包，请前往「应用中心 → 上传安装」安装该官方组件`,
          });
        } else {
          const prob = toProblem(err);
          failed.push({ plugin_id: id, detail: prob.detail || prob.code });
        }
      }
    }

    for (const id of disabled) {
      try {
        let op = await deps.enablePlugin(id, deps.newKey());
        if (op.status === 'AWAITING_APPROVAL') {
          deps.onAwaitingApproval?.(op.approvalId);
          failed.push({ plugin_id: id, detail: '等待审批确认' });
          continue;
        }
        if (op.operationId && !TERMINAL.has(op.status)) {
          op = await deps.waitForOp(op, 60_000);
        }
        if (op.status === 'AWAITING_APPROVAL') {
          deps.onAwaitingApproval?.(op.approvalId);
          failed.push({ plugin_id: id, detail: '等待审批确认' });
          continue;
        }
        const failDetail = opFailureDetail(op, '启用未完成');
        if (failDetail) {
          failed.push({ plugin_id: id, detail: failDetail });
          continue;
        }
        enabled.push(id);
      } catch (err) {
        const prob = toProblem(err);
        failed.push({ plugin_id: id, detail: prob.detail || prob.code });
      }
    }

    if (installed.length > 0 || enabled.length > 0) {
      deps.onChanged?.();
    }

    return {
      ready: failed.length === 0,
      installed,
      enabled,
      already_ready,
      ...(failed.length > 0 ? { failed } : {}),
    };
  };
}

type Hooks = Pick<
  BridgeDeps,
  'onReady' | 'onResize' | 'onToast' | 'onNavigate' | 'onOpenPlugin' | 'onTimeout' | 'onConfirm' | 'onCopy' | 'onEnsurePlugins'
>;

export function bridgeDeps(plugin: Plugin, hooks: Hooks): BridgeDeps {
  const defaultEnsurePlugins = createEnsurePluginsHandler({
    listPlugins: pluginsApi.list,
    installPlugin: async (pluginId: string): Promise<OpResult> => {
      try {
        await installOfficialPlugin(pluginId);
        return { operationId: '', status: 'SUCCEEDED' };
      } catch (err) {
        if (err instanceof ApiError || err instanceof EnsurePluginsError) throw err;
        throw new EnsurePluginsError('FAILED_PRECONDITION', 422, err instanceof Error ? err.message : '官方插件安装失败');
      }
    },
    enablePlugin: pluginsApi.enable,
    waitForOp: waitForOperation,
    newKey: newIdempotencyKey,
    confirmAction: hooks.onConfirm,
    onAwaitingApproval: (approvalId) => dock.open({ approvalId }),
    onChanged: () => {
      resources.invalidate('plugins');
      resources.invalidate('plugin-catalog');
      toasts.success('官方联动组件已就绪');
    },
  });

  return {
    pluginId: plugin.plugin_id,
    operations: (plugin.operations ?? []).map((o) => ({
      id: o.id,
      effect: o.effect,
      mode: o.mode,
      summary: o.summary,
      timeoutMs: o.timeout_ms,
    })),
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
        /* mode="job" 返回 HTTP 202 PENDING/RUNNING 时按声明超时透明等待终态，超时明确报错 */
        const waitMs = computeBridgeJobWaitMs(op.timeoutMs);
        r = await waitForOperation(r, waitMs, meta?.signal);
        if (r.status === 'AWAITING_APPROVAL') {
          dock.open({ approvalId: r.approvalId });
        } else if (!TERMINAL.has(r.status) && !meta?.signal?.aborted) {
          return {
            status: 'FAILED',
            operation_id: r.operationId,
            approval_id: r.approvalId,
            result: r.result,
            error: `TIMEOUT: 后台任务耗时超过 ${Math.round(waitMs / 1000)} 秒仍未结束，可在「动态」中继续查看进度`,
          };
        }
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
      const offs = [
        events.on('resource.changed', relay),
        events.on('plugin.*', relay),
        events.on('operation.updated', (e) => {
          const st = (e.payload as { status?: string } | undefined)?.status;
          if (st && TERMINAL.has(st as 'SUCCEEDED')) relay(e);
        }),
      ];
      return () => offs.forEach((off) => off());
    },
    newKey: newIdempotencyKey,
    onCopy: async ({ text, label }) => {
      const ok = await copyTextWithFallback(text);
      if (ok) {
        toasts.success(label || '已复制到剪贴板');
      } else {
        toasts.error('当前浏览器限制自动复制，请手动选中文本复制');
        throw new Error('当前浏览器限制自动复制，请手动选中文本复制');
      }
    },
    onEnsurePlugins: defaultEnsurePlugins,
    ...hooks,
  };
}
