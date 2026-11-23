// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 插件桥协议（ENG §9 + STEP-16 沙箱受控委托）：消息白名单、结构校验、限流——纯函数，无 DOM
 * --------------------------------------------------------------------------
 *
 *   插件 iframe                         Shell
 *   ───────────                         ─────
 *   window.parent ── plugin.hello ──▶   校验 source === iframe.contentWindow，仅一次
 *                 ◀── plugin.port ───   新建 MessageChannel，交出 port2
 *   port ─────────── ui.ready ──────▶   去骨架（6 秒未到 → 超时态）
 *   port ◀────────── ui.settings ────   主题 / 动效 / 密度 / token / 可见性 / public_origin
 *   port ◀────────── ui.route ───────   浏览器前进后退
 *   port ─── ui.resize / ui.toast / ui.navigate / ui.confirm / ui.copy
 *            api.invoke / api.subscribe / events.unsubscribe ───▶
 *   port ◀────────── api.result / ui.confirm.result / ui.copy.result / api.event
 *
 * 未知类型或结构不符的消息丢弃；超过 4 MiB 的 api.invoke/api.call 返回显式 PAYLOAD_TOO_LARGE 错误。
 * ========================================================================== */

export const READY_TIMEOUT_MS = 6000;
export const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;
export const HEIGHT_MIN = 240;
export const HEIGHT_MAX = 4000;
export const TOAST_MAX_CHARS = 120;
export const TOAST_INTERVAL_MS = 2000;
export const INVOKE_CONCURRENCY = 8;
export const INVOKE_PER_SECOND = 20;
export const OPERATION_RE = /^[a-z0-9._-]+$/;

/* ------------------------------------------------------------------ 消息类型 */

export type RpcId = string | number;

export type PluginToShell =
  | { t: 'ui.ready' }
  | { t: 'ui.resize'; height: number }
  | { t: 'ui.toast'; text: string }
  | { t: 'ui.navigate'; path: string }
  | { t: 'ui.confirm'; id: RpcId; title: string; body: string; confirm_label?: string; danger?: boolean }
  | { t: 'ui.copy'; id: RpcId; text: string; label?: string }
  | {
      t: 'api.invoke';
      id: RpcId;
      operation: string;
      payload: Record<string, unknown>;
      subject?: string;
      expected_revision?: string;
    }
  | { t: 'api.subscribe'; subjects: string[] }
  | { t: 'events.unsubscribe'; subjects: string[] };

export interface HostSettings {
  theme: 'light' | 'dark';
  motion: 'full' | 'reduced' | 'off';
  density: 'comfortable' | 'compact';
  tokens: Record<string, string>;
  visible: boolean;
  public_origin?: string;
}

export type ShellToPlugin =
  | ({ t: 'ui.settings' } & HostSettings)
  | { t: 'ui.route'; path: string }
  | { t: 'api.result'; id: RpcId; ok: true; data: unknown }
  | { t: 'api.result'; id: RpcId; ok: false; problem: { code: string; detail?: string; status?: number } }
  | { t: 'ui.confirm.result'; id: RpcId; ok: true; data: { confirmed: boolean } }
  | { t: 'ui.confirm.result'; id: RpcId; ok: false; problem: { code: string; detail?: string; status?: number } }
  | { t: 'ui.copy.result'; id: RpcId; ok: true; data?: { copied: boolean } }
  | { t: 'ui.copy.result'; id: RpcId; ok: false; problem: { code: string; detail?: string; status?: number } }
  | { t: 'api.event'; event: unknown };

/* ------------------------------------------------------------------ 校验 */

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStr = (v: unknown, max = 4096): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;
const isRpcId = (v: unknown): v is RpcId =>
  (typeof v === 'string' && v.length > 0 && v.length <= 128) || (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0);

const utf8Encoder = new TextEncoder();

/** 计算 UTF-8 字节体积；无法序列化（循环引用、BigInt）或含超大二进制视图视为超限 */
export function sizeOf(v: unknown): number {
  try {
    const seen = new WeakSet<object>();
    let binaryBytes = 0;
    const raw = JSON.stringify(v, (_k, val) => {
      if (val && typeof val === 'object') {
        if (val instanceof ArrayBuffer) {
          binaryBytes += val.byteLength;
          return '';
        }
        if (ArrayBuffer.isView(val)) {
          binaryBytes += val.byteLength;
          return '';
        }
        if (seen.has(val)) throw new Error('circular');
        seen.add(val);
      }
      return val;
    });
    if (raw === undefined) return binaryBytes;
    return utf8Encoder.encode(raw).byteLength + binaryBytes;
  } catch {
    return Infinity;
  }
}

/** 握手首包：{ t:'plugin.hello', kit_major:number } */
export function parseHello(data: unknown): { kitMajor: number } | null {
  if (!isObj(data) || data.t !== 'plugin.hello') return null;
  const k = data.kit_major;
  return typeof k === 'number' && Number.isInteger(k) && k > 0 ? { kitMajor: k } : null;
}

/** 识别超限的 api.invoke / api.call 帧并提取其 id，便于宿主返回显式 PAYLOAD_TOO_LARGE 错误而非静默丢弃 */
export function extractOversizedApiCallId(data: unknown): RpcId | null {
  if (!isObj(data)) return null;
  if ((data.t === 'api.invoke' || data.t === 'api.call') && isRpcId(data.id) && sizeOf(data) > MAX_MESSAGE_BYTES) {
    return data.id;
  }
  return null;
}

/** port 上收到的消息 → 合法消息或 null */
export function parsePluginMessage(data: unknown): PluginToShell | null {
  if (!isObj(data) || typeof data.t !== 'string') return null;
  if (sizeOf(data) > MAX_MESSAGE_BYTES) return null;
  switch (data.t) {
    case 'ui.ready':
      return { t: 'ui.ready' };
    case 'ui.resize':
      return typeof data.height === 'number' && Number.isFinite(data.height) ? { t: 'ui.resize', height: data.height } : null;
    case 'ui.toast':
      return isStr(data.text, 10_000) ? { t: 'ui.toast', text: data.text } : null;
    case 'ui.navigate':
      return isStr(data.path, 2048) ? { t: 'ui.navigate', path: data.path } : null;
    case 'ui.confirm': {
      if (!isRpcId(data.id) || !isStr(data.title, 200)) return null;
      const body = data.body === undefined ? '' : typeof data.body === 'string' && data.body.length <= 2000 ? data.body : null;
      if (body === null) return null;
      if (data.confirm_label !== undefined && !isStr(data.confirm_label, 64)) return null;
      return {
        t: 'ui.confirm',
        id: data.id,
        title: data.title,
        body,
        confirm_label: data.confirm_label as string | undefined,
        danger: Boolean(data.danger),
      };
    }
    case 'ui.copy': {
      if (!isRpcId(data.id) || !isStr(data.text, 65_536)) return null;
      if (data.label !== undefined && !isStr(data.label, 200)) return null;
      return {
        t: 'ui.copy',
        id: data.id,
        text: data.text,
        label: data.label as string | undefined,
      };
    }
    case 'api.invoke':
    case 'api.call': {
      const opName = data.t === 'api.invoke' ? data.operation : data.action;
      const rawPayload = data.t === 'api.invoke' ? data.payload : data.input;
      if (!isRpcId(data.id) || !isStr(opName, 128)) return null;
      const payload = rawPayload === undefined ? {} : rawPayload;
      if (!isObj(payload)) return null;
      if (data.subject !== undefined && !isStr(data.subject, 512)) return null;
      if (data.expected_revision !== undefined && !isStr(data.expected_revision, 128)) return null;
      return {
        t: 'api.invoke',
        id: data.id,
        operation: opName,
        payload,
        subject: data.subject as string | undefined,
        expected_revision: data.expected_revision as string | undefined,
      };
    }
    case 'api.subscribe':
    case 'events.subscribe': {
      const s = data.subjects;
      if (!Array.isArray(s) || s.length > 32 || !s.every((x) => isStr(x, 512))) return null;
      return { t: 'api.subscribe', subjects: s as string[] };
    }
    case 'events.unsubscribe':
    case 'api.unsubscribe': {
      const s = data.subjects;
      if (!Array.isArray(s) || s.length > 64 || !s.every((x) => isStr(x, 512))) return null;
      return { t: 'events.unsubscribe', subjects: s as string[] };
    }
    default:
      return null;
  }
}

export const clampHeight = (h: number): number => Math.round(Math.min(HEIGHT_MAX, Math.max(HEIGHT_MIN, h)));

/** 插件 toast / 对话框单行文本：去控制字符、压空白、截断 */
export function cleanToast(text: string, maxChars = TOAST_MAX_CHARS): string {
  const s = text.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return s.length > maxChars ? s.slice(0, maxChars - 1) + '…' : s;
}

/**
 * 规范化插件内路径：必须以 / 开头，禁 .. 与 // 与反斜杠，去掉 query/hash 外的尾斜杠。
 * 返回 null 表示非法。
 */
export function normalizePluginPath(path: string): string | null {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\')) return null;
  const [p] = path.split(/[?#]/, 1) as [string];
  const segs = p.split('/').filter(Boolean);
  if (segs.some((s) => s === '..' || s === '.')) return null;
  return '/' + segs.join('/');
}

/** ui.navigate 只能去本插件声明的 routes（前缀匹配到段边界） */
export function routeAllowed(routes: readonly { path: string }[], path: string): boolean {
  const p = normalizePluginPath(path);
  if (p === null) return false;
  return routes.some((r) => {
    const base = normalizePluginPath(r.path);
    if (base === null) return false;
    return base === '/' ? true : p === base || p.startsWith(base + '/');
  });
}

/** 本插件事件订阅：subject 必须落在 plugins/{id} 或 nodes/{nodeId}/plugins/{id} 名下 */
export function subjectAllowed(pluginId: string, subject: string): boolean {
  const base = `plugins/${pluginId}`;
  if (subject === base || subject.startsWith(base + '/')) return true;
  if (subject.startsWith('nodes/')) {
    const rest = subject.slice('nodes/'.length);
    const slash = rest.indexOf('/');
    if (slash > 0) {
      const sub = rest.slice(slash + 1);
      return sub === base || sub.startsWith(base + '/');
    }
  }
  return false;
}

/* ------------------------------------------------------------------ 限流 */

/** 并发 ≤ max、每秒 ≤ perSecond 的闸门；acquire() 失败即 RATE_LIMITED */
export class RateGate {
  #inflight = 0;
  #stamps: number[] = [];

  constructor(
    readonly max = INVOKE_CONCURRENCY,
    readonly perSecond = INVOKE_PER_SECOND,
    readonly now: () => number = Date.now,
  ) {}

  acquire(): boolean {
    const t = this.now();
    this.#stamps = this.#stamps.filter((s) => t - s < 1000);
    if (this.#inflight >= this.max || this.#stamps.length >= this.perSecond) return false;
    this.#inflight++;
    this.#stamps.push(t);
    return true;
  }

  release(): void {
    this.#inflight = Math.max(0, this.#inflight - 1);
  }
}

/** 至多每 interval 毫秒放行一次 */
export function throttleGate(interval: number, now: () => number = Date.now): () => boolean {
  let last = -Infinity;
  return () => {
    const t = now();
    if (t - last < interval) return false;
    last = t;
    return true;
  };
}
