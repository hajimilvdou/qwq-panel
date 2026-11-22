// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 插件宿主桥（ENG §9）：握手、消息分发、代理边界、清理
 * --------------------------------------------------------------------------
 *   const bridge = new PluginBridge(deps);
 *   bridge.attach(iframe.contentWindow);         // 每次（重新）加载 iframe 都调用
 *   window.addEventListener('message', bridge.onWindowMessage);
 *   bridge.settings({ theme, motion, ... });      // 变化时推送（未连上则握手后补发）
 *   bridge.route('/bans');                        // 浏览器前进后退
 *   bridge.dispose();                             // 卸载：关 port、清订阅、停计时
 *
 * 安全不变量：
 *   1. 只认 event.source === 当前 iframe.contentWindow（沙箱 origin 为 "null"，不可依赖）
 *   2. 每次 attach 只接受一次 hello；之后一切走 MessageChannel port
 *   3. api.invoke 只能调用本插件 operations 清单内的 op；不代理宿主 API、不代理他插件
 *   4. 非 read 的调用由宿主生成幂等键；AWAITING_APPROVAL 交给悬浮窗，插件拿不到批准能力
 *   5. api.subscribe 只投递 plugins/{本插件} 名下的事件
 * 本模块不碰 DOM 与 $api：真实调用经 deps 注入，便于单测。
 * ========================================================================== */
import {
  OPERATION_RE,
  READY_TIMEOUT_MS,
  RateGate,
  TOAST_INTERVAL_MS,
  clampHeight,
  cleanToast,
  normalizePluginPath,
  parseHello,
  parsePluginMessage,
  routeAllowed,
  subjectAllowed,
  throttleGate,
  type HostSettings,
  type PluginToShell,
  type ShellToPlugin,
} from './protocol';

export * from './protocol';

/** 本插件可调用的 operation（来自 Plugin.operations，id 形如 {plugin_id}/{name}） */
export interface BridgeOperation {
  id: string;
  effect: string;
  mode?: string;
  summary?: string;
}

export interface BridgeInvokeMeta {
  subject?: string;
  expectedRevision?: string;
  signal?: AbortSignal;
}

export interface BridgeProblem {
  code: string;
  detail?: string;
  status?: number;
}

export interface BridgeEvent {
  subject: string;
  [k: string]: unknown;
}

export interface BridgeDeps {
  pluginId: string;
  operations: readonly BridgeOperation[];
  routes: readonly { path: string }[];
  /** 执行调用；key 仅非只读 invoke 时给出。resolve 的值原样作为 api.result.data */
  invoke: (
    op: BridgeOperation,
    payload: Record<string, unknown>,
    key: string | undefined,
    meta?: BridgeInvokeMeta,
  ) => Promise<unknown>;
  /** 把调用异常转成 problem（只含 code / detail / status，不含堆栈） */
  toProblem: (err: unknown) => BridgeProblem;
  /** 订阅宿主事件流；返回取消函数 */
  subscribe: (fn: (e: BridgeEvent) => void) => () => void;
  newKey: () => string;
  onReady: () => void;
  onResize: (height: number) => void;
  onToast: (text: string) => void;
  onNavigate: (path: string) => void;
  onTimeout: () => void;
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (h: unknown) => void;
  /** 测试注入；缺省用全局 MessageChannel */
  createChannel?: () => { port1: MessagePort; port2: MessagePort };
}

type Phase = 'idle' | 'waiting-hello' | 'connected' | 'ready' | 'timeout' | 'disposed';

const MAX_SUBSCRIBED_SUBJECTS = 64;

export class PluginBridge {
  phase: Phase = 'idle';
  kitMajor: number | null = null;

  #win: Window | null = null;
  #port: MessagePort | null = null;
  #connGen = 0;
  #connAbort: AbortController | null = null;
  #timer: unknown = null;
  #settings: HostSettings | null = null;
  #pendingRoute: string | null = null;
  #subjects = new Set<string>();
  #unsub: (() => void) | null = null;
  #gate: RateGate;
  #toastGate: () => boolean;
  #setTimer: (fn: () => void, ms: number) => unknown;
  #clearTimer: (h: unknown) => void;

  constructor(readonly deps: BridgeDeps) {
    const now = deps.now ?? Date.now;
    this.#gate = new RateGate(undefined, undefined, now);
    this.#toastGate = throttleGate(TOAST_INTERVAL_MS, now);
    this.#setTimer = deps.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.#clearTimer = deps.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
  }

  /* ---------------------------------------------------------------- 生命周期 */

  /** 新的 iframe 窗口（首次加载或重试）：重置连接，开始 6 秒计时 */
  attach(win: Window | null): void {
    if (this.phase === 'disposed') return;
    this.#closePort();
    this.#win = win;
    this.phase = 'waiting-hello';
    this.#clearReady();
    this.#timer = this.#setTimer(() => {
      if (this.phase === 'waiting-hello' || this.phase === 'connected') {
        this.phase = 'timeout';
        this.#closePort();
        this.deps.onTimeout();
      }
    }, READY_TIMEOUT_MS);
  }

  dispose(): void {
    this.#clearReady();
    this.#closePort();
    this.#win = null;
    this.phase = 'disposed';
  }

  /* ---------------------------------------------------------------- 握手（window message） */

  onWindowMessage = (e: MessageEvent): void => {
    if (this.phase !== 'waiting-hello' || !this.#win || e.source !== this.#win) return;
    const hello = parseHello(e.data);
    if (!hello || hello.kitMajor !== 1) return;
    this.kitMajor = hello.kitMajor;
    const ch = this.deps.createChannel?.() ?? new MessageChannel();
    this.#connGen++;
    this.#connAbort = new AbortController();
    const gen = this.#connGen;
    const boundPort = ch.port1;
    this.#port = boundPort;
    this.#port.onmessage = (m) => this.#onPortMessage(m.data, gen, boundPort);
    this.#port.start?.();
    this.phase = 'connected';
    this.#win.postMessage({ t: 'plugin.port' }, '*', [ch.port2]);
    if (this.#settings) this.#send({ t: 'ui.settings', ...this.#settings });
    if (this.#pendingRoute) {
      const p = this.#pendingRoute;
      this.#pendingRoute = null;
      this.#send({ t: 'ui.route', path: p });
    }
  };

  /* ---------------------------------------------------------------- S → P */

  settings(s: HostSettings): void {
    this.#settings = s;
    this.#send({ t: 'ui.settings', ...s });
  }

  route(path: string): void {
    const p = normalizePluginPath(path);
    if (p === null) return;
    if (this.phase !== 'connected' && this.phase !== 'ready') {
      this.#pendingRoute = p;
      return;
    }
    this.#send({ t: 'ui.route', path: p });
  }

  /* ---------------------------------------------------------------- P → S */

  #onPortMessage(data: unknown, gen: number, port: MessagePort): void {
    if (this.#connGen !== gen || this.#port !== port) return;
    if (this.phase !== 'connected' && this.phase !== 'ready') return;
    const msg = parsePluginMessage(data);
    if (!msg) return;
    switch (msg.t) {
      case 'ui.ready':
        if (this.phase === 'connected') {
          this.phase = 'ready';
          this.#clearReady();
          this.deps.onReady();
        }
        return;
      case 'ui.resize':
        this.deps.onResize(clampHeight(msg.height));
        return;
      case 'ui.toast': {
        const text = cleanToast(msg.text);
        if (text && this.#toastGate()) this.deps.onToast(text);
        return;
      }
      case 'ui.navigate': {
        const p = normalizePluginPath(msg.path);
        if (p !== null && routeAllowed(this.deps.routes, p)) this.deps.onNavigate(p);
        return;
      }
      case 'api.invoke':
        void this.#invoke(msg, gen, port);
        return;
      case 'api.subscribe':
        this.#subscribe(msg.subjects);
        return;
    }
  }

  /** 解析 op 名 → 本插件清单内的 operation；不在清单内一律 null */
  resolveOperation(name: string): BridgeOperation | null {
    if (!OPERATION_RE.test(name)) return null;
    const id = `${this.deps.pluginId}/${name}`;
    return this.deps.operations.find((o) => o.id === id) ?? null;
  }

  async #invoke(msg: Extract<PluginToShell, { t: 'api.invoke' }>, gen: number, port: MessagePort): Promise<void> {
    const sendForConn = (out: ShellToPlugin) => {
      if (this.#connGen !== gen || this.#port !== port) return;
      this.#send(out);
    };
    const op = this.resolveOperation(msg.operation);
    if (!op) {
      sendForConn({ t: 'api.result', id: msg.id, ok: false, problem: { code: 'PERMISSION_DENIED', status: 403 } });
      return;
    }
    if (!this.#gate.acquire()) {
      sendForConn({ t: 'api.result', id: msg.id, ok: false, problem: { code: 'RATE_LIMITED', status: 429 } });
      return;
    }
    try {
      const needsKey = !(op.effect === 'read' && (!op.mode || op.mode === 'invoke'));
      const key = needsKey ? this.deps.newKey() : undefined;
      const data = await this.deps.invoke(op, msg.payload, key, {
        subject: msg.subject,
        expectedRevision: msg.expected_revision,
        signal: this.#connAbort?.signal,
      });
      sendForConn({ t: 'api.result', id: msg.id, ok: true, data });
    } catch (err) {
      sendForConn({ t: 'api.result', id: msg.id, ok: false, problem: this.deps.toProblem(err) });
    } finally {
      this.#gate.release();
    }
  }

  #subscribe(subjects: readonly string[]): void {
    for (const s of subjects) {
      if (this.#subjects.size >= MAX_SUBSCRIBED_SUBJECTS) break;
      if (subjectAllowed(this.deps.pluginId, s)) this.#subjects.add(s);
    }
    if (this.#unsub || this.#subjects.size === 0) return;
    this.#unsub = this.deps.subscribe((e) => {
      if (!subjectAllowed(this.deps.pluginId, e.subject)) return;
      for (const s of this.#subjects) {
        if (e.subject === s || e.subject.startsWith(s.endsWith('/') ? s : s + '/')) {
          this.#send({ t: 'api.event', event: e });
          return;
        }
      }
    });
  }

  /* ---------------------------------------------------------------- 内部 */

  #send(msg: ShellToPlugin): void {
    if (!this.#port || (this.phase !== 'connected' && this.phase !== 'ready')) return;
    try {
      this.#port.postMessage(msg);
    } catch {
      /* 数据不可克隆：静默丢弃，插件侧会超时 */
    }
  }

  #clearReady(): void {
    if (this.#timer !== null) this.#clearTimer(this.#timer);
    this.#timer = null;
  }

  #closePort(): void {
    this.#connGen++;
    this.#connAbort?.abort();
    this.#connAbort = null;
    this.#unsub?.();
    this.#unsub = null;
    this.#subjects.clear();
    if (this.#port) {
      this.#port.onmessage = null;
      this.#port.close();
    }
    this.#port = null;
  }
}
