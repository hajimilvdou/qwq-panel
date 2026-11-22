// SPDX-License-Identifier: Apache-2.0
/* ==========================================================================
 * @qwq/kit v1 · 插件沙箱客户端 SDK（ENG §9）
 * --------------------------------------------------------------------------
 * 运行于 <iframe sandbox="allow-scripts"> 唯一不透明源内，零依赖、不引用 shell：
 *   1. 向 window.parent 发送 { t: 'plugin.hello', kit_major: 1 }
 *   2. 接收宿主 { t: 'plugin.port' } + MessagePort 并接管端口通信
 *   3. 自动将 ui.settings 的主题/动效/密度/CSS Token 写入 documentElement
 *   4. 发送 { t: 'ui.ready' } 通知宿主撤下骨架屏
 *   5. 提供类型安全的 invoke / subscribe / resize / toast / navigate / onRoute / onSettings
 * ========================================================================== */

export const KIT_MAJOR = 1;

export interface KitHostSettings {
  theme: 'light' | 'dark';
  motion: 'full' | 'reduced' | 'off';
  density: 'comfortable' | 'compact';
  tokens: Record<string, string>;
  visible: boolean;
}

export interface KitInvokeOptions {
  subject?: string;
  expectedRevision?: string;
  signal?: AbortSignal;
}

export interface KitEvent {
  type?: string;
  subject: string;
  occurred_at?: string;
  payload?: Record<string, unknown>;
  [k: string]: unknown;
}

export class PluginHostError extends Error {
  readonly code: string;
  readonly status?: number;

  constructor(code: string, message: string, status?: number) {
    super(message);
    this.name = 'PluginHostError';
    this.code = code;
    this.status = status;
  }
}

export interface PluginBridgeClient {
  readonly settings: KitHostSettings;
  readonly route: string;
  invoke<TRes = unknown>(operation: string, payload?: Record<string, unknown>, options?: KitInvokeOptions): Promise<TRes>;
  subscribe(subjects: readonly string[], fn: (event: KitEvent) => void): () => void;
  resize(height: number): void;
  toast(text: string): void;
  navigate(path: string): void;
  onSettings(fn: (s: KitHostSettings) => void): () => void;
  onRoute(fn: (path: string) => void): () => void;
  dispose(): void;
}

export interface BridgeConnectOptions {
  /** 测试注入；默认使用 window */
  win?: Pick<Window, 'addEventListener' | 'removeEventListener'>;
  /** 测试注入；默认使用 window.parent */
  parent?: Pick<Window, 'postMessage'>;
  /** 测试注入；默认读取 location.hash */
  hash?: string;
  /** 握手超时（毫秒，默认 6000） */
  timeoutMs?: number;
}

/** 将宿主下发的主题、动效、密度与 CSS 变量白名单同步到沙箱文档根节点 */
export function applyHostSettings(s: KitHostSettings, root?: HTMLElement | null): void {
  const el = root ?? (typeof document !== 'undefined' ? document.documentElement : null);
  if (!el) return;
  el.dataset.theme = s.theme;
  el.dataset.motion = s.motion;
  el.dataset.density = s.density;
  if (s.tokens) {
    for (const [k, v] of Object.entries(s.tokens)) {
      if (k.startsWith('--') && typeof v === 'string') el.style.setProperty(k, v);
    }
  }
}

/** 解析首帧 URL fragment（#theme=light&motion=full&density=comfortable&path=/） */
export function parseInitialFragment(hash: string): { settings: KitHostSettings; route: string } {
  const q = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
  const theme = q.get('theme') === 'dark' ? 'dark' : 'light';
  const rawMotion = q.get('motion');
  const motion = rawMotion === 'reduced' || rawMotion === 'off' ? rawMotion : 'full';
  const density = q.get('density') === 'compact' ? 'compact' : 'comfortable';
  const route = q.get('path') || '/';
  return {
    settings: { theme, motion, density, tokens: {}, visible: true },
    route,
  };
}

/** 与宿主 Shell 完成 ENG §9 MessageChannel 握手并返回客户端实例 */
export function createPluginBridge(opts: BridgeConnectOptions = {}): Promise<PluginBridgeClient> {
  const win = opts.win ?? window;
  const parent = opts.parent ?? window.parent;
  const initialHash = opts.hash ?? (typeof location !== 'undefined' ? location.hash : '');
  const init = parseInitialFragment(initialHash);
  applyHostSettings(init.settings);

  return new Promise<PluginBridgeClient>((resolve, reject) => {
    let port: MessagePort | null = null;
    let seq = 0;
    let disposed = false;
    let currentSettings: KitHostSettings = init.settings;
    let currentRoute = init.route;

    const pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
    const settingsListeners = new Set<(s: KitHostSettings) => void>();
    const routeListeners = new Set<(p: string) => void>();
    const eventListeners = new Set<{ subjects: readonly string[]; fn: (e: KitEvent) => void }>();

    const timeout = setTimeout(() => {
      win.removeEventListener('message', onWindowMessage as EventListener);
      reject(new PluginHostError('TIMEOUT', 'Plugin bridge handshake timed out'));
    }, opts.timeoutMs ?? 6000);

    const client: PluginBridgeClient = {
      get settings() {
        return currentSettings;
      },
      get route() {
        return currentRoute;
      },
      invoke<TRes = unknown>(operation: string, payload: Record<string, unknown> = {}, options?: KitInvokeOptions): Promise<TRes> {
        if (disposed || !port) {
          return Promise.reject(new PluginHostError('UNAVAILABLE', 'Plugin bridge is not connected'));
        }
        if (options?.signal?.aborted) {
          return Promise.reject(new PluginHostError('ABORTED', 'Request aborted'));
        }
        const id = `kit_${++seq}`;
        return new Promise<TRes>((res, rej) => {
          const onAbort = () => {
            if (pending.delete(id)) rej(new PluginHostError('ABORTED', 'Request aborted'));
          };
          options?.signal?.addEventListener('abort', onAbort, { once: true });
          pending.set(id, {
            resolve: (v) => {
              options?.signal?.removeEventListener('abort', onAbort);
              res(v as TRes);
            },
            reject: (e) => {
              options?.signal?.removeEventListener('abort', onAbort);
              rej(e);
            },
          });
          const frame: Record<string, unknown> = { t: 'api.invoke', id, operation, payload };
          if (options?.subject) frame.subject = options.subject;
          if (options?.expectedRevision) frame.expected_revision = options.expectedRevision;
          try {
            port!.postMessage(frame);
          } catch (err) {
            if (pending.delete(id)) {
              options?.signal?.removeEventListener('abort', onAbort);
              rej(new PluginHostError('SERIALIZE_ERROR', err instanceof Error ? err.message : 'Failed to post invoke frame'));
            }
          }
        });
      },
      subscribe(subjects, fn) {
        const entry = { subjects: [...subjects], fn };
        eventListeners.add(entry);
        if (!disposed && port && subjects.length > 0) {
          port.postMessage({ t: 'api.subscribe', subjects: [...subjects] });
        }
        return () => {
          eventListeners.delete(entry);
        };
      },
      resize(height) {
        if (!disposed && port && Number.isFinite(height)) {
          port.postMessage({ t: 'ui.resize', height: Math.round(height) });
        }
      },
      toast(text) {
        if (!disposed && port && text.trim()) {
          port.postMessage({ t: 'ui.toast', text });
        }
      },
      navigate(path) {
        if (!disposed && port && path.startsWith('/')) {
          port.postMessage({ t: 'ui.navigate', path });
        }
      },
      onSettings(fn) {
        settingsListeners.add(fn);
        return () => settingsListeners.delete(fn);
      },
      onRoute(fn) {
        routeListeners.add(fn);
        return () => routeListeners.delete(fn);
      },
      dispose() {
        disposed = true;
        clearTimeout(timeout);
        win.removeEventListener('message', onWindowMessage as EventListener);
        if (port) {
          port.onmessage = null;
          port.close();
          port = null;
        }
        for (const [, p] of pending) p.reject(new PluginHostError('DISPOSED', 'Plugin bridge disposed'));
        pending.clear();
        settingsListeners.clear();
        routeListeners.clear();
        eventListeners.clear();
      },
    };

    function onWindowMessage(ev: MessageEvent): void {
      if (disposed || port !== null) return;
      if (ev.source !== parent) return;
      const d = ev.data as { t?: string } | null;
      if (!d || d.t !== 'plugin.port' || !ev.ports || !ev.ports[0]) return;
      clearTimeout(timeout);
      win.removeEventListener('message', onWindowMessage as EventListener);
      port = ev.ports[0];
      port.onmessage = (m: MessageEvent) => {
        const msg = m.data as Record<string, unknown> | null;
        if (!msg || typeof msg.t !== 'string') return;
        switch (msg.t) {
          case 'ui.settings': {
            currentSettings = {
              theme: msg.theme === 'dark' ? 'dark' : 'light',
              motion: msg.motion === 'reduced' || msg.motion === 'off' ? msg.motion : 'full',
              density: msg.density === 'compact' ? 'compact' : 'comfortable',
              tokens: (msg.tokens && typeof msg.tokens === 'object' ? msg.tokens : {}) as Record<string, string>,
              visible: msg.visible !== false,
            };
            applyHostSettings(currentSettings);
            for (const fn of settingsListeners) fn(currentSettings);
            break;
          }
          case 'ui.route': {
            if (typeof msg.path === 'string') {
              currentRoute = msg.path;
              for (const fn of routeListeners) fn(currentRoute);
            }
            break;
          }
          case 'api.result': {
            const id = typeof msg.id === 'string' ? msg.id : '';
            const entry = pending.get(id);
            if (!entry) return;
            pending.delete(id);
            if (msg.ok === true) {
              entry.resolve(msg.data);
            } else {
              const prob = (msg.problem ?? {}) as { code?: string; detail?: string; status?: number };
              entry.reject(new PluginHostError(prob.code || 'INTERNAL', prob.detail || prob.code || 'Operation failed', prob.status));
            }
            break;
          }
          case 'api.event': {
            const evObj = msg.event as KitEvent | undefined;
            if (evObj && typeof evObj === 'object' && typeof evObj.subject === 'string') {
              for (const sub of eventListeners) {
                if (
                  sub.subjects.length === 0 ||
                  sub.subjects.some((s) => evObj.subject === s || evObj.subject.startsWith(s.endsWith('/') ? s : s + '/'))
                ) {
                  sub.fn(evObj);
                }
              }
            }
            break;
          }
        }
      };
      port.start?.();
      port.postMessage({ t: 'ui.ready' });
      resolve(client);
    }

    win.addEventListener('message', onWindowMessage as EventListener);
    parent.postMessage({ t: 'plugin.hello', kit_major: KIT_MAJOR }, '*');
  });
}
