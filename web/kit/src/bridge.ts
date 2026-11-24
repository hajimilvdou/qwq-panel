// SPDX-License-Identifier: Apache-2.0
/* ==========================================================================
 * @qwq/kit v2 · 插件沙箱客户端 SDK（ENG §9 + STEP-16 沙箱受控委托）
 * --------------------------------------------------------------------------
 * 运行于 <iframe sandbox="allow-scripts allow-forms allow-downloads"> 唯一不透明源内，
 * 零依赖、不引用 shell：
 *   1. 向 window.parent 发送 { t: 'plugin.hello', kit_major: 1 }
 *   2. 接收宿主 { t: 'plugin.port' } + MessagePort 并接管端口通信
 *   3. 自动将 ui.settings 的主题/动效/密度/CSS Token/public_origin 同步至文档
 *   4. 发送 { t: 'ui.ready' } 通知宿主撤下骨架屏
 *   5. 提供类型安全的 invoke / invokeOutcome / confirm / copyText / buildPublicURL /
 *      subscribe(+自动 unsubscribe) / resize / toast / navigate / onRoute / onSettings
 * ========================================================================== */

export const KIT_MAJOR = 1;

export interface KitHostSettings {
  theme: 'light' | 'dark';
  motion: 'full' | 'reduced' | 'off';
  density: 'comfortable' | 'compact';
  tokens: Record<string, string>;
  visible: boolean;
  public_origin?: string;
  panel_tls_mode?: string;
  panel_tls_sha256?: string;
}

export interface KitEnsurePluginsFailure {
  plugin_id: string;
  detail: string;
}

export interface KitEnsurePluginsResult {
  ready: boolean;
  cancelled?: boolean;
  installed: string[];
  enabled: string[];
  already_ready: string[];
  failed?: KitEnsurePluginsFailure[];
}

export interface KitInvokeOptions {
  subject?: string;
  expectedRevision?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface KitConfirmOptions {
  title: string;
  body: string;
  confirmLabel?: string;
  danger?: boolean;
}

export type InvokeOutcome<T = unknown> =
  | { kind: 'done'; operationId: string; result: T }
  | { kind: 'running'; operationId: string }
  | { kind: 'awaiting_approval'; operationId: string; approvalId: string };

export interface HostProblem {
  code: string;
  detail?: string;
  status?: number;
  violations?: Array<{ pointer: string; code: string; message: string }>;
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
  readonly violations?: HostProblem['violations'];

  constructor(code: string, message: string, status?: number, violations?: HostProblem['violations']) {
    super(message);
    this.name = 'PluginHostError';
    this.code = code;
    this.status = status;
    this.violations = violations;
  }
}

export class PluginInvokeError extends PluginHostError {
  constructor(problem: HostProblem) {
    super(problem.code || 'INTERNAL', problem.detail || problem.code || '操作失败', problem.status, problem.violations);
    this.name = 'PluginInvokeError';
  }
}

/** 将宿主 api.result.data 规范解包为 done / running / awaiting_approval 三态；终态失败或带 error 时抛出 PluginInvokeError */
export function unwrapInvokeOutcome<T = unknown>(envelope: unknown): InvokeOutcome<T> {
  const env = (envelope && typeof envelope === 'object' ? envelope : null) as {
    status?: string;
    operation_id?: string;
    approval_id?: string;
    result?: T;
    error?:
      | string
      | HostProblem
      | { code?: string; message?: string; detail?: string; status?: number; violations?: HostProblem['violations'] }
      | null;
  } | null;
  const status = String(env?.status || 'SUCCEEDED').toUpperCase();
  const opId = env?.operation_id || '';
  if (status === 'AWAITING_APPROVAL' || env?.approval_id) {
    return {
      kind: 'awaiting_approval',
      operationId: opId,
      approvalId: env?.approval_id || '',
    };
  }
  if (status === 'RUNNING' || status === 'PENDING') {
    return { kind: 'running', operationId: opId };
  }
  const isTerminalFailure =
    status === 'FAILED' || status === 'REJECTED' || status === 'CANCELED' || status === 'EXPIRED';
  const hasError =
    (typeof env?.error === 'string' && env.error.trim().length > 0) ||
    (env?.error !== undefined && env?.error !== null && typeof env.error === 'object');
  if (isTerminalFailure || hasError) {
    if (typeof env?.error === 'string' && env.error.trim().length > 0) {
      const code = env.error.trim();
      throw new PluginInvokeError({ code, detail: code });
    }
    if (env?.error && typeof env.error === 'object') {
      const errObj = env.error as {
        code?: string;
        detail?: string;
        message?: string;
        status?: number;
        violations?: HostProblem['violations'];
      };
      const code = errObj.code || (isTerminalFailure ? status : 'OPERATION_FAILED');
      const detail = errObj.detail || errObj.message || code;
      throw new PluginInvokeError({ code, detail, status: errObj.status, violations: errObj.violations });
    }
    throw new PluginInvokeError({ code: status, detail: `操作未完成 (${status})` });
  }
  return {
    kind: 'done',
    operationId: opId,
    result: (env && 'result' in env && env.result !== undefined ? env.result : (envelope as T)) as T,
  };
}

export interface PluginBridgeClient {
  readonly settings: KitHostSettings;
  readonly route: string;
  readonly publicOrigin: string;
  invoke<TRes = unknown>(operation: string, payload?: Record<string, unknown>, options?: KitInvokeOptions): Promise<TRes>;
  invokeOutcome<TRes = unknown>(
    operation: string,
    payload?: Record<string, unknown>,
    options?: KitInvokeOptions,
  ): Promise<InvokeOutcome<TRes>>;
  confirm(options: KitConfirmOptions): Promise<boolean>;
  copyText(text: string, label?: string): Promise<void>;
  ensurePlugins(plugins: readonly string[], reason?: string): Promise<KitEnsurePluginsResult>;
  buildPublicURL(publicSubpath: string): string;
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

let sharedTokenSheet: CSSStyleSheet | null = null;

function applyTokenStylesheet(tokens: Record<string, string>): boolean {
  if (typeof document === 'undefined' || typeof CSSStyleSheet === 'undefined' || !('adoptedStyleSheets' in document)) {
    return false;
  }
  try {
    if (!sharedTokenSheet) {
      sharedTokenSheet = new CSSStyleSheet();
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sharedTokenSheet];
    }
    const decls: string[] = [];
    for (const [k, v] of Object.entries(tokens)) {
      if (typeof v === 'string' && /^--[a-zA-Z0-9_-]+$/.test(k) && !/[{};\\]/.test(v)) {
        decls.push(`${k}: ${v};`);
      }
    }
    sharedTokenSheet.replaceSync(decls.length > 0 ? `:root { ${decls.join(' ')} }` : '');
    return true;
  } catch {
    return false;
  }
}

export interface KitHostViewport {
  offsetTopPx: number;
  viewportHeightPx: number;
  visibleTop: number;
  visibleHeight: number;
  visibleCenterY: number;
}

/** 将宿主下发的主题、动效、密度与 CSS 变量白名单同步到沙箱文档根节点（优先使用 CSP 安全的 adoptedStyleSheets） */
export function applyHostSettings(s: KitHostSettings, root?: HTMLElement | null): void {
  const el = root ?? (typeof document !== 'undefined' ? document.documentElement : null);
  if (!el) return;
  el.dataset.theme = s.theme;
  el.style.colorScheme = s.theme;
  el.dataset.motion = s.motion;
  el.dataset.density = s.density;
  if (s.tokens && Object.keys(s.tokens).length > 0) {
    applyTokenStylesheet(s.tokens);
  }
}

function applyHostViewport(msg: Record<string, unknown>, root?: HTMLElement | null): void {
  const el = root ?? (typeof document !== 'undefined' ? document.documentElement : null);
  if (!el) return;
  const rawTop =
    typeof msg.offsetTopPx === 'number'
      ? msg.offsetTopPx
      : typeof msg.visibleTop === 'number'
        ? msg.visibleTop
        : typeof msg.scroll_top === 'number'
          ? msg.scroll_top
          : 0;
  const rawHeight =
    typeof msg.viewportHeightPx === 'number'
      ? msg.viewportHeightPx
      : typeof msg.visibleHeight === 'number'
        ? msg.visibleHeight
        : typeof msg.visible_height === 'number'
          ? msg.visible_height
          : 720;
  const topPx = Math.max(0, Math.round(rawTop));
  const hPx = Math.max(240, Math.round(rawHeight));
  el.style.setProperty('--qwq-vp-top', `${topPx}px`);
  el.style.setProperty('--qwq-vp-h', `${hPx}px`);
  el.style.setProperty('--host-modal-top', `${Math.max(16, topPx + 24)}px`);
}

function matchesKitSubject(pattern: string, incoming: string): boolean {
  const clean = pattern.replace(/\/\*+$/, '').replace(/\/+$/, '');
  if (!clean) return false;
  return incoming === clean || incoming.startsWith(clean + '/');
}

/** 解析首帧 URL fragment（#theme=light&motion=full&density=comfortable&path=/） */
export function parseInitialFragment(hash: string): { settings: KitHostSettings; route: string } {
  const q = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
  const theme = q.get('theme') === 'dark' ? 'dark' : 'light';
  const rawMotion = q.get('motion');
  const motion = rawMotion === 'reduced' || rawMotion === 'off' ? rawMotion : 'full';
  const density = q.get('density') === 'compact' ? 'compact' : 'comfortable';
  const route = q.get('path') || q.get('route') || '/';
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
    let publicOrigin = '';

    const pending = new Map<
      string,
      { resolve: (v: unknown) => void; reject: (e: Error) => void; timer?: ReturnType<typeof setTimeout> }
    >();
    const settingsListeners = new Set<(s: KitHostSettings) => void>();
    const routeListeners = new Set<(p: string) => void>();
    const eventListeners = new Set<{ subjects: readonly string[]; fn: (e: KitEvent) => void }>();

    const timeout = setTimeout(() => {
      win.removeEventListener('message', onWindowMessage as EventListener);
      reject(new PluginHostError('TIMEOUT', 'Plugin bridge handshake timed out'));
    }, opts.timeoutMs ?? 6000);

    const rpc = <TRes>(frame: Record<string, unknown>, options?: { signal?: AbortSignal; timeoutMs?: number }): Promise<TRes> => {
      if (disposed || !port) {
        return Promise.reject(new PluginHostError('UNAVAILABLE', 'Plugin bridge is not connected'));
      }
      if (options?.signal?.aborted) {
        return Promise.reject(new PluginHostError('ABORTED', 'Request aborted'));
      }
      const id = `kit_${++seq}`;
      return new Promise<TRes>((res, rej) => {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const cleanup = () => {
          if (timer !== undefined) clearTimeout(timer);
          options?.signal?.removeEventListener('abort', onAbort);
        };
        const onAbort = () => {
          if (pending.delete(id)) {
            cleanup();
            rej(new PluginHostError('ABORTED', 'Request aborted'));
          }
        };
        options?.signal?.addEventListener('abort', onAbort, { once: true });
        if (options?.timeoutMs && options.timeoutMs > 0) {
          timer = setTimeout(() => {
            if (pending.delete(id)) {
              cleanup();
              rej(new PluginHostError('TIMEOUT', 'Request timed out'));
            }
          }, options.timeoutMs);
        }
        pending.set(id, {
          resolve: (v) => {
            cleanup();
            res(v as TRes);
          },
          reject: (e) => {
            cleanup();
            rej(e);
          },
          timer,
        });
        try {
          port!.postMessage({ ...frame, id });
        } catch (err) {
          if (pending.delete(id)) {
            cleanup();
            rej(new PluginHostError('SERIALIZE_ERROR', err instanceof Error ? err.message : 'Failed to post frame'));
          }
        }
      });
    };

    const client: PluginBridgeClient = {
      get settings() {
        return currentSettings;
      },
      get route() {
        return currentRoute;
      },
      get publicOrigin() {
        return publicOrigin;
      },
      invoke<TRes = unknown>(operation: string, payload: Record<string, unknown> = {}, options?: KitInvokeOptions): Promise<TRes> {
        const frame: Record<string, unknown> = { t: 'api.invoke', operation, payload };
        if (options?.subject) frame.subject = options.subject;
        if (options?.expectedRevision) frame.expected_revision = options.expectedRevision;
        return rpc<TRes>(frame, { signal: options?.signal, timeoutMs: options?.timeoutMs });
      },
      invokeOutcome<TRes = unknown>(
        operation: string,
        payload: Record<string, unknown> = {},
        options?: KitInvokeOptions,
      ): Promise<InvokeOutcome<TRes>> {
        return client.invoke<unknown>(operation, payload, options).then((data) => unwrapInvokeOutcome<TRes>(data));
      },
      confirm(options: KitConfirmOptions): Promise<boolean> {
        return rpc<{ confirmed?: boolean }>(
          {
            t: 'ui.confirm',
            title: options.title,
            body: options.body,
            confirm_label: options.confirmLabel,
            danger: Boolean(options.danger),
          },
          { timeoutMs: 120_000 },
        ).then((r) => Boolean(r?.confirmed));
      },
      copyText(text: string, label = '已复制到剪贴板'): Promise<void> {
        return rpc<unknown>({ t: 'ui.copy', text, label }, { timeoutMs: 5000 }).then(() => undefined);
      },
      ensurePlugins(plugins: readonly string[], reason?: string): Promise<KitEnsurePluginsResult> {
        return rpc<KitEnsurePluginsResult>(
          { t: 'ui.ensure_plugins', plugins: [...plugins], ...(reason ? { reason } : {}) },
          { timeoutMs: 300_000 },
        );
      },
      buildPublicURL(publicSubpath: string): string {
        const clean = publicSubpath.startsWith('/') ? publicSubpath : `/${publicSubpath}`;
        return publicOrigin ? `${publicOrigin}${clean}` : clean;
      },
      subscribe(subjects, fn) {
        const list = [...subjects];
        const entry = { subjects: list, fn };
        eventListeners.add(entry);
        if (!disposed && port && list.length > 0) {
          port.postMessage({ t: 'api.subscribe', subjects: list });
        }
        return () => {
          eventListeners.delete(entry);
          if (!disposed && port && list.length > 0) {
            const unused = list.filter((s) => {
              for (const other of eventListeners) {
                if (other.subjects.includes(s)) return false;
              }
              return true;
            });
            if (unused.length > 0) {
              port.postMessage({ t: 'events.unsubscribe', subjects: unused });
            }
          }
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
        for (const [, p] of pending) {
          if (p.timer !== undefined) clearTimeout(p.timer);
          p.reject(new PluginHostError('DISPOSED', 'Plugin bridge disposed'));
        }
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
            if (typeof msg.public_origin === 'string') {
              publicOrigin = msg.public_origin.replace(/\/+$/, '');
            }
            currentSettings = {
              theme: msg.theme === 'dark' || msg.scheme === 'dark' ? 'dark' : 'light',
              motion: msg.motion === 'reduced' || msg.motion === 'off' ? msg.motion : 'full',
              density: msg.density === 'compact' ? 'compact' : 'comfortable',
              tokens: (msg.tokens && typeof msg.tokens === 'object' ? msg.tokens : {}) as Record<string, string>,
              visible: msg.visible !== false,
              public_origin: publicOrigin || undefined,
              panel_tls_mode: typeof msg.panel_tls_mode === 'string' && msg.panel_tls_mode ? msg.panel_tls_mode : undefined,
              panel_tls_sha256: typeof msg.panel_tls_sha256 === 'string' && msg.panel_tls_sha256 ? msg.panel_tls_sha256 : undefined,
            };
            applyHostSettings(currentSettings);
            for (const fn of settingsListeners) fn(currentSettings);
            break;
          }
          case 'ui.viewport': {
            applyHostViewport(msg);
            break;
          }
          case 'ui.route': {
            if (typeof msg.path === 'string') {
              currentRoute = msg.path;
              for (const fn of routeListeners) fn(currentRoute);
            }
            break;
          }
          case 'api.result':
          case 'ui.confirm.result':
          case 'ui.copy.result':
          case 'ui.ensure_plugins.result': {
            const id = typeof msg.id === 'string' || typeof msg.id === 'number' ? String(msg.id) : '';
            const entry = pending.get(id);
            if (!entry) return;
            pending.delete(id);
            if (msg.ok === true) {
              entry.resolve(msg.data);
            } else {
              const prob = (msg.problem ?? {}) as HostProblem;
              entry.reject(
                new PluginHostError(
                  prob.code || 'INTERNAL',
                  prob.detail || prob.code || 'Operation failed',
                  prob.status,
                  prob.violations,
                ),
              );
            }
            break;
          }
          case 'api.event': {
            const evObj = msg.event as KitEvent | undefined;
            if (evObj && typeof evObj === 'object' && typeof evObj.subject === 'string') {
              for (const sub of eventListeners) {
                if (
                  sub.subjects.length === 0 ||
                  sub.subjects.some((s) => matchesKitSubject(s, evObj.subject))
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

/**
 * QwqPluginBridge · 面向对象封装的 @qwq/kit v2 沙箱桥接客户端：
 * - 严格兼容 `script-src 'self'; style-src 'self'` CSP（通过 adoptedStyleSheets 同步宿主主题 Token）
 * - `invoke()` 直接返回三态 `InvokeOutcome<T>`（done / running / awaiting_approval）
 * - 提供 `confirm()` / `copyText()` / `buildPublicURL()` / `subscribe()`(+自动 unsubscribe) / `observeAutoResize()`
 */
export class QwqPluginBridge {
  #client: PluginBridgeClient | null = null;
  #themeSheet: CSSStyleSheet | null = null;
  #currentPath = '/';

  constructor(private readonly opts: BridgeConnectOptions = {}) {
    if (typeof document !== 'undefined' && typeof CSSStyleSheet !== 'undefined' && 'adoptedStyleSheets' in document) {
      try {
        this.#themeSheet = new CSSStyleSheet();
        document.adoptedStyleSheets = [...document.adoptedStyleSheets, this.#themeSheet];
      } catch {
        this.#themeSheet = null;
      }
    }
    const hash = opts.hash ?? (typeof location !== 'undefined' ? location.hash : '');
    this.#currentPath = parseInitialFragment(hash).route;
  }

  get publicOrigin(): string {
    return this.#client?.publicOrigin ?? '';
  }

  get currentPath(): string {
    return this.#client?.route ?? this.#currentPath;
  }

  async connect(): Promise<void> {
    if (this.#client) return;
    const client = await createPluginBridge(this.opts);
    this.#client = client;
    this.#currentPath = client.route;
    this.#syncThemeSheet(client.settings);
    client.onSettings((s) => this.#syncThemeSheet(s));
    client.onRoute((p) => {
      this.#currentPath = p;
    });
    if (typeof window !== 'undefined') {
      window.addEventListener('pagehide', () => this.dispose(), { once: true });
    }
  }

  invoke<T = unknown>(action: string, input: Record<string, unknown> = {}, timeoutMs = 15000): Promise<InvokeOutcome<T>> {
    if (!this.#client) return Promise.reject(new PluginInvokeError({ code: 'UNAVAILABLE', detail: '插件尚未完成宿主握手' }));
    return this.#client.invokeOutcome<T>(action, input, { timeoutMs }).catch((err) => {
      if (err instanceof PluginHostError) {
        throw new PluginInvokeError({ code: err.code, detail: err.message, status: err.status, violations: err.violations });
      }
      throw err;
    });
  }

  confirm(options: KitConfirmOptions): Promise<boolean> {
    if (!this.#client) return Promise.reject(new PluginInvokeError({ code: 'UNAVAILABLE', detail: '插件尚未完成宿主握手' }));
    return this.#client.confirm(options);
  }

  copyText(text: string, label = '已复制到剪贴板'): Promise<void> {
    if (!this.#client) return Promise.reject(new PluginInvokeError({ code: 'UNAVAILABLE', detail: '插件尚未完成宿主握手' }));
    return this.#client.copyText(text, label);
  }

  ensurePlugins(plugins: readonly string[], reason?: string): Promise<KitEnsurePluginsResult> {
    if (!this.#client) return Promise.reject(new PluginInvokeError({ code: 'UNAVAILABLE', detail: '插件尚未完成宿主握手' }));
    return this.#client.ensurePlugins(plugins, reason);
  }

  buildPublicURL(publicSubpath: string): string {
    if (this.#client) return this.#client.buildPublicURL(publicSubpath);
    return publicSubpath.startsWith('/') ? publicSubpath : `/${publicSubpath}`;
  }

  navigate(path: string): void {
    this.#currentPath = path;
    this.#client?.navigate(path);
  }

  toast(text: string): void {
    this.#client?.toast(text);
  }

  onRouteChange(fn: (path: string) => void): () => void {
    return this.#client ? this.#client.onRoute(fn) : () => {};
  }

  subscribe(subject: string, fn: (event: KitEvent) => void): () => void {
    return this.#client ? this.#client.subscribe([subject], fn) : () => {};
  }

  observeAutoResize(rootEl: HTMLElement): () => void {
    const ro = new ResizeObserver(() => {
      const height = Math.ceil(rootEl.getBoundingClientRect().height) + 16;
      this.#client?.resize(height);
    });
    ro.observe(rootEl);
    return () => ro.disconnect();
  }

  dispose(): void {
    this.#client?.dispose();
    this.#client = null;
  }

  #syncThemeSheet(s: KitHostSettings): void {
    if (!this.#themeSheet || !s.tokens) return;
    const decls: string[] = [];
    for (const [k, v] of Object.entries(s.tokens)) {
      if (/^--[a-zA-Z0-9_-]+$/.test(k) && !/[{};\\]/.test(v)) {
        decls.push(`${k}: ${v};`);
      }
    }
    if (decls.length > 0) {
      this.#themeSheet.replaceSync(`:root { ${decls.join(' ')} }`);
    }
  }
}
