// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * History 路由（ENG §2，自写，无第三方）
 * --------------------------------------------------------------------------
 *   router.path / router.query / router.match   当前位置（响应式）
 *   navigate(to, { replace })                    跳转（站内路径）
 *   router.setQuery({ tab: 'audit' })            改 query（筛选、Tab），replace
 *   installLinkInterceptor()                     拦截同源 <a> 点击
 *   safeNext(raw)                                校验 ?next= 回跳地址
 *
 * 滚动：前进归顶，后退恢复（位置记在 history.state.scroll）。
 * 焦点：页面渲染后由 <Outlet> 调 focusHeading() 移到顶栏 <h1 id="page-title">。
 * 路径无尾斜杠：/apps/ 会被 replace 成 /apps。
 * ========================================================================== */
import type { Component } from 'svelte';

/* ------------------------------------------------------------------ 路由表类型 */

export interface RouteDef {
  /** '/activity/:operationId'；末段 '*' 匹配任意子路径（params.rest） */
  pattern: string;
  /** 页面组件，一律动态 import（每页一个 chunk） */
  load: () => Promise<{ default: Component<any> }>;
  /** 顶栏标题 */
  title: string;
  /** 匿名可访问（setup / login / enroll） */
  public?: boolean;
  /** 最低权限（仅用于隐藏与权限态，后端仍是唯一裁决） */
  perm?: string;
  /** 不套 Shell 布局（登录类页面） */
  bare?: boolean;
  /** 重定向目标（如 /settings → /settings/account） */
  redirect?: string;
}

/* ------------------------------------------------------------------ 匹配 */

export interface Match {
  route: RouteDef;
  params: Record<string, string>;
}

interface Compiled {
  route: RouteDef;
  re: RegExp;
  keys: string[];
}

/** '/plugins/:pluginId/*' → /^\/plugins\/([^/]+)(?:\/(.*))?$/，'*' 捕获为 params.rest */
export function compile(pattern: string): { re: RegExp; keys: string[] } {
  const keys: string[] = [];
  let src = '';
  for (const seg of pattern.split('/').filter(Boolean)) {
    if (seg === '*') {
      keys.push('rest');
      src += '(?:/(.*))?';
    } else if (seg.startsWith(':')) {
      keys.push(seg.slice(1));
      src += '/([^/]+)';
    } else {
      src += '/' + seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
  }
  return { re: new RegExp(`^${src || '/'}$`), keys };
}

export function createMatcher(routes: readonly RouteDef[]): (path: string) => Match | null {
  const table: Compiled[] = routes.map((route) => ({ route, ...compile(route.pattern) }));
  return (path) => {
    for (const c of table) {
      const m = c.re.exec(path);
      if (!m) continue;
      const params: Record<string, string> = {};
      c.keys.forEach((k, i) => {
        const v = m[i + 1];
        if (v !== undefined) params[k] = safeDecode(v);
      });
      return { route: c.route, params };
    }
    return null;
  };
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/* ------------------------------------------------------------------ 回跳地址校验 */

/** 只接受站内相对路径：以单个 / 开头，且不以 // 或 /\ 开头；否则回主页 */
export function safeNext(raw: string | null | undefined, fallback = '/'): string {
  if (!raw || raw[0] !== '/' || raw[1] === '/' || raw[1] === '\\') return fallback;
  for (let i = 0; i < raw.length; i++) if (raw.charCodeAt(i) < 0x20 || raw.charCodeAt(i) === 0x7f) return fallback;
  return raw;
}

/** 当前地址作为 next 参数（登录后返回） */
export function loginUrl(next: string): string {
  return next === '/' || next.startsWith('/login') ? '/login' : `/login?next=${encodeURIComponent(next)}`;
}

/* ------------------------------------------------------------------ 路由器 */

interface HistoryState {
  key: string;
  scroll?: number;
}

class Router {
  path = $state('/');
  search = $state('');
  match = $state<Match | null>(null);
  /** 每次导航自增，供 <Outlet> 判断"新页面"（触发焦点与滚动） */
  version = $state(0);

  readonly query = $derived(new URLSearchParams(this.search));

  #matcher: ((path: string) => Match | null) | null = null;
  #restoreScroll: number | null = null;

  init(routes: readonly RouteDef[]): void {
    this.#matcher = createMatcher(routes);
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
    addEventListener('popstate', (e) => {
      this.#restoreScroll = (e.state as HistoryState | null)?.scroll ?? 0;
      this.#sync();
    });
    this.#normalize();
    this.#sync();
  }

  /** 站内跳转；外部地址交给浏览器 */
  navigate = (to: string, opts: { replace?: boolean } = {}): void => {
    const url = new URL(to, location.href);
    if (url.origin !== location.origin) {
      location.assign(url.href);
      return;
    }
    const target = stripTrailingSlash(url.pathname) + url.search + url.hash;
    if (target === location.pathname + location.search + location.hash && !opts.replace) return;
    /* 离开前把当前滚动位置记进当前条目，后退时恢复 */
    const cur = (history.state as HistoryState | null) ?? { key: newKey() };
    history.replaceState({ ...cur, scroll: scrollY }, '');
    const state: HistoryState = { key: newKey() };
    if (opts.replace) history.replaceState(state, '', target);
    else history.pushState(state, '', target);
    this.#restoreScroll = 0;
    this.#sync();
  };

  /** 合并改写 query（值为空则删除），不产生历史记录 */
  setQuery(patch: Record<string, string | number | null | undefined>): void {
    const q = new URLSearchParams(location.search);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === undefined || v === '') q.delete(k);
      else q.set(k, String(v));
    }
    const s = q.toString();
    history.replaceState(history.state, '', location.pathname + (s ? '?' + s : '') + location.hash);
    this.search = location.search;
  }

  /** 由 <Outlet> 在新页面渲染后调用 */
  settle(): void {
    const y = this.#restoreScroll;
    this.#restoreScroll = null;
    if (y !== null) scrollTo({ top: y, behavior: 'instant' });
    focusHeading();
  }

  #normalize() {
    const clean = stripTrailingSlash(location.pathname);
    if (clean !== location.pathname || !history.state) {
      history.replaceState(history.state ?? { key: newKey() }, '', clean + location.search + location.hash);
    }
  }

  #sync() {
    this.path = location.pathname;
    this.search = location.search;
    this.match = this.#matcher?.(this.path) ?? null;
    this.version++;
  }
}

function stripTrailingSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, '') || '/' : p;
}

const newKey = () => Math.random().toString(36).slice(2, 10);

/** 焦点移到页面标题（顶栏 #page-title；无顶栏的页面用 main h1），供读屏与键盘用户定位 */
export function focusHeading(): void {
  const h =
    document.querySelector<HTMLElement>('#page-title') ??
    document.querySelector<HTMLElement>('main h1') ??
    document.querySelector<HTMLElement>('main');
  if (!h) return;
  if (!h.hasAttribute('tabindex')) h.setAttribute('tabindex', '-1');
  h.focus({ preventScroll: true });
}

export const router = new Router();
export const navigate = router.navigate;

/* ------------------------------------------------------------------ 链接拦截 */

/** 拦截同源 <a href> 点击；尊重修饰键、target、download 与 data-external */
export function installLinkInterceptor(root: Document | HTMLElement = document): () => void {
  const onClick = (e: Event) => {
    const ev = e as MouseEvent;
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
    const a = (ev.target as Element | null)?.closest?.('a');
    if (!a || !a.href || a.hasAttribute('download') || a.dataset.external !== undefined) return;
    if (a.target && a.target !== '_self') return;
    const url = new URL(a.href);
    if (url.origin !== location.origin) return;
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/plugin-ui/')) return;
    ev.preventDefault();
    navigate(url.pathname + url.search + url.hash);
  };
  root.addEventListener('click', onClick);
  return () => root.removeEventListener('click', onClick);
}
