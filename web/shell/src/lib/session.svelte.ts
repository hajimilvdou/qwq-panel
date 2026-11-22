// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 会话与启动（ENG §4）
 * --------------------------------------------------------------------------
 *   session.status   booting → uninitialized | anonymous | authenticated
 *   session.user     当前用户（authenticated 时）
 *   session.can(p)   权限判断——只用于隐藏 UI，后端是唯一裁决
 *
 * 启动：GET /setup → GET /sessions/current → setCsrfToken。
 * 登录、MFA、setup、enroll、TOTP 启用的响应都会带新 csrf：一律经 adopt() 覆盖。
 * 401：清内存、通知订阅方（关 SSE）、暂存草稿、跳 /login?next=；并发 401 只跳一次。
 * 多标签：BroadcastChannel('qwq.session') 广播 logout/login，不广播 csrf 值。
 *
 * 本模块不直接依赖 events：订阅方通过 onSignedIn / onSignedOut 挂钩。
 * ========================================================================== */
import { setCsrfRefresher, setCsrfToken, setUnauthenticatedHandler } from '$api/client';
import { sessions, system } from '$api/endpoints';
import type { Role, Session, SetupStatus, User } from '$api/types';
import { ApiError } from '$api/client';
import { persistDrafts } from './drafts';
import { loginUrl, navigate, router } from './router.svelte';

export type SessionStatus = 'booting' | 'uninitialized' | 'anonymous' | 'authenticated' | 'error';

/* ------------------------------------------------------------------ 内置角色映射（仅 UI） */

/** 冷启动：整段引导请求的硬上限与重试等待预算（超过即显示"连不上服务器"） */
const BOOT_DEADLINE_MS = 3000;
const BOOT_RETRY_BUDGET_MS = 1000;

const ADMIN_ONLY_RES = new Set(['host.users', 'host.service_accounts', 'host.audit']);
const SELF_SERVICE_RES = new Set(['host.account']);
const OPERATOR_DENY = new Set(['host.ai_providers:create', 'host.ai_providers:update', 'host.ai_providers:delete']);
/** 与后端 sdk/manifest/rules.go ReadOnlyActions 1:1 对齐 */
const READ_VERBS = new Set(['read', 'list', 'get', 'export', 'describe', 'watch']);

/** 与后端 internal/authz/roles.go 对齐的 UI 权限判断（后端仍为唯一裁决） */
export function roleCan(role: Role | undefined, perm: string | undefined): boolean {
  if (!perm) return true;
  if (!role) return false;
  if (role === 'admin') return true;
  const [res = '', verb = ''] = perm.split(':');
  if (SELF_SERVICE_RES.has(res)) return true;
  if (ADMIN_ONLY_RES.has(res)) return false;
  if (role === 'operator') return !OPERATOR_DENY.has(perm);
  if (role === 'viewer') return READ_VERBS.has(verb);
  return false;
}

/* ------------------------------------------------------------------ 存储 */

type Hook = () => void;

class SessionStore {
  status = $state<SessionStatus>('booting');
  user = $state<User | null>(null);
  setup = $state<SetupStatus | null>(null);
  /** 会话绝对到期时间（只展示，不设本地定时登出） */
  expiresAt = $state<string | null>(null);
  mfaVerifiedAt = $state<string | null>(null);

  readonly role = $derived(this.user?.role);

  #signedIn = new Set<Hook>();
  #signedOut = new Set<Hook>();
  #redirecting = false;
  #channel: BroadcastChannel | null = null;

  can = (perm: string | undefined): boolean => roleCan(this.role, perm);

  onSignedIn(fn: Hook): () => void {
    this.#signedIn.add(fn);
    return () => this.#signedIn.delete(fn);
  }
  onSignedOut(fn: Hook): () => void {
    this.#signedOut.add(fn);
    return () => this.#signedOut.delete(fn);
  }

  /** 启动流程；main.ts 调一次 */
  async bootstrap(): Promise<void> {
    setUnauthenticatedHandler(() => this.expire());
    setCsrfRefresher(() => this.refresh());
    this.#listenTabs();
    /* 冷启动要快速给结论：两次请求共用 3 秒硬上限，503 + Retry-After 也不长等 */
    const opts = { signal: AbortSignal.timeout(BOOT_DEADLINE_MS), retryBudgetMs: BOOT_RETRY_BUDGET_MS };
    try {
      this.setup = await system.setupStatus(opts);
      if (!this.setup.initialized) {
        this.status = 'uninitialized';
        return;
      }
      const s = await sessions.current(opts);
      this.adopt(s, false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) this.status = 'anonymous';
      else this.status = 'error';
    }
  }

  /** 采用一个新的会话（登录 / MFA / setup / enroll / 会话轮换）；会覆盖 csrf */
  adopt(s: Session, broadcast = true): void {
    setCsrfToken(s.csrf_token);
    const wasIn = this.status === 'authenticated';
    this.user = s.user;
    this.expiresAt = s.expires_at;
    this.mfaVerifiedAt = s.mfa_verified_at ?? null;
    this.status = 'authenticated';
    this.#redirecting = false;
    if (!wasIn) this.#signedIn.forEach((f) => f());
    if (broadcast) this.#channel?.postMessage({ t: 'login' });
  }

  /** 资料更新后的局部刷新（如显示名、TOTP 状态） */
  updateUser(u: User): void {
    if (this.user && u.user_id === this.user.user_id) this.user = u;
  }

  /** 取新 csrf（CSRF_FAILED、其他标签登录后） */
  async refresh(): Promise<void> {
    const s = await sessions.current();
    this.adopt(s, false);
  }

  /** 主动登出；无论服务端是否成功都清本地 */
  async logout(): Promise<void> {
    try {
      await sessions.logout();
    } catch {
      /* 已过期等：照样清本地 */
    }
    this.#channel?.postMessage({ t: 'logout' });
    this.#clear();
    navigate('/login', { replace: true });
  }

  /** 401 / SSE 401 / 其他标签登出：清内存、暂存草稿、跳登录（并发只跳一次） */
  expire(): void {
    if (this.#redirecting || this.status !== 'authenticated') return;
    this.#redirecting = true;
    persistDrafts();
    const here = router.path + router.search;
    this.#clear();
    navigate(loginUrl(here), { replace: true });
  }

  #clear() {
    setCsrfToken(null);
    this.user = null;
    this.expiresAt = null;
    this.mfaVerifiedAt = null;
    this.status = 'anonymous';
    this.#signedOut.forEach((f) => f());
  }

  #listenTabs() {
    if (typeof BroadcastChannel === 'undefined' || this.#channel) return;
    this.#channel = new BroadcastChannel('qwq.session');
    this.#channel.onmessage = (e: MessageEvent<{ t?: string }>) => {
      if (e.data?.t === 'logout') this.expire();
      else if (e.data?.t === 'login' && this.status !== 'authenticated') {
        void this.refresh().then(
          () => {
            if (router.path === '/login') navigate('/', { replace: true });
          },
          () => {},
        );
      }
    };
  }
}

export const session = new SessionStore();
