// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 初始化、会话、账户（GAPS 缺口 1）
 * --------------------------------------------------------------------------
 * Cookie：qwq_session; HttpOnly; SameSite=Lax; Path=/api/（开发为 http，无 __Secure-）
 * 登录、MFA、setup、enroll 会轮换会话并返回新 csrf_token；TOTP confirm 不轮换
 * （CSRF 不变、不标新鲜 MFA），disable 走 POST …/totp/disable（验证码错 403）。
 * 机密例外路由（口令 / TOTP / 令牌）不进 operation，只写审计并发 resource.changed。
 * 两步验证码在模拟环境中固定为 123456，恢复码为 qwq-rec-0001。
 * ========================================================================== */
import { randomBytes } from 'node:crypto';
import { checkRevision, denied, invalid, MockProblem, noContent, ok, requireString, type Ctx, type Result, type RouteSpec, type S } from '../http.ts';
import { actorOf, changed, newId, nowIso, rev, runOperation, writeAudit, type Db, type MockSession } from '../store.ts';

export const MOCK_TOTP = '123456';
export const MOCK_RECOVERY = 'qwq-rec-0001';
const SESSION_TTL = 12 * 3600_000;

/* ------------------------------------------------------------------ 会话工具 */

export function cookieOf(ctx: Ctx): string | undefined {
  const raw = ctx.req.headers.cookie ?? '';
  return /(?:^|;\s*)qwq_session=([^;]+)/.exec(raw)?.[1];
}

function issue(db: Db, userId: string, mfa: boolean): MockSession {
  const now = Date.now();
  const s: MockSession = {
    sid: randomBytes(18).toString('base64url'),
    userId,
    csrf: randomBytes(18).toString('base64url'),
    createdAt: now,
    expiresAt: now + (db.flags.sessionTtlMs || SESSION_TTL),
    mfaVerifiedAt: mfa ? now : undefined,
  };
  db.sessions.set(s.sid, s);
  return s;
}

export function sessionDto(db: Db, s: MockSession): S['Session'] {
  return {
    status: 'authenticated',
    user: db.users.get(s.userId)!,
    csrf_token: s.csrf,
    mfa_verified_at: s.mfaVerifiedAt ? nowIso(s.mfaVerifiedAt) : undefined,
    created_at: nowIso(s.createdAt),
    idle_expires_at: nowIso(Math.min(s.expiresAt, Date.now() + 30 * 60_000)),
    expires_at: nowIso(s.expiresAt),
  };
}

const setCookie = (sid: string, maxAge: number) =>
  `qwq_session=${sid}; HttpOnly; SameSite=Lax; Path=/api/; Max-Age=${Math.floor(maxAge / 1000)}`;

/** 签发（或轮换）会话，返回带 Set-Cookie 的结果 */
function signIn(ctx: Ctx, userId: string, mfa: boolean, status = 200): Result {
  const old = cookieOf(ctx);
  if (old) ctx.db.sessions.delete(old);
  const s = issue(ctx.db, userId, mfa);
  const user = ctx.db.users.get(userId)!;
  writeAudit(ctx.db, { actor: actorOf(user), action: 'session.login', subject: 'sessions', outcome: 'success', request_id: ctx.requestId });
  return { status, body: sessionDto(ctx.db, s), headers: { 'Set-Cookie': setCookie(s.sid, s.expiresAt - Date.now()) } };
}

const findUser = (db: Db, username: string) => [...db.users.values()].find((u) => u.username === username.toLowerCase());

function passwordPolicy(pw: unknown): string {
  if (typeof pw !== 'string' || pw.length < 12) throw invalid('/password', '至少 12 个字符', 'TOO_SHORT');
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (pw.length < 20 && classes < 3) throw invalid('/password', '少于 20 位时需包含大小写字母、数字、符号中的 3 类', 'TOO_WEAK');
  return pw;
}

const checkCode = (code: unknown) => {
  if (code !== MOCK_TOTP) throw invalid('/code', '验证码不对', 'MFA_INVALID');
};

/* ------------------------------------------------------------------ 路由 */

export const authRoutes: RouteSpec[] = [
  {
    method: 'GET',
    pattern: '/api/v1/setup',
    public: true,
    handler: ({ db }) => ok({ initialized: db.setup.initialized, tls_fingerprint: db.setup.tls_fingerprint }),
  },
  {
    method: 'POST',
    pattern: '/api/v1/setup',
    public: true,
    idempotency: 'none',
    fields: ['setup_token', 'username', 'password', 'display_name'],
    handler: (ctx) => {
      const { db, body } = ctx;
      if (db.setup.initialized) throw new MockProblem(409, 'STATE_CONFLICT', '已经初始化过了');
      if (body.setup_token !== db.setup.token) throw new MockProblem(401, 'UNAUTHENTICATED', '初始化令牌不对');
      const username = requireString(body, 'username', 32).toLowerCase();
      passwordPolicy(body.password);
      const u: S['User'] = {
        user_id: newId('usr'),
        username,
        display_name: body.display_name || username,
        role: 'admin',
        mfa_enabled: false,
        disabled: false,
        created_at: nowIso(),
        updated_at: nowIso(),
        revision: rev(db),
      };
      db.users.set(u.user_id, u);
      db.passwords.set(u.user_id, body.password);
      db.setup.initialized = true;
      return signIn(ctx, u.user_id, false, 201);
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/sessions',
    public: true,
    idempotency: 'none',
    fields: ['username', 'password'],
    handler: (ctx) => {
      const { db, body } = ctx;
      const u = findUser(db, String(body.username ?? ''));
      if (!u || u.disabled || db.passwords.get(u.user_id) !== body.password) {
        writeAudit(db, { actor: { kind: 'human', id: 'unknown', display_name: String(body.username ?? '') }, action: 'session.login', subject: 'sessions', outcome: 'failure', request_id: ctx.requestId });
        throw new MockProblem(401, 'UNAUTHENTICATED', '用户名或密码不对');
      }
      if (u.mfa_enabled) {
        const id = newId('mfa');
        db.challenges.set(id, { userId: u.user_id, expiresAt: Date.now() + 5 * 60_000 });
        return ok({ status: 'mfa_required', challenge_id: id, methods: ['totp', 'recovery_code'], expires_at: nowIso(Date.now() + 5 * 60_000) });
      }
      return signIn(ctx, u.user_id, false);
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/sessions/mfa',
    public: true,
    idempotency: 'none',
    fields: ['challenge_id', 'method', 'code'],
    handler: (ctx) => {
      const c = ctx.db.challenges.get(String(ctx.body.challenge_id));
      if (!c || c.expiresAt < Date.now()) throw new MockProblem(401, 'UNAUTHENTICATED', '验证已过期，请重新登录');
      const good = ctx.body.method === 'recovery_code' ? ctx.body.code === MOCK_RECOVERY : ctx.body.code === MOCK_TOTP;
      if (!good) throw new MockProblem(401, 'UNAUTHENTICATED', '验证码不对');
      ctx.db.challenges.delete(String(ctx.body.challenge_id));
      return signIn(ctx, c.userId, true);
    },
  },
  {
    method: 'GET',
    pattern: '/api/v1/sessions/current',
    handler: (ctx) => ok(sessionDto(ctx.db, ctx.session!)),
  },
  {
    method: 'DELETE',
    pattern: '/api/v1/sessions/current',
    idempotency: 'none',
    handler: (ctx) => {
      ctx.db.sessions.delete(ctx.session!.sid);
      return { status: 204, headers: { 'Set-Cookie': setCookie('', 0) } };
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/enrollments',
    public: true,
    fields: ['token', 'password'],
    handler: (ctx) => {
      const t = ctx.db.enrollTokens.get(String(ctx.body.token ?? ''));
      if (!t || t.expiresAt < Date.now()) throw new MockProblem(401, 'UNAUTHENTICATED', '注册链接无效或已过期');
      passwordPolicy(ctx.body.password);
      ctx.db.enrollTokens.delete(String(ctx.body.token));
      ctx.db.passwords.set(t.userId, ctx.body.password);
      return signIn(ctx, t.userId, false, 201);
    },
  },
  {
    method: 'PATCH',
    pattern: '/api/v1/sessions/current/profile',
    fields: ['display_name', 'expected_revision'],
    handler: (ctx) => {
      const u = ctx.user!;
      checkRevision(u.revision, ctx.body.expected_revision);
      const dn = ctx.body.display_name;
      if (typeof dn !== 'string' || dn.length > 64) throw invalid('/display_name', '显示名需为不超过 64 字符的字符串', 'INVALID');
      return runOperation(ctx, { action: 'host.account.update', target: { subject: `users/${u.user_id}` }, args: { display_name: dn } }, () => {
        u.display_name = dn;
        u.updated_at = nowIso();
        u.revision = rev(ctx.db);
        changed(ctx.db, `users/${u.user_id}`, 'update', actorOf(u), { revision: u.revision, pointers: ['/display_name'] });
        return u;
      });
    },
  },
  {
    method: 'PUT',
    pattern: '/api/v1/sessions/current/password',
    fields: ['current_password', 'new_password'],
    handler: (ctx) => {
      const { db, user, session } = ctx;
      if (db.passwords.get(user!.user_id) !== ctx.body.current_password) throw denied('当前密码不对');
      try {
        passwordPolicy(ctx.body.new_password);
      } catch {
        throw invalid('/new_password', '至少 12 位；少于 20 位时需 3 类字符', 'TOO_WEAK');
      }
      db.passwords.set(user!.user_id, ctx.body.new_password);
      for (const [sid, s] of db.sessions) if (s.userId === user!.user_id && sid !== session!.sid) db.sessions.delete(sid);
      writeAudit(db, { actor: actorOf(user), action: 'account.password', subject: `users/${user!.user_id}`, outcome: 'success', request_id: ctx.requestId });
      return noContent();
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/sessions/current/mfa/totp',
    secretFields: ['secret', 'otpauth_url'],
    handler: (ctx) => {
      const { db, user, session } = ctx;
      if (user!.mfa_enabled && !(session!.mfaVerifiedAt && Date.now() - session!.mfaVerifiedAt < 10 * 60_000)) {
        throw new MockProblem(403, 'MFA_REQUIRED', '需要先验证两步验证码');
      }
      const secret = 'JBSWY3DPEHPK3PXP';
      db.totpPending.set(user!.user_id, secret);
      return ok({ secret, otpauth_url: `otpauth://totp/qwq:${user!.username}?secret=${secret}&issuer=qwq`, expires_at: nowIso(Date.now() + 10 * 60_000) });
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/sessions/current/mfa/totp/confirm',
    fields: ['code'],
    secretFields: ['recovery_codes', 'session'],
    handler: (ctx) => {
      const { db, user, session } = ctx;
      if (!db.totpPending.has(user!.user_id)) throw new MockProblem(409, 'STATE_CONFLICT', '请先开始绑定');
      checkCode(ctx.body.code);
      db.totpPending.delete(user!.user_id);
      user!.mfa_enabled = true;
      user!.revision = rev(db);
      changed(db, `users/${user!.user_id}`, 'update', actorOf(user), { revision: user!.revision, pointers: ['/mfa_enabled'] });
      const recovery_codes = Array.from({ length: 8 }, (_, i) => (i === 0 ? MOCK_RECOVERY : `qwq-rec-${randomBytes(3).toString('hex')}`));
      /* confirm 不轮换会话、不标新鲜 MFA、CSRF 不变：session 是当前会话 */
      return ok({ recovery_codes, user, session: sessionDto(db, session!) });
    },
  },
  {
    method: 'POST',
    pattern: '/api/v1/sessions/current/mfa/totp/disable',
    fields: ['code'],
    handler: (ctx) => {
      const { db, user } = ctx;
      const code = ctx.body.code;
      if (code !== MOCK_TOTP && code !== MOCK_RECOVERY) throw new MockProblem(403, 'MFA_REQUIRED', '验证码不对');
      user!.mfa_enabled = false;
      user!.revision = rev(db);
      changed(db, `users/${user!.user_id}`, 'update', actorOf(user), { revision: user!.revision, pointers: ['/mfa_enabled'] });
      return ok(user);
    },
  },
];

/** 管理员为用户签发注册令牌（缺口 1；令牌只在本次响应） */
export function issueEnrollment(db: Db, userId: string): { enrollment_token: string; expires_at: string } {
  const token = 'qwq-enr-' + randomBytes(12).toString('base64url');
  const expiresAt = Date.now() + 24 * 3600_000;
  db.enrollTokens.set(token, { userId, expiresAt });
  return { enrollment_token: token, expires_at: nowIso(expiresAt) };
}

