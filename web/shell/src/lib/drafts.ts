// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 表单草稿（会话过期时暂存，登录回来后恢复）
 * --------------------------------------------------------------------------
 *   const off = registerDraft('settings.users.new', () => form);   // 组件内
 *   const saved = takeDraft<Form>('settings.users.new');           // 恢复一次
 *
 * 只在 401 跳转时由会话层调用 persistDrafts() 写 sessionStorage。
 * 字段名命中 password / secret / token / key / code / otp 的一律剔除。
 * ========================================================================== */

const PREFIX = 'qwq.draft.';
const SECRET = /pass|secret|token|key|code|otp|mfa/i;
const providers = new Map<string, () => Record<string, unknown>>();

export function registerDraft(key: string, read: () => Record<string, unknown>): () => void {
  providers.set(key, read);
  return () => providers.delete(key);
}

function stripValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stripValue);
  if (v && typeof v === 'object') return stripSecrets(v as Record<string, unknown>);
  return v;
}

export function stripSecrets(data: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    if (SECRET.test(k)) continue;
    out[k] = stripValue(v);
  }
  return out;
}

export function persistDrafts(): void {
  for (const [key, read] of providers) {
    try {
      sessionStorage.setItem(PREFIX + key, JSON.stringify(stripSecrets(read())));
    } catch {
      /* 存储不可用或数据不可序列化：放弃该草稿 */
    }
  }
}

export function takeDraft<T extends Record<string, unknown>>(key: string): Partial<T> | null {
  try {
    const raw = sessionStorage.getItem(PREFIX + key);
    if (!raw) return null;
    sessionStorage.removeItem(PREFIX + key);
    return JSON.parse(raw) as Partial<T>;
  } catch {
    return null;
  }
}
