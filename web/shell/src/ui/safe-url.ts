// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 宿主 URL 安全校验原语（根除 javascript: XSS 与 //evil.com 开放重定向）
 * ========================================================================== */

/** 仅放行站内绝对路径（拒绝 //、反斜杠、控制字符及任意跨源归一化） */
export function safeInternalPath(candidate: string | null | undefined, fallback = '/'): string {
  if (!candidate || typeof candidate !== 'string') return fallback;
  const trimmed = candidate.trim();
  if (
    !trimmed.startsWith('/') ||
    trimmed.startsWith('//') ||
    trimmed.startsWith('/\\') ||
    trimmed.includes('\\') ||
    /[\u0000-\u001f\u007f]/.test(trimmed)
  ) {
    return fallback;
  }
  try {
    const u = new URL(trimmed, 'https://qwq.invalid');
    return u.origin === 'https://qwq.invalid' ? trimmed : fallback;
  } catch {
    return fallback;
  }
}

/** 仅放行绝对 http: / https: 外部链接（拒绝 javascript: / data: / vbscript: 等） */
export function safeExternalHref(candidate: string | null | undefined): string | null {
  if (!candidate || typeof candidate !== 'string') return null;
  const trimmed = candidate.trim();
  if (!trimmed || /[\u0000-\u001f\u007f]/.test(trimmed)) return null;
  try {
    const u = new URL(trimmed);
    if (u.protocol === 'https:' || u.protocol === 'http:') {
      return u.toString();
    }
  } catch {
    /* 非合法绝对 URL 一律拒绝 */
  }
  return null;
}
