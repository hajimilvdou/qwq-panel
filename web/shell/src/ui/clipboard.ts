// SPDX-License-Identifier: AGPL-3.0-only
/* 兼容非 HTTPS 裸 IP 上下文的剪贴板写入工具 */

export async function copyTextWithFallback(text: string): Promise<boolean> {
  if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      /* 降级走传统选区复制 */
    }
  }
  if (typeof document === 'undefined') return false;
  const active = document.activeElement as HTMLElement | null;
  const container =
    (active?.closest?.('dialog[open]') as HTMLElement | null) ??
    (document.querySelector('dialog[open]') as HTMLElement | null) ??
    document.body;
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', 'true');
  ta.style.position = 'fixed';
  ta.style.top = '-9999px';
  ta.style.left = '-9999px';
  ta.style.opacity = '0';
  container.appendChild(ta);
  try {
    ta.focus({ preventScroll: true });
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    ta.remove();
    active?.focus?.({ preventScroll: true });
  }
}
