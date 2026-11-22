// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 格式化：时间、字节、数字（中文、无第三方）
 * ========================================================================== */

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** "刚刚 / 5 分钟前 / 3 小时前 / 昨天 14:20 / 11月3日" */
export function relativeTime(iso: string | undefined, now = Date.now()): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const d = now - t;
  if (d < 0) return clock(t);
  if (d < MIN) return '刚刚';
  if (d < HOUR) return `${Math.floor(d / MIN)} 分钟前`;
  if (d < DAY && new Date(t).getDate() === new Date(now).getDate()) return `${Math.floor(d / HOUR)} 小时前`;
  if (d < 2 * DAY) return `昨天 ${clock(t)}`;
  const date = new Date(t);
  const sameYear = date.getFullYear() === new Date(now).getFullYear();
  return `${sameYear ? '' : date.getFullYear() + '年'}${date.getMonth() + 1}月${date.getDate()}日`;
}

/** "2026-11-09 14:20:05"（本地时区），用于详情与审计 */
export function dateTime(iso: string | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function clock(t: number): string {
  const d = new Date(t);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

/** "3 天 4 小时 / 5 小时 12 分 / 8 分钟" */
export function duration(ms: number): string {
  if (ms < MIN) return `${Math.max(0, Math.round(ms / 1000))} 秒`;
  const d = Math.floor(ms / DAY);
  const h = Math.floor((ms % DAY) / HOUR);
  const m = Math.floor((ms % HOUR) / MIN);
  if (d) return h ? `${d} 天 ${h} 小时` : `${d} 天`;
  if (h) return m ? `${h} 小时 ${m} 分` : `${h} 小时`;
  return `${m} 分钟`;
}

/** 1536 → "1.5 KB"（1024 进制） */
export function bytes(n: number | undefined): string {
  if (n === undefined || !Number.isFinite(n)) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}

/** 名字首字（头像用）：中文取首字，英文取首字母大写 */
export function initial(name: string | undefined): string {
  const s = (name ?? '').trim();
  if (!s) return '?';
  const ch = Array.from(s)[0]!;
  return ch.toUpperCase();
}

/** 字符串稳定哈希 → 0..n-1（插件底块色等） */
export function hashIndex(s: string, n: number): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return (h >>> 0) % n;
}
