// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * ⌘K 面板的条目模型（纯逻辑：页面目录、匹配、最近使用、键盘游标）
 * --------------------------------------------------------------------------
 * 分组顺序（SPEC §5）：页面 → 操作 → 最近 → 末项"问 AI：{输入}"。
 * 匹配：忽略大小写与空白的子串匹配，标签命中优先于关键词命中。
 * ========================================================================== */
import type { ActionMeta } from '$api/additions';
import type { IconName } from '$ui';

export type PaletteItem =
  | { kind: 'page'; id: string; label: string; href: string; icon: IconName; keywords?: string }
  | { kind: 'action'; id: string; label: string; action: ActionMeta }
  | { kind: 'ask'; id: 'ask'; label: string; prompt: string };

export interface PaletteGroup {
  title: string;
  items: PaletteItem[];
}

const norm = (s: string) => s.toLowerCase().replace(/\s+/g, '');

/** 0 = 不匹配；2 = 标签命中；1 = 关键词命中 */
export function score(item: { label: string; keywords?: string }, q: string): number {
  const n = norm(q);
  if (!n) return 1;
  if (norm(item.label).includes(n)) return 2;
  return item.keywords && norm(item.keywords).includes(n) ? 1 : 0;
}

export function filterPages<T extends { label: string; keywords?: string }>(pages: readonly T[], q: string, max = 6): T[] {
  return pages
    .map((p, i) => ({ p, s: score(p, q), i }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || a.i - b.i)
    .slice(0, max)
    .map((x) => x.p);
}

/** 组装分组；最近项去掉已出现在上面的；问 AI 永远在末尾 */
export function buildGroups(input: {
  q: string;
  pages: readonly Extract<PaletteItem, { kind: 'page' }>[];
  actions: readonly ActionMeta[];
  recent: readonly PaletteItem[];
}): PaletteGroup[] {
  const { q } = input;
  const pages = filterPages(input.pages, q);
  const actions: PaletteItem[] = input.actions.map((a) => ({ kind: 'action', id: 'action:' + a.id, label: a.summary || a.id, action: a }));
  const shown = new Set([...pages, ...actions].map((x) => x.id));
  const recent = input.recent.filter((r) => r.kind !== 'ask' && !shown.has(r.id) && score(r, q) > 0).slice(0, 4);
  const trimmed = q.trim();
  const groups: PaletteGroup[] = [
    { title: '页面', items: pages },
    { title: '操作', items: actions },
    { title: '最近', items: recent },
    { title: 'AI', items: [{ kind: 'ask', id: 'ask', label: trimmed ? `问 AI：${trimmed}` : '问 AI', prompt: trimmed }] },
  ];
  return groups.filter((g) => g.items.length);
}

/** ↑↓ 循环移动游标 */
export function moveCursor(cur: number, delta: number, count: number): number {
  if (!count) return 0;
  return (((cur + delta) % count) + count) % count;
}

/* ------------------------------------------------------------------ 最近使用 */

const RECENT_KEY = 'qwq.palette.recent';
const RECENT_MAX = 8;

/** 只存可序列化的最小信息；操作项只存 id/summary（详情选中时再取） */
export function pushRecent(list: readonly PaletteItem[], item: PaletteItem): PaletteItem[] {
  if (item.kind === 'ask') return [...list];
  return [item, ...list.filter((x) => x.id !== item.id)].slice(0, RECENT_MAX);
}

export function loadRecent(): PaletteItem[] {
  try {
    const v = JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]') as PaletteItem[];
    return Array.isArray(v) ? v.filter((x) => x && (x.kind === 'page' || x.kind === 'action')) : [];
  } catch {
    return [];
  }
}

export function saveRecent(list: readonly PaletteItem[]): void {
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(list));
  } catch {
    /* 忽略 */
  }
}

/* ------------------------------------------------------------------ 定级展示 */

/**
 * 人发起时会不会进审批（契约 §5.3，非 AI 调用者固定 safe + auto_approve_max_risk=low）：
 * destructive、风险 ≥ medium、或插件声明 confirm → 执行后进悬浮窗确认（需要 MFA 时另提示）。
 */
export function gradeOf(a: Pick<ActionMeta, 'effect' | 'risk' | 'approval'>): { label: string; needsApproval: boolean } {
  if (a.effect === 'read' && a.risk !== 'high') return { label: '只读，直接执行', needsApproval: false };
  if (a.effect === 'destructive') return { label: '破坏性操作，需确认并输入验证码', needsApproval: true };
  if (a.approval === 'confirm' || a.risk !== 'low') return { label: '提交后需要确认', needsApproval: true };
  return { label: '直接执行', needsApproval: false };
}
