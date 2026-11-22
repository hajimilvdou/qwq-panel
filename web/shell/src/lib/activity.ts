// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 动态：把 operation 写成人话（SPEC §1 "说人话"、§3.2）
 * --------------------------------------------------------------------------
 *   actorView(actor, meId)        谁：你 / 显示名 / AI 助手 / 系统 + 头像形态
 *   STATUS[status]                状态标签文字与色调
 *   STATUS_FILTERS                筛选项（一个筛选项可对应多个状态）
 *   opSentence(op, catalog)       做了什么："封禁可疑 IP"
 *   opObject(op, pluginName)      对什么："203.0.113.42" / "bob" / "系统监控"
 *   groupByDay(items, at, now)    按本地日期分组 → Timeline 的 groups
 *   actionCatalogResource         动作目录（缺口 5）→ id 到人话摘要
 *
 * 技术字段（action id、operation_id、request_id）只在详情的"技术信息"里出现。
 * ========================================================================== */
import { actions as actionsApi, type Op } from '$api/endpoints';
import type { Actor, OperationStatus } from '$api/types';
import type { Tone } from '$ui/types';
import type { ResourceOptions } from './resource.svelte';

/* ------------------------------------------------------------------ 行为人 */

export type ActorFace = 'human' | 'ai' | 'system';

export interface ActorView {
  name: string;
  face: ActorFace;
  ai: boolean;
}

export function actorView(a: Actor, meId?: string): ActorView {
  switch (a.kind) {
    case 'ai_agent':
      return { name: a.display_name || 'AI 助手', face: 'ai', ai: true };
    case 'system':
    case 'service':
      return { name: a.display_name || '系统', face: 'system', ai: false };
    default:
      return { name: meId && a.id === meId ? '你' : a.display_name || a.id, face: 'human', ai: false };
  }
}

/* ------------------------------------------------------------------ 状态 */

export const STATUS: Record<OperationStatus, { label: string; tone: Tone }> = {
  PENDING: { label: '排队中', tone: 'neutral' },
  AWAITING_APPROVAL: { label: '等待批准', tone: 'warn' },
  APPROVED: { label: '已批准', tone: 'info' },
  RUNNING: { label: '进行中', tone: 'info' },
  SUCCEEDED: { label: '已完成', tone: 'ok' },
  FAILED: { label: '失败', tone: 'bad' },
  REJECTED: { label: '已拒绝', tone: 'neutral' },
  EXPIRED: { label: '已过期', tone: 'neutral' },
  CANCELED: { label: '已取消', tone: 'neutral' },
};

export type StatusFilter = 'running' | 'awaiting' | 'succeeded' | 'failed' | 'ended';

export const STATUS_FILTERS: readonly { value: StatusFilter; label: string; statuses: OperationStatus[] }[] = [
  { value: 'running', label: '进行中', statuses: ['PENDING', 'APPROVED', 'RUNNING'] },
  { value: 'awaiting', label: '等待批准', statuses: ['AWAITING_APPROVAL'] },
  { value: 'succeeded', label: '已完成', statuses: ['SUCCEEDED'] },
  { value: 'failed', label: '失败', statuses: ['FAILED'] },
  { value: 'ended', label: '取消、拒绝或过期', statuses: ['CANCELED', 'REJECTED', 'EXPIRED'] },
];

export const ACTOR_FILTERS = [
  { value: 'human', label: '人' },
  { value: 'ai_agent', label: 'AI' },
  { value: 'system', label: '系统' },
] as const;

/* ------------------------------------------------------------------ 句子 */

/** id → 人话摘要（approval_summary 优先，其次 summary） */
export type ActionCatalog = ReadonlyMap<string, string>;

/** 动作目录只读一次（50 条上限；查不到的回退为 id 末段，不影响功能） */
export const actionCatalogResource: ResourceOptions<ActionCatalog> = {
  key: 'actions-catalog',
  load: () =>
    actionsApi
      .search('', { limit: 50 })
      .then((r) => new Map(r.items.map((a) => [a.id, a.approval_summary || a.summary]))),
  subjects: ['plugins/'],
};

/** "host.users.update" → "users update"：目录缺失时的兜底 */
function fallbackSummary(action: string): string {
  const tail = action.split('/').pop() ?? action;
  return tail.replace(/^host\./, '').replace(/[._]+/g, ' ').trim() || action;
}

export function opSentence(op: Pick<Op, 'action'>, catalog?: ActionCatalog): string {
  return catalog?.get(op.action) ?? fallbackSummary(op.action);
}

/** 参数里最能代表"对象"的字段，按优先级 */
const OBJECT_KEYS = ['username', 'name', 'ip', 'label', 'title', 'version', 'port', 'path', 'pid'] as const;

export function opObject(op: Pick<Op, 'args' | 'target'>, pluginName?: (id: string) => string | undefined): string | undefined {
  for (const k of OBJECT_KEYS) {
    const v = op.args?.[k];
    if (typeof v === 'string' && v) return v.slice(0, 64);
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  }
  const subject = op.target?.subject;
  if (subject) return subject.split('/').pop()?.replace(/^(usr|dlg|plg)_/, '') || subject;
  const pid = op.target?.plugin_id;
  return pid ? (pluginName?.(pid) ?? pid) : undefined;
}

/* ------------------------------------------------------------------ 按天分组 */

const WEEK = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];

function dayKey(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

export function dayLabel(d: Date, now: Date): string {
  const today = dayKey(now);
  const y = new Date(now);
  y.setDate(y.getDate() - 1);
  const k = dayKey(d);
  if (k === today) return '今天';
  if (k === dayKey(y)) return '昨天';
  const year = d.getFullYear() === now.getFullYear() ? '' : `${d.getFullYear()}年`;
  return `${year}${d.getMonth() + 1}月${d.getDate()}日 ${WEEK[d.getDay()]}`;
}

/** 输入应已按时间倒序；组按首次出现排列，乱序项并入已有组（key 不重复） */
export function groupByDay<T>(
  items: readonly T[],
  at: (x: T) => string,
  now: number = Date.now(),
): { key: string; label: string; items: T[] }[] {
  const groups = new Map<string, { key: string; label: string; items: T[] }>();
  const nowD = new Date(now);
  for (const x of items) {
    const d = new Date(at(x));
    if (Number.isNaN(d.getTime())) continue;
    const key = dayKey(d);
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { key, label: dayLabel(d, nowD), items: [] }));
    g.items.push(x);
  }
  return [...groups.values()];
}
