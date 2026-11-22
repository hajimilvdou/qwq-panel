// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 概览小组件：结果校验与健康度聚合（SPEC §3.1 / GAPS 缺口 7）
 * --------------------------------------------------------------------------
 *   parseWidget(kind, raw)   插件返回值 → 已校验的形状；非法抛 WidgetShapeError
 *   levelOf(w)               单卡健康度（stat / checks；series、list 是趋势与流水，不参与）
 *   worstLevel(levels)       全 ok→ok；任一 warn→warn；任一 bad→bad
 *   refreshMs(widget)        轮询间隔，下限 2 秒
 *   SPAN                     size → 12 列栅格跨度
 *   collectWidgets(plugins)  运行中插件的全部小组件槽位
 *
 * 组件：WidgetGrid（栅格 + 健康度写入 health.level）、WidgetCard（单卡轮询）。
 *
 * 插件结果属于 untrusted：只取已知字段，数值必须有限，字符串截断，
 * 数组限长——非法值只令该卡报错，绝不影响整页。
 * ========================================================================== */
import type {
  ChecksWidgetData,
  Level,
  ListWidgetData,
  Plugin,
  PluginWidget,
  SeriesWidgetData,
  StatWidgetData,
} from '$api/additions';
import { CATEGORY_COLORS, type CategoryColor } from '$ui/types';

export type WidgetData =
  | { kind: 'stat'; data: StatWidgetData }
  | { kind: 'series'; data: SeriesWidgetData }
  | { kind: 'checks'; data: ChecksWidgetData }
  | { kind: 'list'; data: ListWidgetData };

export class WidgetShapeError extends Error {
  constructor(readonly path: string) {
    super(`小组件数据格式不对（${path}）`);
    this.name = 'WidgetShapeError';
  }
}

export const MIN_REFRESH_SECONDS = 2;
export const SPAN: Record<PluginWidget['size'], number> = { s: 3, m: 6, l: 12 };

const MAX_TEXT = 120;
const MAX_ITEMS = 50;
const MAX_POINTS = 2000;
const LEVELS: readonly Level[] = ['ok', 'warn', 'bad'];

/* ------------------------------------------------------------------ 基础校验 */

type Obj = Record<string, unknown>;

function obj(v: unknown, path: string): Obj {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new WidgetShapeError(path);
  return v as Obj;
}
function arr(v: unknown, path: string, max = MAX_ITEMS): unknown[] {
  if (!Array.isArray(v)) throw new WidgetShapeError(path);
  return v.slice(0, max);
}
function num(v: unknown, path: string): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new WidgetShapeError(path);
  return v;
}
function str(v: unknown, path: string): string {
  if (typeof v !== 'string') throw new WidgetShapeError(path);
  return v.slice(0, MAX_TEXT);
}
function numOrStr(v: unknown, path: string): number | string {
  return typeof v === 'string' ? str(v, path) : num(v, path);
}
function level(v: unknown, path: string): Level {
  if (!LEVELS.includes(v as Level)) throw new WidgetShapeError(path);
  return v as Level;
}
function color(v: unknown): CategoryColor | undefined {
  return CATEGORY_COLORS.includes(v as CategoryColor) ? (v as CategoryColor) : undefined;
}
/** 可选字段：缺省为 undefined，存在则必须合法 */
function opt<T>(v: unknown, f: (v: unknown, path: string) => T, path: string): T | undefined {
  return v === undefined || v === null ? undefined : f(v, path);
}

/* ------------------------------------------------------------------ 各形态 */

function parseStat(o: Obj): StatWidgetData {
  return {
    value: numOrStr(o.value, 'value'),
    unit: opt(o.unit, str, 'unit'),
    sub: opt(o.sub, str, 'sub'),
    percent: opt(o.percent, (v, p) => Math.max(0, Math.min(100, num(v, p))), 'percent'),
    spark: opt(o.spark, (v, p) => arr(v, p, 200).map((x, i) => num(x, `${p}[${i}]`)), 'spark'),
    level: opt(o.level, level, 'level'),
  };
}

function parseSeries(o: Obj): SeriesWidgetData {
  const series = arr(o.series, 'series', 8).map((raw, i) => {
    const s = obj(raw, `series[${i}]`);
    const points = arr(s.points, `series[${i}].points`, MAX_POINTS).map((p, j) => {
      const pair = arr(p, `series[${i}].points[${j}]`, 2);
      return [num(pair[0], `series[${i}].points[${j}][0]`), num(pair[1], `series[${i}].points[${j}][1]`)] as [number, number];
    });
    points.sort((a, b) => a[0] - b[0]);
    return { name: str(s.name, `series[${i}].name`), color: color(s.color), points };
  });
  return { unit: opt(o.unit, str, 'unit'), max: opt(o.max, num, 'max'), series };
}

function parseChecks(o: Obj): ChecksWidgetData {
  const h = o.headline === undefined || o.headline === null ? undefined : obj(o.headline, 'headline');
  return {
    headline: h ? { value: numOrStr(h.value, 'headline.value'), label: str(h.label, 'headline.label') } : undefined,
    bars: opt(o.bars, (v, p) => arr(v, p, 60).map((x, i) => num(x, `${p}[${i}]`)), 'bars'),
    items: arr(o.items, 'items').map((raw, i) => {
      const it = obj(raw, `items[${i}]`);
      return { label: str(it.label, `items[${i}].label`), value: str(it.value, `items[${i}].value`), level: level(it.level, `items[${i}].level`) };
    }),
  };
}

function parseList(o: Obj): ListWidgetData {
  return {
    items: arr(o.items, 'items').map((raw, i) => {
      const it = obj(raw, `items[${i}]`);
      return {
        title: str(it.title, `items[${i}].title`),
        sub: opt(it.sub, str, `items[${i}].sub`),
        level: opt(it.level, level, `items[${i}].level`),
        at: opt(it.at, str, `items[${i}].at`),
      };
    }),
  };
}

export function parseWidget(kind: PluginWidget['kind'], raw: unknown): WidgetData {
  const o = obj(raw, '$');
  switch (kind) {
    case 'stat':
      return { kind, data: parseStat(o) };
    case 'series':
      return { kind, data: parseSeries(o) };
    case 'checks':
      return { kind, data: parseChecks(o) };
    case 'list':
      return { kind, data: parseList(o) };
    default:
      throw new WidgetShapeError('kind');
  }
}

/* ------------------------------------------------------------------ 健康度 */

export function worstLevel(levels: Iterable<Level | undefined>): Level {
  let worst: Level = 'ok';
  for (const l of levels) {
    if (l === 'bad') return 'bad';
    if (l === 'warn') worst = 'warn';
  }
  return worst;
}

export function levelOf(w: WidgetData): Level | undefined {
  switch (w.kind) {
    case 'stat':
      return w.data.level;
    case 'checks':
      return worstLevel(w.data.items.map((i) => i.level));
    default:
      return undefined;
  }
}

export function refreshMs(w: Pick<PluginWidget, 'refresh_seconds'>): number {
  const s = Number.isFinite(w.refresh_seconds) ? w.refresh_seconds : MIN_REFRESH_SECONDS;
  return Math.max(MIN_REFRESH_SECONDS, s) * 1000;
}

/* ------------------------------------------------------------------ 收集 */

export interface WidgetSlot {
  /** `${plugin_id}/${widget.id}`，栅格 key 与健康度表的键 */
  key: string;
  plugin: Plugin;
  widget: PluginWidget;
}

/** 运行中插件声明的全部小组件（宿主已限 ≤16/插件，这里再保守截断） */
export function collectWidgets(list: readonly Plugin[] | undefined): WidgetSlot[] {
  const out: WidgetSlot[] = [];
  for (const p of list ?? []) {
    if (p.runtime && p.runtime.state !== 'running') continue;
    for (const w of (p.ui?.widgets ?? []).slice(0, 16)) out.push({ key: `${p.plugin_id}/${w.id}`, plugin: p, widget: w });
  }
  return out;
}
