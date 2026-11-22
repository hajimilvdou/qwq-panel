// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 折线几何（SeriesChart 用；纯函数，无 DOM，便于测试）
 * --------------------------------------------------------------------------
 *   const g = chartGeometry(series, { width: 600, height: 180 });
 *   g.lines[i].line / g.lines[i].area   SVG path
 *   g.lo / g.hi                         纵轴范围（hi 取"好看"的整数）
 *   g.t0 / g.t1                         横轴时间范围（与输入同单位）
 *   g.nearest(x)                        视图坐标 x → 最近的点下标（悬停读数）
 *
 * 约定：points 为 [时间, 数值]，按时间升序；各系列可不等长、不对齐。
 * ========================================================================== */
import type { CategoryColor } from './types';

export type ChartPoint = readonly [number, number];

export interface ChartSeries {
  name: string;
  color?: CategoryColor;
  points: readonly ChartPoint[];
}

export interface ChartLine {
  line: string;
  area: string;
}

export interface ChartGeometry {
  lines: ChartLine[];
  lo: number;
  hi: number;
  t0: number;
  t1: number;
  /** 横向网格线的纵坐标（视图坐标） */
  grid: number[];
  /** 视图坐标 x → 第 i 条系列里时间最近的点下标（无点时 -1） */
  nearest: (x: number, i?: number) => number;
  /** 数据点 → 视图坐标 */
  project: (p: ChartPoint) => [number, number];
}

/** 向上取"好看"的刻度上限：1/2/2.5/5 × 10^n */
export function niceCeil(v: number): number {
  if (!Number.isFinite(v) || v <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * exp + 1e-9) return m * exp;
  return 10 * exp;
}

/** 内边距：线宽与圆点不被裁掉 */
const PAD = 3;

export function chartGeometry(
  series: readonly ChartSeries[],
  opts: { width: number; height: number; max?: number; gridLines?: number },
): ChartGeometry {
  const { width, height } = opts;
  const all = series.flatMap((s) => s.points).filter(([t, v]) => Number.isFinite(t) && Number.isFinite(v));

  /* ---------------------------------------------------------------- 范围 */
  let t0 = Infinity;
  let t1 = -Infinity;
  let vmin = 0;
  let vmax = 0;
  for (const [t, v] of all) {
    if (t < t0) t0 = t;
    if (t > t1) t1 = t;
    if (v < vmin) vmin = v;
    if (v > vmax) vmax = v;
  }
  if (!all.length) t0 = t1 = 0;
  const lo = vmin < 0 ? -niceCeil(-vmin) : 0;
  const hi = opts.max !== undefined && opts.max > lo ? opts.max : niceCeil(vmax);
  const tSpan = t1 - t0 || 1;
  const vSpan = hi - lo || 1;

  const project = ([t, v]: ChartPoint): [number, number] => [
    ((t - t0) / tSpan) * width,
    PAD + (1 - (Math.min(Math.max(v, lo), hi) - lo) / vSpan) * (height - PAD * 2),
  ];

  /* ---------------------------------------------------------------- 路径 */
  const base = project([t0, lo])[1];
  const lines = series.map((s) => {
    const pts = s.points.filter(([t, v]) => Number.isFinite(t) && Number.isFinite(v)).map(project);
    if (!pts.length) return { line: '', area: '' };
    const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join('');
    const first = pts[0]!;
    const last = pts[pts.length - 1]!;
    return { line, area: `${line}L${last[0].toFixed(1)} ${base.toFixed(1)}L${first[0].toFixed(1)} ${base.toFixed(1)}Z` };
  });

  const n = opts.gridLines ?? 3;
  const grid = Array.from({ length: n }, (_, i) => PAD + ((i + 1) / (n + 1)) * (height - PAD * 2));

  const nearest = (x: number, i = 0): number => {
    const pts = series[i]?.points;
    if (!pts?.length) return -1;
    const t = t0 + (Math.min(Math.max(x, 0), width) / width) * tSpan;
    let best = 0;
    for (let k = 1; k < pts.length; k++) if (Math.abs(pts[k]![0] - t) < Math.abs(pts[best]![0] - t)) best = k;
    return best;
  };

  return { lines, lo, hi, t0, t1, grid, nearest, project };
}
