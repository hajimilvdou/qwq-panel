// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 平滑曲线几何（SeriesChart 用；纯函数，无 DOM，便于测试）
 * --------------------------------------------------------------------------
 *   const g = chartGeometry(series, { width: 600, height: 180 });
 *   g.lines[i].line / g.lines[i].area   Fritsch-Carlson 单调三次贝塞尔 SVG path
 *   g.lo / g.hi                         纵轴范围（hi 取"好看"的整数）
 *   g.t0 / g.t1                         横轴时间范围（与输入同单位）
 *   g.yTicks / g.xTicks                 坐标轴刻度标签位置与值
 *   g.nearest(x)                        视图坐标 x → 最近的点下标（悬停读数）
 *
 * 约定：points 为 [时间, 数值]，按时间升序；单调三次样条既平滑自然，又绝不产生下冲负值或上冲越界。
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

export interface ChartYTick {
  y: number;
  pct: number;
  value: number;
}

export interface ChartXTick {
  x: number;
  pct: number;
  t: number;
  isEnd: boolean;
}

export interface ChartGeometry {
  lines: ChartLine[];
  lo: number;
  hi: number;
  t0: number;
  t1: number;
  /** 横向网格线的纵坐标（视图坐标） */
  grid: number[];
  /** 纵轴刻度（自顶向下：hi → lo） */
  yTicks: ChartYTick[];
  /** 横轴时间刻度（自左向右：t0 → t1） */
  xTicks: ChartXTick[];
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

/**
 * Fritsch-Carlson 单调三次 Hermite 样条转 SVG 三次贝塞尔路径（M ... C ...）：
 * 彻底消除尖刺折线；对大跨度空白断点改用平滑直线桥接避免拱形过冲，
 * 并将控制点严格夹紧在相邻点纵坐标与画布安全区内，绝不产生回绕、下冲负值或上冲越界。
 */
function smoothBezierPath(pts: readonly [number, number][], yMin: number, yMax: number): string {
  const n = pts.length;
  if (!n) return '';
  if (n === 1) return `M${pts[0]![0].toFixed(1)} ${pts[0]![1].toFixed(1)}`;
  if (n === 2) {
    return `M${pts[0]![0].toFixed(1)} ${pts[0]![1].toFixed(1)}L${pts[1]![0].toFixed(1)} ${pts[1]![1].toFixed(1)}`;
  }

  const dx: number[] = new Array(n - 1);
  const dy: number[] = new Array(n - 1);
  const d: number[] = new Array(n - 1);
  const posDx: number[] = [];
  for (let i = 0; i < n - 1; i++) {
    dx[i] = Math.max(0, pts[i + 1]![0] - pts[i]![0]);
    dy[i] = pts[i + 1]![1] - pts[i]![1];
    d[i] = dx[i]! > 1e-6 ? dy[i]! / dx[i]! : 0;
    if (dx[i]! > 1e-6) posDx.push(dx[i]!);
  }
  posDx.sort((a, b) => a - b);
  const medianDx = posDx.length ? posDx[Math.floor(posDx.length / 2)]! : 0;
  const gapThreshold = medianDx > 0 ? medianDx * 3.5 : Infinity;

  const m: number[] = new Array(n);
  m[0] = dx[0]! > gapThreshold ? 0 : d[0]!;
  m[n - 1] = dx[n - 2]! > gapThreshold ? 0 : d[n - 2]!;
  for (let i = 1; i < n - 1; i++) {
    if (dx[i - 1]! > gapThreshold || dx[i]! > gapThreshold || d[i - 1]! * d[i]! <= 0) {
      m[i] = 0;
    } else {
      /* 非均匀采样步长时使用加权调和均值（Steffen/Fritsch-Butland），避免宽窄相邻段拉出怪异弧度 */
      const w1 = 2 * dx[i]! + dx[i - 1]!;
      const w2 = dx[i]! + 2 * dx[i - 1]!;
      m[i] = (w1 + w2) / (w1 / d[i - 1]! + w2 / d[i]!);
    }
  }

  for (let i = 0; i < n - 1; i++) {
    if (dx[i]! > gapThreshold || Math.abs(d[i]!) < 1e-9) {
      m[i] = 0;
      m[i + 1] = 0;
    } else {
      const a = m[i]! / d[i]!;
      const b = m[i + 1]! / d[i]!;
      const s = a * a + b * b;
      if (s > 9) {
        const tau = 3 / Math.sqrt(s);
        m[i] = tau * a * d[i]!;
        m[i + 1] = tau * b * d[i]!;
      }
    }
  }

  const clampY = (y: number, a: number, b: number) => {
    const segLo = Math.max(yMin, Math.min(a, b));
    const segHi = Math.min(yMax, Math.max(a, b));
    return Math.min(segHi, Math.max(segLo, y));
  };

  let path = `M${pts[0]![0].toFixed(1)} ${pts[0]![1].toFixed(1)}`;
  for (let i = 0; i < n - 1; i++) {
    const [x0, y0] = pts[i]!;
    const [x1, y1] = pts[i + 1]!;
    const h = dx[i]!;
    if (h <= 1e-6 || h > gapThreshold) {
      path += `L${x1.toFixed(1)} ${y1.toFixed(1)}`;
      continue;
    }
    const c1x = x0 + h / 3;
    const c1y = clampY(y0 + (m[i]! * h) / 3, y0, y1);
    const c2x = x1 - h / 3;
    const c2y = clampY(y1 - (m[i + 1]! * h) / 3, y0, y1);
    path += `C${c1x.toFixed(1)} ${c1y.toFixed(1)},${c2x.toFixed(1)} ${c2y.toFixed(1)},${x1.toFixed(1)} ${y1.toFixed(1)}`;
  }
  return path;
}

/** 清洗并按时间严格升序去重（同时间戳保留后者） */
function cleanPoints(raw: readonly ChartPoint[]): ChartPoint[] {
  const valid = raw.filter(([t, v]) => Number.isFinite(t) && Number.isFinite(v));
  if (valid.length <= 1) return valid.slice();
  const sorted = valid.slice().sort((a, b) => a[0] - b[0]);
  const out: ChartPoint[] = [];
  for (const pt of sorted) {
    if (out.length && out[out.length - 1]![0] === pt[0]) {
      out[out.length - 1] = pt;
    } else {
      out.push(pt);
    }
  }
  return out;
}

/** 内边距：线宽与圆点不被裁掉 */
const PAD = 6;

export function chartGeometry(
  series: readonly ChartSeries[],
  opts: { width: number; height: number; max?: number; gridLines?: number; xTickCount?: number },
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

  /* ---------------------------------------------------------------- 平滑路径 */
  const base = project([t0, lo])[1];
  const yMin = PAD;
  const yMax = Math.max(PAD, height - PAD);
  const cleaned = series.map((s) => cleanPoints(s.points));
  const lines = cleaned.map((rawPts) => {
    const pts = rawPts.map(project);
    if (!pts.length) return { line: '', area: '' };
    const line = smoothBezierPath(pts, yMin, yMax);
    const first = pts[0]!;
    const last = pts[pts.length - 1]!;
    return { line, area: `${line}L${last[0].toFixed(1)} ${base.toFixed(1)}L${first[0].toFixed(1)} ${base.toFixed(1)}Z` };
  });

  /* ---------------------------------------------------------------- 刻度与网格 */
  const n = opts.gridLines ?? 3;
  const grid = Array.from({ length: n }, (_, i) => PAD + ((i + 1) / (n + 1)) * (height - PAD * 2));
  const ySteps = n + 1;
  const yTicks: ChartYTick[] = Array.from({ length: ySteps + 1 }, (_, i) => {
    const frac = i / ySteps;
    const y = PAD + frac * (height - PAD * 2);
    const value = hi - frac * (hi - lo);
    return { y, pct: (y / height) * 100, value };
  });

  const xCount = Math.max(2, opts.xTickCount ?? 4);
  const xTicks: ChartXTick[] = Array.from({ length: xCount }, (_, i) => {
    const frac = i / (xCount - 1);
    return {
      x: frac * width,
      pct: frac * 100,
      t: t0 + frac * (t1 - t0),
      isEnd: i === xCount - 1,
    };
  });

  const nearest = (x: number, i = 0): number => {
    const pts = series[i]?.points;
    if (!pts?.length) return -1;
    const t = t0 + (Math.min(Math.max(x, 0), width) / width) * tSpan;
    let best = 0;
    for (let k = 1; k < pts.length; k++) if (Math.abs(pts[k]![0] - t) < Math.abs(pts[best]![0] - t)) best = k;
    return best;
  };

  return { lines, lo, hi, t0, t1, grid, yTicks, xTicks, nearest, project };
}
