<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  SeriesChart · 带坐标刻度、渐变填充与悬停读数的平滑贝塞尔曲线图（零外部依赖）
  ──────────────────────────────────────────────────────────────────────────
  <SeriesChart label="网络流量" unit="MB/s" series={[{ name: '下行', color: 'teal', points }]} />

  · Fritsch-Carlson 单调三次贝塞尔平滑曲线 + 顶部柔光渐变面积
  · 左侧完整纵轴数值刻度 + 底部多点时间刻度 + 水平虚线网格
  · 指针悬停显示垂直准线、圆点高亮与悬浮读数卡
-->
<script lang="ts">
  import { chartGeometry, type ChartSeries } from './chart';
  import type { CategoryColor } from './types';

  interface Props {
    series: readonly ChartSeries[];
    /** 读屏用的图表说明，如"CPU 与内存最近 15 分钟趋势" */
    label: string;
    unit?: string;
    max?: number;
    height?: number;
    timeUnit?: 's' | 'ms';
    /** 自定义数值格式化（如动态 B/s · KB/s · MB/s） */
    formatValue?: (v: number) => string;
    /** 横轴刻度时间文案 */
    formatTime?: (t: number, isEnd: boolean) => string;
  }
  let { series, label, unit = '', max, height = 190, timeUnit = 's', formatValue, formatTime }: Props = $props();

  const uid = $props.id();
  const W = 600;
  const FALLBACK: readonly CategoryColor[] = ['blue', 'violet', 'teal', 'orange', 'pink', 'green'];

  const geo = $derived(chartGeometry(series, { width: W, height, max, gridLines: 3, xTickCount: 4 }));
  const colorOf = (i: number) => series[i]?.color ?? FALLBACK[i % FALLBACK.length]!;
  const empty = $derived(series.every((s) => s.points.length < 2));

  /* ---------------------------------------------------------------- 文本格式化 */
  function fmtVal(v: number): string {
    if (formatValue) return formatValue(v);
    const num = Math.abs(v) >= 100 || Number.isInteger(v) ? String(Math.round(v)) : v.toFixed(1);
    return unit ? `${num}${unit === '%' ? '%' : ' ' + unit}` : num;
  }

  const latest = (s: ChartSeries) => s.points[s.points.length - 1]?.[1];
  const peak = (s: ChartSeries) => {
    if (!s.points.length) return undefined;
    let m = -Infinity;
    for (const p of s.points) if (p[1] > m) m = p[1];
    return Number.isFinite(m) ? m : undefined;
  };

  function axisText(t: number, isEnd: boolean): string {
    if (formatTime) return formatTime(t, isEnd);
    if (isEnd) return '现在';
    const ms = timeUnit === 'ms' ? t : t * 1000;
    if (ms > 1_000_000_000_000) {
      const d = new Date(ms);
      const hh = String(d.getHours()).padStart(2, '0');
      const mm = String(d.getMinutes()).padStart(2, '0');
      const ss = String(d.getSeconds()).padStart(2, '0');
      const spanSec = (geo.t1 - geo.t0) / (timeUnit === 'ms' ? 1000 : 1);
      return spanSec < 300 ? `${hh}:${mm}:${ss}` : `${hh}:${mm}`;
    }
    const sec = (geo.t1 - t) / (timeUnit === 'ms' ? 1000 : 1);
    if (sec < 90) return `${Math.round(sec)} 秒前`;
    if (sec < 5400) return `${Math.round(sec / 60)} 分钟前`;
    return `${Math.round(sec / 3600)} 小时前`;
  }

  /* ---------------------------------------------------------------- 悬停读数 */
  let hoverX = $state<number | null>(null);
  let svgEl: SVGSVGElement;

  function onmove(e: PointerEvent) {
    const r = svgEl.getBoundingClientRect();
    if (!r.width) return;
    hoverX = ((e.clientX - r.left) / r.width) * W;
  }

  const hover = $derived.by(() => {
    if (hoverX === null || empty) return null;
    const k = geo.nearest(hoverX);
    const p = series[0]?.points[k];
    if (!p) return null;
    const [x] = geo.project(p);
    const rows = series.map((s, i) => {
      const j = geo.nearest(x, i);
      const q = s.points[j];
      const py = q ? geo.project(q)[1] : 0;
      return {
        name: s.name,
        color: colorOf(i),
        value: q ? q[1] : undefined,
        yPct: (py / height) * 100,
      };
    });
    return { x, pct: (x / W) * 100, rows, at: axisText(p[0], k === series[0]!.points.length - 1) };
  });
</script>

<div class="chart-wrap">
  <ul class="legend">
    {#each series as s, i (s.name)}
      {@const v = latest(s)}
      {@const pk = peak(s)}
      <li>
        <i class="sw c-{colorOf(i)}"></i>
        <span class="lg-name">{s.name}</span>
        {#if v !== undefined}<b class="num">{fmtVal(v)}</b>{/if}
        {#if pk !== undefined && s.points.length > 2}
          <small class="lg-peak num">峰值 {fmtVal(pk)}</small>
        {/if}
      </li>
    {/each}
  </ul>

  <div class="frame">
    <div class="yaxis" style:height="{height}px" aria-hidden="true">
      {#each geo.yTicks as tk, idx (idx)}
        <span class="ytick num" style:top="{tk.pct}%">{fmtVal(tk.value)}</span>
      {/each}
    </div>

    <div class="main-col">
      <div class="plot">
        <svg
          bind:this={svgEl}
          viewBox="0 0 {W} {height}"
          preserveAspectRatio="none"
          role="img"
          aria-label={label}
          style:height="{height}px"
          onpointermove={onmove}
          onpointerleave={() => (hoverX = null)}
        >
          <defs>
            {#each series as _, i (i)}
              <linearGradient id="{uid}-g-{i}" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="var(--tone)" stop-opacity="0.24" />
                <stop offset="100%" stop-color="var(--tone)" stop-opacity="0.01" />
              </linearGradient>
            {/each}
          </defs>

          {#each geo.yTicks as tk, idx (idx)}
            <path class="grid-line" class:base={idx === geo.yTicks.length - 1} d="M0 {tk.y.toFixed(1)}H{W}" />
          {/each}

          {#each geo.lines as l, i (i)}
            <g class="c-{colorOf(i)}">
              <path class="area" d={l.area} fill="url(#{uid}-g-{i})" />
              <path class="line" d={l.line} />
            </g>
          {/each}

          {#if hover}
            <path class="cursor" d="M{hover.x.toFixed(1)} 0V{height}" />
          {/if}
        </svg>

        {#if hover}
          {#each hover.rows as r (r.name)}
            {#if r.value !== undefined}
              <span
                class="hdot c-{r.color}"
                style:left="{hover.pct}%"
                style:top="{r.yPct}%"
                aria-hidden="true"
              ></span>
            {/if}
          {/each}

          <div class="tip" class:flip={hover.pct > 62} style:left="{hover.pct}%" aria-hidden="true">
            <span class="tip-at num">{hover.at}</span>
            {#each hover.rows as r (r.name)}
              <span><i class="sw c-{r.color}"></i>{r.name}<b class="num">{r.value === undefined ? '—' : fmtVal(r.value)}</b></span>
            {/each}
          </div>
        {/if}

        {#if empty}<p class="nodata">正在采集中，几秒后呈现平滑趋势…</p>{/if}
      </div>

      {#if !empty}
        <div class="axis" aria-hidden="true">
          {#each geo.xTicks as xt, idx (idx)}
            <span class="num">{axisText(xt.t, xt.isEnd)}</span>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .chart-wrap {
    min-width: 0;
  }

  /* ---------------------------------------------------------------- 图例 */
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 18px;
    margin-bottom: var(--s-3);
    color: var(--text-2);
    font-size: var(--fs-xs);
  }
  .legend li {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .legend b {
    color: var(--text);
    font-weight: var(--fw-semibold);
  }
  .lg-peak {
    color: var(--text-3);
    font-size: var(--fs-2xs);
  }
  .sw {
    width: 9px;
    height: 9px;
    border-radius: 99px;
    background: var(--tone);
    flex: none;
  }

  /* ---------------------------------------------------------------- 坐标框架 */
  .frame {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 10px;
    align-items: start;
  }
  .yaxis {
    position: relative;
    min-width: 48px;
    text-align: right;
  }
  .ytick {
    position: absolute;
    right: 0;
    transform: translateY(-50%);
    color: var(--text-3);
    font-size: var(--fs-2xs);
    line-height: 1;
    white-space: nowrap;
  }
  .main-col {
    min-width: 0;
  }

  /* ---------------------------------------------------------------- 绘图区 */
  .plot {
    position: relative;
  }
  svg {
    display: block;
    width: 100%;
    overflow: visible;
    touch-action: pan-y;
  }
  .grid-line {
    stroke: var(--line);
    stroke-dasharray: 3 4;
    vector-effect: non-scaling-stroke;
  }
  .grid-line.base {
    stroke-dasharray: none;
  }
  .line {
    fill: none;
    stroke: var(--tone);
    stroke-width: 2.2;
    stroke-linejoin: round;
    stroke-linecap: round;
    vector-effect: non-scaling-stroke;
  }
  .cursor {
    stroke: var(--line-strong);
    stroke-dasharray: 3 3;
    vector-effect: non-scaling-stroke;
  }
  .hdot {
    position: absolute;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--tone);
    border: 2px solid var(--surface);
    box-shadow: 0 1px 4px rgb(0 0 0 / 0.2);
    transform: translate(-50%, -50%);
    pointer-events: none;
  }
  .nodata {
    position: absolute;
    inset: 0;
    display: grid;
    place-items: center;
    color: var(--text-3);
    font-size: var(--fs-xs);
  }

  /* ---------------------------------------------------------------- 读数浮层 */
  .tip {
    position: absolute;
    top: 8px;
    z-index: 4;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 138px;
    padding: 8px 11px;
    margin-left: 12px;
    border-radius: var(--r-sm);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-2);
    font-size: var(--fs-xs);
    pointer-events: none;
  }
  .tip.flip {
    transform: translateX(calc(-100% - 24px));
  }
  .tip span {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text-2);
    white-space: nowrap;
  }
  .tip b {
    margin-left: auto;
    padding-left: 12px;
    color: var(--text);
  }
  .tip-at {
    color: var(--text-3);
    font-size: var(--fs-2xs);
    padding-bottom: 2px;
    border-bottom: 1px solid var(--line);
  }

  .axis {
    display: flex;
    justify-content: space-between;
    margin-top: 8px;
    color: var(--text-3);
    font-size: var(--fs-2xs);
  }

  /* ---------------------------------------------------------------- 分类色 */
  .c-blue { --tone: var(--c-blue); }
  .c-indigo { --tone: var(--c-indigo); }
  .c-violet { --tone: var(--c-violet); }
  .c-teal { --tone: var(--c-teal); }
  .c-cyan { --tone: var(--c-cyan); }
  .c-green { --tone: var(--c-green); }
  .c-amber { --tone: var(--c-amber); }
  .c-orange { --tone: var(--c-orange); }
  .c-red { --tone: var(--c-red); }
  .c-pink { --tone: var(--c-pink); }
  .c-slate { --tone: var(--c-slate); }
</style>
