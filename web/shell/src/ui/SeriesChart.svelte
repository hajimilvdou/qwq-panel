<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  SeriesChart · 轻量 SVG 折线（无依赖）
  ──────────────────────────────────────────────────────────────────────────
  <SeriesChart label="网络流量" unit="MB/s" series={[{ name: '下行', color: 'teal', points }]} />

  · points 为 [时间, 数值] 升序；时间单位由 timeUnit 指定（默认秒，与小组件结果一致）
  · 图例显示每条系列的最新值；指针悬停显示读数（键盘用户读图例即可，图本身 role=img）
  · 颜色只用分类色；未指定时按 FALLBACK 轮换
-->
<script lang="ts">
  import { chartGeometry, type ChartSeries } from './chart';
  import type { CategoryColor } from './types';

  interface Props {
    series: readonly ChartSeries[];
    /** 读屏用的图表说明，如"CPU 与内存最近一小时" */
    label: string;
    unit?: string;
    max?: number;
    height?: number;
    timeUnit?: 's' | 'ms';
    /** 横轴两端文字；缺省为"N 分钟前 / 现在" */
    formatTime?: (t: number, isEnd: boolean) => string;
  }
  let { series, label, unit = '', max, height = 180, timeUnit = 's', formatTime }: Props = $props();

  const W = 600;
  const FALLBACK: readonly CategoryColor[] = ['blue', 'violet', 'teal', 'orange', 'pink', 'green'];

  const geo = $derived(chartGeometry(series, { width: W, height, max }));
  const colorOf = (i: number) => series[i]?.color ?? FALLBACK[i % FALLBACK.length]!;
  const empty = $derived(series.every((s) => s.points.length < 2));

  /* ---------------------------------------------------------------- 文字 */
  const fmt = (v: number) => (Math.abs(v) >= 100 || Number.isInteger(v) ? String(Math.round(v)) : v.toFixed(1));
  const latest = (s: ChartSeries) => s.points[s.points.length - 1]?.[1];

  function axisText(t: number, isEnd: boolean): string {
    if (formatTime) return formatTime(t, isEnd);
    if (isEnd) return '现在';
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
      return { name: s.name, color: colorOf(i), value: q ? q[1] : undefined, y: q ? geo.project(q)[1] : 0 };
    });
    return { x, pct: (x / W) * 100, rows, at: axisText(p[0], k === series[0]!.points.length - 1) };
  });
</script>

<div class="chart-wrap">
  <ul class="legend">
    {#each series as s, i (s.name)}
      {@const v = latest(s)}
      <li>
        <i class="sw c-{colorOf(i)}"></i>{s.name}
        {#if v !== undefined}<b class="num">{fmt(v)}{unit ? ' ' + unit : ''}</b>{/if}
      </li>
    {/each}
  </ul>

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
      {#each geo.grid as y (y)}
        <path class="grid-line" d="M0 {y}H{W}" />
      {/each}
      {#each geo.lines as l, i (i)}
        <g class="c-{colorOf(i)}">
          <path class="area" d={l.area} />
          <path class="line" d={l.line} />
        </g>
      {/each}
      {#if hover}
        <path class="cursor" d="M{hover.x} 0V{height}" />
      {/if}
    </svg>

    {#if hover}
      <div class="tip" class:flip={hover.pct > 65} style:left="{hover.pct}%" aria-hidden="true">
        <span class="tip-at">{hover.at}</span>
        {#each hover.rows as r (r.name)}
          <span><i class="sw c-{r.color}"></i>{r.name}<b class="num">{r.value === undefined ? '—' : fmt(r.value)}</b></span>
        {/each}
      </div>
    {/if}
    <span class="ymax num" aria-hidden="true">{fmt(geo.hi)}{unit ? ' ' + unit : ''}</span>
    {#if empty}<p class="nodata">暂时还没有数据</p>{/if}
  </div>

  {#if !empty}
    <div class="axis" aria-hidden="true"><span>{axisText(geo.t0, false)}</span><span>{axisText(geo.t1, true)}</span></div>
  {/if}
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
    margin-bottom: var(--s-2);
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .legend li {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .legend b {
    color: var(--text);
    font-weight: var(--fw-semibold);
  }
  .sw {
    width: 10px;
    height: 10px;
    border-radius: 4px;
    background: var(--tone);
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
    stroke-dasharray: 3 5;
    vector-effect: non-scaling-stroke;
  }
  .line {
    fill: none;
    stroke: var(--tone);
    stroke-width: 2.4;
    stroke-linejoin: round;
    stroke-linecap: round;
    vector-effect: non-scaling-stroke;
  }
  .area {
    fill: var(--tone);
    opacity: 0.12;
  }
  :global([data-theme='dark']) .area {
    opacity: 0.18;
  }
  .cursor {
    stroke: var(--line-strong);
    vector-effect: non-scaling-stroke;
  }
  .ymax {
    position: absolute;
    top: -2px;
    right: 0;
    color: var(--text-3);
    font-size: var(--fs-2xs);
    pointer-events: none;
  }
  .nodata {
    position: absolute;
    inset: 0;
    display: grid;
    place-items: center;
    color: var(--text-3);
    font-size: var(--fs-sm);
  }

  /* ---------------------------------------------------------------- 读数浮层 */
  .tip {
    position: absolute;
    top: 8px;
    z-index: 1;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 120px;
    padding: 8px 10px;
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
  }
  .tip b {
    margin-left: auto;
    padding-left: 12px;
    color: var(--text);
  }
  .tip-at {
    color: var(--text-3);
  }

  .axis {
    display: flex;
    justify-content: space-between;
    margin-top: var(--s-2);
    color: var(--text-3);
    font-size: var(--fs-xs);
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
