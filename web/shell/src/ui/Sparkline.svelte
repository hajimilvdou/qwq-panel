<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Sparkline · 迷你折线（装饰性趋势；数值本身须在旁边以文字给出）
  <Sparkline points={[3, 5, 4, 8, 6]} tone="accent" />
-->
<script lang="ts">
  import type { CategoryColor } from './types';

  interface Props {
    points: readonly number[];
    width?: number;
    height?: number;
    tone?: 'accent' | 'ok' | 'warn' | 'bad' | CategoryColor;
    /** 纵轴上限；缺省取数据最大值 */
    max?: number;
  }
  let { points, width = 112, height = 44, tone = 'accent', max }: Props = $props();

  const d = $derived.by(() => {
    if (points.length < 2) return '';
    const hi = max ?? Math.max(...points);
    const lo = max !== undefined ? 0 : Math.min(...points);
    const span = hi - lo || 1;
    const step = width / (points.length - 1);
    return points
      .map((v, i) => `${i ? 'L' : 'M'}${(i * step).toFixed(1)} ${(height - 2 - ((v - lo) / span) * (height - 4)).toFixed(1)}`)
      .join('');
  });
</script>

<svg class="spark t-{tone}" {width} {height} viewBox="0 0 {width} {height}" aria-hidden="true">
  <path {d} />
</svg>

<style>
  .spark {
    flex: none;
    overflow: visible;
  }
  path {
    fill: none;
    stroke: var(--accent);
    stroke-width: 2.2;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .t-ok path { stroke: var(--ok); }
  .t-warn path { stroke: var(--warn); }
  .t-bad path { stroke: var(--bad); }
  .t-blue path { stroke: var(--c-blue); }
  .t-indigo path { stroke: var(--c-indigo); }
  .t-violet path { stroke: var(--c-violet); }
  .t-teal path { stroke: var(--c-teal); }
  .t-cyan path { stroke: var(--c-cyan); }
  .t-green path { stroke: var(--c-green); }
  .t-amber path { stroke: var(--c-amber); }
  .t-orange path { stroke: var(--c-orange); }
  .t-red path { stroke: var(--c-red); }
  .t-pink path { stroke: var(--c-pink); }
  .t-slate path { stroke: var(--c-slate); }
</style>
