<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  WidgetGrid · 插件声明式小组件栅格（SPEC §3.1 第 2 条）
  ──────────────────────────────────────────────────────────────────────────
  <WidgetGrid slots={collectWidgets(plugins)} />

  · size s/m/l → span 3/6/12；≤1180 → 6/12/12；≤560 单列
  · 各卡上报 level，聚合后写入 health.level（侧栏表情跟随）；
    onlevel 把聚合结果同时交给父组件（主页问候标题）
-->
<script lang="ts">
  import { SvelteMap } from 'svelte/reactivity';
  import type { Level } from '$api/additions';
  import { health } from '$lib/page.svelte';
  import { SPAN, worstLevel, type WidgetSlot } from './index';
  import WidgetCard from './WidgetCard.svelte';

  interface Props {
    slots: readonly WidgetSlot[];
    label?: string;
    onlevel?: (level: Level) => void;
  }
  let { slots, label = '概览', onlevel }: Props = $props();

  const levels = new SvelteMap<string, Level | undefined>();
  const overall = $derived(worstLevel(slots.map((s) => levels.get(s.key))));

  $effect(() => {
    health.level = overall;
    onlevel?.(overall);
  });
</script>

<section class="grid" aria-label={label}>
  {#each slots as s (s.key)}
    <div class="cell span-{SPAN[s.widget.size] ?? 6}">
      <WidgetCard slot={s} onlevel={(l) => levels.set(s.key, l)} />
    </div>
  {/each}
</section>

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(12, minmax(0, 1fr));
    gap: var(--gap);
  }
  .cell {
    display: flex;
    min-width: 0;
  }
  .cell > :global(*) {
    flex: 1;
  }
  .span-3 { grid-column: span 3; }
  .span-6 { grid-column: span 6; }
  .span-12 { grid-column: span 12; }

  @media (max-width: 1180px) {
    .span-3 { grid-column: span 6; }
    .span-6 { grid-column: span 12; }
  }
  @media (max-width: 560px) {
    .cell { grid-column: span 12; }
  }
</style>
