<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Timeline · 按组（通常按天）排列的纵向时间线
  ──────────────────────────────────────────────────────────────────────────
  <Timeline label="操作动态" groups={[{ key: '2026-11-09', label: '今天', items }]} itemKey={(o) => o.id}>
    {#snippet item(o)}…一行内容…{/snippet}
  </Timeline>

  · 组标题吸顶（sticky，位于顶栏之下）；每组是一个 <ol>，行之间画细竖线
  · 只管排版，不关心数据：分组见 $lib/activity 的 groupByDay
-->
<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';
  import type { TimelineGroup } from './types';

  interface Props {
    groups: readonly TimelineGroup<T>[];
    itemKey: (x: T) => string;
    label: string;
    item: Snippet<[T]>;
  }
  let { groups, itemKey, label, item }: Props = $props();

  const uid = $props.id();
</script>

<div class="timeline" role="feed" aria-label={label}>
  {#each groups as g (g.key)}
    <section aria-labelledby="{uid}-{g.key}">
      <h3 id="{uid}-{g.key}" class="day">{g.label}</h3>
      <ol>
        {#each g.items as x (itemKey(x))}
          <li>{@render item(x)}</li>
        {/each}
      </ol>
    </section>
  {/each}
</div>

<style>
  .timeline {
    display: flex;
    flex-direction: column;
    gap: var(--s-5);
  }
  .day {
    position: sticky;
    top: var(--top-h);
    z-index: var(--z-content);
    padding: var(--s-2) 0;
    background: color-mix(in oklab, var(--bg) 88%, transparent);
    backdrop-filter: blur(8px);
    color: var(--text-3);
    font-size: var(--fs-xs);
    font-weight: var(--fw-semibold);
    letter-spacing: 0.02em;
  }
  ol {
    position: relative;
    display: flex;
    flex-direction: column;
  }
  /* 贯穿各行头像中心的细线 */
  ol::before {
    content: '';
    position: absolute;
    top: 18px;
    bottom: 18px;
    left: 17px;
    width: 1px;
    background: var(--line);
  }
  li {
    position: relative;
  }
</style>
