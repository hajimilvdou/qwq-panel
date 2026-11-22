<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Card · 卡片
  ───────────────────────────────────────────────────────────────
  <Card title="最近动态" subtitle="过去 24 小时" icon="activity" color="teal">
    {#snippet actions()}<Button size="sm" variant="plain" href="/activity">全部</Button>{/snippet}
    ……内容……
  </Card>

  不给 title 时就是一个白底圆角容器。padding: none | sm | md（默认）
  as: 外层标签（section / article / div）；有 title 时 section 自动以标题命名
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Tile from './Tile.svelte';
  import type { IconName } from './icons';
  import type { CategoryColor } from './types';

  interface Props {
    title?: string;
    subtitle?: string;
    icon?: IconName;
    color?: CategoryColor | 'ai' | 'accent';
    padding?: 'none' | 'sm' | 'md';
    as?: 'section' | 'article' | 'div';
    actions?: Snippet;
    children?: Snippet;
    class?: string;
  }
  let {
    title,
    subtitle,
    icon,
    color = 'slate',
    padding = 'md',
    as = 'section',
    actions,
    children,
    class: cls = '',
  }: Props = $props();

  const headId = $props.id();
</script>

<svelte:element this={as} class="card pad-{padding} {cls}" aria-labelledby={title ? headId : undefined}>
  {#if title}
    <header class="head">
      {#if icon}<Tile {icon} {color} size="sm" />{/if}
      <div class="titles">
        <h2 id={headId}>{title}</h2>
        {#if subtitle}<p>{subtitle}</p>{/if}
      </div>
      {#if actions}<div class="actions">{@render actions()}</div>{/if}
    </header>
  {/if}
  {@render children?.()}
</svelte:element>

<style>
  .card {
    position: relative;
    min-width: 0;
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid color-mix(in oklab, var(--line) 70%, transparent);
    box-shadow: var(--shadow-1);
  }
  .pad-md {
    padding: var(--pad);
  }
  .pad-sm {
    padding: var(--s-3);
  }
  .head {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: var(--s-4);
  }
  .pad-none .head {
    padding: var(--pad) var(--pad) 0;
  }
  .titles {
    min-width: 0;
  }
  h2 {
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  p {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .actions {
    display: flex;
    gap: 6px;
    margin-left: auto;
  }
</style>
