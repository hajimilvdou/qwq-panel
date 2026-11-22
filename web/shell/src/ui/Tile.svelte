<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Tile · 图标底块（彩色只表示类别；极光只属于 AI）
  ───────────────────────────────────────────────────────────────
  <Tile icon="cpu" color="blue" />
  <Tile icon="ai" color="ai" size="sm" />
  color  分类色 11 种 | 'ai' | 'accent'；size sm 28 | md 34 | lg 44
-->
<script lang="ts">
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';
  import type { CategoryColor } from './types';

  interface Props {
    icon: IconName;
    color?: CategoryColor | 'ai' | 'accent';
    size?: 'sm' | 'md' | 'lg';
  }
  let { icon, color = 'slate', size = 'md' }: Props = $props();
  const px = $derived(size === 'sm' ? 16 : size === 'lg' ? 22 : 18);
</script>

<span class="tile t-{color} {size}" aria-hidden="true"><Icon name={icon} size={px} /></span>

<style>
  .tile {
    display: inline-grid;
    place-items: center;
    flex: none;
    width: 34px;
    height: 34px;
    border-radius: 11px;
    color: #fff;
  }
  .tile :global(svg) {
    stroke-width: 2;
  }
  .sm {
    width: 28px;
    height: 28px;
    border-radius: 9px;
  }
  .lg {
    width: 44px;
    height: 44px;
    border-radius: 14px;
  }
  .t-blue { background: linear-gradient(140deg, #6ea2ff, var(--c-blue)); }
  .t-indigo { background: linear-gradient(140deg, #8d98ff, var(--c-indigo)); }
  .t-violet { background: linear-gradient(140deg, #ae8cff, var(--c-violet)); }
  .t-teal { background: linear-gradient(140deg, #4fd6c8, var(--c-teal)); }
  .t-cyan { background: linear-gradient(140deg, #5ccdf0, var(--c-cyan)); }
  .t-green { background: linear-gradient(140deg, #5fdca7, var(--c-green)); }
  .t-amber { background: linear-gradient(140deg, #ffd36b, var(--c-amber)); }
  .t-orange { background: linear-gradient(140deg, #ffad6b, var(--c-orange)); }
  .t-red { background: linear-gradient(140deg, #ff8a88, var(--c-red)); }
  .t-pink { background: linear-gradient(140deg, #ff8cb6, var(--c-pink)); }
  .t-slate { background: linear-gradient(140deg, #a5aec0, var(--c-slate)); }
  .t-accent { background: linear-gradient(140deg, var(--accent-2), var(--accent)); }
  .t-ai { background: var(--ai-gradient); }
</style>
