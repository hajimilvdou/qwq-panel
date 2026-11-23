<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- HomeBottom · 主页下方两栏（最近动态 + 我的应用） -->
<script lang="ts">
  import type { Plugin } from '$api/types';
  import AppsCard from './AppsCard.svelte';
  import RecentCard from './RecentCard.svelte';

  interface Props {
    canOps: boolean;
    plugins?: readonly Plugin[];
  }
  let { canOps, plugins }: Props = $props();
</script>

<div class="bottom">
  {#if canOps}
    <div class="recent"><RecentCard {plugins} /></div>
  {/if}
  {#if plugins}
    <div class="apps" class:full={!canOps}><AppsCard {plugins} /></div>
  {/if}
</div>

<style>
  .bottom {
    display: grid;
    grid-template-columns: repeat(12, minmax(0, 1fr));
    gap: var(--gap);
    align-items: start;
  }
  .recent {
    grid-column: span 7;
  }
  .apps {
    grid-column: span 5;
  }
  .apps.full {
    grid-column: span 12;
  }
  @media (max-width: 1180px) {
    .recent,
    .apps {
      grid-column: span 12;
    }
  }
</style>
