<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  主页 `/`（SPEC §3.1）
  ──────────────────────────────────────────────────────────────────────────
    问候区（level 聚合）
    小组件栅格（运行中插件的 ui.widgets）  · 无小组件 → 引导卡
    最近动态 span 7  │  我的应用 span 5
  安静：无横幅、无待办；需要人处理的事只走悬浮窗。
-->
<script lang="ts">
  import type { Level } from '$api/additions';
  import { listPlugins } from '$api/endpoints-core';
  import { health } from '$lib/page.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { collectWidgets } from '$lib/widgets/collect';
  import Mood from '$ui/Mood.svelte';
  import Skeleton from '$ui/Skeleton.svelte';
  import Greeting from './Greeting.svelte';

  let widgetGridMod: Promise<typeof import('$lib/widgets/WidgetGrid.svelte')> | null = null;
  const loadWidgetGrid = () => (widgetGridMod ??= import('$lib/widgets/WidgetGrid.svelte'));
  let bottomMod: Promise<typeof import('./HomeBottom.svelte')> | null = null;
  const loadBottom = () => (bottomMod ??= import('./HomeBottom.svelte'));

  let { params: _params }: { params: Record<string, string> } = $props();

  const canPlugins = session.can('host.plugins:read');
  const canOps = session.can('host.operations:read');
  const plugins = canPlugins
    ? useResource({
        key: 'plugins',
        load: () => listPlugins().then((p) => p.items),
        subjects: ['plugins/'],
      })
    : null;

  const slots = $derived(collectWidgets(plugins?.data));
  let level = $state<Level>('ok');

  /* 没有小组件时不声称监测了什么：问候固定"一切安好"，侧栏表情复位 */
  const shown = $derived<Level>(slots.length ? level : 'ok');
  $effect(() => {
    if (!slots.length) health.level = 'ok';
  });

  const pluginsFailed = $derived(plugins?.status === 'error');
</script>

{#snippet skGrid()}
  <div class="sk-grid" aria-hidden="true">
    {#each [0, 1, 2, 3] as i (i)}<div class="panel"><Skeleton lines={3} /></div>{/each}
  </div>
{/snippet}

<div class="home">
  <Greeting level={shown} />

  {#if plugins}
    {#if pluginsFailed}
      <div class="panel err">
        <p>没能加载应用概览，请稍后重试。</p>
        <button type="button" class="guide-btn" onclick={() => void plugins.refresh()}>重试</button>
      </div>
    {:else if !plugins.data}
      {@render skGrid()}
    {:else if slots.length}
      {#await loadWidgetGrid()}
        {@render skGrid()}
      {:then mod}
        <mod.default {slots} label="服务器概览" onlevel={(l) => (level = l)} />
      {/await}
    {:else}
      <div class="panel">
        <div class="guide">
          <Mood mood="ok" size="md" />
          <div>
            <h2>装上系统监控，这里就能看到服务器状态</h2>
            <p>CPU、内存、磁盘和网络都由应用提供，装好后会自动出现在主页。</p>
          </div>
          <a class="guide-btn" href="/apps">去应用中心</a>
        </div>
      </div>
    {/if}
  {/if}

  {#if canOps || plugins?.data}
    {#await loadBottom()}
      <div class="panel"><Skeleton lines={5} height={18} /></div>
    {:then mod}
      <mod.default {canOps} plugins={plugins?.data} />
    {/await}
  {/if}
</div>

<style>
  .home {
    display: flex;
    flex-direction: column;
    gap: var(--gap);
  }
  .panel {
    padding: var(--s-5);
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
  }
  .err {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-3);
    color: var(--text-2);
  }
  .sk-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: var(--gap);
  }
  .guide {
    display: flex;
    align-items: center;
    gap: var(--s-4);
  }
  .guide div {
    flex: 1;
    min-width: 0;
  }
  .guide h2 {
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .guide p {
    margin-top: 4px;
    color: var(--text-3);
    font-size: var(--fs-sm);
  }
  .guide-btn {
    display: inline-flex;
    align-items: center;
    height: 40px;
    padding: 0 18px;
    border-radius: var(--r-pill);
    background: var(--accent-strong);
    color: var(--on-accent);
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
    white-space: nowrap;
  }

  @media (max-width: 1180px) {
    .sk-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
  @media (max-width: 860px) {
    .guide {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
