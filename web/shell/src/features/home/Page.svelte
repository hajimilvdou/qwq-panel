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
  import Skeleton from '$ui/Skeleton.svelte';
  import Greeting from './Greeting.svelte';
  import HostMetricsDashboard from './HostMetricsDashboard.svelte';

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
  let hostLevel = $state<Level>('ok');
  let widgetLevel = $state<Level>('ok');

  const ORDER: Record<Level, number> = { ok: 0, warn: 1, bad: 2 };
  const shown = $derived<Level>(
    slots.length && ORDER[widgetLevel] > ORDER[hostLevel] ? widgetLevel : hostLevel,
  );
  $effect(() => {
    health.level = shown;
  });

  const pluginsFailed = $derived(plugins?.status === 'error');
</script>

<div class="home">
  <Greeting level={shown} />

  <!-- 主页 C 位：底层框架内置实时资源监控（CPU / 内存 / 磁盘 / 网络），开箱即用无需额外部署 -->
  <HostMetricsDashboard onlevel={(l) => (hostLevel = l)} />

  {#if plugins}
    {#if pluginsFailed}
      <div class="panel err">
        <p>没能加载应用概览，请稍后重试。</p>
        <button type="button" class="guide-btn" onclick={() => void plugins.refresh()}>重试</button>
      </div>
    {:else if slots.length}
      {#await loadWidgetGrid() then mod}
        <mod.default {slots} label="应用扩展概览" onlevel={(l) => (widgetLevel = l)} />
      {/await}
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
</style>
