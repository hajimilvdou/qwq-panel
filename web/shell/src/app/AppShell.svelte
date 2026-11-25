<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  AppShell · 登录后的整体布局（含宽屏模式 + 插件保活驻留池）
-->
<script lang="ts">
  import { onDestroy, type Snippet } from 'svelte';
  import { palette } from '$lib/palette.svelte';
  import { prefs } from '$lib/prefs.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { router } from '$lib/router.svelte';
  import { pluginFramePool } from '../features/plugins/plugin-frame-pool.svelte';
  import ConnectionBar from './ConnectionBar.svelte';
  import { pluginsResource } from './nav';
  import Sidebar from './Sidebar.svelte';
  import TabBar from './TabBar.svelte';
  import Topbar from './Topbar.svelte';

  let { children }: { children: Snippet } = $props();

  const plugins = useResource(pluginsResource);
  const wideMode = $derived(router.path.startsWith('/agent'));

  /* 插件状态变化时同步淘汰已停用/已卸载/已升级的保活 iframe */
  $effect(() => {
    if (plugins.data) pluginFramePool.syncWithPlugins(plugins.data);
  });

  onDestroy(() => pluginFramePool.clear());

  /* 悬浮窗、命令面板与 PluginFrame 均按需动态加载，保持首屏最小化 */
  const dockMod = import('../features/dock/AiDock.svelte');
  let frameMod: Promise<typeof import('../features/plugins/PluginFrame.svelte')> | null = null;
  const loadPluginFrame = () => (frameMod ??= import('../features/plugins/PluginFrame.svelte'));

  let paletteMounted = $state(false);
  let paletteMod: Promise<typeof import('../features/palette/CommandPalette.svelte')> | null = null;
  const loadPalette = () => (paletteMod ??= import('../features/palette/CommandPalette.svelte'));

  $effect(() => {
    if (palette.opened) paletteMounted = true;
  });
</script>

<a class="skip" href="#main">跳到主要内容</a>
<div class="app" class:top-nav={prefs.layout === 'top'}>
  {#if prefs.layout !== 'top'}
    <Sidebar />
  {/if}
  <div class="stage">
    <Topbar />
    <ConnectionBar />
    <main id="main" class="main" class:wide={wideMode} tabindex="-1">
      {@render children()}

      {#if pluginFramePool.entries.length > 0}
        {#await loadPluginFrame() then mod}
          {#each pluginFramePool.entries as entry (entry.key)}
            {@const isActive = pluginFramePool.activeKey === entry.key}
            <div class="pool-slot" class:inactive={!isActive} aria-hidden={!isActive}>
              <mod.default
                plugin={entry.plugin}
                path={entry.path}
                active={isActive}
                reloadTick={entry.reloadTick}
              />
            </div>
          {/each}
        {/await}
      {/if}
    </main>
  </div>
</div>
<TabBar />

{#await dockMod then mod}
  <mod.default />
{/await}
{#if paletteMounted}
  {#await loadPalette() then mod}
    <mod.default />
  {/await}
{/if}

<style>
  .app {
    position: relative;
    z-index: var(--z-content);
    display: grid;
    grid-template-columns: var(--side-w) minmax(0, 1fr);
    min-height: 100dvh;
  }
  .app.top-nav {
    grid-template-columns: minmax(0, 1fr);
  }
  .stage {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .main {
    width: 100%;
    max-width: var(--content-max);
    margin: 0 auto;
    padding: var(--s-2) var(--s-5) 88px;
    outline: none;
  }
  .main.wide {
    max-width: none;
    padding: var(--s-1) var(--s-4) var(--s-3);
  }
  .pool-slot.inactive {
    display: none;
  }
  .skip {
    position: fixed;
    top: 8px;
    left: 8px;
    z-index: var(--z-toast);
    padding: 8px 14px;
    border-radius: 10px;
    background: var(--surface);
    box-shadow: var(--shadow-2);
    transform: translateY(-200%);
  }
  .skip:focus {
    transform: none;
  }
  @media (max-width: 1180px) {
    .main {
      padding-inline: var(--s-5);
    }
    .main.wide {
      padding-inline: var(--s-3);
    }
  }
  @media (max-width: 860px) {
    .app {
      grid-template-columns: minmax(0, 1fr);
    }
    .main,
    .main.wide {
      padding: var(--s-2) var(--s-4) 150px;
    }
  }
</style>
