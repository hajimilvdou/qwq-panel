<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  AppShell · 登录后的整体布局
  · 默认 layout='top'：全宽简洁顶部横向栏，无左侧栏
  · 可选 layout='side'：左侧可收放折叠栏，桌面端无顶栏，搜索置右上角
  · 全局 Ctrl+K / ⌘K 与插件保活驻留池统一由此管理
-->
<script lang="ts">
  import { onDestroy, untrack, type Snippet } from 'svelte';
  import { page } from '$lib/page.svelte';
  import { palette, paletteShortcut } from '$lib/palette.svelte';
  import { prefs } from '$lib/prefs.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { router } from '$lib/router.svelte';
  import { Icon } from '$ui';
  import { pluginFramePool } from '../features/plugins/plugin-frame-pool.svelte';
  import ConnectionBar from './ConnectionBar.svelte';
  import { pluginsResource } from './nav';
  import Sidebar from './Sidebar.svelte';
  import TabBar from './TabBar.svelte';
  import Topbar from './Topbar.svelte';

  let { children }: { children: Snippet } = $props();

  const plugins = useResource(pluginsResource);
  const wideMode = $derived(router.path.startsWith('/agent'));
  const isSide = $derived(prefs.layout === 'side');
  const shortcut = paletteShortcut();

  /* 全局 ⌘K / Ctrl+K（顶栏与左侧栏两种模式下始终生效） */
  $effect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        palette.opened ? palette.close() : palette.open();
      }
    };
    addEventListener('keydown', onKey);
    return () => removeEventListener('keydown', onKey);
  });

  /* 插件状态变化时同步淘汰已停用/已卸载/已升级的保活 iframe（untrack 避免读取 entries 形成回路） */
  $effect(() => {
    const data = plugins.data;
    if (data) untrack(() => pluginFramePool.syncWithPlugins(data));
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
<div class="app" class:top-nav={!isSide} class:side-collapsed={isSide && prefs.sideCollapsed} class:p-modal={pluginFramePool.modalOpen}>
  {#if isSide}
    <Sidebar />
  {/if}
  <div class="stage">
    {#if isSide}
      <!-- 左侧栏模式：桌面端不渲染顶栏，仅在 ≤860px 移动端兜底；桌面右上角提供独立搜索按钮 -->
      <Topbar mobileOnly={true} />
      <h1 id="page-title" class="sr-only" tabindex="-1">{page.title}</h1>
      <div class="side-util">
        <button
          type="button"
          class="side-search"
          onclick={() => palette.open()}
          aria-label="搜索页面和操作"
          aria-keyshortcuts="Control+K Meta+K"
        >
          <Icon name="search" size={15} />
          <span>搜索</span>
          <kbd>{shortcut}</kbd>
        </button>
      </div>
    {:else}
      <Topbar />
    {/if}
    <ConnectionBar />
    <main id="main" class="main" class:wide={wideMode} class:side-pad={isSide} tabindex="-1">
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
    grid-template-columns: 244px minmax(0, 1fr);
    min-height: 100dvh;
    transition: grid-template-columns var(--dur-2) var(--ease);
  }
  .app.side-collapsed {
    grid-template-columns: 78px minmax(0, 1fr);
  }
  .app.top-nav {
    grid-template-columns: minmax(0, 1fr);
  }
  .app.p-modal {
    z-index: var(--z-scrim);
  }
  .stage {
    position: relative;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .side-util {
    display: flex;
    justify-content: flex-end;
    width: 100%;
    max-width: var(--content-max);
    margin: 0 auto;
    padding: 12px var(--s-5) 0;
  }
  .side-search {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    height: 34px;
    padding: 0 9px 0 12px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface);
    color: var(--text-2);
    font-size: var(--fs-xs);
    box-shadow: var(--shadow-1);
    transition: border-color var(--dur-1) var(--ease), color var(--dur-1) var(--ease);
  }
  .side-search:hover {
    border-color: var(--line-strong);
    color: var(--text);
  }
  .side-search kbd {
    padding: 1px 6px;
    border-radius: 6px;
    background: var(--surface-2);
    border: 1px solid var(--line);
    color: var(--text-3);
    font: var(--fw-semibold) 10px / 16px var(--font-sans);
  }
  .main {
    width: 100%;
    max-width: var(--content-max);
    margin: 0 auto;
    padding: var(--s-4) var(--s-5) 88px;
    outline: none;
  }
  .main.side-pad {
    padding-top: var(--s-2);
  }
  .main.wide {
    max-width: none;
    padding: var(--s-2) var(--s-4) var(--s-3);
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
      padding-inline: var(--s-4);
    }
  }
  @media (max-width: 860px) {
    .app,
    .app.side-collapsed {
      grid-template-columns: minmax(0, 1fr);
    }
    .side-util {
      display: none;
    }
    .main,
    .main.wide {
      padding: var(--s-3) var(--s-4) 150px;
    }
  }
</style>
