<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  AppShell · 登录后的整体布局（SPEC §2）
  ───────────────────────────────────────────────────────────────
  ┌──────────┬───────────────────────────────┐
  │ Sidebar  │ Topbar（sticky，毛玻璃）       │
  │  248     │ ConnectionBar（断线时）        │
  │          │ main（max 1280，居中）         │
  └──────────┴───────────────────────────────┘
  ≤860：侧栏隐藏，底部 TabBar（5 项），内容区底部留白 150。
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { palette } from '$lib/palette.svelte';
  import { prefs } from '$lib/prefs.svelte';
  import ConnectionBar from './ConnectionBar.svelte';
  import Sidebar from './Sidebar.svelte';
  import TabBar from './TabBar.svelte';
  import Topbar from './Topbar.svelte';

  let { children }: { children: Snippet } = $props();

  /* 悬浮窗与命令面板均动态按需加载，避免拖慢首屏 */
  const dockMod = import('../features/dock/AiDock.svelte');
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
    <main id="main" class="main" tabindex="-1">
      {@render children()}
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
  }
  @media (max-width: 860px) {
    .app {
      grid-template-columns: minmax(0, 1fr);
    }
    .main {
      padding: var(--s-2) var(--s-4) 150px;
    }
  }
</style>
