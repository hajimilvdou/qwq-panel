<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Topbar · 页面标题 → 搜索入口（⌘K）→ 主题切换 → 头像菜单。无通知铃（提醒统一归悬浮窗） -->
<script lang="ts">
  import { page } from '$lib/page.svelte';
  import { palette, paletteShortcut } from '$lib/palette.svelte';
  import { prefs } from '$lib/prefs.svelte';
  import { router } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { Avatar, Icon, IconButton, Menu, Mood } from '$ui';
  import { APP_CENTER, isActive, PRIMARY, SETTINGS } from './nav';

  const shortcut = paletteShortcut();
  const name = $derived(session.user?.display_name || session.user?.username || '');
  const topNavItems = $derived([...PRIMARY, APP_CENTER, SETTINGS].filter((i) => session.can(i.perm)));

  /* 全局 ⌘K / Ctrl+K */
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
</script>

<header class="top" class:capsule={prefs.layout === 'top'}>
  {#if prefs.layout === 'top'}
    <a href="/" class="t-brand" aria-label="qwq X 主页">
      <Mood size="sm" />
      <b>qwq<em>X</em></b>
    </a>
    <nav class="t-nav" aria-label="主导航">
      {#each topNavItems as it (it.href)}
        <a href={it.href} class="t-pill" aria-current={isActive(it.href, router.path) ? 'page' : undefined}>
          <Icon name={it.icon} size={15} />
          <span>{it.label}</span>
        </a>
      {/each}
    </nav>
    <h1 id="page-title" class="sr-only" tabindex="-1">{page.title}</h1>
  {:else}
    <h1 id="page-title" tabindex="-1">{page.title}</h1>
    <button type="button" class="search" onclick={() => palette.open()} aria-keyshortcuts="Control+K Meta+K">
      <Icon name="search" size={18} />
      <span class="ph">搜索页面和操作…</span>
      <kbd>{shortcut}</kbd>
    </button>
  {/if}

  <div class="actions">
    <IconButton
      class={prefs.layout === 'top' ? '' : 'search-icon'}
      icon="search"
      label="搜索页面和操作"
      onclick={() => palette.open()}
    />
    <IconButton
      class="layout-btn"
      icon="menu"
      label={prefs.layout === 'top' ? '切换到悬浮侧栏' : '切换到悬浮顶栏'}
      onclick={() => prefs.toggleLayout()}
    />
    <IconButton
      icon={prefs.resolvedTheme === 'dark' ? 'moon' : 'sun'}
      label={prefs.resolvedTheme === 'dark' ? '切换到浅色' : '切换到深色'}
      onclick={() => prefs.toggleTheme()}
    />
    <Menu
      label="账户菜单"
      items={[
        { label: '账户', icon: 'user', href: '/settings/account' },
        { label: '外观', icon: 'sun', href: '/settings/appearance' },
        { label: '登出', icon: 'logout', tone: 'danger', onselect: () => void session.logout() },
      ]}
    >
      {#snippet trigger(props)}
        <button type="button" class="avatar-btn" {...props}><Avatar {name} size="md" /></button>
      {/snippet}
    </Menu>
  </div>
</header>

<style>
  .top {
    position: sticky;
    top: 0;
    z-index: var(--z-sticky);
    display: flex;
    align-items: center;
    gap: var(--s-4);
    height: var(--top-h);
    padding: 0 var(--s-5);
    background: color-mix(in oklab, var(--bg) 86%, transparent);
    backdrop-filter: blur(12px) saturate(1.2);
  }
  h1 {
    min-width: 120px;
    font-size: var(--fs-xl);
    font-weight: var(--fw-semibold);
    outline: none;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .search {
    display: flex;
    align-items: center;
    gap: 10px;
    flex: 0 1 420px;
    height: 40px;
    margin: 0 auto;
    padding: 0 8px 0 14px;
    border: 1px solid var(--line);
    border-radius: var(--r-pill);
    background: var(--surface);
    color: var(--text-3);
    box-shadow: var(--shadow-1);
    transition:
      border-color var(--dur-1) var(--ease),
      box-shadow var(--dur-1) var(--ease);
  }
  .search:hover {
    border-color: var(--line-strong);
    box-shadow: var(--shadow-2);
  }
  .ph {
    flex: 1;
    text-align: left;
  }
  kbd {
    padding: 2px 8px;
    border-radius: 7px;
    background: var(--surface-3);
    color: var(--text-2);
    font: var(--fw-semibold) var(--fs-2xs) / 18px var(--font-sans);
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-left: auto;
  }
  .search + .actions {
    margin-left: 0;
  }
  .actions :global(.search-icon) {
    display: none;
  }
  .avatar-btn {
    border-radius: 50%;
  }
  .top.capsule {
    top: 12px;
    width: min(var(--content-max), calc(100% - 28px));
    margin: 12px auto 6px;
    padding: 0 14px;
    border-radius: var(--r-pill);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
  }
  .t-brand {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-lg);
    font-weight: var(--fw-bold);
    flex: none;
  }
  .t-brand em {
    font-style: normal;
    color: var(--accent);
    margin-left: 1px;
  }
  .t-nav {
    display: flex;
    align-items: center;
    gap: 4px;
    overflow-x: auto;
    margin: 0 auto;
  }
  .t-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 36px;
    padding: 0 12px;
    border-radius: var(--r-pill);
    color: var(--text-2);
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    white-space: nowrap;
  }
  .t-pill:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .t-pill[aria-current='page'] {
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: var(--fw-semibold);
  }
  @media (max-width: 1180px) {
    .top {
      padding: 0 var(--s-5);
    }
  }
  @media (max-width: 860px) {
    .top {
      padding: 0 var(--s-4);
    }
    .t-nav,
    .actions :global(.layout-btn),
    .search {
      display: none;
    }
    .actions {
      margin-left: auto !important;
    }
    .actions :global(.search-icon) {
      display: inline-grid;
    }
  }
</style>
