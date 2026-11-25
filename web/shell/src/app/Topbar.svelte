<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Topbar · 默认顶部横向导航栏（仿妙妙屋清晰结构；切为左侧栏模式时桌面端完全隐藏） -->
<script lang="ts">
  import { page } from '$lib/page.svelte';
  import { palette, paletteShortcut } from '$lib/palette.svelte';
  import { prefs } from '$lib/prefs.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { router } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { Avatar, Icon, IconButton, Menu, Mood } from '$ui';
  import { APP_CENTER, isActive, pluginNav, pluginsResource, PRIMARY, SETTINGS } from './nav';

  interface Props {
    /** 左侧栏模式下仅在 ≤860px 移动端作为顶栏使用，桌面端完全隐藏 */
    mobileOnly?: boolean;
  }
  let { mobileOnly = false }: Props = $props();

  const shortcut = paletteShortcut();
  const name = $derived(session.user?.display_name || session.user?.username || '');
  const roleLabel = $derived(
    session.user?.role === 'admin' ? 'ADMIN' : session.user?.role === 'operator' ? 'OP' : 'VIEW',
  );
  const plugins = useResource(pluginsResource);
  const topNavItems = $derived(
    [...PRIMARY, ...pluginNav(plugins.data ?? []), APP_CENTER, SETTINGS].filter((i) => session.can(i.perm)),
  );
</script>

<header class="top" class:mobile-only={mobileOnly}>
  <div class="top-in">
    <a href="/" class="t-brand" aria-label="qwq X 主页">
      <Mood size="sm" />
      <b>qwq<em>X</em></b>
    </a>

    {#if !mobileOnly}
      <nav class="t-nav" aria-label="主导航">
        {#each topNavItems as it (it.href)}
          <a href={it.href} class="t-pill" aria-current={isActive(it.href, router.path, topNavItems) ? 'page' : undefined}>
            <Icon name={it.icon} size={15} />
            <span>{it.label}</span>
          </a>
        {/each}
      </nav>
    {/if}

    <h1 id={mobileOnly ? undefined : 'page-title'} class="sr-only" tabindex="-1">{page.title}</h1>

    <div class="actions">
      <button
        type="button"
        class="search-pill"
        onclick={() => palette.open()}
        aria-label="搜索页面和操作"
        aria-keyshortcuts="Control+K Meta+K"
      >
        <Icon name="search" size={15} />
        <span class="sp-txt">搜索</span>
        <kbd>{shortcut}</kbd>
      </button>
      {#if !mobileOnly}
        <IconButton
          class="layout-btn"
          icon="sidebar"
          label="切换为左侧折叠导航栏"
          onclick={() => prefs.toggleLayout()}
        />
      {/if}
      <IconButton
        icon={prefs.resolvedTheme === 'dark' ? 'moon' : 'sun'}
        label={prefs.resolvedTheme === 'dark' ? '切换到浅色' : '切换到深色'}
        onclick={() => prefs.toggleTheme()}
      />
      <Menu
        label="账户菜单"
        items={[
          { label: '账户资料', icon: 'user', href: '/settings/account' },
          { label: '外观与布局', icon: 'sun', href: '/settings/appearance' },
          ...(!mobileOnly ? [{ label: '切换为左侧导航栏', icon: 'sidebar' as const, onselect: () => prefs.toggleLayout() }] : []),
          { label: '退出登录', icon: 'logout', tone: 'danger', onselect: () => void session.logout() },
        ]}
      >
        {#snippet trigger(props)}
          <button
            type="button"
            class="user-pill"
            aria-haspopup={props['aria-haspopup']}
            aria-expanded={props['aria-expanded']}
            aria-controls={props['aria-controls']}
            aria-label={props['aria-label']}
            onclick={props.onclick}
            onkeydown={props.onkeydown}
          >
            <Avatar {name} size="sm" />
            <span class="u-meta">
              <b class="ellipsis">{name || '管理员'}</b>
              <small>{roleLabel}</small>
            </span>
          </button>
        {/snippet}
      </Menu>
    </div>
  </div>
</header>

<style>
  .top {
    position: sticky;
    top: 0;
    z-index: var(--z-sticky);
    background: color-mix(in oklab, var(--surface) 92%, transparent);
    border-bottom: 1px solid var(--line);
    backdrop-filter: blur(14px) saturate(1.25);
  }
  .top.mobile-only {
    display: none;
  }
  .top-in {
    display: flex;
    align-items: center;
    gap: var(--s-3);
    width: 100%;
    max-width: var(--content-max);
    height: 54px;
    margin: 0 auto;
    padding: 0 var(--s-5);
  }
  .t-brand {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-lg);
    font-weight: var(--fw-bold);
    letter-spacing: -0.02em;
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
    gap: 3px;
    flex: 1;
    min-width: 0;
    overflow-x: auto;
    scrollbar-width: none;
    padding: 2px 4px;
  }
  .t-nav::-webkit-scrollbar {
    display: none;
  }
  .t-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 34px;
    padding: 0 12px;
    border-radius: var(--r-pill);
    color: var(--text-2);
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    white-space: nowrap;
    flex: none;
    transition: background var(--dur-1) var(--ease), color var(--dur-1) var(--ease);
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
  .actions {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-left: auto;
    flex: none;
  }
  .search-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 34px;
    padding: 0 8px 0 11px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface-2);
    color: var(--text-2);
    font-size: var(--fs-xs);
    transition: border-color var(--dur-1) var(--ease), color var(--dur-1) var(--ease);
  }
  .search-pill:hover {
    border-color: var(--line-strong);
    color: var(--text);
  }
  .search-pill kbd {
    padding: 1px 6px;
    border-radius: 6px;
    background: var(--surface);
    border: 1px solid var(--line);
    color: var(--text-3);
    font: var(--fw-semibold) 10px / 16px var(--font-sans);
  }
  .user-pill {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    height: 34px;
    padding: 2px 10px 2px 3px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface-2);
    transition: border-color var(--dur-1) var(--ease), background var(--dur-1) var(--ease);
  }
  .user-pill:hover {
    border-color: var(--line-strong);
    background: var(--surface-3);
  }
  .u-meta {
    display: flex;
    flex-direction: column;
    text-align: left;
    line-height: 1.1;
    max-width: 88px;
  }
  .u-meta b {
    font-size: var(--fs-xs);
    font-weight: var(--fw-semibold);
  }
  .u-meta small {
    font-size: 10px;
    color: var(--text-3);
    letter-spacing: 0.03em;
  }
  @media (max-width: 1080px) {
    .sp-txt,
    .search-pill kbd,
    .u-meta {
      display: none;
    }
    .search-pill {
      padding: 0 9px;
    }
    .user-pill {
      padding: 2px;
    }
  }
  @media (max-width: 860px) {
    .top.mobile-only {
      display: block;
    }
    .top-in {
      padding: 0 var(--s-4);
    }
    .t-nav,
    .actions :global(.layout-btn) {
      display: none;
    }
  }
</style>
