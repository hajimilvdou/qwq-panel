<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Sidebar · 左侧可收放折叠导航栏（启用时桌面端无顶栏，含收起/展开、切回顶栏、主题与账户菜单） -->
<script lang="ts">
  import { nodes as nodesApi } from '$api/endpoints';
  import { events } from '$lib/events.svelte';
  import { health } from '$lib/page.svelte';
  import { prefs } from '$lib/prefs.svelte';
  import { router } from '$lib/router.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { Avatar, Icon, IconButton, Menu, Mood, Tile } from '$ui';
  import { APP_CENTER, isActive, pluginNav, pluginsResource, PRIMARY, SETTINGS, type NavItem } from './nav';

  const plugins = useResource(pluginsResource);
  const nodes = useResource({
    key: 'nodes',
    load: () => nodesApi.list().then((p) => p.items),
    subjects: ['nodes/'],
  });

  const collapsed = $derived(prefs.sideCollapsed);
  const appItems = $derived([...pluginNav(plugins.data ?? []), APP_CENTER].filter((i) => session.can(i.perm)));
  const primary = $derived(PRIMARY.filter((i) => session.can(i.perm)));
  const allNavItems = $derived([...primary, ...appItems, SETTINGS]);
  const node = $derived(nodes.data?.[0]);
  const lost = $derived(events.offline);
  const online = $derived(!node || node.status === 'online');
  const mood = $derived(lost ? 'warn' : online ? health.level : 'bad');
  const userName = $derived(session.user?.display_name || session.user?.username || '管理员');
</script>

{#snippet item(it: NavItem)}
  <a
    href={it.href}
    class="item"
    title={collapsed ? it.label : undefined}
    aria-current={isActive(it.href, router.path, allNavItems) ? 'page' : undefined}
  >
    <Tile icon={it.icon} color={it.color} size="sm" />
    {#if !collapsed}<span class="ellipsis">{it.label}</span>{/if}
  </a>
{/snippet}

<aside class="side" class:collapsed>
  <div class="brand-bar">
    <a href="/" class="brand" aria-label="qwq X 主页" title="qwq X 主页">
      <Mood size="sm" />
      {#if !collapsed}
        <span class="brand-text"><b>qwq<em class="x">X</em></b><small>轻面板 · 多 Agent</small></span>
      {/if}
    </a>
    <button
      type="button"
      class="collapse-btn"
      title={collapsed ? '展开左侧导航栏' : '收起左侧导航栏'}
      aria-label={collapsed ? '展开左侧导航栏' : '收起左侧导航栏'}
      onclick={() => prefs.toggleSidebarCollapsed()}
    >
      <Icon name={collapsed ? 'chevron-right' : 'chevron-left'} size={15} />
    </button>
  </div>

  <nav aria-label="主导航">
    <ul>
      {#each primary as it (it.href)}<li>{@render item(it)}</li>{/each}
    </ul>
    {#if appItems.length}
      {#if !collapsed}<h2 class="label">应用</h2>{:else}<hr class="sep" />{/if}
      <ul>
        {#each appItems as it (it.href)}<li>{@render item(it)}</li>{/each}
      </ul>
    {/if}
    {#if !collapsed}<h2 class="label">系统</h2>{:else}<hr class="sep" />{/if}
    <ul>
      <li>{@render item(SETTINGS)}</li>
    </ul>
  </nav>

  <div class="foot">
    <a
      href="/settings/system"
      class="server"
      title={collapsed ? `${node?.name ?? '本机'} · ${lost ? '连接中断' : online ? '在线' : '离线'}` : '查看本机系统信息'}
      aria-current={router.path === '/settings/system' ? 'page' : undefined}
    >
      <Mood {mood} size="sm" />
      {#if !collapsed}
        <div class="server-text">
          <b class="ellipsis">{node?.name ?? '本机'}</b>
          <small>{lost ? '连接中断' : online ? '在线' : '离线'}</small>
        </div>
      {/if}
    </a>

    <div class="foot-tools">
      <IconButton
        size="sm"
        icon="topbar"
        label="切回顶部横向导航栏"
        onclick={() => prefs.toggleLayout()}
      />
      <IconButton
        size="sm"
        icon={prefs.resolvedTheme === 'dark' ? 'moon' : 'sun'}
        label={prefs.resolvedTheme === 'dark' ? '切换到浅色' : '切换到深色'}
        onclick={() => prefs.toggleTheme()}
      />
      <Menu
        label="账户菜单"
        align="start"
        placement="up"
        items={[
          { label: '账户资料', icon: 'user', href: '/settings/account' },
          { label: '外观与布局', icon: 'sun', href: '/settings/appearance' },
          { label: '切回顶部导航栏', icon: 'topbar', onselect: () => prefs.toggleLayout() },
          { label: '退出登录', icon: 'logout', tone: 'danger', onselect: () => void session.logout() },
        ]}
      >
        {#snippet trigger(props)}
          <button
            type="button"
            class="u-btn"
            aria-haspopup={props['aria-haspopup']}
            aria-expanded={props['aria-expanded']}
            aria-controls={props['aria-controls']}
            aria-label={props['aria-label']}
            title={userName}
            onclick={props.onclick}
            onkeydown={props.onkeydown}
          >
            <Avatar name={userName} size="sm" />
            {#if !collapsed}<span class="ellipsis">{userName}</span>{/if}
          </button>
        {/snippet}
      </Menu>
    </div>
  </div>
</aside>

<style>
  .side {
    position: sticky;
    top: 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    height: calc(100dvh - 24px);
    margin: 12px 0 12px 12px;
    padding: 14px 10px 12px;
    border-radius: var(--r-xl);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    overflow-y: auto;
    overflow-x: hidden;
  }
  .side.collapsed {
    padding: 14px 8px 12px;
    align-items: center;
  }
  .brand-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    padding: 2px 4px 10px;
    width: 100%;
  }
  .collapsed .brand-bar {
    flex-direction: column;
    padding: 0 0 8px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }
  .brand-text {
    display: flex;
    flex-direction: column;
    line-height: 1.2;
  }
  .brand-text b {
    font-size: var(--fs-lg);
    font-weight: var(--fw-bold);
    letter-spacing: -0.02em;
  }
  .brand-text .x {
    font-style: normal;
    margin-left: 2px;
    color: var(--accent);
  }
  .brand-text small {
    color: var(--text-3);
    font-size: 11px;
  }
  .collapse-btn {
    display: inline-grid;
    place-items: center;
    width: 28px;
    height: 28px;
    border-radius: var(--r-pill);
    color: var(--text-3);
    flex: none;
  }
  .collapse-btn:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  nav {
    width: 100%;
  }
  ul {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .label {
    padding: 12px 10px 4px;
    color: var(--text-3);
    font-size: var(--fs-2xs);
    font-weight: var(--fw-semibold);
    letter-spacing: 0.04em;
  }
  .sep {
    margin: 8px 6px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 38px;
    padding: 0 9px;
    border-radius: var(--r-pill);
    color: var(--text-2);
    font-weight: var(--fw-medium);
    transition: background var(--dur-1) var(--ease), color var(--dur-1) var(--ease);
  }
  .collapsed .item {
    justify-content: center;
    padding: 0;
    width: 42px;
    margin: 0 auto;
  }
  .item:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .item[aria-current='page'] {
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: var(--fw-semibold);
  }
  .foot {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
    width: 100%;
    padding-top: 8px;
    border-top: 1px solid var(--line);
  }
  .server {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 8px 10px;
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
  }
  .collapsed .server {
    justify-content: center;
    padding: 6px;
  }
  .server:hover,
  .server[aria-current='page'] {
    background: var(--surface-3);
    border-color: var(--line-strong);
  }
  .server-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.25;
  }
  .server-text b {
    font-size: var(--fs-xs);
    font-weight: var(--fw-semibold);
  }
  .server-text small {
    color: var(--text-3);
    font-size: 11px;
  }
  .foot-tools {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .collapsed .foot-tools {
    flex-direction: column;
  }
  .u-btn {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
    padding: 3px 8px 3px 3px;
    border-radius: var(--r-pill);
    color: var(--text-2);
    font-size: var(--fs-xs);
    font-weight: var(--fw-medium);
  }
  .collapsed .u-btn {
    padding: 2px;
  }
  .u-btn:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  @media (max-width: 860px) {
    .side {
      display: none;
    }
  }
</style>
