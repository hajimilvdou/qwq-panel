<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Sidebar · 主导航（品牌、固定项、插件项、设置、服务器卡；无待办与计数徽章） -->
<script lang="ts">
  import { nodes as nodesApi } from '$api/endpoints';
  import { events } from '$lib/events.svelte';
  import { health } from '$lib/page.svelte';
  import { router } from '$lib/router.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { Mood, Tile } from '$ui';
  import { APP_CENTER, isActive, pluginNav, pluginsResource, PRIMARY, SETTINGS, type NavItem } from './nav';

  const plugins = useResource(pluginsResource);
  const nodes = useResource({
    key: 'nodes',
    load: () => nodesApi.list().then((p) => p.items),
    subjects: ['nodes/'],
  });

  const appItems = $derived([...pluginNav(plugins.data ?? []), APP_CENTER].filter((i) => session.can(i.perm)));
  const primary = $derived(PRIMARY.filter((i) => session.can(i.perm)));
  const allNavItems = $derived([...primary, ...appItems, SETTINGS]);
  const node = $derived(nodes.data?.[0]);
  /* 事件流断开时节点状态是旧快照，不能继续宣称"在线" */
  const lost = $derived(events.offline);
  const online = $derived(!node || node.status === 'online');
  const mood = $derived(lost ? 'warn' : online ? health.level : 'bad');
</script>

{#snippet item(it: NavItem)}
  <a href={it.href} class="item" aria-current={isActive(it.href, router.path, allNavItems) ? 'page' : undefined}>
    <Tile icon={it.icon} color={it.color} size="sm" />
    <span class="ellipsis">{it.label}</span>
  </a>
{/snippet}

<aside class="side">
  <a href="/" class="brand" aria-label="qwq X 主页">
    <Mood size="md" />
    <span class="brand-text"><b>qwq<em class="x">X</em></b><small>轻面板 · 多 Agent</small></span>
  </a>

  <nav aria-label="主导航">
    <ul>
      {#each primary as it (it.href)}<li>{@render item(it)}</li>{/each}
    </ul>
    {#if appItems.length}
      <h2 class="label">应用</h2>
      <ul>
        {#each appItems as it (it.href)}<li>{@render item(it)}</li>{/each}
      </ul>
    {/if}
    <h2 class="label">系统</h2>
    <ul>
      <li>{@render item(SETTINGS)}</li>
    </ul>
  </nav>

  <div class="server">
    <Mood {mood} size="sm" />
    <div class="server-text">
      <b class="ellipsis">{node?.name ?? '本机'}</b>
      <small>{lost ? '连接中断' : online ? '在线' : '离线'}</small>
    </div>
  </div>
</aside>

<style>
  /* 悬浮大圆角胶囊侧栏（定稿 v4 qwq X） */
  .side {
    position: sticky;
    top: 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    height: calc(100dvh - 28px);
    margin: 14px 0 14px 14px;
    padding: 18px 12px 14px;
    border-radius: var(--r-xl);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    overflow-y: auto;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 4px 10px 14px;
    border-radius: var(--r-md);
  }
  .brand-text {
    display: flex;
    flex-direction: column;
    line-height: 1.2;
  }
  .brand-text b {
    font-size: var(--fs-xl);
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
    font-size: var(--fs-xs);
  }
  ul {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .label {
    padding: 14px 12px 5px;
    color: var(--text-3);
    font-size: var(--fs-2xs);
    font-weight: var(--fw-semibold);
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 11px;
    height: 40px;
    padding: 0 10px;
    border-radius: var(--r-pill);
    color: var(--text-2);
    font-weight: var(--fw-medium);
    transition:
      background var(--dur-1) var(--ease),
      color var(--dur-1) var(--ease);
  }
  .item:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .item[aria-current='page'] {
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: var(--fw-semibold);
  }
  :global([data-theme='dark']) .item[aria-current='page'] {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .server {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: auto;
    padding: 10px 12px;
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
  }
  .server-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.3;
  }
  .server-text b {
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
  }
  .server-text small {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  @media (max-width: 860px) {
    .side {
      display: none;
    }
  }
</style>
