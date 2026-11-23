<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  插件页 /plugins/:pluginId/*（SPEC §3.5 / ENG §9）
  ───────────────────────────────────────────────────────────────
  全宽 iframe（sandbox 仅 allow-scripts allow-forms allow-downloads，绝无
  allow-same-origin / allow-top-navigation* / allow-popups-to-escape-sandbox）。
  骨架 → 握手（PluginBridge）→ ui.ready 去骨架；6 秒无 ready → 错误态 + 重试
  （重建 iframe 与 channel）。子路径 rest 与浏览器前进后退经 ui.route 同步。
  路由权限取 manifest ui.routes[].permission（前缀匹配最长者）。
-->
<script lang="ts">
  import { Button, Card, ErrorState, Skeleton } from '$ui';
  import { describeError } from '$lib/errors';
  import { page } from '$lib/page.svelte';
  import { normalizePluginPath } from '$lib/plugin-host';
  import { useResource } from '$lib/resource.svelte';
  import { navigate } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { pluginsResource } from '../../app/nav';
  import PluginFrame from './PluginFrame.svelte';

  let { params }: { params: Record<string, string> } = $props();

  const list = useResource(pluginsResource);
  const pid = $derived(params.pluginId ?? '');
  const path = $derived(normalizePluginPath('/' + (params.rest ?? '')) ?? '/');
  const plugin = $derived(list.data?.find((p) => p.plugin_id === pid));

  /* 最长前缀匹配的路由声明 → 标题与权限 */
  const route = $derived.by(() => {
    const routes = plugin?.ui?.routes ?? [];
    let best: (typeof routes)[number] | undefined;
    for (const r of routes) {
      const base = normalizePluginPath(r.path);
      if (base === null) continue;
      const hit = base === '/' || path === base || path.startsWith(base + '/');
      if (hit && (!best || base.length > (normalizePluginPath(best.path) ?? '').length)) best = r;
    }
    return best;
  });
  const allowed = $derived(!!route && session.can(route.permission));
  const running = $derived(plugin?.runtime?.state === undefined || plugin.runtime.state === 'running');

  const redirectTarget = $derived.by(() => {
    if (path !== '/' || route || !plugin?.ui?.routes?.length) return null;
    const first = plugin.ui.routes.find((r) => r.nav) ?? plugin.ui.routes[0];
    const target = first ? normalizePluginPath(first.path) : null;
    return target && target !== '/' ? `/plugins/${encodeURIComponent(plugin.plugin_id)}${target}` : null;
  });

  $effect(() => {
    if (redirectTarget) navigate(redirectTarget, { replace: true });
  });

  $effect(() => {
    if (plugin) page.setTitle(route && route.title !== plugin.name ? `${plugin.name} · ${route.title}` : plugin.name);
  });
</script>

{#if list.status === 'loading' || redirectTarget}
  <Skeleton height={480} radius={20} />
{:else if list.status === 'error' && !list.data}
  <Card><ErrorState message={describeError(list.error).message} onretry={list.refresh} /></Card>
{:else if !plugin || !plugin.ui}
  <Card><ErrorState kind="notfound" message="找不到这个应用的页面" /></Card>
{:else if !route}
  <Card><ErrorState kind="notfound" message="这个应用没有这个页面" /></Card>
{:else if !allowed}
  <Card><ErrorState kind="permission" /></Card>
{:else if !running}
  <Card>
    <ErrorState message="{plugin.name} 没有在运行" />
    <div class="center"><Button variant="soft" href="/apps/{encodeURIComponent(plugin.plugin_id)}">去应用详情</Button></div>
  </Card>
{:else}
  <!-- 换插件或换版本（entry_url 含版本）即重建 iframe 与桥 -->
  {#key plugin.plugin_id + plugin.ui.entry_url}
    <PluginFrame {plugin} {path} />
  {/key}
{/if}

<style>
  .center {
    display: flex;
    justify-content: center;
    padding-bottom: var(--s-5);
  }
</style>
