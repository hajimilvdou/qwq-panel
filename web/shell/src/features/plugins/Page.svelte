<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  插件统一工作区 /plugins/:pluginId/*
  ───────────────────────────────────────────────────────────────
  把「工作台」「设置与资源」「日志」收口到每个插件自己的页面，彻底取消冗余概览页
  与误导性的“版本 1”角标；UI 插件使用驻留池保活（切页 0ms 瞬开），无前端引擎插件
  （如 core.xray）自动呈现原生管理工作台。
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Button, Card, Checkbox, Chip, ConfirmDialog, ErrorState, OtpInput, Skeleton, Tabs } from '$ui';
  import { ApiError } from '$api/client';
  import { plugins } from '$api/endpoints';
  import { isPluginActiveReady } from '$api/endpoints-plugins';
  import { describeError, reportError } from '$lib/errors';
  import { createFormIntent, createIntent, runIntent } from '$lib/ops';
  import { page } from '$lib/page.svelte';
  import { normalizePluginPath } from '$lib/plugin-host';
  import { resources, useResource } from '$lib/resource.svelte';
  import { navigate, router } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { pluginsResource } from '../../app/nav';
  import ConfigTab from '../apps/ConfigTab.svelte';
  import LogsTab from '../apps/LogsTab.svelte';
  import PluginIcon from '../apps/PluginIcon.svelte';
  import { runtimeOf } from '../apps/runtime';
  import HeadlessPluginPane from './HeadlessPluginPane.svelte';
  import SecurityTakeoverBar from './SecurityTakeoverBar.svelte';
  import { pluginFramePool } from './plugin-frame-pool.svelte';

  let { params }: { params: Record<string, string> } = $props();

  const list = useResource(pluginsResource);
  const pid = $derived(params.pluginId ?? '');
  const path = $derived(normalizePluginPath('/' + (params.rest ?? '')) ?? '/');
  const plugin = $derived(list.data?.find((p) => p.plugin_id === pid));

  /* ---------------------------------------------------------------- Tab */
  type TabId = 'workspace' | 'settings' | 'logs';
  const canUpdate = $derived(session.can('host.plugins:update'));
  const canLogs = $derived(session.can('host.plugins:logs'));
  const canUninstall = $derived(session.can('host.plugins:uninstall') && !plugin?.builtin);

  const tabs = $derived([
    { id: 'workspace' as const, label: '工作台' },
    { id: 'settings' as const, label: '设置与资源', hidden: !canUpdate && plugin?.has_config === false },
    { id: 'logs' as const, label: '日志', hidden: !canLogs },
  ]);

  const queryTab = $derived.by<TabId>(() => {
    const raw = router.query.get('tab');
    if (raw === 'settings' && !tabs.find((t) => t.id === 'settings')?.hidden) return 'settings';
    if (raw === 'logs' && !tabs.find((t) => t.id === 'logs')?.hidden) return 'logs';
    return 'workspace';
  });

  function setTab(next: TabId) {
    router.setQuery({ tab: next === 'workspace' ? null : next });
  }

  /* ---------------------------------------------------------------- 路由与权限 */
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

  const hasUI = $derived(Boolean(plugin?.ui?.entry_url));
  const allowed = $derived(!hasUI || (!!route && session.can(route.permission)));
  const running = $derived(isPluginActiveReady(plugin));
  const stopped = $derived(
    plugin?.enabled === false || plugin?.runtime?.state === 'stopped' || plugin?.active_status === 'STOPPED',
  );

  const redirectTarget = $derived.by(() => {
    if (queryTab !== 'workspace' || path !== '/' || route || !plugin?.ui?.routes?.length) return null;
    const first = plugin.ui.routes.find((r) => r.nav) ?? plugin.ui.routes[0];
    const target = first ? normalizePluginPath(first.path) : null;
    return target && target !== '/' ? `/plugins/${encodeURIComponent(plugin.plugin_id)}${target}` : null;
  });

  $effect(() => {
    if (redirectTarget) navigate(redirectTarget, { replace: true });
  });

  $effect(() => {
    if (plugin) {
      page.setTitle(route && route.title !== plugin.name ? `${plugin.name} · ${route.title}` : plugin.name);
    }
  });

  /* 驱动驻留池：仅当工作台 Tab 激活且插件 UI 运行中且有权限时显现保活 iframe */
  let ownedFrameKey: string | null = null;
  $effect(() => {
    if (queryTab === 'workspace' && plugin && hasUI && running && route && allowed && !redirectTarget) {
      ownedFrameKey = pluginFramePool.activate(plugin, path);
    } else if (ownedFrameKey) {
      pluginFramePool.deactivate(ownedFrameKey);
      ownedFrameKey = null;
    }
  });

  onDestroy(() => {
    if (ownedFrameKey) {
      pluginFramePool.deactivate(ownedFrameKey);
      ownedFrameKey = null;
    }
  });

  /* ---------------------------------------------------------------- 启停 / 重启 / 卸载 */
  let toggling = $state(false);
  let restarting = $state(false);

  async function toggleEnabled() {
    if (!plugin || toggling) return;
    toggling = true;
    const enable = stopped;
    try {
      await runIntent(
        createIntent(),
        (key) => (enable ? plugins.enable(plugin.plugin_id, key) : plugins.disable(plugin.plugin_id, key)),
        { label: `${enable ? '启用' : '停用'} ${plugin.name}` },
      );
      if (!enable) pluginFramePool.evict(plugin.plugin_id);
      resources.invalidate('plugins');
    } catch (err) {
      reportError(err, enable ? '启用失败' : '停用失败');
    } finally {
      toggling = false;
    }
  }

  async function restart() {
    if (!plugin || restarting) return;
    restarting = true;
    try {
      await plugins.restart(plugin.plugin_id, createIntent().key);
      pluginFramePool.reload(plugin.plugin_id);
      resources.invalidate('plugins');
    } catch (err) {
      reportError(err, '重启失败');
    } finally {
      restarting = false;
    }
  }

  const dependents = $derived(
    (list.data ?? []).filter((x) => x.dependencies?.includes(pid)).map((x) => x.name),
  );
  let removeOpen = $state(false);
  let purge = $state(false);
  let removeMfa = $state('');
  let removeMfaNeed = $state(false);
  let removeMfaErr = $state<string>();
  let removeErr = $state('');
  const removeIntent = createFormIntent();
  const showRemoveOtp = $derived(purge && (Boolean(session.user?.mfa_enabled) || removeMfaNeed));

  function openRemove() {
    purge = false;
    removeMfa = '';
    removeMfaNeed = false;
    removeMfaErr = undefined;
    removeErr = '';
    removeIntent.reset();
    removeOpen = true;
  }

  async function submitRemove() {
    const cur = plugin!;
    removeErr = '';
    removeMfaErr = undefined;
    if (showRemoveOtp && removeMfa.length !== 6) {
      removeMfaErr = '请输入 6 位两步验证码';
      throw new Error(removeMfaErr);
    }
    const key = removeIntent.keyFor({ id: cur.plugin_id, rev: cur.revision, purge });
    try {
      const r = await runIntent(
        { key },
        (k) => plugins.uninstall(cur.plugin_id, cur.revision, k, purge, showRemoveOtp ? removeMfa : undefined),
        { label: `卸载 ${cur.name}` },
      );
      removeIntent.reset();
      pluginFramePool.evict(cur.plugin_id);
      resources.invalidate('plugins');
      resources.invalidate('plugin-catalog');
      if (r.kind !== 'awaiting') navigate('/apps', { replace: true });
    } catch (err) {
      removeIntent.onError(err instanceof ApiError ? err.status : undefined);
      const v = describeError(err);
      if (v.code === 'MFA_REQUIRED') {
        removeMfaNeed = true;
        removeMfa = '';
        removeMfaErr = '请输入有效的 6 位两步验证码';
      } else {
        removeErr = v.code === 'STATE_CONFLICT' && dependents.length ? `这些应用依赖它：${dependents.join('、')}` : v.message;
      }
      throw err;
    }
  }
</script>

{#if list.status === 'loading' && !list.data}
  <Card><Skeleton lines={3} height={24} /></Card>
{:else if list.status === 'error' && !list.data}
  <Card><ErrorState message={describeError(list.error).message} onretry={list.refresh} /></Card>
{:else if !plugin}
  <Card><ErrorState kind="notfound" message="找不到这个应用，可能已卸载" /></Card>
{:else}
  {@const st = runtimeOf(plugin)}
  <header class="phead">
    <div class="phead-main">
      <PluginIcon {plugin} size="md" />
      <div class="phead-id">
        <div class="phead-row">
          <h2>{plugin.name}</h2>
          <Chip size="sm" tone={st.tone}>{st.label}</Chip>
          {#if plugin.active_version}<span class="tiny faint mono">v{plugin.active_version}</span>{/if}
        </div>
      </div>
      <div class="phead-ops">
        {#if canUpdate}
          <Button size="sm" variant={stopped ? 'primary' : 'ghost'} icon={stopped ? 'play' : 'pause'} loading={toggling} onclick={toggleEnabled}>
            {stopped ? '启用' : '停用'}
          </Button>
          {#if !stopped}
            <Button size="sm" variant="ghost" icon="refresh" loading={restarting} onclick={restart}>重启</Button>
          {/if}
        {/if}
        {#if canUninstall}
          <Button size="sm" variant="ghost" icon="trash" onclick={openRemove}>卸载</Button>
        {/if}
      </div>
    </div>
    <Tabs label="应用分区" {tabs} value={queryTab} onchange={setTab} />
  </header>

  {#if queryTab === 'workspace'}
    {#if plugin.plugin_id === 'security.basic' && running}
      <div class="takeover-slot">
        <SecurityTakeoverBar
          onchanged={() => {
            pluginFramePool.reload('security.basic');
            void list.refresh();
          }}
        />
      </div>
    {/if}

    {#if !running}
      <Card>
        <div class="stopped">
          <p class="strong">{plugin.name} 当前处于停用状态</p>
          <p class="small muted">启用后即可使用它的工作台能力；你也可以先切换到上方「设置与资源」或「日志」排查。</p>
          {#if canUpdate}
            <Button variant="primary" icon="play" loading={toggling} onclick={toggleEnabled}>立即启用</Button>
          {/if}
        </div>
      </Card>
    {:else if !hasUI}
      <HeadlessPluginPane {plugin} allPlugins={list.data ?? []} />
    {:else if !route}
      <Card><ErrorState kind="notfound" message="这个应用没有这个子页面" /></Card>
    {:else if !allowed}
      <Card><ErrorState kind="permission" /></Card>
    {/if}
    <!-- UI iframe 由 AppShell 内的驻留池渲染并保活，无需在此重复创建 -->
  {:else if queryTab === 'settings'}
    <ConfigTab {plugin} onrestart={restart} onupdated={() => void list.refresh()} />
  {:else if queryTab === 'logs'}
    <LogsTab pluginId={plugin.plugin_id} />
  {/if}

  <ConfirmDialog
    bind:open={removeOpen}
    title="卸载 {plugin.name}"
    tone="danger"
    confirmLabel="卸载"
    warning={dependents.length ? `这些应用依赖它，需先卸载：${dependents.join('、')}` : '卸载后它的页面、小组件和后台服务都会停止。'}
    confirmText={plugin.name}
    errorText={removeErr}
    onconfirm={submitRemove}
  >
    <div class="rm-opts">
      <Checkbox label="同时删除它的数据" hint="不可恢复；仅在已开启两步验证时需验证" bind:checked={purge} />
      {#if showRemoveOtp}
        <OtpInput bind:value={removeMfa} label="两步验证码" error={removeMfaErr} />
      {/if}
    </div>
  </ConfirmDialog>
{/if}

<style>
  .phead {
    display: grid;
    gap: var(--s-2);
    margin-bottom: var(--s-4);
  }
  .phead-main {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s-3);
  }
  .phead-id {
    flex: 1;
    min-width: 0;
  }
  .phead-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .phead-row h2 {
    margin: 0;
    font-size: var(--fs-xl);
  }
  .phead-ops {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .takeover-slot {
    margin-bottom: var(--s-3);
  }
  .stopped {
    display: grid;
    justify-items: center;
    gap: var(--s-3);
    padding: var(--s-6) var(--s-4);
    text-align: center;
  }
  .rm-opts {
    display: grid;
    gap: var(--s-3);
  }
</style>
