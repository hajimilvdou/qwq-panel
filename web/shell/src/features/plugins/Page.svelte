<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  插件工作区 /plugins/:pluginId/*
  ───────────────────────────────────────────────────────────────
  · 取消冗余的「工作台 / 设置与资源 / 日志」顶层占位标签
  · 将插件自身的功能分区直接提升到左上角（仿妙妙屋清晰导航层级）
  · 设置、日志与启停管理收纳为右上角轻量侧滑抽屉/菜单，不喧宾夺主
  · 驻留池调用严格 untrack，杜绝 Svelte 5 响应式循环崩溃
-->
<script lang="ts">
  import { onDestroy, untrack, type ComponentProps } from 'svelte';
  import { Button, Card, Checkbox, ConfirmDialog, Drawer, ErrorState, Icon, Menu, OtpInput, Skeleton } from '$ui';
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

  const canUpdate = $derived(session.can('host.plugins:update'));
  const canConfig = $derived(session.can('host.plugins:config'));
  const canLogs = $derived(session.can('host.plugins:logs'));
  const canUninstall = $derived(session.can('host.plugins:uninstall') && !plugin?.builtin);
  const showSettingsBtn = $derived(Boolean(plugin && (plugin.has_config !== false || canUpdate || canConfig)));

  /* 右上角侧滑抽屉：仅在用户主动需要时打开，不再占据左上角功能分类位 */
  let drawerMode = $state<'settings' | 'logs' | null>(null);

  $effect(() => {
    const raw = router.query.get('tab');
    if (raw === 'settings' && showSettingsBtn) {
      drawerMode = 'settings';
      untrack(() => router.setQuery({ tab: null }));
    } else if (raw === 'logs' && canLogs) {
      drawerMode = 'logs';
      untrack(() => router.setQuery({ tab: null }));
    }
  });

  /* ---------------------------------------------------------------- 路由与功能分区 */
  const visibleRoutes = $derived.by(() => {
    const routes = plugin?.ui?.routes ?? [];
    return routes
      .map((r) => ({ ...r, norm: normalizePluginPath(r.path) ?? '/' }))
      .filter((r) => session.can(r.permission));
  });

  const route = $derived.by(() => {
    let best: (typeof visibleRoutes)[number] | undefined;
    for (const r of visibleRoutes) {
      const base = r.norm;
      const hit = base === '/' || path === base || path.startsWith(base + '/');
      if (hit && (!best || base.length > best.norm.length)) best = r;
    }
    return best;
  });

  const hasUI = $derived(Boolean(plugin?.ui?.entry_url));
  const allowed = $derived(!hasUI || Boolean(route));
  const running = $derived(isPluginActiveReady(plugin));
  const stopped = $derived(
    plugin?.enabled === false || plugin?.runtime?.state === 'stopped' || plugin?.active_status === 'STOPPED',
  );

  const redirectTarget = $derived.by(() => {
    if (path !== '/' || route || !visibleRoutes.length || !plugin) return null;
    const first = visibleRoutes.find((r) => r.nav) ?? visibleRoutes[0];
    return first && first.norm !== '/' ? `/plugins/${encodeURIComponent(plugin.plugin_id)}${first.norm}` : null;
  });

  $effect(() => {
    if (redirectTarget) untrack(() => navigate(redirectTarget, { replace: true }));
  });

  $effect(() => {
    if (plugin) {
      page.setTitle(route && route.title !== plugin.name ? `${plugin.name} · ${route.title}` : plugin.name);
    }
  });

  /* 驱动驻留池：严格 untrack 避免读取 pluginFramePool.entries 造成 Svelte 5 递归循环 */
  let ownedFrameKey: string | null = null;
  $effect(() => {
    const curPlugin = plugin;
    const curPath = path;
    const shouldShow = Boolean(curPlugin && hasUI && running && route && allowed && !redirectTarget);
    untrack(() => {
      if (shouldShow && curPlugin) {
        ownedFrameKey = pluginFramePool.activate(curPlugin, curPath);
      } else if (ownedFrameKey) {
        pluginFramePool.deactivate(ownedFrameKey);
        ownedFrameKey = null;
      }
    });
  });

  onDestroy(() => {
    if (ownedFrameKey) {
      pluginFramePool.deactivate(ownedFrameKey);
      ownedFrameKey = null;
    }
  });

  function routeHref(norm: string): string {
    if (!plugin) return '/apps';
    const sub = norm.replace(/^\/+/, '');
    return `/plugins/${encodeURIComponent(plugin.plugin_id)}${sub ? '/' + sub : ''}`;
  }

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
        { label: `${enable ? '启用' : '停用'} ${plugin.name}`, preConfirmed: true },
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
        { label: `卸载 ${cur.name}`, preConfirmed: true, mfaCode: showRemoveOtp ? removeMfa : undefined },
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

  type ManageMenuItem = ComponentProps<typeof Menu>['items'][number];
  const manageItems = $derived.by<ManageMenuItem[]>(() => {
    const out: ManageMenuItem[] = [];
    if (canUpdate && !stopped) {
      out.push({ label: restarting ? '重启中…' : '重启应用', icon: 'refresh', disabled: restarting, onselect: () => void restart() });
    }
    if (canUpdate) {
      out.push({
        label: stopped ? '启用应用' : '停用应用',
        icon: stopped ? 'play' : 'pause',
        disabled: toggling,
        onselect: () => void toggleEnabled(),
      });
    }
    if (canUninstall) {
      out.push({ label: '卸载应用', icon: 'trash', tone: 'danger', onselect: openRemove });
    }
    return out;
  });
</script>

{#if list.status === 'loading' && !list.data}
  <Card><Skeleton lines={3} height={24} /></Card>
{:else if list.status === 'error' && !list.data}
  <Card><ErrorState message={describeError(list.error).message} onretry={list.refresh} /></Card>
{:else if !plugin}
  <Card><ErrorState kind="notfound" message="找不到这个应用，可能已卸载" /></Card>
{:else}
  {@const st = runtimeOf(plugin)}
  <header class="pbar">
    <div class="pbar-left">
      {#if visibleRoutes.length > 1 && running}
        <!-- 多功能分区插件（如代理与订阅中心）：将插件自身的功能分类直接提升到左上角 -->
        <nav class="cat-pills" aria-label="{plugin.name} 功能分类">
          {#each visibleRoutes as r (r.norm)}
            <a href={routeHref(r.norm)} class="cat-pill" aria-current={route?.norm === r.norm ? 'page' : undefined}>
              {r.title}
            </a>
          {/each}
        </nav>
      {:else}
        <div class="pbar-id">
          <PluginIcon {plugin} size="md" />
          <h2>{plugin.name}</h2>
          <span class="st-dot t-{st.tone}" title={st.label}></span>
          <span class="st-txt">{st.label}</span>
        </div>
      {/if}
    </div>

    <div class="pbar-ops">
      {#if showSettingsBtn}
        <button type="button" class="op-btn" onclick={() => (drawerMode = 'settings')}>
          <Icon name="settings" size={14} />设置
        </button>
      {/if}
      {#if canLogs}
        <button type="button" class="op-btn" onclick={() => (drawerMode = 'logs')}>
          <Icon name="file" size={14} />日志
        </button>
      {/if}
      {#if manageItems.length}
        <Menu label="应用管理" items={manageItems}>
          {#snippet trigger(props)}
            <button
              type="button"
              class="op-btn icon-only"
              aria-haspopup={props['aria-haspopup']}
              aria-expanded={props['aria-expanded']}
              aria-controls={props['aria-controls']}
              aria-label={props['aria-label']}
              onclick={props.onclick}
              onkeydown={props.onkeydown}
            >
              <Icon name="more" size={15} />
            </button>
          {/snippet}
        </Menu>
      {/if}
    </div>
  </header>

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
        <p class="small muted">启用后即可使用它的完整功能；也可以点击右上角「设置」或「日志」排查问题。</p>
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

  <Drawer
    open={drawerMode !== null}
    title={drawerMode === 'logs' ? `${plugin.name} · 运行日志` : `${plugin.name} · 设置`}
    size="lg"
    onclose={() => (drawerMode = null)}
  >
    {#if drawerMode === 'settings'}
      <ConfigTab {plugin} onrestart={restart} onupdated={() => void list.refresh()} />
    {:else if drawerMode === 'logs'}
      <LogsTab pluginId={plugin.plugin_id} />
    {/if}
  </Drawer>

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
  .pbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: var(--s-3);
  }
  .pbar-left {
    display: flex;
    align-items: center;
    min-width: 0;
    flex: 1;
  }
  .cat-pills {
    display: inline-flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 4px;
    padding: 4px;
    border-radius: var(--r-pill);
    background: var(--surface-2);
    border: 1px solid var(--line);
  }
  .cat-pill {
    display: inline-flex;
    align-items: center;
    height: 30px;
    padding: 0 14px;
    border-radius: var(--r-pill);
    color: var(--text-2);
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    white-space: nowrap;
    transition: background var(--dur-1) var(--ease), color var(--dur-1) var(--ease);
  }
  .cat-pill:hover {
    color: var(--text);
  }
  .cat-pill[aria-current='page'] {
    background: var(--accent-strong);
    color: var(--on-accent);
    font-weight: var(--fw-semibold);
  }
  .pbar-id {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
  .pbar-id h2 {
    margin: 0;
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .st-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--text-3);
  }
  .st-dot.t-ok { background: var(--ok); }
  .st-dot.t-warn { background: var(--warn); }
  .st-dot.t-bad { background: var(--bad); }
  .st-dot.t-info { background: var(--info); }
  .st-txt {
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .pbar-ops {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: none;
  }
  .op-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 32px;
    padding: 0 11px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface);
    color: var(--text-2);
    font-size: var(--fs-xs);
    font-weight: var(--fw-medium);
    transition: background var(--dur-1) var(--ease), color var(--dur-1) var(--ease), border-color var(--dur-1) var(--ease);
  }
  .op-btn:hover {
    background: var(--surface-2);
    border-color: var(--line-strong);
    color: var(--text);
  }
  .op-btn.icon-only {
    width: 32px;
    padding: 0;
    justify-content: center;
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
