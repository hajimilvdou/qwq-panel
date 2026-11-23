<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  PluginDetail · 应用详情主体
  ───────────────────────────────────────────────────────────────
  头部：图标、名称、版本、运行态；操作：打开、重启、卸载（danger，列出依赖方）
  Tab（写入 ?tab=）：概览 / 设置 / 日志 / 版本
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { Button, Card, Checkbox, Chip, ConfirmDialog, ErrorState, Skeleton, Tabs } from '$ui';
  import { plugins } from '$api/endpoints';
  import type { Plugin } from '$api/types';
  import { describeError, reportError } from '$lib/errors';
  import { createIntent, runIntent, type Intent } from '$lib/ops';
  import { page } from '$lib/page.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { navigate, router } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { pluginsResource } from '../../app/nav';
  import ConfigTab from './ConfigTab.svelte';
  import LogsTab from './LogsTab.svelte';
  import OverviewTab from './OverviewTab.svelte';
  import PluginIcon from './PluginIcon.svelte';
  import VersionsTab from './VersionsTab.svelte';
  import { runtimeOf } from './runtime';

  interface Props {
    id: string;
  }
  let { id }: Props = $props();

  const pid = untrack(() => id);
  const detail = useResource<Plugin>({
    key: `plugin:${pid}`,
    load: () => plugins.get(pid),
    subjects: [`plugins/${pid}`],
    revisionOf: (p) => p.revision,
  });
  const all = useResource(pluginsResource);
  const p = $derived(detail.data);

  $effect(() => {
    if (p) page.setTitle(p.name);
  });

  /* ---------------------------------------------------------------- Tab */
  type TabId = 'overview' | 'settings' | 'logs' | 'versions';
  const tabs = $derived([
    { id: 'overview' as const, label: '概览' },
    { id: 'settings' as const, label: '设置', hidden: p?.has_config === false },
    { id: 'logs' as const, label: '日志', hidden: !session.can('host.plugins:logs') },
    { id: 'versions' as const, label: '版本', count: p?.versions.length },
  ]);
  let tab = $state<TabId>(untrack(() => (router.query.get('tab') as TabId | null) ?? 'overview'));
  $effect(() => {
    if (tabs.find((t) => t.id === tab)?.hidden) tab = 'overview';
  });

  /* ---------------------------------------------------------------- 打开 / 启停 / 重启 */
  const entry = $derived(p?.ui?.routes.find((r) => r.nav) ?? p?.ui?.routes[0]);
  const canUpdate = $derived(session.can('host.plugins:update'));
  const stopped = $derived(p?.runtime?.state === 'stopped' || p?.active_status === 'STOPPED');
  let restarting = $state(false);
  let toggling = $state(false);

  async function toggleEnabled() {
    if (!p || toggling) return;
    toggling = true;
    const enable = stopped;
    try {
      await runIntent(
        createIntent(),
        (key) => (enable ? plugins.enable(p.plugin_id, key) : plugins.disable(p.plugin_id, key)),
        { label: `${enable ? '启用' : '停用'} ${p.name}` },
      );
      void detail.refresh();
      void all.refresh();
    } catch (err) {
      reportError(err, enable ? '启用失败' : '停用失败');
    } finally {
      toggling = false;
    }
  }

  async function restart() {
    if (!p) return;
    restarting = true;
    try {
      await plugins.restart(p.plugin_id, createIntent().key);
      void detail.refresh();
    } catch (err) {
      reportError(err, '重启失败');
    } finally {
      restarting = false;
    }
  }

  /* ---------------------------------------------------------------- 卸载 */
  const canUninstall = $derived(session.can('host.plugins:uninstall') && !p?.builtin);
  const dependents = $derived((all.data ?? []).filter((x) => x.dependencies?.includes(pid)).map((x) => x.name));
  let removeOpen = $state(false);
  let purge = $state(false);
  let removeErr = $state('');
  let removeIntent: Intent = createIntent();

  function openRemove() {
    purge = false;
    removeErr = '';
    removeIntent = createIntent();
    removeOpen = true;
  }

  async function submitRemove() {
    const cur = p!;
    try {
      const r = await runIntent(removeIntent, (key) => plugins.uninstall(cur.plugin_id, cur.revision, key, purge), {
        label: `卸载 ${cur.name}`,
      });
      if (r.kind !== 'awaiting') navigate('/apps', { replace: true });
    } catch (err) {
      const v = describeError(err);
      /* 被依赖时 409 STATE_CONFLICT：优先用本地算出的依赖方列表说人话 */
      removeErr = v.code === 'STATE_CONFLICT' && dependents.length ? `这些应用依赖它：${dependents.join('、')}` : v.message;
      throw err;
    }
  }
</script>

{#if detail.status === 'loading'}
  <Card><Skeleton lines={4} height={18} /></Card>
{:else if detail.status === 'error' && !p}
  {@const v = describeError(detail.error)}
  <Card>
    <ErrorState kind={v.code === 'NOT_FOUND' ? 'notfound' : 'error'} message={v.message} requestId={v.requestId} onretry={v.code === 'NOT_FOUND' ? undefined : detail.refresh} />
  </Card>
{:else if p}
  {@const st = runtimeOf(p)}
  <header class="head">
    <PluginIcon plugin={p} size="lg" />
    <div class="names">
      <h2>{p.name}</h2>
      <div class="meta">
        <Chip size="sm" tone={st.tone}>{st.label}</Chip>
        {#if p.active_version}<span class="small faint mono">v{p.active_version}</span>{/if}
        <span class="small faint mono">{p.plugin_id}</span>
      </div>
    </div>
    <div class="ops">
      {#if entry && p.runtime?.state === 'running' && session.can(entry.permission)}
        <Button variant="soft" icon="external" href="/plugins/{encodeURIComponent(p.plugin_id)}{entry.path === '/' ? '' : entry.path}">打开</Button>
      {/if}
      {#if canUpdate}
        <Button variant={stopped ? 'soft' : 'ghost'} icon={stopped ? 'play' : 'pause'} loading={toggling} onclick={toggleEnabled}>
          {stopped ? '启用' : '停用'}
        </Button>
        <Button variant="ghost" icon="refresh" loading={restarting} onclick={restart}>重启</Button>
      {/if}
      {#if canUninstall}<Button variant="ghost" icon="trash" onclick={openRemove}>卸载</Button>{/if}
    </div>
  </header>

  <Tabs label="应用详情" {tabs} bind:value={tab} onchange={(t) => router.setQuery({ tab: t === 'overview' ? null : t })}>
    {#snippet children(t)}
      {#if t === 'overview'}
        <OverviewTab plugin={p} />
      {:else if t === 'settings'}
        <ConfigTab plugin={p} onrestart={restart} />
      {:else if t === 'logs'}
        <LogsTab pluginId={p.plugin_id} />
      {:else}
        <VersionsTab plugin={p} onchanged={detail.refresh} />
      {/if}
    {/snippet}
  </Tabs>

  <ConfirmDialog
    bind:open={removeOpen}
    title="卸载 {p.name}"
    tone="danger"
    confirmLabel="卸载"
    warning={dependents.length ? `这些应用依赖它，需先卸载：${dependents.join('、')}` : '卸载后它的页面、小组件和后台任务都会停止。'}
    confirmText={p.name}
    errorText={removeErr}
    onconfirm={submitRemove}
  >
    <Checkbox label="同时删除它的数据" hint="不可恢复；可能需要两步验证" bind:checked={purge} />
  </ConfirmDialog>
{/if}

<style>
  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s-4);
    margin-bottom: var(--s-5);
  }
  .names {
    display: flex;
    flex: 1;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }
  h2 {
    margin: 0;
    font-size: var(--fs-2xl);
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }
  .ops {
    display: flex;
    gap: 8px;
  }
</style>
