<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  应用中心 /apps（商店 + 已安装管理 + 集中更新与版本回滚 + 弹窗式人话介绍与安装配额）
-->
<script lang="ts">
  import { Alert, Button, Card, Chip, Dialog, EmptyState, ErrorState, Input, Skeleton, Tile } from '$ui';
  import type { IconName } from '$ui/icons';
  import type { CategoryColor, PluginCatalogItem, PluginResourceOverrideRequest } from '$api/additions';
  import { plugins as pluginsApi } from '$api/endpoints-plugins';
  import type { Plugin } from '$api/types';
  import { describeError } from '$lib/errors';
  import { bytes } from '$lib/format';
  import { resources, useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';
  import { pluginsResource } from '../../app/nav';
  import { guideForPlugin } from './catalog-guides';
  import {
    installOfficialPlugin,
    type OfficialInstallProgress,
    type OfficialInstallStage,
  } from './official-install';
  import PluginIcon from './PluginIcon.svelte';
  import VersionsTab from './VersionsTab.svelte';
  import { runtimeOf } from './runtime';

  let { params: _params }: { params: Record<string, string> } = $props();

  const list = useResource(pluginsResource);
  const catalog = useResource({
    key: 'plugin-catalog',
    load: () => pluginsApi.catalog(),
    subjects: ['plugins/'],
  });

  const canInstall = $derived(session.can('host.plugins:install'));
  const sorted = $derived(
    [...(list.data ?? [])].sort((a, b) => Number(!!a.builtin) - Number(!!b.builtin) || a.name.localeCompare(b.name, 'zh')),
  );

  const catalogById = $derived.by(() => {
    const map = new Map<string, PluginCatalogItem>();
    for (const item of catalog.data?.items ?? []) map.set(item.plugin_id, item);
    return map;
  });

  const storeItems = $derived.by(() => {
    const items = [...(catalog.data?.items ?? [])];
    return items.sort((a, b) => Number(a.installed) - Number(b.installed));
  });

  const updatableItems = $derived(
    (catalog.data?.items ?? []).filter((it) => it.installed && it.update_available && it.download_url),
  );

  const STAGE_LABEL: Record<OfficialInstallStage, string> = {
    downloading: '下载中…',
    verifying: '验签中…',
    installing: '安装中…',
    updating: '更新中…',
    enabling: '启动中…',
  };

  const VISUAL_MAP: Record<string, { icon: IconName; color: CategoryColor }> = {
    'security.basic': { icon: 'shield', color: 'green' },
    'monitor.basic': { icon: 'activity', color: 'blue' },
    'web.ingress': { icon: 'net', color: 'teal' },
    'tls.certificates': { icon: 'lock', color: 'green' },
    'domain.dns': { icon: 'external', color: 'cyan' },
    'containers.docker': { icon: 'apps', color: 'indigo' },
    'server.probe': { icon: 'cpu', color: 'violet' },
    'core.xray': { icon: 'shield', color: 'orange' },
    'proxy.advanced': { icon: 'net', color: 'amber' },
    'ai.relay': { icon: 'ai', color: 'pink' },
    'notify.hub': { icon: 'send', color: 'red' },
  };

  function visualOf(pluginId: string): { icon: IconName; color: CategoryColor } {
    return VISUAL_MAP[pluginId] ?? { icon: 'apps', color: 'slate' };
  }

  let busyId = $state<string | null>(null);
  let busyText = $state('');
  let storeErr = $state('');
  let refreshing = $state(false);

  /* 商店详情与安装前资源配置弹窗 */
  let detailItem = $state<PluginCatalogItem | null>(null);
  let customResOpen = $state(false);
  let resMem = $state('');
  let resCpu = $state('');
  let resPids = $state('');
  let resFds = $state('');

  /* 集中版本与回滚弹窗 */
  let versionTarget = $state<Plugin | null>(null);

  function openDetail(item: PluginCatalogItem) {
    const g = guideForPlugin(item.plugin_id);
    detailItem = item;
    customResOpen = false;
    resMem = String(item.memory_max_mb || g?.defaults.memory_max_mb || 256);
    resCpu = String(g?.defaults.cpu_quota_percent || 100);
    resPids = String(g?.defaults.pids_max || 64);
    resFds = String(g?.defaults.fds_max || 1024);
  }

  function buildInstallResources(item: PluginCatalogItem): PluginResourceOverrideRequest | undefined {
    if (!customResOpen) return undefined;
    const g = guideForPlugin(item.plugin_id);
    const defMem = item.memory_max_mb || g?.defaults.memory_max_mb || 256;
    const defCpu = g?.defaults.cpu_quota_percent || 100;
    const defPids = g?.defaults.pids_max || 64;
    const defFds = g?.defaults.fds_max || 1024;
    const m = Number.parseInt(resMem, 10);
    const c = Number.parseInt(resCpu, 10);
    const p = Number.parseInt(resPids, 10);
    const f = Number.parseInt(resFds, 10);
    const nextMem = Number.isFinite(m) && m >= 16 ? m : defMem;
    const nextCpu = Number.isFinite(c) && c >= 5 ? c : defCpu;
    const nextPids = Number.isFinite(p) && p >= 8 ? p : defPids;
    const nextFds = Number.isFinite(f) && f >= 64 ? f : defFds;
    if (nextMem === defMem && nextCpu === defCpu && nextPids === defPids && nextFds === defFds) {
      return undefined;
    }
    return {
      memory_max_mb: nextMem,
      cpu_quota_percent: nextCpu,
      pids_max: nextPids,
      fds_max: nextFds,
    };
  }

  async function refreshCatalog() {
    if (refreshing) return;
    refreshing = true;
    storeErr = '';
    try {
      await pluginsApi.catalog(true);
      resources.invalidate('plugin-catalog');
    } catch (err) {
      storeErr = describeError(err).message;
    } finally {
      refreshing = false;
    }
  }

  async function installOne(item: PluginCatalogItem, customRes?: PluginResourceOverrideRequest) {
    if (busyId || !canInstall) return;
    busyId = item.plugin_id;
    busyText = '准备下载…';
    storeErr = '';
    let touched = false;
    try {
      const res = await installOfficialPlugin(item.plugin_id, {
        items: catalog.data?.items,
        resources: customRes,
        onProgress: (p: OfficialInstallProgress) => {
          touched = true;
          const prefix = p.totalSteps > 1 ? `(${p.stepIndex}/${p.totalSteps}) ` : '';
          busyText = `${prefix}${STAGE_LABEL[p.stage]}`;
        },
      });
      if (res.updated.length > 0) {
        toasts.success(`${item.name} 已更新至 v${item.version}`);
      } else if (res.installed.length > 1) {
        toasts.success(`已安装并启用 ${item.name} 及依赖插件`);
      } else {
        toasts.success(`${item.name} 已安装并启用`);
      }
      if (detailItem?.plugin_id === item.plugin_id) detailItem = null;
    } catch (err) {
      storeErr = describeError(err).message;
    } finally {
      if (touched) {
        resources.invalidate('plugins');
        resources.invalidate('plugin-catalog');
      }
      busyId = null;
      busyText = '';
    }
  }

  async function updateAll() {
    for (const item of updatableItems) {
      await installOne(item);
    }
  }
</script>

<div class="head">
  <div>
    <h2>已安装的应用</h2>
    <p class="muted small">{list.data ? `共 ${list.data.length} 个 · 点击直接进入工作台、设置与日志` : ' '}</p>
  </div>
  <div class="head-ops">
    {#if canInstall && updatableItems.length > 0}
      <Button variant="soft" icon="refresh" loading={!!busyId} onclick={() => void updateAll()}>
        一键更新全部 ({updatableItems.length})
      </Button>
    {/if}
    {#if canInstall}<Button variant="primary" icon="upload" href="/apps/install">上传 / URL 安装</Button>{/if}
  </div>
</div>

{#if list.status === 'loading' && !list.data}
  <div class="grid">
    {#each [0, 1, 2] as i (i)}<Card><Skeleton lines={3} height={16} /></Card>{/each}
  </div>
{:else if list.status === 'error' && !list.data}
  <Card>
    <ErrorState message={describeError(list.error).message} requestId={describeError(list.error).requestId} onretry={list.refresh} />
  </Card>
{:else if !sorted.length}
  <Card>
    <EmptyState title="还没有安装应用" description="可以直接在下方官方插件商店点击了解详情并一键安装。">
      {#snippet action()}
        {#if canInstall}<Button variant="primary" icon="upload" href="/apps/install">上传安装包</Button>{/if}
      {/snippet}
    </EmptyState>
  </Card>
{:else}
  <ul class="grid">
    {#each sorted as p (p.plugin_id)}
      {@const st = runtimeOf(p)}
      {@const cat = catalogById.get(p.plugin_id)}
      {@const g = guideForPlugin(p.plugin_id)}
      <li>
        <div class="app">
          <a class="app-link" href="/plugins/{encodeURIComponent(p.plugin_id)}">
            <div class="top">
              <PluginIcon plugin={p} size="lg" />
              <div class="names">
                <span class="name">{p.name}</span>
                <span class="tiny faint mono ellipsis">{p.plugin_id}</span>
              </div>
            </div>
            <p class="summary clamp-2">{g?.tagline || p.summary}</p>
          </a>
          <div class="meta">
            <Chip size="sm" tone={st.tone}>{st.label}</Chip>
            {#if p.active_version}<span class="tiny faint mono">v{p.active_version}</span>{/if}
            <div class="meta-act">
              {#if p.versions.length > 1}
                <Button size="sm" variant="plain" onclick={() => (versionTarget = p)}>版本</Button>
              {/if}
              {#if canInstall && cat?.update_available && cat.download_url}
                <Button
                  size="sm"
                  variant="soft"
                  loading={busyId === cat.plugin_id}
                  disabled={!!busyId}
                  onclick={() => void installOne(cat)}
                >
                  {busyId === cat.plugin_id ? busyText : `更新 v${cat.version}`}
                </Button>
              {/if}
            </div>
          </div>
        </div>
      </li>
    {/each}
  </ul>
{/if}

<section class="store-section" aria-label="官方插件商店">
  <div class="head">
    <div>
      <h2>官方插件商店</h2>
      <p class="muted small">
        {#if catalog.data}
          点击任意插件卡片查看白话功能说明、配置资源配额或一键安装更新（{catalog.data.release} · <span class="mono">{catalog.data.platform}</span>）
        {:else}
          正在加载官方插件目录…
        {/if}
      </p>
    </div>
    <Button variant="ghost" icon="refresh" loading={refreshing} disabled={!!busyId} onclick={() => void refreshCatalog()}>
      刷新目录
    </Button>
  </div>

  {#if storeErr}
    <div class="store-alert"><Alert tone="bad" title="操作未能完成">{storeErr}</Alert></div>
  {/if}

  {#if catalog.data && !catalog.data.online}
    <div class="store-alert">
      <Alert tone="warn" title="当前处于离线目录回退模式">
        暂时无法连接 GitHub Releases 拉取最新索引，已展示内置官方列表；可点击「刷新目录」重试，或通过「上传 / URL 安装」离线安装。
      </Alert>
    </div>
  {/if}

  {#if catalog.status === 'loading' && !catalog.data}
    <div class="grid">
      {#each [0, 1, 2, 3] as i (i)}<Card><Skeleton lines={3} height={16} /></Card>{/each}
    </div>
  {:else if catalog.status === 'error' && !catalog.data}
    <Card><ErrorState message={describeError(catalog.error).message} onretry={catalog.refresh} /></Card>
  {:else}
    <ul class="grid">
      {#each storeItems as item (item.plugin_id)}
        {@const vis = visualOf(item.plugin_id)}
        {@const isBusy = busyId === item.plugin_id}
        {@const g = guideForPlugin(item.plugin_id)}
        <li>
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <div
            class="app store-card"
            class:installed={item.installed}
            role="button"
            tabindex="0"
            onclick={() => openDetail(item)}
            onkeydown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                openDetail(item);
              }
            }}
          >
            <div class="top">
              <Tile icon={vis.icon} color={vis.color} size="lg" />
              <div class="names">
                <span class="name">{item.name}</span>
                <span class="tiny faint mono ellipsis">{item.plugin_id}</span>
              </div>
            </div>
            <p class="summary clamp-2">{g?.tagline || item.summary}</p>
            <div class="badges">
              {#if item.memory_max_mb > 0}<span class="tiny faint mono">默认上限 {item.memory_max_mb} MiB</span>{/if}
              {#if item.size > 0}<span class="tiny faint mono">{bytes(item.size)}</span>{/if}
              {#if item.version}<span class="tiny faint mono">v{item.version}</span>{/if}
              {#if item.dependencies.length > 0 && !item.installed}
                <span class="tiny dep">自动连带安装 {item.dependencies.join(', ')}</span>
              {/if}
            </div>
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <div class="meta" onclick={(e) => e.stopPropagation()}>
              {#if item.installed && !item.update_available}
                <Chip size="sm" tone="ok">已安装</Chip>
                <div class="meta-act">
                  <Button size="sm" variant="ghost" href="/plugins/{encodeURIComponent(item.plugin_id)}">打开</Button>
                </div>
              {:else if item.installed && item.update_available}
                <Chip size="sm" tone="info">有新版本</Chip>
                {#if canInstall}
                  <div class="meta-act">
                    <Button size="sm" variant="primary" loading={isBusy} disabled={!!busyId || !item.download_url} onclick={() => void installOne(item)}>
                      {isBusy ? busyText : `更新 v${item.version}`}
                    </Button>
                  </div>
                {/if}
              {:else}
                <span class="tiny faint">点击查看介绍</span>
                {#if canInstall}
                  <div class="meta-act">
                    <Button size="sm" variant="primary" loading={isBusy} disabled={!!busyId || !item.download_url} onclick={() => void installOne(item)}>
                      {isBusy ? busyText : '安装'}
                    </Button>
                  </div>
                {/if}
              {/if}
            </div>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<!-- 商店插件白话详情与安装配额弹窗 -->
{#if detailItem}
  {@const item = detailItem}
  {@const g = guideForPlugin(item.plugin_id)}
  {@const vis = visualOf(item.plugin_id)}
  {@const isBusy = busyId === item.plugin_id}
  <Dialog open={true} title={item.name} description={g?.tagline || item.summary} size="md" onclose={() => (detailItem = null)}>
    {#snippet lead()}<Tile icon={vis.icon} color={vis.color} size="md" />{/snippet}
    <div class="dlg-body">
      <div class="dlg-block">
        <h4>这是用来干什么的？</h4>
        <p class="small">{g?.whatItDoes || item.summary}</p>
      </div>

      {#if g?.highlights?.length}
        <div class="dlg-block">
          <h4>常见用法</h4>
          <ul class="hl-list">
            {#each g.highlights as h (h)}
              <li>{h}</li>
            {/each}
          </ul>
        </div>
      {/if}

      {#if g?.tip}
        <p class="tip-box small">{g.tip}</p>
      {/if}

      <div class="dlg-meta tiny faint mono">
        <span>ID: {item.plugin_id}</span>
        {#if item.version}<span>版本: v{item.version}</span>{/if}
        {#if item.size > 0}<span>包大小: {bytes(item.size)}</span>{/if}
        {#if item.dependencies.length > 0}<span>依赖: {item.dependencies.join(', ')}</span>{/if}
      </div>

      {#if canInstall && !item.installed}
        <div class="res-box">
          <div class="res-head">
            <div>
              <span class="small strong">资源占用上限（默认 {resMem} MiB 内存 / {resCpu}% CPU）</span>
              <p class="tiny muted">按默认即可稳定运行，也可在安装前按机器配置调整，装完随时能在「设置与资源」中改。</p>
            </div>
            <Button size="sm" variant="ghost" onclick={() => (customResOpen = !customResOpen)}>
              {customResOpen ? '使用默认' : '自定义配额'}
            </Button>
          </div>
          {#if customResOpen}
            <div class="res-grid">
              <Input label="内存上限 (MiB)" type="number" min={16} max={65536} bind:value={resMem} />
              <Input label="CPU 配额 (%)" type="number" min={5} max={1600} bind:value={resCpu} />
              <Input label="最大进程数" type="number" min={8} max={4096} bind:value={resPids} />
              <Input label="最大文件句柄" type="number" min={64} max={1048576} bind:value={resFds} />
            </div>
          {/if}
        </div>
      {/if}
    </div>

    {#snippet footer()}
      <Button variant="ghost" onclick={() => (detailItem = null)}>关闭</Button>
      {#if item.installed && !item.update_available}
        <Button variant="primary" href="/plugins/{encodeURIComponent(item.plugin_id)}" onclick={() => (detailItem = null)}>打开应用</Button>
      {:else if canInstall}
        <Button
          variant="primary"
          loading={isBusy}
          disabled={!!busyId || !item.download_url}
          onclick={() => void installOne(item, buildInstallResources(item))}
        >
          {#if isBusy}
            {busyText}
          {:else if item.installed && item.update_available}
            更新到 v{item.version}
          {:else}
            一键安装并启用
          {/if}
        </Button>
      {/if}
    {/snippet}
  </Dialog>
{/if}

<!-- 集中版本历史与回滚弹窗 -->
{#if versionTarget}
  <Dialog open={true} title="{versionTarget.name} · 版本与回滚" size="md" onclose={() => (versionTarget = null)}>
    <VersionsTab
      plugin={versionTarget}
      onchanged={() => {
        resources.invalidate('plugins');
        versionTarget = null;
      }}
    />
    {#snippet footer()}
      <Button variant="ghost" onclick={() => (versionTarget = null)}>关闭</Button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--s-4);
    margin-bottom: var(--s-5);
  }
  .head-ops {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .store-section {
    margin-top: var(--s-7);
    padding-top: var(--s-6);
    border-top: 1px solid var(--line);
  }
  .store-alert {
    margin-bottom: var(--s-4);
  }
  h2 {
    margin: 0;
    font-size: var(--fs-xl);
  }
  .head p {
    margin: 2px 0 0;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));
    gap: var(--s-4);
  }
  .app {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
    height: 100%;
    padding: var(--s-5);
    border: 1px solid color-mix(in oklab, var(--line) 75%, transparent);
    border-radius: var(--r-lg);
    background: var(--surface);
    box-shadow: var(--shadow-1);
    transition: box-shadow var(--dur-2) var(--ease), transform var(--dur-2) var(--ease);
  }
  .app:hover {
    box-shadow: var(--shadow-2);
    transform: translateY(-1px);
  }
  .store-card {
    cursor: pointer;
  }
  .store-card.installed {
    opacity: 0.9;
  }
  .app-link {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
  }
  .top {
    display: flex;
    align-items: center;
    gap: var(--s-3);
  }
  .names {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .name {
    font-weight: var(--fw-semibold);
    font-size: var(--fs-md);
  }
  .summary {
    color: var(--text-2);
    font-size: var(--fs-sm);
    line-height: 1.5;
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .dep {
    color: var(--accent-text);
  }
  .meta {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    margin-top: auto;
    padding-top: var(--s-2);
  }
  .meta-act {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .dlg-body {
    display: grid;
    gap: var(--s-4);
  }
  .dlg-block {
    display: grid;
    gap: 6px;
  }
  .dlg-block h4 {
    font-size: var(--fs-sm);
    color: var(--text-2);
  }
  .hl-list {
    display: grid;
    gap: 6px;
    padding-left: 16px;
    list-style: disc;
    font-size: var(--fs-sm);
    color: var(--text);
  }
  .tip-box {
    padding: 10px 12px;
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
    color: var(--text-2);
  }
  .dlg-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
  }
  .res-box {
    display: grid;
    gap: var(--s-3);
    padding: var(--s-3);
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
  }
  .res-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-3);
    flex-wrap: wrap;
  }
  .res-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--s-3);
  }
</style>
