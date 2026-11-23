<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  应用中心 /apps（SPEC §3.4）
  ───────────────────────────────────────────────────────────────
  上方：已安装的应用网格 + 右上角"上传安装"；
  下方：官方插件商店（自动匹配当前面板版本与 CPU 架构，一键下载、验签、安装并启用）。
-->
<script lang="ts">
  import { Alert, Button, Card, Chip, EmptyState, ErrorState, Skeleton, Tile } from '$ui';
  import type { IconName } from '$ui/icons';
  import type { CategoryColor, PluginCatalogItem } from '$api/additions';
  import { plugins as pluginsApi } from '$api/endpoints-plugins';
  import { describeError } from '$lib/errors';
  import { bytes } from '$lib/format';
  import { resources, useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';
  import { pluginsResource } from '../../app/nav';
  import {
    installOfficialPlugin,
    type OfficialInstallProgress,
    type OfficialInstallStage,
  } from './official-install';
  import PluginIcon from './PluginIcon.svelte';
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

  /** 未安装的官方插件排在前面，已安装的排在后面方便查看或一键更新 */
  const storeItems = $derived.by(() => {
    const items = [...(catalog.data?.items ?? [])];
    return items.sort((a, b) => Number(a.installed) - Number(b.installed));
  });

  const STAGE_LABEL: Record<OfficialInstallStage, string> = {
    downloading: '下载中…',
    verifying: '验签中…',
    installing: '安装中…',
    updating: '更新中…',
    enabling: '启动中…',
  };

  const VISUAL_MAP: Record<string, { icon: IconName; color: CategoryColor }> = {
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

  async function installOne(item: PluginCatalogItem) {
    if (busyId || !canInstall) return;
    busyId = item.plugin_id;
    busyText = '准备下载…';
    storeErr = '';
    try {
      const res = await installOfficialPlugin(item.plugin_id, {
        items: catalog.data?.items,
        onProgress: (p: OfficialInstallProgress) => {
          const prefix = p.totalSteps > 1 ? `(${p.stepIndex}/${p.totalSteps}) ` : '';
          busyText = `${prefix}${STAGE_LABEL[p.stage]}`;
        },
      });
      resources.invalidate('plugins');
      resources.invalidate('plugin-catalog');
      if (res.updated.length > 0) {
        toasts.success(`${item.name} 已更新至 v${item.version}`);
      } else if (res.installed.length > 1) {
        toasts.success(`已安装并启用 ${item.name} 及依赖插件`);
      } else {
        toasts.success(`${item.name} 已安装并启用`);
      }
    } catch (err) {
      storeErr = err instanceof Error ? err.message : describeError(err).message;
    } finally {
      busyId = null;
      busyText = '';
    }
  }
</script>

<div class="head">
  <div>
    <h2>已安装的应用</h2>
    <p class="muted small">{list.data ? `共 ${list.data.length} 个` : ' '}</p>
  </div>
  {#if canInstall}<Button variant="primary" icon="upload" href="/apps/install">上传 / URL 安装</Button>{/if}
</div>

{#if list.status === 'loading'}
  <div class="grid">
    {#each [0, 1, 2] as i (i)}<Card><Skeleton lines={3} height={16} /></Card>{/each}
  </div>
{:else if list.status === 'error' && !list.data}
  <Card>
    <ErrorState message={describeError(list.error).message} requestId={describeError(list.error).requestId} onretry={list.refresh} />
  </Card>
{:else if !sorted.length}
  <Card>
    <EmptyState title="还没有安装应用" description="可以直接在下方官方插件商店一键安装，或上传自定义 .qwqpkg 安装包。">
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
      <li>
        <div class="app">
          <a class="app-link" href="/apps/{encodeURIComponent(p.plugin_id)}">
            <div class="top">
              <PluginIcon plugin={p} size="lg" />
              <div class="names">
                <span class="name">{p.name}</span>
                <span class="tiny faint mono ellipsis">{p.plugin_id}</span>
              </div>
            </div>
            <p class="summary clamp-2">{p.summary}</p>
          </a>
          <div class="meta">
            <Chip size="sm" tone={st.tone}>{st.label}</Chip>
            {#if p.active_version}<span class="tiny faint mono">v{p.active_version}</span>{/if}
            {#if p.builtin}<span class="tiny faint">内置</span>{/if}
            {#if canInstall && cat?.update_available && cat.download_url}
              <div class="meta-act">
                <Button
                  size="sm"
                  variant="ghost"
                  loading={busyId === cat.plugin_id}
                  disabled={!!busyId}
                  onclick={() => void installOne(cat)}
                >
                  {busyId === cat.plugin_id ? busyText : `更新到 v${cat.version}`}
                </Button>
              </div>
            {/if}
          </div>
        </div>
      </li>
    {/each}
  </ul>
{/if}

<section class="store-section" aria-label="官方插件商店">
  <div class="head store-head">
    <div>
      <h2>官方插件商店</h2>
      <p class="muted small">
        {#if catalog.data}
          官方预构建签名包 · {catalog.data.release} · <span class="mono">{catalog.data.platform}</span>（点击一键下载、验签并启用）
        {:else}
          正在加载官方预构建插件目录…
        {/if}
      </p>
    </div>
    <Button variant="ghost" icon="refresh" loading={refreshing} disabled={!!busyId} onclick={() => void refreshCatalog()}>
      刷新目录
    </Button>
  </div>

  {#if storeErr}
    <div class="store-alert">
      <Alert tone="bad" title="操作未能完成">{storeErr}</Alert>
    </div>
  {/if}

  {#if catalog.data && !catalog.data.online}
    <div class="store-alert">
      <Alert tone="warn" title="当前处于离线目录回退模式">
        暂时无法连接 GitHub Releases 拉取最新插件索引，已展示内置官方插件列表；可点击「刷新目录」重试，或通过右上角「上传 / URL 安装」离线安装。
      </Alert>
    </div>
  {/if}

  {#if catalog.status === 'loading' && !catalog.data}
    <div class="grid">
      {#each [0, 1, 2, 3] as i (i)}<Card><Skeleton lines={3} height={16} /></Card>{/each}
    </div>
  {:else if catalog.status === 'error' && !catalog.data}
    <Card>
      <ErrorState message={describeError(catalog.error).message} onretry={catalog.refresh} />
    </Card>
  {:else}
    <ul class="grid">
      {#each storeItems as item (item.plugin_id)}
        {@const vis = visualOf(item.plugin_id)}
        {@const isBusy = busyId === item.plugin_id}
        <li>
          <div class="app store-card" class:installed={item.installed}>
            <div class="top">
              <Tile icon={vis.icon} color={vis.color} size="lg" />
              <div class="names">
                <span class="name">{item.name}</span>
                <span class="tiny faint mono ellipsis">{item.plugin_id}</span>
              </div>
            </div>
            <p class="summary clamp-2">{item.summary}</p>
            <div class="badges">
              {#if item.memory_max_mb > 0}
                <span class="tiny faint mono">~{item.memory_max_mb} MiB</span>
              {/if}
              {#if item.size > 0}
                <span class="tiny faint mono">{bytes(item.size)}</span>
              {/if}
              {#if item.version}
                <span class="tiny faint mono">v{item.version}</span>
              {/if}
              {#if item.dependencies.length > 0 && !item.installed}
                <span class="tiny dep">自动连带安装 {item.dependencies.join(', ')}</span>
              {/if}
            </div>
            <div class="meta store-foot">
              {#if item.installed && !item.update_available}
                <Chip size="sm" tone="ok">已安装</Chip>
                <div class="meta-act">
                  <Button size="sm" variant="ghost" href="/apps/{encodeURIComponent(item.plugin_id)}">管理</Button>
                </div>
              {:else if item.installed && item.update_available}
                <Chip size="sm" tone="info">有新版本</Chip>
                {#if canInstall}
                  <div class="meta-act">
                    <Button
                      size="sm"
                      variant="primary"
                      loading={isBusy}
                      disabled={!!busyId || !item.download_url}
                      onclick={() => void installOne(item)}
                    >
                      {isBusy ? busyText : `更新到 v${item.version}`}
                    </Button>
                  </div>
                {/if}
              {:else}
                <Chip size="sm" tone="neutral">官方预构建</Chip>
                {#if canInstall}
                  <div class="meta-act">
                    <Button
                      size="sm"
                      variant="primary"
                      loading={isBusy}
                      disabled={!!busyId || !item.download_url}
                      onclick={() => void installOne(item)}
                    >
                      {isBusy ? busyText : '一键安装'}
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

<style>
  .head {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--s-4);
    margin-bottom: var(--s-5);
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
    gap: var(--s-5);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .app {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
    height: 100%;
    padding: var(--s-5);
    border: 1px solid color-mix(in oklab, var(--line) 70%, transparent);
    border-radius: var(--r-lg);
    background: var(--surface);
    box-shadow: var(--shadow-1);
    color: inherit;
    transition:
      box-shadow var(--dur-2) var(--ease),
      transform var(--dur-2) var(--ease);
  }
  .app:hover {
    box-shadow: var(--shadow-2);
    transform: translateY(-2px);
  }
  .app-link {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
    color: inherit;
    text-decoration: none;
  }
  .store-card.installed {
    opacity: 0.88;
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
    margin: 0;
    color: var(--text-2);
    font-size: var(--fs-sm);
    line-height: 1.5;
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
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
  }
</style>
