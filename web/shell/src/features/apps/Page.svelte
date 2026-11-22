<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  应用中心 /apps（SPEC §3.4）
  ───────────────────────────────────────────────────────────────
  卡片网格：图标、名称、摘要、版本、运行态；顶部"上传安装"。
  数据复用侧栏的 pluginsResource（同 key 共享，plugins/ 事件自动重取）。
-->
<script lang="ts">
  import { Button, Card, Chip, EmptyState, ErrorState, Skeleton } from '$ui';
  import { describeError } from '$lib/errors';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { pluginsResource } from '../../app/nav';
  import PluginIcon from './PluginIcon.svelte';
  import { runtimeOf } from './runtime';

  let { params: _params }: { params: Record<string, string> } = $props();

  const list = useResource(pluginsResource);
  const canInstall = $derived(session.can('host.plugins:install'));
  const sorted = $derived([...(list.data ?? [])].sort((a, b) => Number(!!a.builtin) - Number(!!b.builtin) || a.name.localeCompare(b.name, 'zh')));
</script>

<div class="head">
  <div>
    <h2>已安装的应用</h2>
    <p class="muted small">{list.data ? `共 ${list.data.length} 个` : ' '}</p>
  </div>
  {#if canInstall}<Button variant="primary" icon="upload" href="/apps/install">上传安装</Button>{/if}
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
    <EmptyState title="还没有安装应用" description="装上系统监控，主页就能看到服务器状态。">
      {#snippet action()}
        {#if canInstall}<Button variant="primary" icon="upload" href="/apps/install">上传安装包</Button>{/if}
      {/snippet}
    </EmptyState>
  </Card>
{:else}
  <ul class="grid">
    {#each sorted as p (p.plugin_id)}
      {@const st = runtimeOf(p)}
      <li>
        <a class="app" href="/apps/{encodeURIComponent(p.plugin_id)}">
          <div class="top">
            <PluginIcon plugin={p} size="lg" />
            <div class="names">
              <span class="name">{p.name}</span>
              <span class="tiny faint mono ellipsis">{p.plugin_id}</span>
            </div>
          </div>
          <p class="summary clamp-2">{p.summary}</p>
          <div class="meta">
            <Chip size="sm" tone={st.tone}>{st.label}</Chip>
            {#if p.active_version}<span class="tiny faint mono">v{p.active_version}</span>{/if}
            {#if p.builtin}<span class="tiny faint">内置</span>{/if}
          </div>
        </a>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .head {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--s-4);
    margin-bottom: var(--s-5);
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
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
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
    text-decoration: none;
    transition:
      box-shadow var(--dur-2) var(--ease),
      transform var(--dur-2) var(--ease);
  }
  .app:hover {
    box-shadow: var(--shadow-2);
    transform: translateY(-2px);
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
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .summary {
    flex: 1;
    margin: 0;
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .meta {
    display: flex;
    align-items: center;
    gap: 10px;
  }
</style>
