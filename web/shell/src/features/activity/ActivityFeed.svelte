<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ActivityFeed · 动态时间线（SPEC §3.2）
  ──────────────────────────────────────────────────────────────────────────
  筛选写在 URL（status / actor / app），按天分组；operation.updated 与
  operations/ 的 resource.changed 合并 300ms 后走 since_revision 增量，resync 全量重取。
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { operations as opsApi } from '$api/endpoints';
  import type { Plugin } from '$api/types';
  import { ACTOR_FILTERS, actionCatalogResource, groupByDay, STATUS_FILTERS, type StatusFilter } from '$lib/activity';
  import { describeError } from '$lib/errors';
  import { events } from '$lib/events.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { router } from '$lib/router.svelte';
  import { Button, EmptyState, ErrorState, Select, Skeleton, Timeline } from '$ui';
  import { OpsFeed } from './feed.svelte';
  import OpRow from './OpRow.svelte';

  interface Props {
    plugins?: readonly Plugin[];
  }
  let { plugins = [] }: Props = $props();

  const catalog = useResource(actionCatalogResource);
  const pluginName = (id: string) => plugins.find((p) => p.plugin_id === id)?.name;

  /* ---------------------------------------------------------------- 筛选（URL 为唯一来源） */
  const status = $derived((router.query.get('status') ?? '') as StatusFilter | '');
  const actor = $derived(router.query.get('actor') ?? '');
  const app = $derived(router.query.get('app') ?? '');
  const filtered = $derived(Boolean(status || actor || app));

  const statusOptions = [{ value: '', label: '全部状态' }, ...STATUS_FILTERS.map((f) => ({ value: f.value, label: f.label }))];
  const actorOptions = [{ value: '', label: '所有人' }, ...ACTOR_FILTERS];
  const appOptions = $derived([{ value: '', label: '全部应用' }, ...plugins.map((p) => ({ value: p.plugin_id, label: p.name }))]);

  /* ---------------------------------------------------------------- 数据 */
  const feed = new OpsFeed((q) =>
    opsApi.list({
      ...q,
      status: STATUS_FILTERS.find((f) => f.value === status)?.statuses,
      actor_kind: actor || undefined,
      plugin_id: app || undefined,
    }),
  );

  $effect(() => {
    void [status, actor, app];
    untrack(() => void feed.reload());
  });

  $effect(() => {
    let t: ReturnType<typeof setTimeout> | null = null;
    const soon = () => {
      t ??= setTimeout(() => {
        t = null;
        void feed.sync();
      }, 300);
    };
    const offOp = events.on('operation.updated', soon);
    const offRes = events.on('resource.changed', (e) => {
      const subject = (e.payload as { subject?: string })?.subject ?? e.subject;
      if (subject?.startsWith('operations/')) soon();
    });
    const offResync = events.onResync(() => void feed.reload());
    return () => {
      if (t) clearTimeout(t);
      offOp();
      offRes();
      offResync();
    };
  });

  const groups = $derived(groupByDay(feed.items, (o) => o.created_at));
  const err = $derived(feed.status === 'error' ? describeError(feed.error) : null);
  const moreErr = $derived(feed.moreError ? describeError(feed.moreError).message : '');
</script>

<div class="filters" role="group" aria-label="筛选动态">
  <Select label="状态" hideLabel options={statusOptions} value={status} onchange={(e) => router.setQuery({ status: e.currentTarget.value })} />
  <Select label="发起者" hideLabel options={actorOptions} value={actor} onchange={(e) => router.setQuery({ actor: e.currentTarget.value })} />
  {#if plugins.length}
    <Select label="应用" hideLabel options={appOptions} value={app} onchange={(e) => router.setQuery({ app: e.currentTarget.value })} />
  {/if}
  {#if filtered}
    <Button variant="plain" size="sm" onclick={() => router.setQuery({ status: null, actor: null, app: null })}>清除筛选</Button>
  {/if}
</div>

{#if err}
  <ErrorState message={err.message} requestId={err.requestId} onretry={feed.reload} />
{:else if feed.status === 'loading'}
  <Skeleton lines={8} height={22} label="动态加载中" />
{:else if !feed.items.length}
  <EmptyState
    title={filtered ? '没有符合条件的动态' : '还没有任何操作'}
    description={filtered ? '换个筛选条件试试' : '你、同事或 AI 做的每一次改动都会记在这里'}
  />
{:else}
  <Timeline label="操作动态" {groups} itemKey={(o) => o.operation_id}>
    {#snippet item(op)}
      <OpRow {op} catalog={catalog.data} {pluginName} />
    {/snippet}
  </Timeline>

  <div class="more">
    {#if feed.next}
      <Button variant="ghost" loading={feed.loadingMore} onclick={feed.more}>加载更多</Button>
    {:else if feed.items.length > 10}
      <p class="end">已经到底了</p>
    {/if}
    {#if moreErr}<p class="more-err" role="alert">{moreErr}</p>{/if}
  </div>
{/if}

<style>
  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    margin-bottom: var(--s-4);
  }
  .filters > :global(*) {
    min-width: 140px;
  }
  .more {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--s-2);
    margin-top: var(--s-5);
  }
  .end {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .more-err {
    color: var(--bad-text);
    font-size: var(--fs-sm);
  }
</style>
