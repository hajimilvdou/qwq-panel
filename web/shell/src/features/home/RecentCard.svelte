<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  RecentCard · 主页"最近动态"（GET /operations?limit=6，operation.updated 驱动刷新）
-->
<script lang="ts">
  import { operations as opsApi } from '$api/endpoints';
  import type { Plugin } from '$api/types';
  import { actionCatalogResource } from '$lib/activity';
  import { describeError } from '$lib/errors';
  import { useResource } from '$lib/resource.svelte';
  import { Button, Card, EmptyState, ErrorState, Skeleton } from '$ui';
  import OpRow from '../activity/OpRow.svelte';

  interface Props {
    plugins?: readonly Plugin[];
  }
  let { plugins = [] }: Props = $props();

  const recent = useResource({
    key: 'ops-recent',
    load: () => opsApi.list({ limit: 6 }).then((p) => p.items),
    subjects: ['operations/'],
    events: ['operation.updated'],
  });
  const catalog = useResource(actionCatalogResource);
  const pluginName = (id: string) => plugins.find((p) => p.plugin_id === id)?.name;
  const err = $derived(recent.status === 'error' ? describeError(recent.error) : null);
</script>

<Card title="最近动态" subtitle="你、同事和 AI 做的每一次改动" icon="clock" color="teal">
  {#snippet actions()}
    <Button variant="plain" size="sm" href="/activity">全部</Button>
  {/snippet}

  {#if err}
    <ErrorState compact message={err.message} requestId={err.requestId} onretry={recent.refresh} />
  {:else if !recent.data}
    <Skeleton lines={5} height={18} label="最近动态加载中" />
  {:else if !recent.data.length}
    <EmptyState compact title="还没有任何操作" description="你、同事或 AI 做的改动都会出现在这里" />
  {:else}
    <ol>
      {#each recent.data as op (op.operation_id)}
        <li><OpRow {op} catalog={catalog.data} {pluginName} /></li>
      {/each}
    </ol>
  {/if}
</Card>

<style>
  li + li {
    border-top: 1px solid var(--line);
  }
</style>
