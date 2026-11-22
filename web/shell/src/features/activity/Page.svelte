<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  动态 `/activity`（SPEC §3.2）：Tab 动态 / 审计（审计仅 host.audit:read，无权隐藏）
  Tab 写在 URL：?tab=audit
-->
<script lang="ts">
  import { pluginsResource } from '../../app/nav';
  import { useResource } from '$lib/resource.svelte';
  import { router } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { Tabs } from '$ui';
  import ActivityFeed from './ActivityFeed.svelte';
  import AuditPanel from './AuditPanel.svelte';

  let { params: _params }: { params: Record<string, string> } = $props();

  type TabId = 'feed' | 'audit';
  const canAudit = session.can('host.audit:read');
  const plugins = session.can('host.plugins:read') ? useResource(pluginsResource) : null;

  const tab = $derived<TabId>(canAudit && router.query.get('tab') === 'audit' ? 'audit' : 'feed');
  const tabs = $derived([
    { id: 'feed' as TabId, label: '动态' },
    { id: 'audit' as TabId, label: '审计', hidden: !canAudit },
  ]);
</script>

<div class="activity">
  {#if canAudit}
    <Tabs {tabs} value={tab} label="动态与审计" onchange={(id) => router.setQuery({ tab: id === 'feed' ? null : id, status: null, actor: null, app: null })}>
      {#snippet children(id)}
        {#if id === 'audit'}<AuditPanel />{:else}<ActivityFeed plugins={plugins?.data} />{/if}
      {/snippet}
    </Tabs>
  {:else}
    <ActivityFeed plugins={plugins?.data} />
  {/if}
</div>

<style>
  .activity {
    max-width: 960px;
  }
</style>
