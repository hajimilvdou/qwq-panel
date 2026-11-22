<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  主页 `/`（SPEC §3.1）
  ──────────────────────────────────────────────────────────────────────────
    问候区（level 聚合）
    小组件栅格（运行中插件的 ui.widgets）  · 无小组件 → 引导卡
    最近动态 span 7  │  我的应用 span 5
  安静：无横幅、无待办；需要人处理的事只走悬浮窗。
-->
<script lang="ts">
  import type { Level } from '$api/additions';
  import { pluginsResource } from '../../app/nav';
  import { describeError } from '$lib/errors';
  import { health } from '$lib/page.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { collectWidgets } from '$lib/widgets';
  import WidgetGrid from '$lib/widgets/WidgetGrid.svelte';
  import { Button, Card, ErrorState, Mood, Skeleton } from '$ui';
  import AppsCard from './AppsCard.svelte';
  import Greeting from './Greeting.svelte';
  import RecentCard from './RecentCard.svelte';

  let { params: _params }: { params: Record<string, string> } = $props();

  const canPlugins = session.can('host.plugins:read');
  const canOps = session.can('host.operations:read');
  const plugins = canPlugins ? useResource(pluginsResource) : null;

  const slots = $derived(collectWidgets(plugins?.data));
  let level = $state<Level>('ok');

  /* 没有小组件时不声称监测了什么：问候固定"一切安好"，侧栏表情复位 */
  const shown = $derived<Level>(slots.length ? level : 'ok');
  $effect(() => {
    if (!slots.length) health.level = 'ok';
  });

  const pluginsErr = $derived(plugins?.status === 'error' ? describeError(plugins.error) : null);
</script>

<div class="home">
  <Greeting level={shown} />

  {#if plugins}
    {#if pluginsErr}
      <Card>
        <ErrorState compact message={pluginsErr.message} requestId={pluginsErr.requestId} onretry={plugins.refresh} />
      </Card>
    {:else if !plugins.data}
      <div class="sk-grid" aria-hidden="true">
        {#each [0, 1, 2, 3] as i (i)}<Card><Skeleton lines={3} /></Card>{/each}
      </div>
    {:else if slots.length}
      <WidgetGrid {slots} label="服务器概览" onlevel={(l) => (level = l)} />
    {:else}
      <Card>
        <div class="guide">
          <Mood mood="ok" size="md" />
          <div>
            <h2>装上系统监控，这里就能看到服务器状态</h2>
            <p>CPU、内存、磁盘和网络都由应用提供，装好后会自动出现在主页。</p>
          </div>
          <Button variant="primary" href="/apps">去应用中心</Button>
        </div>
      </Card>
    {/if}
  {/if}

  <div class="bottom">
    {#if canOps}
      <div class="recent"><RecentCard plugins={plugins?.data} /></div>
    {/if}
    {#if plugins?.data}
      <div class="apps" class:full={!canOps}><AppsCard plugins={plugins.data} /></div>
    {/if}
  </div>
</div>

<style>
  .home {
    display: flex;
    flex-direction: column;
    gap: var(--gap);
  }
  .sk-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: var(--gap);
  }

  /* ---------------------------------------------------------------- 引导卡 */
  .guide {
    display: flex;
    align-items: center;
    gap: var(--s-4);
  }
  .guide div {
    flex: 1;
    min-width: 0;
  }
  .guide h2 {
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .guide p {
    margin-top: 4px;
    color: var(--text-3);
    font-size: var(--fs-sm);
  }

  /* ---------------------------------------------------------------- 底部两栏 */
  .bottom {
    display: grid;
    grid-template-columns: repeat(12, minmax(0, 1fr));
    gap: var(--gap);
    align-items: start;
  }
  .recent {
    grid-column: span 7;
  }
  .apps {
    grid-column: span 5;
  }
  .apps.full {
    grid-column: span 12;
  }

  @media (max-width: 1180px) {
    .sk-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .recent,
    .apps {
      grid-column: span 12;
    }
  }
  @media (max-width: 860px) {
    .guide {
      flex-direction: column;
      align-items: flex-start;
    }
  }
</style>
