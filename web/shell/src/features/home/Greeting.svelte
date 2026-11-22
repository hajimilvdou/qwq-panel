<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Greeting · 主页问候区（SPEC §3.1 第 1 条）
  ──────────────────────────────────────────────────────────────────────────
  表情 + "下午好，{display_name}" + 大标题 + 状态行（节点在线、运行时长）
  标题由小组件 level 聚合：ok 一切安好 / warn 有点状况 / bad 出故障了；
  没有小组件时固定"一切安好"，状态行也只说宿主自己知道的事。
  宿主断线时不再报平安：标题改"暂时连不上"，节点状态未知故不显示 Chip。
-->
<script lang="ts">
  import { nodes as nodesApi, system as systemApi } from '$api/endpoints';
  import type { Level } from '$api/additions';
  import { dock } from '$lib/ai/dock.svelte';
  import { events } from '$lib/events.svelte';
  import { duration } from '$lib/format';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { Button, Chip, Mood } from '$ui';

  interface Props {
    level: Level;
  }
  let { level }: Props = $props();

  const TITLE: Record<Level, string> = { ok: '一切安好', warn: '有点状况', bad: '出故障了' };

  function salute(h: number): string {
    if (h >= 5 && h < 11) return '早上好';
    if (h >= 11 && h < 13) return '中午好';
    if (h >= 13 && h < 18) return '下午好';
    if (h >= 18 && h < 23) return '晚上好';
    return '夜深了';
  }
  const mood = $derived<Level>(events.offline ? 'warn' : level);
  const title = $derived(events.offline ? '暂时连不上' : TITLE[level]);
  const name = $derived(session.user?.display_name || session.user?.username || '');
  const hello = $derived(`${salute(new Date().getHours())}${name ? '，' + name : ''}`);

  /* ---------------------------------------------------------------- 状态行（无权则不显示该项） */
  const nodeRes = session.can('host.nodes:read')
    ? useResource({ key: 'nodes', load: () => nodesApi.list().then((p) => p.items), subjects: ['nodes/'] })
    : null;
  const sysRes = session.can('host.system:read') ? useResource({ key: 'system', load: () => systemApi.info() }) : null;

  const node = $derived(events.offline ? undefined : nodeRes?.data?.find((n) => n.node_id === 'local') ?? nodeRes?.data?.[0]);
  const uptime = $derived.by(() => {
    const t = Date.parse(sysRes?.data?.started_at ?? '');
    return Number.isNaN(t) ? '' : duration(Date.now() - t);
  });
</script>

<section class="hero">
  <div class="main">
    <Mood {mood} size="lg" />
    <div>
      <p class="hello">{hello}</p>
      <h2 class="title">{title}</h2>
      {#if node || uptime}
        <p class="sub">
          {#if node}
            <Chip tone={node.status === 'online' ? 'ok' : node.status === 'offline' ? 'bad' : 'neutral'} size="sm">
              {node.name}{node.status === 'online' ? ' 在线' : node.status === 'offline' ? ' 离线' : ''}
            </Chip>
          {/if}
          {#if uptime}<span>{mood === 'ok' ? '已稳定运行' : '已运行'} {uptime}</span>{/if}
        </p>
      {/if}
    </div>
  </div>
  <div class="actions">
    {#if session.can('host.plugins:install')}
      <Button variant="ghost" icon="plus" href="/apps/install">安装应用</Button>
    {/if}
    <Button variant="ai" icon="ai" onclick={() => dock.open()}>问问 AI</Button>
  </div>
</section>

<style>
  .hero {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-5);
    padding: var(--s-2) 0 var(--s-6);
  }
  .main {
    display: flex;
    align-items: center;
    gap: 18px;
    min-width: 0;
  }
  .hello {
    color: var(--text-2);
    font-weight: var(--fw-medium);
  }
  .title {
    margin-top: 2px;
    font-size: var(--fs-4xl);
    font-weight: var(--fw-bold);
    line-height: 1.2;
    letter-spacing: -0.01em;
  }
  .sub {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    margin-top: var(--s-2);
    color: var(--text-3);
    font-size: var(--fs-sm);
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }

  @media (max-width: 860px) {
    .hero {
      flex-direction: column;
      align-items: flex-start;
    }
    .title {
      font-size: var(--fs-3xl);
    }
  }
</style>
