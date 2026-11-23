<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Greeting · 主页问候区（SPEC §3.1 第 1 条）
  ──────────────────────────────────────────────────────────────────────────
  表情 + "下午好，{display_name}" + 大标题 + 状态行（节点在线、运行时长）
  标题由小组件 level 聚合：ok 一切安好 / warn 有点状况 / bad 出故障了；
  没有小组件时固定"一切安好"，状态行也只说宿主自己知道的事。
  宿主断线时不再报平安：标题改"暂时连不上"，节点状态未知故不显示状态胶囊。
-->
<script lang="ts">
  import { nodes as nodesApi, system as systemApi } from '$api/endpoints-core';
  import type { Level } from '$api/additions';
  import { health } from '$lib/page.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import Mood from '$ui/Mood.svelte';

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
  function formatUptime(ms: number): string {
    const m = Math.max(0, Math.floor(ms / 60_000));
    if (m < 60) return `${m} 分钟`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h} 小时${m % 60 ? ` ${m % 60} 分钟` : ''}`;
    const d = Math.floor(h / 24);
    return `${d} 天${h % 24 ? ` ${h % 24} 小时` : ''}`;
  }

  const mood = $derived<Level>(health.offline ? 'warn' : level);
  const title = $derived(health.offline ? '暂时连不上' : TITLE[level]);
  const name = $derived(session.user?.display_name || session.user?.username || '');
  const hello = $derived(`${salute(new Date().getHours())}${name ? '，' + name : ''}`);

  /* ---------------------------------------------------------------- 状态行（无权则不显示该项） */
  const nodeRes = session.can('host.nodes:read')
    ? useResource({ key: 'nodes', load: () => nodesApi.list().then((p) => p.items), subjects: ['nodes/'] })
    : null;
  const sysRes = session.can('host.system:read') ? useResource({ key: 'system', load: () => systemApi.info() }) : null;

  const node = $derived(health.offline ? undefined : nodeRes?.data?.find((n) => n.node_id === 'local') ?? nodeRes?.data?.[0]);
  const uptime = $derived.by(() => {
    const t = Date.parse(sysRes?.data?.started_at ?? '');
    return Number.isNaN(t) ? '' : formatUptime(Date.now() - t);
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
            <span class="pill" class:ok={node.status === 'online'} class:bad={node.status === 'offline'}>
              <i aria-hidden="true"></i>
              {node.name}{node.status === 'online' ? ' 在线' : node.status === 'offline' ? ' 离线' : ''}
            </span>
          {/if}
          {#if uptime}<span>{mood === 'ok' ? '已稳定运行' : '已运行'} {uptime}</span>{/if}
        </p>
      {/if}
    </div>
  </div>
  <div class="actions">
    {#if session.can('host.plugins:install')}
      <a class="act ghost" href="/apps/install">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
          <path d="M12 5v14M5 12h14" />
        </svg>
        安装应用
      </a>
    {/if}
    <button type="button" class="act ai" onclick={() => void import('$lib/ai/dock.svelte').then((m) => m.dock.open())}>
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="m12 3 1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9Z" />
      </svg>
      问问 AI
    </button>
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
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 24px;
    padding: 0 10px;
    border-radius: var(--r-pill);
    background: var(--surface-3);
    color: var(--text-2);
    font-size: var(--fs-xs);
    font-weight: var(--fw-medium);
  }
  .pill i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
  }
  .pill.ok {
    background: var(--ok-soft);
    color: var(--ok-text);
  }
  .pill.bad {
    background: var(--bad-soft);
    color: var(--bad-text);
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }
  .act {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 40px;
    padding: 0 18px;
    border-radius: var(--r-pill);
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
    transition: transform var(--dur-1) var(--ease), background var(--dur-1) var(--ease);
  }
  .act:active {
    transform: scale(0.98);
  }
  .act.ghost {
    border: 1px solid var(--line);
    background: var(--surface);
    color: var(--text);
  }
  .act.ghost:hover {
    background: var(--surface-2);
  }
  .act.ai {
    background: var(--ai-grad, linear-gradient(135deg, var(--ai-1), var(--ai-2)));
    color: #fff;
    box-shadow: var(--shadow-1);
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
