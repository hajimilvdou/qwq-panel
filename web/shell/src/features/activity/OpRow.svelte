<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  OpRow · 一条操作动态（主页"最近动态"与动态时间线共用）
  ──────────────────────────────────────────────────────────────────────────
  头像（人=字母、AI=极光球、系统=齿轮）· "谁 做了什么 对什么" · 状态 · 相对时间
  整行是指向 /activity/:id 的链接；状态优先取 liveOps 的实时推送。
-->
<script lang="ts">
  import type { Op } from '$api/endpoints';
  import { actorView, opObject, opSentence, STATUS, type ActionCatalog } from '$lib/activity';
  import { relativeTime, dateTime } from '$lib/format';
  import { liveOps } from '$lib/operations.svelte';
  import { session } from '$lib/session.svelte';
  import { Avatar, Chip } from '$ui';

  interface Props {
    op: Op;
    catalog?: ActionCatalog;
    pluginName?: (id: string) => string | undefined;
  }
  let { op, catalog, pluginName }: Props = $props();

  const who = $derived(actorView(op.actor, session.user?.user_id));
  const what = $derived(opSentence(op, catalog));
  const object = $derived(opObject(op, pluginName));
  const status = $derived(liveOps.get(op.operation_id)?.status ?? op.status);
  const s = $derived(STATUS[status]);
</script>

<a class="row" href="/activity/{encodeURIComponent(op.operation_id)}">
  <Avatar kind={who.face} name={who.name} size="md" />
  <div class="body">
    <p class="line">
      <span class="who">{who.name}</span>
      <span class="what">{what}{#if object}<span class="obj"> {object}</span>{/if}</span>
    </p>
    <p class="meta">
      {#if status !== 'SUCCEEDED'}<Chip tone={s.tone} size="sm">{s.label}</Chip>{/if}
      {#if who.ai}<Chip tone="ai" size="sm" dot={false}>AI 代你操作</Chip>{/if}
    </p>
  </div>
  <time datetime={op.created_at} title={dateTime(op.created_at)}>{relativeTime(op.created_at)}</time>
</a>

<style>
  .row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px var(--s-2);
    margin: 0 calc(var(--s-2) * -1);
    border-radius: var(--r-md);
    color: inherit;
    text-decoration: none;
    transition: background var(--dur-1) var(--ease);
  }
  .row:hover {
    background: var(--surface-2);
  }
  .body {
    flex: 1;
    min-width: 0;
  }
  .line {
    line-height: 1.5;
    overflow-wrap: anywhere;
  }
  .who {
    font-weight: var(--fw-semibold);
  }
  .what {
    margin-left: 4px;
    color: var(--text-2);
  }
  .obj {
    color: var(--text);
    font-weight: var(--fw-medium);
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .meta:not(:empty) {
    margin-top: 6px;
  }
  time {
    flex: none;
    padding-left: var(--s-3);
    padding-top: 2px;
    color: var(--text-3);
    font-size: var(--fs-xs);
    white-space: nowrap;
  }
</style>
