<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ToolRow · 工具调用折叠行（action、状态、耗时；展开看 action id 与错误；链接操作详情）
-->
<script lang="ts">
  import { Chip, Icon, Spinner } from '$ui';
  import type { Tone } from '$ui';
  import type { AgentToolStatus } from '$api/types';
  import { duration } from '$lib/format';
  import type { ToolItem } from '$lib/ai/transcript';

  let { item }: { item: ToolItem } = $props();

  const uid = $props.id();
  let open = $state(false);

  const STATUS: Record<AgentToolStatus, { label: string; tone: Tone }> = {
    proposed: { label: '准备中', tone: 'neutral' },
    running: { label: '进行中', tone: 'ai' },
    awaiting_approval: { label: '等你确认', tone: 'warn' },
    succeeded: { label: '完成', tone: 'ok' },
    failed: { label: '失败', tone: 'bad' },
    rejected: { label: '已拒绝', tone: 'neutral' },
    cancelled: { label: '已取消', tone: 'neutral' },
  };

  const st = $derived(STATUS[item.status] ?? STATUS.running);
  /* 人话优先；没有时显示 action 末段 */
  const label = $derived(item.text || item.action.split('/').pop() || '工具调用');
  const took = $derived(item.startedAt && item.endedAt ? duration(item.endedAt - item.startedAt) : '');
</script>

<div class="tool" class:open>
  <button type="button" class="head" aria-expanded={open} aria-controls="{uid}-d" onclick={() => (open = !open)}>
    <span class="ic">
      {#if item.status === 'running'}<Spinner size={14} label="进行中" />{:else}<Icon name="gear" size={15} />{/if}
    </span>
    <span class="label">{label}</span>
    {#if took}<span class="took">{took}</span>{/if}
    <Chip size="sm" tone={st.tone}>{st.label}</Chip>
    <span class="chev"><Icon name="chevron" size={14} /></span>
  </button>
  {#if open}
    <div id="{uid}-d" class="detail">
      <p><span class="k">动作</span> <code>{item.action || '—'}</code></p>
      {#if item.error}<p class="err"><span class="k">错误</span> {item.error}</p>{/if}
      {#if item.operationId}
        <p><a href="/activity/{encodeURIComponent(item.operationId)}">查看操作详情</a></p>
      {/if}
    </div>
  {/if}
</div>

<style>
  .tool {
    border-radius: var(--r-md);
    background: var(--surface-2);
    font-size: var(--fs-sm);
  }
  .head {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    width: 100%;
    min-height: 40px;
    padding: 0 var(--s-3);
    border: 0;
    background: none;
    color: var(--text-2);
    font: inherit;
    text-align: left;
    cursor: pointer;
    border-radius: inherit;
  }
  .head:hover {
    background: var(--surface-3);
  }
  .ic {
    display: inline-flex;
    color: var(--text-3);
  }
  .label {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .took {
    color: var(--text-3);
    font-size: var(--fs-xs);
    font-variant-numeric: tabular-nums;
  }
  .chev {
    display: inline-flex;
    color: var(--text-3);
    transition: transform var(--dur-1) var(--ease);
  }
  .open .chev {
    transform: rotate(90deg);
  }
  .detail {
    padding: 0 var(--s-3) var(--s-3) calc(var(--s-3) + 15px + var(--s-2));
    display: grid;
    gap: 4px;
  }
  .detail p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .k {
    color: var(--text-3);
    margin-right: 4px;
  }
  code {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
  }
  .err {
    color: var(--bad-text);
  }
  a {
    color: var(--accent-text);
  }
</style>
