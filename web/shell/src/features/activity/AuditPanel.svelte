<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  AuditPanel · 审计 Tab（SPEC §3.2，缺口 7；仅 host.audit:read）
  ──────────────────────────────────────────────────────────────────────────
  表格：时间 / 行为人 / 动作 / 对象 / 结果；筛选提交后重取，cursor 翻页。
  id 一律等宽；detail 已由服务端脱敏，这里只按文本展示。
-->
<script lang="ts">
  import { audit as auditApi } from '$api/endpoints';
  import type { AuditEntry } from '$api/additions';
  import { actorView } from '$lib/activity';
  import { describeError } from '$lib/errors';
  import { dateTime } from '$lib/format';
  import { session } from '$lib/session.svelte';
  import { Avatar, Button, Chip, DataTable, EmptyState, ErrorState, Input, Select, type Tone } from '$ui';

  interface Props {
    /** 限定某个 operation（详情页内嵌时） */
    operationId?: string;
    compact?: boolean;
  }
  let { operationId, compact = false }: Props = $props();

  const OUTCOME: Record<AuditEntry['outcome'], { label: string; tone: Tone }> = {
    success: { label: '成功', tone: 'ok' },
    failure: { label: '失败', tone: 'bad' },
    denied: { label: '被拒绝', tone: 'warn' },
  };
  const outcomeOptions = [
    { value: '', label: '全部结果' },
    { value: 'success', label: '成功' },
    { value: 'failure', label: '失败' },
    { value: 'denied', label: '被拒绝' },
  ];

  /* ---------------------------------------------------------------- 筛选（表单提交才生效） */
  let actor = $state('');
  let action = $state('');
  let outcome = $state<AuditEntry['outcome'] | ''>('');

  /* ---------------------------------------------------------------- 数据 */
  let items = $state<AuditEntry[]>([]);
  let next = $state<string | undefined>(undefined);
  let phase = $state<'loading' | 'ready' | 'error'>('loading');
  let error = $state<unknown>(null);
  let loadingMore = $state(false);
  let gen = 0;

  const query = () => ({
    actor: actor.trim() || undefined,
    action: action.trim() || undefined,
    outcome: outcome || undefined,
    operation_id: operationId,
    limit: compact ? 20 : 50,
  });

  async function load(cursor?: string) {
    const g = cursor ? gen : ++gen;
    if (cursor) loadingMore = true;
    else phase = 'loading';
    try {
      const page = await auditApi.list({ ...query(), cursor });
      if (g !== gen) return;
      items = cursor ? [...items, ...page.items] : page.items;
      next = page.meta?.next_cursor;
      phase = 'ready';
      error = null;
    } catch (err) {
      if (g !== gen) return;
      error = err;
      if (!cursor) phase = 'error';
    } finally {
      if (g === gen) loadingMore = false;
    }
  }

  $effect(() => {
    void load();
  });

  const rows = $derived(
    items.map((e) => ({ id: e.audit_id, at: e.at, actor: e.actor, action: e.action, subject: e.subject, outcome: e.outcome, op: e.operation_id ?? '' })),
  );
  const columns = [
    { key: 'at', label: '时间', width: '170px' },
    { key: 'actor', label: '行为人', width: '160px' },
    { key: 'action', label: '动作', mono: true },
    { key: 'subject', label: '对象', mono: true },
    { key: 'outcome', label: '结果', width: '96px' },
  ];
  const err = $derived(phase === 'error' ? describeError(error) : null);
  const moreErr = $derived(phase === 'ready' && error ? describeError(error).message : '');
  const filtered = $derived(Boolean(actor || action || outcome));
</script>

{#if !compact}
  <form
    class="filters"
    aria-label="筛选审计"
    onsubmit={(e) => {
      e.preventDefault();
      void load();
    }}
  >
    <Input label="行为人" hideLabel placeholder="行为人（用户名或 id）" bind:value={actor} />
    <Input label="动作" hideLabel placeholder="动作，如 host.users" mono bind:value={action} />
    <Select label="结果" hideLabel options={outcomeOptions} bind:value={outcome} />
    <Button type="submit" variant="soft" icon="search">筛选</Button>
  </form>
{/if}

{#if err}
  <ErrorState compact={compact} message={err.message} requestId={err.requestId} onretry={() => load()} />
{:else}
  <DataTable caption="审计记录" {columns} {rows} rowKey={(r) => r.id} loading={phase === 'loading'}>
    {#snippet cell(r, key)}
      {#if key === 'at'}
        <time datetime={r.at}>{dateTime(r.at)}</time>
      {:else if key === 'actor'}
        {@const v = actorView(r.actor, session.user?.user_id)}
        <span class="who"><Avatar kind={v.face} name={v.name} size="sm" />{v.name}</span>
      {:else if key === 'outcome'}
        <Chip tone={OUTCOME[r.outcome].tone} size="sm">{OUTCOME[r.outcome].label}</Chip>
      {:else if key === 'action'}
        {#if r.op && !operationId}
          <a href="/activity/{encodeURIComponent(r.op)}">{r.action}</a>
        {:else}{r.action}{/if}
      {:else}
        {r.subject}
      {/if}
    {/snippet}
    {#snippet empty()}
      <EmptyState compact title={filtered ? '没有符合条件的记录' : '还没有审计记录'} />
    {/snippet}
  </DataTable>

  {#if next || moreErr}
    <div class="more">
      {#if next}<Button variant="ghost" loading={loadingMore} onclick={() => load(next)}>加载更多</Button>{/if}
      {#if moreErr}<p class="more-err" role="alert">{moreErr}</p>{/if}
    </div>
  {/if}
{/if}

<style>
  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: var(--s-4);
  }
  .filters > :global(*:not(button)) {
    min-width: 160px;
  }
  .who {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  time {
    color: var(--text-2);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .more {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--s-2);
    margin-top: var(--s-4);
  }
  .more-err {
    color: var(--bad-text);
    font-size: var(--fs-sm);
  }
</style>
