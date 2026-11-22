<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ApprovalHistory · 操作详情里的审批记录（SPEC §3.2：历史审批在此查看）
  ──────────────────────────────────────────────────────────────────────────
  只读：谁发起、何时、谁批准/拒绝、备注。待批准时引导到悬浮窗处理
  （审批卡 ApprovalCard 归悬浮窗所有，这里不重复实现决策流程）。
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { approvals as approvalsApi } from '$api/endpoints';
  import type { ApprovalStatus } from '$api/types';
  import { actorView } from '$lib/activity';
  import { dock } from '$lib/ai/dock.svelte';
  import { describeError } from '$lib/errors';
  import { dateTime, relativeTime } from '$lib/format';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { Avatar, Button, Card, Chip, ErrorState, Skeleton, type Tone } from '$ui';

  let props: { approvalId: string } = $props();
  /* 一个 operation 至多一个审批，父级随 operation 重建，id 不变 */
  const approvalId = untrack(() => props.approvalId);

  const r = useResource({
    key: `approval:${approvalId}`,
    load: () => approvalsApi.get(approvalId),
    subjects: [`approvals/${approvalId}`],
    revisionOf: (a) => a.revision,
  });

  const STATE: Record<ApprovalStatus, { label: string; tone: Tone }> = {
    PENDING: { label: '等待批准', tone: 'warn' },
    APPROVED: { label: '已批准', tone: 'ok' },
    REJECTED: { label: '已拒绝', tone: 'bad' },
    EXPIRED: { label: '已过期', tone: 'neutral' },
    CANCELED: { label: '已取消', tone: 'neutral' },
  };
  const me = $derived(session.user?.user_id);
  const a = $derived(r.data);
  const err = $derived(r.status === 'error' ? describeError(r.error) : null);
</script>

<Card title="审批记录" icon="lock" color="amber">
  {#snippet actions()}
    {#if a?.status === 'PENDING'}
      <Button variant="ai" size="sm" icon="ai" onclick={() => dock.open({ approvalId })}>去处理</Button>
    {/if}
  {/snippet}

  {#if err}
    <ErrorState compact message={err.message} requestId={err.requestId} onretry={r.refresh} />
  {:else if !a}
    <Skeleton lines={2} />
  {:else}
    {@const req = actorView(a.facts.requested_by, me)}
    <ol class="steps">
      <li>
        <Avatar kind={req.face} name={req.name} size="sm" />
        <p>
          <b>{req.name}</b> 请求{a.facts.approval_summary ? `「${a.facts.approval_summary}」` : '执行'}
          {#if a.requires_mfa}<Chip size="sm" tone="neutral" dot={false}>需要两步验证</Chip>{/if}
        </p>
        <time datetime={a.created_at} title={dateTime(a.created_at)}>{relativeTime(a.created_at)}</time>
      </li>
      {#if a.decided_by}
        {@const dec = actorView(a.decided_by, me)}
        <li>
          <Avatar kind={dec.face} name={dec.name} size="sm" />
          <p>
            <b>{dec.name}</b>
            <Chip size="sm" tone={STATE[a.status].tone}>{STATE[a.status].label}</Chip>
            {#if a.comment}<span class="comment">「{a.comment}」</span>{/if}
          </p>
          {#if a.decided_at}<time datetime={a.decided_at} title={dateTime(a.decided_at)}>{relativeTime(a.decided_at)}</time>{/if}
        </li>
      {:else}
        <li class="pending">
          <Chip size="sm" tone={STATE[a.status].tone}>{STATE[a.status].label}</Chip>
          {#if a.status === 'PENDING'}<span>{dateTime(a.expires_at)} 前有效</span>{/if}
        </li>
      {/if}
    </ol>
  {/if}
</Card>

<style>
  .steps {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
  }
  li {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  p {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    flex: 1;
    min-width: 0;
    color: var(--text-2);
  }
  b {
    color: var(--text);
    font-weight: var(--fw-semibold);
  }
  .comment {
    color: var(--text);
    overflow-wrap: anywhere;
  }
  time,
  .pending span {
    color: var(--text-3);
    font-size: var(--fs-xs);
    white-space: nowrap;
  }
</style>
