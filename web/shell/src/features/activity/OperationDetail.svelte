<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  OperationDetail · 单个操作的详情（SPEC §3.2）
  ──────────────────────────────────────────────────────────────────────────
    头部：谁 做了什么 对什么 · 状态 · 时间                 [取消]
    进度（RUNNING）· 等待批准 → 去悬浮窗处理
    出错：人话 + 来自插件 + request_id（可复制）
    参数（已脱敏）· 结果
    审批记录 · 审计（host.audit:read）
    技术信息（折叠）：action、operation_id、风险、尝试次数、revision
  实时：liveOps 推来本操作的新 revision 时按节流重取快照（详情以快照为准）。
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { ApiError, TERMINAL } from '$api/client';
  import { operations as opsApi } from '$api/endpoints';
  import { actionCatalogResource, actorView, opObject, opSentence, STATUS } from '$lib/activity';
  import { dock } from '$lib/ai/dock.svelte';
  import { describeError } from '$lib/errors';
  import { dateTime, relativeTime } from '$lib/format';
  import { liveOps } from '$lib/operations.svelte';
  import { createIntent } from '$lib/ops';
  import { page } from '$lib/page.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';
  import { Avatar, Button, Card, Chip, ConfirmDialog, CopyButton, ErrorState, Skeleton } from '$ui';
  import { pluginsResource } from '../../app/nav';
  import ApprovalHistory from './ApprovalHistory.svelte';
  import AuditPanel from './AuditPanel.svelte';
  import JsonBlock from './JsonBlock.svelte';

  let { id: idProp }: { id: string } = $props();
  /* 父级按 id {#key} 重建本组件，id 在生命周期内不变 */
  const id = untrack(() => idProp);

  const r = useResource({
    key: `operation:${id}`,
    load: (signal) => opsApi.get(id, signal),
    subjects: [`operations/${id}`],
    revisionOf: (o) => o.revision,
  });
  const catalog = useResource(actionCatalogResource);
  const plugins = session.can('host.plugins:read') ? useResource(pluginsResource) : null;
  const pluginName = (pid: string) => plugins?.data?.find((p) => p.plugin_id === pid)?.name;

  /* ---------------------------------------------------------------- 实时：新 revision → 节流重取 */
  $effect(() => {
    const live = liveOps.get(id);
    if (live && r.data && live.revision !== r.data.revision) r.schedule();
  });

  /* ---------------------------------------------------------------- 派生 */
  const op = $derived(r.data);
  const who = $derived(op ? actorView(op.actor, session.user?.user_id) : null);
  const sentence = $derived(op ? opSentence(op, catalog.data) : '');
  const object = $derived(op ? opObject(op, pluginName) : undefined);
  const st = $derived(op ? STATUS[op.status] : null);
  const running = $derived(Boolean(op && !TERMINAL.has(op.status)));
  const percent = $derived(op?.progress?.percent);
  const failure = $derived.by(() => {
    const p = op?.error;
    if (!p) return null;
    const v = describeError(new ApiError(p.status ?? 500, p, p.title ?? ''));
    return { message: p.code === 'PLUGIN_ERROR' ? '应用执行时出错了' : v.message, fromPlugin: v.fromPlugin, requestId: p.request_id, title: p.title };
  });
  const loadErr = $derived(r.status === 'error' ? describeError(r.error) : null);
  const notFound = $derived(r.error instanceof ApiError && r.error.status === 404);
  const hasArgs = $derived(Boolean(op?.args && Object.keys(op.args).length));

  $effect(() => {
    if (sentence) page.setTitle(object ? `${sentence} ${object}` : sentence);
  });

  /* ---------------------------------------------------------------- 取消 */
  const canCancel = $derived(running && !op?.cancel_requested && session.can('host.operations:cancel'));
  let confirmOpen = $state(false);
  let cancelErr = $state('');
  let intent = createIntent();

  async function cancel() {
    cancelErr = '';
    try {
      r.set(await opsApi.cancel(id, intent.key));
      intent = createIntent();
      toasts.info('已请求取消，稍后会停下');
    } catch (err) {
      cancelErr = describeError(err).message;
      throw err;
    }
  }
</script>

{#if loadErr}
  <ErrorState kind={notFound ? 'notfound' : 'error'} message={notFound ? '找不到这个操作，可能已过保留期' : loadErr.message} requestId={loadErr.requestId} onretry={r.refresh} />
{:else if !op || !who || !st}
  <div class="detail"><Card><Skeleton lines={4} /></Card><Card><Skeleton lines={6} /></Card></div>
{:else}
  <div class="detail">
    <!-- ============================================================ 头部 -->
    <Card as="section">
      <div class="head">
        <Avatar kind={who.face} name={who.name} />
        <div class="titles">
          <h2><span class="who">{who.name}</span> {sentence}{#if object}<span class="obj"> {object}</span>{/if}</h2>
          <p class="meta">
            <Chip tone={st.tone}>{st.label}</Chip>
            {#if who.ai}<Chip tone="ai" dot={false}>AI 代你操作</Chip>{/if}
            {#if op.cancel_requested && running}<Chip tone="neutral">正在取消</Chip>{/if}
            <time datetime={op.created_at} title={dateTime(op.created_at)}>{relativeTime(op.created_at)}发起</time>
            {#if op.finished_at}<span>· {dateTime(op.finished_at)} 结束</span>{/if}
          </p>
        </div>
        <div class="actions">
          {#if op.ui_route}<Button variant="ghost" size="sm" href={op.ui_route}>在应用中查看</Button>{/if}
          {#if canCancel}<Button variant="plain" size="sm" icon="x" onclick={() => (confirmOpen = true)}>取消</Button>{/if}
        </div>
      </div>

      {#if op.status === 'RUNNING' || op.status === 'PENDING' || op.status === 'APPROVED'}
        <div class="progress">
          <div
            class="bar"
            class:indeterminate={percent === undefined}
            role="progressbar"
            aria-label="进度"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent}
          >
            <span style:width={percent === undefined ? undefined : `${percent}%`}></span>
          </div>
          <p>{op.progress?.step ?? '正在进行'}{op.progress?.message ? ` · ${op.progress.message}` : ''}{percent !== undefined ? ` · ${percent}%` : ''}</p>
        </div>
      {:else if op.status === 'AWAITING_APPROVAL'}
        <div class="waiting">
          <p>这项操作需要批准后才会执行。</p>
          <Button variant="ai" size="sm" icon="ai" onclick={() => dock.open({ approvalId: op.approval_id })}>去处理</Button>
        </div>
      {/if}

      {#if failure}
        <div class="failure" role="alert">
          <p class="msg">{failure.message}</p>
          {#if failure.fromPlugin}<p class="plugin"><span class="tag">来自插件</span><span class="mono">{failure.fromPlugin}</span></p>{/if}
          {#if failure.requestId}
            <p class="rid">请求编号 <span class="mono">{failure.requestId}</span><CopyButton text={failure.requestId} label="复制请求编号" /></p>
          {/if}
        </div>
      {/if}
    </Card>

    <!-- ============================================================ 参数与结果 -->
    {#if hasArgs || op.result !== undefined}
      <div class="pair">
        {#if hasArgs}
          <Card title="参数" subtitle="敏感值已隐藏" icon="gear" color="slate"><JsonBlock value={op.args} /></Card>
        {/if}
        {#if op.result !== undefined}
          <Card title="结果" icon="check" color="green"><JsonBlock value={op.result} /></Card>
        {/if}
      </div>
    {/if}

    <!-- ============================================================ 审批与审计 -->
    {#if op.approval_id}
      <ApprovalHistory approvalId={op.approval_id} />
    {/if}
    {#if session.can('host.audit:read')}
      <Card title="审计记录" icon="shield" color="slate"><AuditPanel operationId={id} compact /></Card>
    {/if}

    <!-- ============================================================ 技术信息 -->
    <details class="tech">
      <summary>技术信息</summary>
      <dl>
        <dt>动作</dt><dd class="mono">{op.action}</dd>
        <dt>操作编号</dt><dd class="mono">{op.operation_id}<CopyButton text={op.operation_id} label="复制操作编号" /></dd>
        <dt>风险</dt><dd>{op.effective_risk}</dd>
        <dt>尝试次数</dt><dd>{op.attempt}</dd>
        {#if op.target.node_id}<dt>节点</dt><dd class="mono">{op.target.node_id}</dd>{/if}
        {#if op.target.plugin_id}<dt>应用</dt><dd class="mono">{op.target.plugin_id}</dd>{/if}
        {#if op.plan_id}<dt>计划</dt><dd class="mono">{op.plan_id}</dd>{/if}
        {#if failure?.title}<dt>错误</dt><dd class="mono">{op.error?.code} · {failure.title}</dd>{/if}
        <dt>版本</dt><dd class="mono">{op.revision}</dd>
      </dl>
    </details>
  </div>

  <ConfirmDialog
    bind:open={confirmOpen}
    title="取消这项操作？"
    tone="warn"
    confirmLabel="取消操作"
    cancelLabel="先不"
    onconfirm={cancel}
    errorText={cancelErr}
  >
    <p>已经完成的步骤不会自动撤销，应用会在安全的位置停下。</p>
  </ConfirmDialog>
{/if}

<style>
  .detail {
    display: flex;
    flex-direction: column;
    gap: var(--gap);
    max-width: 1080px;
  }

  /* ---------------------------------------------------------------- 头部 */
  .head {
    display: flex;
    align-items: flex-start;
    gap: var(--s-3);
  }
  .titles {
    flex: 1;
    min-width: 0;
  }
  h2 {
    font-size: var(--fs-xl);
    font-weight: var(--fw-medium);
    line-height: 1.4;
    overflow-wrap: anywhere;
  }
  .who,
  .obj {
    font-weight: var(--fw-semibold);
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin-top: var(--s-2);
    color: var(--text-3);
    font-size: var(--fs-sm);
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  /* ---------------------------------------------------------------- 进度 */
  .progress {
    margin-top: var(--s-4);
  }
  .bar {
    height: 8px;
    overflow: hidden;
    border-radius: var(--r-pill);
    background: var(--surface-3);
  }
  .bar span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: var(--accent);
    transition: width var(--dur-3) var(--ease);
  }
  .bar.indeterminate span {
    width: 35%;
    animation: slide 1.4s var(--ease) infinite;
  }
  @keyframes slide {
    from { transform: translateX(-100%); }
    to { transform: translateX(300%); }
  }
  :global([data-motion='reduced']) .bar.indeterminate span {
    animation: none;
    width: 100%;
    opacity: 0.5;
  }
  .progress p {
    margin-top: var(--s-2);
    color: var(--text-2);
    font-size: var(--fs-sm);
  }

  .waiting {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-3);
    margin-top: var(--s-4);
    padding: var(--s-3) var(--s-4);
    border-radius: var(--r-md);
    background: var(--ai-soft);
    color: var(--ai-text);
  }

  /* ---------------------------------------------------------------- 错误 */
  .failure {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-top: var(--s-4);
    padding: var(--s-3) var(--s-4);
    border-radius: var(--r-md);
    background: var(--bad-soft);
    color: var(--bad-text);
  }
  .msg {
    font-weight: var(--fw-semibold);
  }
  .plugin,
  .rid {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    color: var(--text-2);
    font-size: var(--fs-sm);
    overflow-wrap: anywhere;
  }
  .tag {
    padding: 1px 8px;
    border-radius: var(--r-pill);
    background: var(--surface);
    color: var(--text-2);
    font-size: var(--fs-2xs);
    font-weight: var(--fw-semibold);
  }

  /* ---------------------------------------------------------------- 参数与结果 */
  .pair {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: var(--gap);
  }

  /* ---------------------------------------------------------------- 技术信息 */
  .tech {
    padding: var(--s-3) var(--s-4);
    border-radius: var(--r-lg);
    background: var(--surface-2);
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .tech summary {
    cursor: pointer;
    font-weight: var(--fw-semibold);
  }
  dl {
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: 8px var(--s-4);
    margin-top: var(--s-3);
  }
  dt {
    color: var(--text-3);
  }
  dd {
    display: flex;
    align-items: center;
    gap: 6px;
    overflow-wrap: anywhere;
  }

  @media (max-width: 860px) {
    .head {
      flex-wrap: wrap;
    }
    .actions {
      width: 100%;
    }
  }
</style>
