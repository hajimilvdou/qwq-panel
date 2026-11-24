<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ApprovalCard · 审批卡（悬浮窗与 Agent 页共用，宿主渲染；SPEC §4）
  ───────────────────────────────────────────────────────────────
  <ApprovalCard approval={a} ondecided={(id) => …} bind:this={card} />  card.focus()

  自上而下：发起者 → 标题（来自插件）→ 介绍（>4 行折叠）→ 风险/可撤销/节点
  → 可达性警示 → 插件预览 → 详情（args、能力、action id）→ 验证码 → 按钮。
  所有插件/模型文本按纯文本渲染。无倒计时：有效期是静态文字，过期即变灰。
  决定结果：成功 → approvals.upsert；409 → "已被处理"并刷新队列；MFA → 字段错误。
-->
<script lang="ts">
  import { Button, Chip, Icon, Input, Orb, OtpInput, Avatar } from '$ui';
  import type { Approval } from '$api/types';
  import type { ActionMeta } from '$api/additions';
  import { newIdempotencyKey } from '$api/client';
  import { describeError } from '../errors';
  import { session } from '../session.svelte';
  import { approvals } from './approvals.svelte';
  import { dock } from './dock.svelte';
  import { decideApproval, isExpired, requesterOf, RISK_META, validityText, whyAsk } from './decide';

  interface Props {
    approval: Approval;
    /** 决定已提交（或已被他处处理）后回调 */
    ondecided?: (approvalId: string) => void;
  }
  let { approval: a, ondecided }: Props = $props();

  const uid = $props.id();
  let root: HTMLElement;

  const f = $derived(a.facts);
  const action = $derived(f.action as ActionMeta);
  const who = $derived(requesterOf(f, session.user?.user_id));
  const title = $derived(f.approval_summary || action.summary);
  const fromPlugin = $derived(action.source === 'plugin');
  const risk = $derived(RISK_META[f.effective_risk] ?? RISK_META.medium);
  const node = $derived(f.node_name ?? f.target.node_id);
  const expired = $derived(isExpired(a));
  const needsTotpSetup = $derived(a.requires_mfa && session.user?.mfa_enabled === false);

  /* 一张卡一个意图：网络重试复用同一个幂等键 */
  let key = newIdempotencyKey();
  let busy = $state<'approve' | 'reject' | null>(null);
  let handled = $state(false);
  let mfa = $state('');
  let mfaError = $state<string | undefined>();
  let errorText = $state<string | undefined>();
  let showComment = $state(false);
  let comment = $state('');
  let descOpen = $state(false);
  let descLong = $state(false);
  let descEl = $state<HTMLParagraphElement>();

  /* 介绍超过 4 行才出现"展开" */
  $effect(() => {
    if (!descEl || descOpen) return;
    descLong = descEl.scrollHeight > descEl.clientHeight + 2;
  });

  export function focus(): void {
    root?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    root?.querySelector<HTMLElement>('[data-primary]')?.focus({ preventScroll: true });
  }

  async function decide(decision: 'approve' | 'reject') {
    if (busy) return;
    if (decision === 'approve' && a.requires_mfa && mfa.length !== 6) {
      mfaError = '请输入 6 位验证码';
      return;
    }
    busy = decision;
    mfaError = errorText = undefined;
    const r = await decideApproval(a, { decision, mfaCode: decision === 'approve' ? mfa : undefined, comment }, key);
    busy = null;
    switch (r.kind) {
      case 'ok':
        key = newIdempotencyKey();
        approvals.upsert(r.approval);
        ondecided?.(a.approval_id);
        break;
      case 'handled':
        handled = true;
        void approvals.refreshOne(a.approval_id);
        ondecided?.(a.approval_id);
        break;
      case 'mfa':
        mfaError = r.message;
        mfa = '';
        break;
      case 'error':
        errorText = describeError(r.error).message;
    }
  }

  const CHANGE_KIND = { create: '新增', update: '修改', delete: '删除' } as const;
  const json = (v: unknown) => JSON.stringify(v, null, 2);
</script>

<article
  bind:this={root}
  class="card"
  class:expired
  class:handled
  aria-labelledby="{uid}-t"
  data-approval={a.approval_id}
>
  <!-- 1 发起者 -->
  <header class="who">
    {#if who.kind === 'ai' || who.kind === 'external'}
      <Orb size={20} />
    {:else}
      <Avatar size="sm" kind={who.kind === 'human' ? 'human' : 'system'} name={f.requested_by.display_name} />
    {/if}
    <span class="who-text">{who.text}</span>
    <span class="why">· {whyAsk(f)}</span>
  </header>

  <!-- 2 标题 -->
  <h3 id="{uid}-t" class="title">
    {title}
    {#if fromPlugin}<span class="src">来自插件</span>{/if}
  </h3>

  <!-- 3 介绍（纯文本，>4 行折叠） -->
  {#if f.approval_description}
    <p bind:this={descEl} class="desc" class:clamp={!descOpen}>{f.approval_description}</p>
    {#if descLong || descOpen}
      <button type="button" class="more" aria-expanded={descOpen} onclick={() => (descOpen = !descOpen)}>
        {descOpen ? '收起' : '展开全部'}
      </button>
    {/if}
  {/if}

  <!-- 4 标签 -->
  <div class="tags">
    <Chip size="sm" tone={risk.tone}>{risk.label}</Chip>
    <Chip size="sm" tone={f.reversible ? 'neutral' : 'warn'}>{f.reversible ? '可撤销' : '不可撤销'}</Chip>
    {#if node}<Chip size="sm" dot={false}>节点 {node}</Chip>{/if}
  </div>

  <!-- 5 可达性 -->
  {#if action.reachability}
    <p class="reach" role="note">
      <Icon name="alert" size={18} />
      <span><strong>可能导致无法连接服务器。</strong>执行前请确认你还有其它方式登录（例如服务商控制台）。</span>
    </p>
  {/if}

  <!-- 6 插件预览 -->
  {#if a.plugin_preview?.changes?.length || a.plugin_preview?.warnings?.length}
    <section class="preview" aria-label="将发生的变化">
      <p class="sub">将发生的变化 <span class="src">来自插件</span></p>
      <ul>
        {#each a.plugin_preview?.changes ?? [] as c, i (i)}
          <li>
            <span class="kind {c.kind}">{CHANGE_KIND[c.kind]}</span>
            <span class="mono">{(c as { description?: string }).description ?? c.subject + (c.pointer ?? '')}</span>
          </li>
        {/each}
        {#each a.plugin_preview?.warnings ?? [] as w, i (i)}
          <li class="warn"><Icon name="alert" size={16} /> {w.message}</li>
        {/each}
      </ul>
    </section>
  {/if}

  <!-- 7 详情 -->
  <details class="details">
    <summary>详情</summary>
    <dl>
      <dt>动作</dt>
      <dd class="mono">{action.id}</dd>
      {#if Object.keys(f.args ?? {}).length}
        <dt>参数</dt>
        <dd><pre class="mono">{json(f.args)}</pre></dd>
      {/if}
      {#if f.required_capabilities.length}
        <dt>需要的能力</dt>
        <dd>
          {#each f.required_capabilities as c (c.name + c.scope)}
            <span class="mono cap">{c.name}{c.scope ? ` · ${c.scope}` : ''}</span>
          {/each}
        </dd>
      {/if}
      <dt>有效期</dt>
      <dd>{validityText(a)}</dd>
    </dl>
  </details>

  {#if handled}
    <p class="state">这条已被处理过了</p>
  {:else if expired}
    <p class="state">已过期，没有执行。需要的话请重新发起。</p>
  {:else}
    <!-- 8 验证码 -->
    {#if a.requires_mfa}
      {#if needsTotpSetup}
        <p class="mfa-hint">
          <Icon name="lock" size={16} /> 这是破坏性操作，批准需要两步验证。
          <a href="/settings/account" onclick={() => dock.close()}>先去开启两步验证</a>
        </p>
      {:else}
        <div class="mfa">
          <OtpInput bind:value={mfa} label="两步验证码" error={mfaError} disabled={!!busy} />
        </div>
      {/if}
    {/if}

    {#if showComment}
      <Input bind:value={comment} label="备注（可选）" maxlength={500} multiline rows={2} />
    {/if}

    {#if errorText}<p class="err" role="alert">{errorText}</p>{/if}

    <!-- 9 按钮 -->
    <footer class="actions">
      {#if !needsTotpSetup}
        <Button
          data-primary
          variant={f.effective_risk === 'high' ? 'danger' : 'primary'}
          loading={busy === 'approve'}
          disabled={!!busy}
          onclick={() => decide('approve')}>批准</Button
        >
      {/if}
      <Button variant="ghost" loading={busy === 'reject'} disabled={!!busy} onclick={() => decide('reject')}>拒绝</Button>
      {#if !showComment}
        <Button variant="plain" size="sm" onclick={() => (showComment = true)}>加备注</Button>
      {/if}
      <span class="valid">{validityText(a)}</span>
    </footer>
  {/if}
</article>

<style>
  .card {
    display: grid;
    gap: var(--s-3);
    padding: var(--s-4);
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    scroll-margin: var(--s-4);
  }
  .card:focus-within {
    border-color: var(--line-strong);
  }
  .expired,
  .handled {
    opacity: 0.62;
    filter: grayscale(0.6);
  }
  .who {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    font-size: var(--fs-sm);
    color: var(--text-2);
    flex-wrap: wrap;
  }
  .who-text {
    font-weight: var(--fw-medium);
    color: var(--text);
  }
  .why {
    color: var(--text-3);
  }
  .title {
    margin: 0;
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
    line-height: 1.4;
    overflow-wrap: anywhere;
  }
  .src {
    display: inline-block;
    margin-left: var(--s-1);
    font-size: var(--fs-xs);
    font-weight: var(--fw-regular);
    color: var(--text-3);
    vertical-align: 2px;
  }
  .desc {
    margin: 0;
    color: var(--text-2);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    line-height: 1.6;
  }
  .clamp {
    display: -webkit-box;
    -webkit-line-clamp: 4;
    line-clamp: 4;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .more {
    justify-self: start;
    margin-top: calc(-1 * var(--s-2));
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent-text);
    font: inherit;
    font-size: var(--fs-sm);
    cursor: pointer;
  }
  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s-2);
  }
  .reach {
    display: flex;
    gap: var(--s-2);
    margin: 0;
    padding: var(--s-3);
    border-radius: var(--r-md);
    background: var(--warn-soft);
    color: var(--warn-text);
    font-size: var(--fs-sm);
    line-height: 1.5;
  }
  .reach :global(svg) {
    flex: none;
    margin-top: 1px;
  }
  .preview {
    padding: var(--s-3);
    border-radius: var(--r-md);
    background: var(--surface-2);
  }
  .sub {
    margin: 0 0 var(--s-2);
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
  }
  .preview ul {
    display: grid;
    gap: 6px;
    margin: 0;
    padding: 0;
    list-style: none;
    font-size: var(--fs-sm);
  }
  .preview li {
    display: flex;
    gap: var(--s-2);
    align-items: baseline;
    overflow-wrap: anywhere;
  }
  .kind {
    flex: none;
    padding: 0 6px;
    border-radius: var(--r-xs);
    font-size: var(--fs-xs);
    background: var(--info-soft);
    color: var(--info-text);
  }
  .kind.delete {
    background: var(--bad-soft);
    color: var(--bad-text);
  }
  .kind.create {
    background: var(--ok-soft);
    color: var(--ok-text);
  }
  .preview .warn {
    color: var(--warn-text);
    align-items: center;
  }
  .details summary {
    cursor: pointer;
    font-size: var(--fs-sm);
    color: var(--text-2);
    width: fit-content;
  }
  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 6px var(--s-3);
    margin: var(--s-2) 0 0;
    font-size: var(--fs-sm);
  }
  dt {
    color: var(--text-3);
  }
  dd {
    margin: 0;
    min-width: 0;
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    overflow-wrap: anywhere;
  }
  pre {
    margin: 0;
    padding: var(--s-2);
    border-radius: var(--r-sm);
    background: var(--surface-sunk);
    overflow-x: auto;
    max-height: 220px;
  }
  .cap {
    display: inline-block;
    margin: 0 6px 4px 0;
  }
  .mfa-hint {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    margin: 0;
    font-size: var(--fs-sm);
    color: var(--text-2);
  }
  .mfa-hint a {
    color: var(--accent-text);
    font-weight: var(--fw-medium);
  }
  .err {
    margin: 0;
    color: var(--bad-text);
    font-size: var(--fs-sm);
  }
  .state {
    margin: 0;
    font-size: var(--fs-sm);
    color: var(--text-2);
  }
  .actions {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    flex-wrap: wrap;
  }
  .valid {
    margin-left: auto;
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
</style>
