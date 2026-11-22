<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置 · AI 令牌（SPEC §7，host.delegations:read）
  ───────────────────────────────────────────────────────────────
  外部 AI（Claude 桌面版、Cursor…）以委托令牌代你操作面板。
  列表 / 签发（token 只在签发响应里出现一次）/ 暂停·恢复 / 撤销。
  管理员可切到"全部"查看他人的令牌（只读；增删改仅限本人）。
-->
<script lang="ts">
  import { Alert, Button, Card, Chip, ConfirmDialog, CopyButton, DataTable, Dialog, EmptyState, ErrorState, IconButton, Input, Menu, Segmented, Select } from '$ui';
  import { delegations } from '$api/endpoints';
  import type { Delegation, DelegationPolicy } from '$api/types';
  import { describeError, reportError, type ErrorView } from '$lib/errors';
  import { dateTime, relativeTime } from '$lib/format';
  import { createIntent, type Intent } from '$lib/ops';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';

  let owner = $state<'me' | 'all'>('me');
  const isAdmin = $derived(session.role === 'admin');
  const list = useResource({
    key: 'settings.delegations',
    load: () => delegations.list(owner).then((p) => p.items),
    subjects: ['delegations/'],
  });
  /* 切换范围即重取（load 闭包读取当前 owner） */
  let lastOwner: 'me' | 'all' = 'me';
  $effect(() => {
    if (owner === lastOwner) return;
    lastOwner = owner;
    void list.refresh();
  });
  const canCreate = $derived(session.can('host.delegations:create'));
  const mine = (d: Delegation) => d.owner_id === session.user?.user_id;

  const STATUS: Record<Delegation['status'], [string, 'ok' | 'warn' | 'neutral']> = {
    active: ['使用中', 'ok'],
    suspended: ['已暂停', 'warn'],
    expired: ['已过期', 'neutral'],
  };

  /* ---------------------------------------------------------------- 签发 */
  const TTL_OPTS = [
    { value: String(7 * 86400), label: '7 天' },
    { value: String(30 * 86400), label: '30 天' },
    { value: String(90 * 86400), label: '90 天' },
  ];
  const RISK_OPTS = [
    { value: 'none', label: '每项操作都要我批准' },
    { value: 'low', label: '低风险操作自动放行' },
  ] as const satisfies readonly { value: DelegationPolicy['auto_approve_max_risk']; label: string }[];
  const QUEUE_OPTS = [
    { value: 'queue', label: '排队等我批准' },
    { value: 'fail', label: '直接拒绝' },
  ] as const satisfies readonly { value: DelegationPolicy['on_approval_required']; label: string }[];

  let createOpen = $state(false);
  let form = $state({ label: '', ttl: TTL_OPTS[1]!.value, risk: 'none' as DelegationPolicy['auto_approve_max_risk'], queue: 'queue' as DelegationPolicy['on_approval_required'] });
  let createBusy = $state(false);
  let createErr = $state<ErrorView | null>(null);
  let createIntentRef: Intent = createIntent();
  let issued = $state<{ label: string; token: string } | null>(null);

  function openCreate() {
    form = { label: '', ttl: TTL_OPTS[1]!.value, risk: 'none', queue: 'queue' };
    createErr = null;
    createIntentRef = createIntent();
    createOpen = true;
  }

  async function submitCreate(e?: SubmitEvent) {
    e?.preventDefault();
    if (createBusy || !form.label.trim()) return;
    createBusy = true;
    createErr = null;
    try {
      const d = await delegations.create(
        {
          label: form.label.trim(),
          ttl_seconds: Number(form.ttl),
          policy: { auto_approve_max_risk: form.risk, on_approval_required: form.queue, requests_per_minute: 60 },
        },
        createIntentRef.key,
      );
      createOpen = false;
      if (d.token) issued = { label: d.label, token: d.token };
      void list.refresh();
    } catch (err) {
      createErr = describeError(err);
    } finally {
      createBusy = false;
    }
  }

  /* ---------------------------------------------------------------- 暂停 / 恢复 */
  async function toggle(d: Delegation) {
    const next = d.status === 'active' ? 'suspended' : 'active';
    try {
      await delegations.update(d.delegation_id, { expected_revision: d.revision, status: next }, createIntent().key);
      toasts.success(next === 'active' ? `已恢复「${d.label}」` : `已暂停「${d.label}」`);
      void list.refresh();
    } catch (err) {
      reportError(err, next === 'active' ? '恢复失败' : '暂停失败');
    }
  }

  /* ---------------------------------------------------------------- 撤销 */
  let revokeTarget = $state<Delegation | null>(null);
  let revokeOpen = $state(false);
  let revokeErr = $state('');
  let revokeIntent: Intent = createIntent();

  function openRevoke(d: Delegation) {
    revokeTarget = d;
    revokeErr = '';
    revokeIntent = createIntent();
    revokeOpen = true;
  }
  async function submitRevoke() {
    const d = revokeTarget!;
    try {
      await delegations.revoke(d.delegation_id, d.revision, revokeIntent.key);
      toasts.success(`已撤销「${d.label}」`);
      void list.refresh();
    } catch (err) {
      revokeErr = describeError(err).message;
      throw err;
    }
  }

  const COLUMNS = [
    { key: 'label', label: '名称' },
    { key: 'policy', label: '审批策略' },
    { key: 'status', label: '状态', width: '96px' },
    { key: 'used', label: '最近使用', width: '120px' },
    { key: 'expires', label: '到期', width: '120px' },
    { key: 'more', label: '操作', width: '64px', align: 'end' as const },
  ];
</script>

<Card title="AI 令牌" icon="ai" color="violet" subtitle="让外部 AI 工具代你操作面板；它的每个动作都按策略交你批准">
  {#snippet actions()}
    {#if isAdmin}
      <Segmented label="范围" size="sm" options={[{ value: 'me', label: '我的' }, { value: 'all', label: '全部' }]} bind:value={owner} />
    {/if}
    {#if canCreate}<Button variant="primary" size="sm" icon="plus" onclick={openCreate}>签发令牌</Button>{/if}
  {/snippet}

  {#if issued}
    <Alert tone="ok" title="「{issued.label}」的令牌（只显示这一次，关掉后无法再查看）">
      <code class="mono token">{issued.token}</code>
      {#snippet actions()}
        <CopyButton text={issued!.token} label="复制令牌" />
        <IconButton icon="x" label="我已保存，关闭" size="sm" onclick={() => (issued = null)} />
      {/snippet}
    </Alert>
  {/if}

  {#if list.status === 'error' && !list.data}
    <ErrorState compact message={describeError(list.error).message} requestId={describeError(list.error).requestId} onretry={list.refresh} />
  {:else}
    <DataTable caption="AI 令牌" columns={COLUMNS} rows={list.data ?? []} rowKey={(d) => d.delegation_id} loading={list.status === 'loading'}>
      {#snippet cell(d, key)}
        {#if key === 'label'}
          <span class="names">
            <span class="strong">{d.label}</span>
            {#if d.token_prefix}<span class="tiny faint mono">{d.token_prefix}…</span>{/if}
          </span>
        {:else if key === 'policy'}
          <span class="small">{d.policy.auto_approve_max_risk === 'low' ? '低风险自动放行' : '全部需批准'}</span>
        {:else if key === 'status'}
          <Chip size="sm" tone={STATUS[d.status][1]}>{STATUS[d.status][0]}</Chip>
        {:else if key === 'used'}
          <span class="small muted">{d.last_used_at ? relativeTime(d.last_used_at) : '从未'}</span>
        {:else if key === 'expires'}
          <span class="small muted" title={dateTime(d.expires_at)}>{dateTime(d.expires_at).slice(0, 10)}</span>
        {:else if key === 'more' && mine(d) && d.status !== 'expired'}
          <Menu
            label="{d.label} 的操作"
            items={[
              { label: d.status === 'active' ? '暂停' : '恢复', icon: d.status === 'active' ? 'pause' : 'play', onselect: () => toggle(d) },
              { label: '撤销', icon: 'trash', tone: 'danger', onselect: () => openRevoke(d) },
            ]}
          >
            {#snippet trigger(p)}<IconButton icon="more" label="{d.label} 的操作" size="sm" {...p} />{/snippet}
          </Menu>
        {/if}
      {/snippet}
      {#snippet empty()}
        <EmptyState compact title="还没有 AI 令牌" description="签发一个令牌，把它填进外部 AI 工具的 MCP 配置里。" />
      {/snippet}
    </DataTable>
  {/if}
</Card>

<Dialog bind:open={createOpen} title="签发 AI 令牌" description="令牌只在签发后显示一次，请立即复制保存。">
  <form id="dlg-create" class="stack" onsubmit={submitCreate} novalidate>
    <Input label="名称" hint="例如：Claude 桌面版" required maxlength={64} autocomplete="off" bind:value={form.label} error={createErr?.fields['/label']} />
    <Select label="有效期" options={TTL_OPTS} bind:value={form.ttl} />
    <Select label="审批" options={RISK_OPTS} bind:value={form.risk} hint="高风险和可能断开连接的操作始终需要你批准" />
    <Select label="需要批准时" options={QUEUE_OPTS} bind:value={form.queue} />
    {#if createErr && !Object.keys(createErr.fields).length}<Alert>{createErr.message}</Alert>{/if}
  </form>
  {#snippet footer()}
    <Button variant="plain" onclick={() => (createOpen = false)}>取消</Button>
    <Button type="submit" form="dlg-create" variant="primary" loading={createBusy} disabled={!form.label.trim()}>签发</Button>
  {/snippet}
</Dialog>

<ConfirmDialog
  bind:open={revokeOpen}
  title="撤销令牌"
  tone="danger"
  confirmLabel="撤销"
  warning="撤销后使用这个令牌的 AI 工具会立即失去访问权限，无法恢复。"
  errorText={revokeErr}
  onconfirm={submitRevoke}
>
  {#if revokeTarget}确定撤销「{revokeTarget.label}」？{/if}
</ConfirmDialog>

<style>
  .stack {
    gap: var(--s-4);
  }
  .names {
    display: flex;
    flex-direction: column;
    line-height: 1.3;
  }
  .token {
    display: block;
    margin-top: 4px;
    word-break: break-all;
    font-size: var(--fs-xs);
  }
</style>
