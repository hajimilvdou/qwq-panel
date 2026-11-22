<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置 · 用户（SPEC §7，host.users:read）
  ───────────────────────────────────────────────────────────────
  列表 / 新建 / 改角色 / 停用·启用 / 删除：写入走 operation（runIntent，202 自动分流）
  生成注册链接：POST /users/{id}/enrollment-token（要求 MFA 新鲜；链接只显示这一次）
  新建成功（enrollment_pending）后直接引导生成注册链接。
-->
<script lang="ts">
  import { Alert, Avatar, Button, Card, Chip, ConfirmDialog, CopyButton, DataTable, Dialog, EmptyState, ErrorState, IconButton, Input, Menu, Select } from '$ui';
  import { users } from '$api/endpoints';
  import type { Role, User } from '$api/types';
  import { describeError, reportError, type ErrorView } from '$lib/errors';
  import { dateTime, relativeTime } from '$lib/format';
  import { createIntent, runIntent, type Intent } from '$lib/ops';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';

  const list = useResource({ key: 'users', load: () => users.list({ limit: 200 }).then((p) => p.items), subjects: ['users/', 'users'] });
  const canCreate = $derived(session.can('host.users:create'));
  const canUpdate = $derived(session.can('host.users:update'));
  const canDelete = $derived(session.can('host.users:delete'));

  const ROLE_OPTS = [
    { value: 'admin', label: '管理员', hint: '全部权限' },
    { value: 'operator', label: '运维', hint: '管理应用、处理审批' },
    { value: 'viewer', label: '只读', hint: '只能查看' },
  ] as const satisfies readonly { value: Role; label: string; hint: string }[];
  const roleName = (r: Role) => ROLE_OPTS.find((o) => o.value === r)?.label ?? r;
  const nameOf = (u: User) => u.display_name || u.username;

  /* ---------------------------------------------------------------- 新建 */
  let createOpen = $state(false);
  let form = $state({ username: '', display_name: '', role: 'operator' as Role });
  let createBusy = $state(false);
  let createErr = $state<ErrorView | null>(null);
  let createIntentRef: Intent = createIntent();

  function openCreate() {
    form = { username: '', display_name: '', role: 'operator' };
    createErr = null;
    createIntentRef = createIntent();
    createOpen = true;
  }

  async function submitCreate(e?: SubmitEvent) {
    e?.preventDefault();
    if (createBusy || !form.username.trim()) return;
    createBusy = true;
    createErr = null;
    try {
      const body = { username: form.username.trim(), role: form.role, display_name: form.display_name.trim() || undefined };
      const r = await runIntent(createIntentRef, (key) => users.create(body, key), { label: `创建用户 ${body.username}` });
      createOpen = false;
      void list.refresh();
      const created = (r.op.result as { user?: User } | undefined)?.user;
      if (r.kind === 'done' && r.op.status === 'SUCCEEDED' && created) void issueLink(created);
    } catch (err) {
      createErr = describeError(err);
    } finally {
      createBusy = false;
    }
  }

  /* ---------------------------------------------------------------- 改角色 */
  let roleTarget = $state<User | null>(null);
  let roleValue = $state<Role>('viewer');
  let roleBusy = $state(false);
  let roleErr = $state('');
  let roleIntent: Intent = createIntent();

  function openRole(u: User) {
    roleTarget = u;
    roleValue = u.role;
    roleErr = '';
    roleIntent = createIntent();
  }

  async function submitRole() {
    const u = roleTarget;
    if (!u || roleBusy || roleValue === u.role) return;
    roleBusy = true;
    roleErr = '';
    try {
      await runIntent(roleIntent, (key) => users.update(u.user_id, { expected_revision: u.revision, role: roleValue }, key), {
        label: `把 ${nameOf(u)} 改为${roleName(roleValue)}`,
      });
      roleTarget = null;
      void list.refresh();
    } catch (err) {
      roleErr = describeError(err).message;
    } finally {
      roleBusy = false;
    }
  }

  /* ---------------------------------------------------------------- 停用 / 启用 */
  async function toggleDisabled(u: User) {
    try {
      await runIntent(createIntent(), (key) => users.update(u.user_id, { expected_revision: u.revision, disabled: !u.disabled }, key), {
        label: `${u.disabled ? '启用' : '停用'} ${nameOf(u)}`,
      });
      void list.refresh();
    } catch (err) {
      reportError(err, u.disabled ? '启用失败' : '停用失败');
    }
  }

  /* ---------------------------------------------------------------- 删除 */
  let removeTarget = $state<User | null>(null);
  let removeOpen = $state(false);
  let removeErr = $state('');
  let removeIntent: Intent = createIntent();

  function openRemove(u: User) {
    removeTarget = u;
    removeErr = '';
    removeIntent = createIntent();
    removeOpen = true;
  }

  async function submitRemove() {
    const u = removeTarget!;
    try {
      await runIntent(removeIntent, (key) => users.remove(u.user_id, u.revision, key), { label: `删除用户 ${nameOf(u)}` });
      void list.refresh();
    } catch (err) {
      removeErr = describeError(err).message;
      throw err;
    }
  }

  /* ---------------------------------------------------------------- 注册链接（只显示一次） */
  let link = $state<{ user: User; url: string; expires: string } | null>(null);
  let linkErr = $state<{ user: User; message: string } | null>(null);

  async function issueLink(u: User) {
    linkErr = null;
    try {
      const r = await users.createEnrollmentToken(u.user_id, createIntent().key);
      link = { user: u, url: `${location.origin}/enroll#token=${encodeURIComponent(r.enrollment_token!)}`, expires: r.expires_at };
    } catch (err) {
      const v = describeError(err);
      linkErr = {
        user: u,
        message: v.code === 'MFA_REQUIRED' ? '生成注册链接需要最近验证过两步验证：请退出后重新登录再试' : v.message,
      };
    }
  }

  function menuFor(u: User) {
    const self = u.user_id === session.user?.user_id;
    return [
      ...(canUpdate ? [{ label: '生成注册链接', icon: 'key' as const, onselect: () => issueLink(u) }] : []),
      ...(canUpdate && !self ? [{ label: '修改角色', icon: 'user' as const, onselect: () => openRole(u) }] : []),
      ...(canUpdate && !self
        ? [{ label: u.disabled ? '启用' : '停用', icon: (u.disabled ? 'play' : 'pause') as 'play' | 'pause', onselect: () => toggleDisabled(u) }]
        : []),
      ...(canDelete && !self ? [{ label: '删除', icon: 'trash' as const, tone: 'danger' as const, onselect: () => openRemove(u) }] : []),
    ];
  }

  const COLUMNS = [
    { key: 'name', label: '用户' },
    { key: 'role', label: '角色', width: '96px' },
    { key: 'mfa', label: '两步验证', width: '108px' },
    { key: 'state', label: '状态', width: '96px' },
    { key: 'updated', label: '更新', width: '120px' },
    { key: 'more', label: '操作', width: '64px', align: 'end' as const },
  ];
</script>

<Card title="用户" icon="user" color="blue" subtitle="新用户通过一次性注册链接设置自己的密码">
  {#snippet actions()}
    {#if canCreate}<Button variant="primary" size="sm" icon="user-plus" onclick={openCreate}>新建用户</Button>{/if}
  {/snippet}

  {#if link}
    <Alert tone="ok" title="把这个链接发给 {nameOf(link.user)}（只显示这一次，{dateTime(link.expires)} 前有效）">
      <code class="mono link">{link.url}</code>
      {#snippet actions()}
        <CopyButton text={link!.url} label="复制链接" />
        <IconButton icon="x" label="我已发送，关闭" size="sm" onclick={() => (link = null)} />
      {/snippet}
    </Alert>
  {/if}
  {#if linkErr}
    <Alert title="没能为 {nameOf(linkErr.user)} 生成注册链接">
      {linkErr.message}
      {#snippet actions()}<IconButton icon="x" label="关闭" size="sm" onclick={() => (linkErr = null)} />{/snippet}
    </Alert>
  {/if}

  {#if list.status === 'error' && !list.data}
    <ErrorState compact message={describeError(list.error).message} requestId={describeError(list.error).requestId} onretry={list.refresh} />
  {:else}
    <DataTable caption="用户列表" columns={COLUMNS} rows={list.data ?? []} rowKey={(u) => u.user_id} loading={list.status === 'loading'}>
      {#snippet cell(u, key)}
        {#if key === 'name'}
          <span class="who">
            <Avatar name={nameOf(u)} size="sm" />
            <span class="names">
              <span class="strong">{nameOf(u)}{#if u.user_id === session.user?.user_id}<span class="faint">（你）</span>{/if}</span>
              <span class="tiny faint mono">{u.username}</span>
            </span>
          </span>
        {:else if key === 'role'}
          {roleName(u.role)}
        {:else if key === 'mfa'}
          <Chip size="sm" tone={u.mfa_enabled ? 'ok' : 'neutral'}>{u.mfa_enabled ? '已开启' : '未开启'}</Chip>
        {:else if key === 'state'}
          <Chip size="sm" tone={u.disabled ? 'warn' : 'ok'}>{u.disabled ? '已停用' : '正常'}</Chip>
        {:else if key === 'updated'}
          <span class="small muted" title={dateTime(u.updated_at)}>{relativeTime(u.updated_at)}</span>
        {:else if key === 'more'}
          {@const items = menuFor(u)}
          {#if items.length}
            <Menu label="{nameOf(u)} 的操作" {items}>
              {#snippet trigger(p)}<IconButton icon="more" label="{nameOf(u)} 的操作" size="sm" {...p} />{/snippet}
            </Menu>
          {/if}
        {/if}
      {/snippet}
      {#snippet empty()}<EmptyState compact title="还没有其他用户" />{/snippet}
    </DataTable>
  {/if}
</Card>

<!-- ---------------------------------------------------------------- 新建 -->
<Dialog bind:open={createOpen} title="新建用户" description="创建后会生成一次性注册链接，由对方自己设置密码。">
  <form id="user-create" class="stack" onsubmit={submitCreate} novalidate>
    <Input label="用户名" hint="小写字母开头，可含数字和 _.-" required autocomplete="off" bind:value={form.username} error={createErr?.fields['/username']} />
    <Input label="显示名" hint="可选" autocomplete="off" bind:value={form.display_name} error={createErr?.fields['/display_name']} />
    <Select label="角色" options={ROLE_OPTS} bind:value={form.role} error={createErr?.fields['/role']} />
    {#if createErr && !Object.keys(createErr.fields).length}<Alert>{createErr.message}</Alert>{/if}
  </form>
  {#snippet footer()}
    <Button variant="plain" onclick={() => (createOpen = false)}>取消</Button>
    <Button type="submit" form="user-create" variant="primary" loading={createBusy} disabled={!form.username.trim()}>创建</Button>
  {/snippet}
</Dialog>

<!-- ---------------------------------------------------------------- 改角色 -->
<Dialog open={!!roleTarget} title="修改角色" description={roleTarget ? `${nameOf(roleTarget)}（${roleTarget.username}）` : undefined} size="sm" onclose={() => (roleTarget = null)}>
  <Select label="角色" options={ROLE_OPTS} bind:value={roleValue} />
  {#if roleErr}<Alert>{roleErr}</Alert>{/if}
  {#snippet footer()}
    <Button variant="plain" onclick={() => (roleTarget = null)}>取消</Button>
    <Button variant="primary" loading={roleBusy} disabled={roleValue === roleTarget?.role} onclick={submitRole}>保存</Button>
  {/snippet}
</Dialog>

<!-- ---------------------------------------------------------------- 删除 -->
<ConfirmDialog
  bind:open={removeOpen}
  title="删除用户"
  tone="danger"
  confirmLabel="删除"
  warning="删除后对方立即退出登录，且无法恢复。"
  confirmText={removeTarget?.username}
  errorText={removeErr}
  onconfirm={submitRemove}
>
  {#if removeTarget}确定删除 <strong>{nameOf(removeTarget)}</strong>？对方名下的 AI 令牌也会一并失效。{/if}
</ConfirmDialog>

<style>
  .stack {
    gap: var(--s-4);
  }
  .who {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .names {
    display: flex;
    flex-direction: column;
    line-height: 1.3;
  }
  .link {
    display: block;
    margin-top: 4px;
    word-break: break-all;
    font-size: var(--fs-xs);
  }
</style>
