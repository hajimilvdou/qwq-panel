<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置 · 账户（SPEC §7 / GAPS 缺口 1，全部为机密例外路由）
  ───────────────────────────────────────────────────────────────
  显示名   PATCH /sessions/current/profile（host.account.update，outcome.result 是 User）
  密码     PUT  /sessions/current/password（旧口令错 403；成功会撤销其他会话）
  两步验证 开启见 TotpDialog；停用 POST …/mfa/totp/disable（验证码错 403 MFA_REQUIRED）
  ?welcome=1：初始化刚完成，顶部欢迎卡引导开启两步验证（可跳过）。
-->
<script lang="ts">
  import { Alert, Button, Card, Chip, Dialog, Input, OtpInput } from '$ui';
  import { account } from '$api/endpoints';
  import type { User } from '$api/types';
  import { describeError, type ErrorView } from '$lib/errors';
  import { createIntent } from '$lib/ops';
  import { router } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';
  import PasswordFields from '../auth/PasswordFields.svelte';
  import TotpDialog from './TotpDialog.svelte';

  const user = $derived(session.user!);
  const ROLE: Record<string, string> = { admin: '管理员', operator: '运维', viewer: '只读' };

  /* ---------------------------------------------------------------- 欢迎卡 */
  let welcome = $state(router.query.get('welcome') === '1');
  function dismissWelcome() {
    welcome = false;
    router.setQuery({ welcome: null });
  }

  /* ---------------------------------------------------------------- 显示名 */
  let displayName = $state(session.user?.display_name ?? '');
  let nameBusy = $state(false);
  let nameErr = $state<ErrorView | null>(null);
  let nameIntent = createIntent();
  const nameDirty = $derived(displayName.trim() !== (user.display_name ?? ''));

  async function saveName(e: SubmitEvent) {
    e.preventDefault();
    if (!nameDirty || nameBusy || !displayName.trim()) return;
    nameBusy = true;
    nameErr = null;
    try {
      const r = await account.updateProfile({ display_name: displayName.trim(), expected_revision: user.revision }, nameIntent.key);
      session.updateUser(r.result as User);
      nameIntent = createIntent();
      toasts.success('显示名已更新');
    } catch (err) {
      nameErr = describeError(err);
    } finally {
      nameBusy = false;
    }
  }
  function reloadName() {
    void session.refresh().then(
      () => {
        displayName = session.user?.display_name ?? '';
        nameErr = null;
        nameIntent = createIntent();
      },
      (err) => (nameErr = describeError(err)),
    );
  }

  /* ---------------------------------------------------------------- 密码 */
  let currentPw = $state('');
  let newPw = $state('');
  let pwValid = $state(false);
  let pwBusy = $state(false);
  let pwErr = $state<ErrorView | null>(null);
  let pwKey = $state(0);

  async function changePassword(e: SubmitEvent) {
    e.preventDefault();
    if (!pwValid || !currentPw || pwBusy) return;
    pwBusy = true;
    pwErr = null;
    try {
      await account.changePassword(currentPw, newPw, createIntent().key);
      currentPw = '';
      newPw = '';
      pwKey++;
      toasts.success('密码已更新，其他设备已退出登录');
    } catch (err) {
      const v = describeError(err);
      pwErr = v.code === 'PERMISSION_DENIED' ? { ...v, fields: { '/current_password': '当前密码不对' } } : v;
    } finally {
      pwBusy = false;
    }
  }

  /* ---------------------------------------------------------------- 两步验证 */
  let totpOpen = $state(false);
  let disableOpen = $state(false);
  let disableCode = $state('');
  let disableBusy = $state(false);
  let disableErr = $state('');

  async function disableTotp(code = disableCode) {
    if (code.length !== 6 || disableBusy) return;
    disableBusy = true;
    disableErr = '';
    try {
      session.updateUser(await account.disableTotp(code, createIntent().key));
      disableOpen = false;
      toasts.success('两步验证已关闭');
    } catch (err) {
      const v = describeError(err);
      disableCode = '';
      disableErr = v.code === 'VALIDATION_FAILED' || v.code === 'MFA_REQUIRED' ? '验证码不对' : v.message;
    } finally {
      disableBusy = false;
    }
  }
</script>

{#if welcome && !user.mfa_enabled}
  <Card color="accent" icon="shield" title="面板准备好了" subtitle="建议现在开启两步验证：密码泄露时，别人也登不进来。">
    <div class="row">
      <Button variant="primary" icon="shield" onclick={() => (totpOpen = true)}>开启两步验证</Button>
      <Button variant="plain" onclick={dismissWelcome}>以后再说</Button>
    </div>
  </Card>
{/if}

<Card title="个人资料" icon="user" color="blue">
  <form class="stack" onsubmit={saveName} novalidate>
    <dl class="facts">
      <div><dt>用户名</dt><dd class="mono">{user.username}</dd></div>
      <div><dt>角色</dt><dd>{ROLE[user.role] ?? user.role}</dd></div>
    </dl>
    {#if nameErr?.code === 'REVISION_CONFLICT'}
      <Alert tone="warn" title="资料已在别处修改">
        {#snippet actions()}<Button size="sm" variant="soft" onclick={reloadName}>重新加载</Button>{/snippet}
      </Alert>
    {:else if nameErr && !nameErr.fields['/display_name']}
      <Alert>{nameErr.message}</Alert>
    {/if}
    <Input label="显示名" autocomplete="nickname" maxlength={64} bind:value={displayName} error={nameErr?.fields['/display_name']} />
    <div class="actions">
      <Button type="submit" variant="primary" loading={nameBusy} disabled={!nameDirty || !displayName.trim()}>保存</Button>
    </div>
  </form>
</Card>

<Card title="密码" icon="key" color="amber" subtitle="改密码后，其他设备上的登录会失效">
  {#key pwKey}
    <form class="stack narrow" onsubmit={changePassword} novalidate>
      <input type="text" autocomplete="username" value={user.username} hidden readonly />
      <Input
        label="当前密码"
        type="password"
        autocomplete="current-password"
        required
        bind:value={currentPw}
        error={pwErr?.fields['/current_password']}
      />
      <PasswordFields label="新密码" bind:password={newPw} bind:valid={pwValid} serverError={pwErr?.fields['/new_password']} disabled={pwBusy} />
      {#if pwErr && !Object.keys(pwErr.fields).length}<Alert>{pwErr.message}</Alert>{/if}
      <div class="actions">
        <Button type="submit" variant="primary" loading={pwBusy} disabled={!pwValid || !currentPw}>更新密码</Button>
      </div>
    </form>
  {/key}
</Card>

<Card title="两步验证" icon="shield" color="teal" subtitle="登录和批准高风险操作时，需要验证器 App 上的 6 位码">
  <div class="mfa">
    {#if user.mfa_enabled}
      <Chip tone="ok">已开启</Chip>
      <span class="spacer"></span>
      <Button variant="soft" onclick={() => (totpOpen = true)}>重新绑定</Button>
      <Button variant="ghost" onclick={() => ((disableOpen = true), (disableCode = ''), (disableErr = ''))}>关闭</Button>
    {:else}
      <Chip tone="warn">未开启</Chip>
      <span class="spacer"></span>
      <Button variant="primary" icon="shield" onclick={() => (totpOpen = true)}>开启</Button>
    {/if}
  </div>
  {#if user.mfa_enabled}
    <p class="small muted">恢复码在开启时只显示一次；用完或丢失时，重新绑定会生成新的一组。</p>
  {/if}
</Card>

<TotpDialog bind:open={totpOpen} />

<Dialog bind:open={disableOpen} title="关闭两步验证" description="关闭后只靠密码登录，安全性会降低。输入当前验证码确认。" size="sm">
  <div class="otp">
    <OtpInput bind:value={disableCode} autofocus disabled={disableBusy} oncomplete={(c) => disableTotp(c)} />
  </div>
  {#if disableErr}<Alert>{disableErr}</Alert>{/if}
  {#snippet footer()}
    <Button variant="plain" onclick={() => (disableOpen = false)}>取消</Button>
    <Button variant="danger" loading={disableBusy} disabled={disableCode.length !== 6} onclick={() => disableTotp()}>关闭两步验证</Button>
  {/snippet}
</Dialog>

<style>
  .stack {
    gap: var(--s-4);
  }
  .narrow {
    max-width: 420px;
  }
  .row {
    gap: 8px;
  }
  .facts {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s-6);
    margin: 0;
  }
  .facts dt {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .facts dd {
    margin: 2px 0 0;
    font-weight: var(--fw-medium);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
  }
  .mfa {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .mfa + p {
    margin: var(--s-3) 0 0;
  }
  .otp {
    display: flex;
    justify-content: center;
    margin-bottom: var(--s-3);
  }
</style>
