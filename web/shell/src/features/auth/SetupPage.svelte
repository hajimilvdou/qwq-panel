<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  首次初始化（SPEC §6）
  ───────────────────────────────────────────────────────────────
  令牌来自安装时打印的链接 /setup#token=…（读后即清）；没有令牌时提示
  打开终端打印的初始化链接或手工粘贴初始化令牌。展示 tls_fingerprint 供核对。
  成功后会话即建立：跳到账户设置，以欢迎卡引导开启两步验证（可跳过）。
-->
<script lang="ts">
  import { Alert, Button, CopyButton, Input } from '$ui';
  import { system } from '$api/endpoints';
  import { describeError, type ErrorView } from '$lib/errors';
  import { navigate } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import AuthLayout from './AuthLayout.svelte';
  import PasswordFields from './PasswordFields.svelte';
  import { clearFragmentToken, takeFragmentToken } from './fragment';

  const SETUP_TOKEN_KEY = 'qwq.setup_token';
  const fromLink = takeFragmentToken(SETUP_TOKEN_KEY);
  let token = $state(fromLink);
  let showTokenInput = $state(!fromLink);
  let username = $state('admin');
  let displayName = $state('');
  let password = $state('');
  let valid = $state(false);
  let busy = $state(false);
  let err = $state<ErrorView | null>(null);

  const fingerprint = $derived(session.setup?.tls_fingerprint);
  const canSubmit = $derived(!!token.trim() && !!username.trim() && valid && !busy);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    busy = true;
    err = null;
    try {
      const s = await system.completeSetup({
        setup_token: token.trim(),
        username: username.trim(),
        password,
        display_name: displayName.trim() || undefined,
      });
      clearFragmentToken(SETUP_TOKEN_KEY);
      session.setup = { ...session.setup, initialized: true };
      session.adopt(s);
      navigate('/settings/account?welcome=1', { replace: true });
    } catch (e2) {
      err = describeError(e2);
      if (err.code === 'UNAUTHENTICATED') {
        clearFragmentToken(SETUP_TOKEN_KEY);
        showTokenInput = true;
        err = {
          ...err,
          message: '初始化令牌不对或已失效，请粘贴终端最新输出的「初始化令牌」或重新打开最新初始化链接（重复执行 sudo qwq setup-token 会使旧令牌作废）',
        };
      }
    } finally {
      busy = false;
    }
  }
</script>

<AuthLayout title="你好，初次见面" subtitle="设置管理员账号，面板就准备好了">
  <form class="stack" onsubmit={submit} novalidate>
    {#if showTokenInput}
      <div class="tip">
        <p><strong>打开终端打印的「初始化链接」</strong>会自动填入令牌，也可直接粘贴终端中的<strong>「初始化令牌」</strong>。</p>
        <p class="faint">
          令牌过期或遗失时可在服务器执行 <code class="mono">sudo qwq setup-token</code> 重新获取（重跑会使旧令牌失效）。
        </p>
      </div>
      <Input label="初始化令牌" mono required autocomplete="off" bind:value={token} error={err?.fields['/setup_token']} />
    {/if}

    {#if fingerprint}
      <div class="fp">
        <span class="small muted">核对证书指纹，与安装输出一致再继续</span>
        <div class="fp-row">
          <code class="mono">{fingerprint}</code>
          <CopyButton text={fingerprint} label="复制指纹" />
        </div>
      </div>
    {/if}

    <Input label="用户名" autocomplete="username" required bind:value={username} error={err?.fields['/username']} />
    <Input label="显示名" hint="可选，主页会这样称呼你" autocomplete="nickname" bind:value={displayName} />
    <PasswordFields bind:password bind:valid {username} serverError={err?.fields['/password']} disabled={busy} />

    {#if err && !Object.keys(err.fields).length}<Alert>{err.message}</Alert>{/if}
    <Button type="submit" variant="primary" size="lg" wide loading={busy} disabled={!canSubmit}>完成初始化</Button>
  </form>
</AuthLayout>

<style>
  .stack {
    gap: var(--s-4);
  }
  .tip {
    padding: var(--s-3) var(--s-4);
    border-radius: var(--r-md);
    background: var(--info-soft);
    font-size: var(--fs-sm);
  }
  .tip p {
    margin: 0;
  }
  .tip p + p {
    margin-top: 4px;
  }
  .tip code {
    word-break: break-all;
  }
  .fp {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .fp-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .fp-row code {
    flex: 1;
    min-width: 0;
    font-size: var(--fs-2xs);
    word-break: break-all;
  }
</style>
