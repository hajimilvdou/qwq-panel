<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  首次初始化（SPEC §6）
  ───────────────────────────────────────────────────────────────
  令牌来自安装时打印的链接 /setup#token=…（读后即清）；没有令牌时提示
  "打开安装时打印的链接"与 SSH 隧道，并允许手工粘贴。展示 tls_fingerprint 供核对。
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
  const currentPort = $derived(typeof location !== 'undefined' && location.port ? location.port : '8443');
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
        err = { ...err, message: '初始化令牌不对或已过期，请重新打开安装链接或在下方手动粘贴新令牌' };
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
        <p><strong>打开安装时打印的链接</strong>，令牌会自动填好。</p>
        <p class="faint">
          面板默认只监听本机，可以用 SSH 隧道访问：<code class="mono">ssh -L {currentPort}:127.0.0.1:{currentPort} 你的服务器</code>
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
