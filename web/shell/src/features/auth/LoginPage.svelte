<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  登录（SPEC §6）
  ───────────────────────────────────────────────────────────────
  credentials ──POST /sessions──▶ Session ─────────────▶ adopt → 回到 ?next=
                         └──────▶ mfa_required ─▶ mfa ──POST /sessions/mfa──▶ adopt
  401 统一"用户名或密码不对"；429 按 retry_after 禁用并静态显示"请在 N 秒后再试"，到时恢复。
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Alert, Button, Input, OtpInput } from '$ui';
  import { ApiError } from '$api/client';
  import { sessions } from '$api/endpoints';
  import type { MfaChallenge } from '$api/types';
  import { describeError } from '$lib/errors';
  import { navigate, router, safeNext } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import AuthLayout from './AuthLayout.svelte';

  let username = $state('');
  let password = $state('');
  let code = $state('');
  let method = $state<'totp' | 'recovery_code'>('totp');
  let challenge = $state<MfaChallenge | null>(null);
  let busy = $state(false);
  let error = $state('');
  let lockedFor = $state(0);
  let unlock: ReturnType<typeof setTimeout> | undefined;
  onDestroy(() => clearTimeout(unlock));

  const locked = $derived(lockedFor > 0);

  function fail(err: unknown, unauthorized: string) {
    if (err instanceof ApiError && err.status === 401) {
      error = unauthorized;
    } else if (err instanceof ApiError && err.status === 429) {
      lockedFor = Math.max(1, Math.ceil(err.retryAfter ?? 30));
      error = `尝试太多次了，请在 ${lockedFor} 秒后再试`;
      clearTimeout(unlock);
      unlock = setTimeout(() => {
        lockedFor = 0;
        error = '';
      }, lockedFor * 1000);
    } else {
      error = describeError(err).message;
    }
  }

  function done(s: Parameters<typeof session.adopt>[0]) {
    session.adopt(s);
    navigate(safeNext(router.query.get('next')), { replace: true });
  }

  async function submitPassword(e: SubmitEvent) {
    e.preventDefault();
    if (busy || locked) return;
    busy = true;
    error = '';
    try {
      const r = await sessions.login(username.trim(), password);
      if (r.status === 'mfa_required') {
        challenge = r;
        method = r.methods.includes('totp') ? 'totp' : 'recovery_code';
        password = '';
      } else done(r);
    } catch (err) {
      fail(err, '用户名或密码不对');
    } finally {
      busy = false;
    }
  }

  async function submitCode(value = code) {
    if (!challenge || busy || locked || !value.trim()) return;
    busy = true;
    error = '';
    try {
      done(await sessions.verifyMfa(challenge.challenge_id, method, value.trim()));
    } catch (err) {
      code = '';
      fail(err, method === 'totp' ? '验证码不对，或已过期' : '恢复码不对，或已用过');
    } finally {
      busy = false;
    }
  }

  function switchMethod() {
    method = method === 'totp' ? 'recovery_code' : 'totp';
    code = '';
    error = '';
  }

  function back() {
    challenge = null;
    code = '';
    error = '';
  }
</script>

{#if !challenge}
  <AuthLayout title="欢迎回来" subtitle="登录 qwq 面板">
    <form class="stack" onsubmit={submitPassword} novalidate>
      <Input label="用户名" autocomplete="username" required bind:value={username} autofocus />
      <Input label="密码" type="password" autocomplete="current-password" required bind:value={password} />
      {#if error}<Alert>{error}</Alert>{/if}
      <Button type="submit" variant="primary" size="lg" wide loading={busy} disabled={locked || !username || !password}>
        登录
      </Button>
    </form>
  </AuthLayout>
{:else}
  <AuthLayout title="两步验证" subtitle={method === 'totp' ? '打开验证器 App，输入 6 位验证码' : '输入一条还没用过的恢复码'}>
    <form
      class="stack"
      onsubmit={(e) => {
        e.preventDefault();
        void submitCode();
      }}
      novalidate
    >
      {#if method === 'totp'}
        <div class="otp">
          <OtpInput bind:value={code} autofocus disabled={busy || locked} oncomplete={(c) => submitCode(c)} />
        </div>
      {:else}
        <Input label="恢复码" autocomplete="one-time-code" mono required bind:value={code} autofocus />
      {/if}
      {#if error}<Alert>{error}</Alert>{/if}
      <Button type="submit" variant="primary" size="lg" wide loading={busy} disabled={locked || !code}>验证</Button>
      <div class="alt">
        {#if challenge.methods.length > 1}
          <Button variant="plain" size="sm" onclick={switchMethod}>
            {method === 'totp' ? '改用恢复码' : '改用验证码'}
          </Button>
        {/if}
        <Button variant="plain" size="sm" onclick={back}>换个账号</Button>
      </div>
    </form>
  </AuthLayout>
{/if}

<style>
  .stack {
    gap: var(--s-4);
  }
  .otp {
    display: flex;
    justify-content: center;
  }
  .alt {
    display: flex;
    justify-content: space-between;
  }
</style>
