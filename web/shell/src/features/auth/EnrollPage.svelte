<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  注册（SPEC §6 / GAPS 缺口 1）：管理员生成的一次性链接 /enroll#token=…
  POST /enrollments {token, password} → 201 Session，成功即登录。
  令牌错 / 用过 / 过期统一 401：提示找管理员重新生成。
-->
<script lang="ts">
  import { Alert, Button, EmptyState, Input } from '$ui';
  import { account } from '$api/endpoints';
  import { describeError, type ErrorView } from '$lib/errors';
  import { createIntent } from '$lib/ops';
  import { navigate } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import AuthLayout from './AuthLayout.svelte';
  import PasswordFields from './PasswordFields.svelte';
  import { takeFragmentToken } from './fragment';

  const fromLink = takeFragmentToken();
  let token = $state(fromLink);
  let password = $state('');
  let valid = $state(false);
  let busy = $state(false);
  let err = $state<ErrorView | null>(null);
  let dead = $state(false);
  /* 同一次提交意图复用幂等键（网络重试不重复兑换） */
  let intent = createIntent();

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (busy || !valid || !token.trim()) return;
    busy = true;
    err = null;
    try {
      const s = await account.redeemEnrollment(token.trim(), password, intent.key);
      session.adopt(s);
      navigate('/', { replace: true });
    } catch (e2) {
      err = describeError(e2);
      if (err.code === 'UNAUTHENTICATED') dead = true;
      else if (err.code === 'VALIDATION_FAILED') intent = createIntent();
    } finally {
      busy = false;
    }
  }
</script>

{#if dead}
  <AuthLayout title="链接用不了了" mood="warn">
    <EmptyState compact mood="warn" title="注册链接已失效" description="它可能已经用过或过期了。请联系管理员重新生成一个。">
      {#snippet action()}<Button href="/login" variant="soft">去登录</Button>{/snippet}
    </EmptyState>
  </AuthLayout>
{:else}
  <AuthLayout title="设置你的密码" subtitle="设好之后就能登录面板了">
    <form class="stack" onsubmit={submit} novalidate>
      {#if !fromLink}
        <Input label="注册令牌" hint="打开管理员发给你的链接会自动填好" mono required autocomplete="off" bind:value={token} />
      {/if}
      <PasswordFields bind:password bind:valid serverError={err?.fields['/password']} disabled={busy} />
      {#if err && !Object.keys(err.fields).length}<Alert>{err.message}</Alert>{/if}
      <Button type="submit" variant="primary" size="lg" wide loading={busy} disabled={!valid || !token.trim()}>完成并登录</Button>
    </form>
  </AuthLayout>
{/if}

<style>
  .stack {
    gap: var(--s-4);
  }
</style>
