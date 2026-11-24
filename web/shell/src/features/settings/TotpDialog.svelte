<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  TotpDialog · 开启两步验证（SPEC §6 / GAPS 缺口 1）
  ───────────────────────────────────────────────────────────────
    begin ──POST …/mfa/totp──▶ scan（二维码 + 手输密钥 + 6 位码）
          ──POST …/confirm───▶ codes（恢复码只显示一次：复制 / 下载 txt，
                                 勾选"已保存"才能关闭）
  confirm 不轮换会话、CSRF 不变、不标新鲜 MFA：响应里的 session 是当前会话，
  经 adopt(…, false) 同步用户与到期时间，不向其他标签广播登录。
  密钥与恢复码只存在本组件内存，关闭即丢弃。
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Alert, Button, Checkbox, CopyButton, Dialog, Input, OtpInput, QrCode, Skeleton } from '$ui';
  import { account } from '$api/endpoints';
  import type { TotpEnrollment } from '$api/additions';
  import { describeError } from '$lib/errors';
  import { createIntent } from '$lib/ops';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';

  interface Props {
    open: boolean;
  }
  let { open = $bindable() }: Props = $props();

  type Stage = 'begin' | 'verify' | 'scan' | 'codes';
  let stage = $state<Stage>('begin');
  let enrollment = $state<TotpEnrollment | null>(null);
  let codes = $state<string[]>([]);
  let code = $state('');
  let rebindMfaCode = $state('');
  let rebindUseRecovery = $state(false);
  let saved = $state(false);
  let busy = $state(false);
  let error = $state('');
  let downloadUrl = '';

  const codesText = $derived(codes.join('\n'));

  /* 每次打开只申请一次密钥；失败停在错误态，不自动重试 */
  let started = false;
  $effect(() => {
    if (open && !started) {
      started = true;
      void begin();
    }
  });

  onDestroy(() => {
    if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  });

  async function begin(mfaCode?: string) {
    busy = true;
    error = '';
    try {
      enrollment = await account.beginTotp(createIntent().key, mfaCode);
      rebindMfaCode = '';
      stage = 'scan';
    } catch (e) {
      const v = describeError(e);
      if (v.code === 'MFA_REQUIRED') {
        if (stage !== 'verify') {
          stage = 'verify';
          rebindMfaCode = '';
          rebindUseRecovery = false;
          error = '';
        } else {
          rebindMfaCode = '';
          error = '当前两步验证码或恢复码不正确或已过期，请重试';
        }
      } else {
        error = v.message;
      }
    } finally {
      busy = false;
    }
  }

  function submitRebindMfa(val = rebindMfaCode) {
    const trimmed = val.trim();
    if (busy || !trimmed) return;
    void begin(trimmed);
  }

  async function confirm(value = code) {
    if (busy || value.length !== 6) return;
    busy = true;
    error = '';
    try {
      const r = await account.confirmTotp(value, createIntent().key);
      session.adopt(r.session, false);
      codes = r.recovery_codes;
      enrollment = null;
      stage = 'codes';
    } catch (e) {
      code = '';
      const v = describeError(e);
      error = v.code === 'VALIDATION_FAILED' || v.code === 'MFA_REQUIRED' ? '验证码不对，请等下一个码再试' : v.message;
    } finally {
      busy = false;
    }
  }

  function download() {
    if (downloadUrl) URL.revokeObjectURL(downloadUrl);
    downloadUrl = URL.createObjectURL(new Blob([`qwq 面板恢复码（每条只能用一次）\n\n${codesText}\n`], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = 'qwq-recovery-codes.txt';
    a.click();
  }

  function reset() {
    if (stage === 'codes') toasts.success('两步验证已开启');
    started = false;
    stage = 'begin';
    enrollment = null;
    codes = [];
    code = '';
    rebindMfaCode = '';
    rebindUseRecovery = false;
    saved = false;
    error = '';
  }
</script>

<Dialog
  bind:open
  title={stage === 'codes' ? '保存恢复码' : stage === 'verify' ? '验证当前两步验证' : '开启两步验证'}
  description={stage === 'codes'
    ? '手机丢了时用它登录。每条只能用一次，只显示这一次。'
    : stage === 'verify'
      ? '重新绑定两步验证前，请输入当前 6 位动态验证码或恢复码。'
      : undefined}
  dismissible={stage !== 'codes' || saved}
  onclose={reset}
>
  {#if stage === 'begin'}
    {#if error}<Alert>{error}</Alert>{:else}<Skeleton height={184} width="184px" label="正在生成密钥" />{/if}
  {:else if stage === 'verify'}
    {#if rebindUseRecovery}
      <form
        onsubmit={(e) => {
          e.preventDefault();
          submitRebindMfa();
        }}
      >
        <Input label="当前恢复码" mono placeholder="xxxx-xxxx" bind:value={rebindMfaCode} autofocus disabled={busy} />
      </form>
    {:else}
      <div class="otp">
        <OtpInput bind:value={rebindMfaCode} autofocus disabled={busy} oncomplete={(c) => submitRebindMfa(c)} />
      </div>
    {/if}
    <div class="otp">
      <Button
        type="button"
        variant="plain"
        size="sm"
        onclick={() => {
          rebindUseRecovery = !rebindUseRecovery;
          rebindMfaCode = '';
          error = '';
        }}
      >
        {rebindUseRecovery ? '改用 6 位动态验证码' : '改用恢复码验证'}
      </Button>
    </div>
    {#if error}<Alert>{error}</Alert>{/if}
  {:else if stage === 'scan' && enrollment}
    <div class="scan">
      <QrCode text={enrollment.otpauth_url} label="用验证器 App 扫描这个二维码" />
      <ol class="steps">
        <li>用验证器 App（如 Google Authenticator、1Password）扫码</li>
        <li>
          扫不了？手动输入密钥
          <span class="secret"><code class="mono">{enrollment.secret}</code><CopyButton text={enrollment.secret} label="复制密钥" /></span>
        </li>
        <li>输入 App 上显示的 6 位验证码</li>
      </ol>
    </div>
    <div class="otp">
      <OtpInput bind:value={code} autofocus disabled={busy} oncomplete={(c) => confirm(c)} />
    </div>
    {#if error}<Alert>{error}</Alert>{/if}
  {:else if stage === 'codes'}
    <ul class="codes mono" aria-label="恢复码">
      {#each codes as c (c)}<li>{c}</li>{/each}
    </ul>
    <div class="row">
      <CopyButton text={codesText} label="复制全部" />
      <Button variant="soft" size="sm" icon="external" onclick={download}>下载 txt</Button>
    </div>
    <Checkbox label="我已把恢复码存到安全的地方" bind:checked={saved} />
  {/if}

  {#snippet footer()}
    {#if stage === 'verify'}
      <Button variant="plain" onclick={() => (open = false)}>取消</Button>
      <Button
        variant="primary"
        loading={busy}
        disabled={rebindUseRecovery ? rebindMfaCode.trim().length < 6 : rebindMfaCode.length !== 6}
        onclick={() => submitRebindMfa()}
      >
        验证并继续
      </Button>
    {:else if stage === 'scan'}
      <Button variant="plain" onclick={() => (open = false)}>取消</Button>
      <Button variant="primary" loading={busy} disabled={code.length !== 6} onclick={() => confirm()}>开启</Button>
    {:else if stage === 'codes'}
      <Button variant="primary" disabled={!saved} onclick={() => (open = false)}>完成</Button>
    {:else}
      <Button variant="plain" onclick={() => (open = false)}>关闭</Button>
    {/if}
  {/snippet}
</Dialog>

<style>
  .scan {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s-5);
    align-items: center;
  }
  .steps {
    display: flex;
    flex: 1 1 220px;
    flex-direction: column;
    gap: var(--s-3);
    margin: 0;
    padding-left: 1.2em;
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .secret {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-top: 4px;
  }
  .secret code {
    padding: 2px 8px;
    border-radius: var(--r-xs);
    background: var(--surface-3);
    color: var(--text);
    letter-spacing: 0.08em;
    word-break: break-all;
  }
  .otp {
    display: flex;
    justify-content: center;
    margin-top: var(--s-5);
  }
  .codes {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 6px 16px;
    margin: 0 0 var(--s-3);
    padding: var(--s-4);
    border-radius: var(--r-md);
    background: var(--surface-2);
    list-style: none;
    font-size: var(--fs-sm);
  }
  .row {
    gap: 8px;
    margin-bottom: var(--s-3);
  }
</style>
