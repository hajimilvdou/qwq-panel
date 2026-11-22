<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ConfirmDialog · 写操作确认（SPEC §8）
  ───────────────────────────────────────────────────────────────
  tone      primary | danger | warn       确认按钮样式
  warning   高风险警示条（warn-soft，图标 + 文字），如"可能导致无法连接服务器"
  confirmText  destructive：需输入该文字（通常是资源名）才能确认
  onconfirm    可返回 Promise：期间按钮转圈、对话框不可关闭；
               抛错时留在对话框并显示 errorText（由调用方经 describeError 给出）

  <ConfirmDialog bind:open title="卸载 系统监控？" tone="danger"
    confirmLabel="卸载" confirmText="系统监控"
    warning="卸载后监控数据会一并删除，无法恢复"
    onconfirm={uninstall}>
    依赖它的应用：安全防护
  </ConfirmDialog>
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Button from './Button.svelte';
  import Dialog from './Dialog.svelte';
  import Icon from './Icon.svelte';
  import Input from './Input.svelte';

  interface Props {
    open?: boolean;
    title: string;
    tone?: 'primary' | 'danger' | 'warn';
    confirmLabel?: string;
    cancelLabel?: string;
    warning?: string;
    confirmText?: string;
    /** 返回 Promise 时等待；抛错由调用方转成 errorText */
    onconfirm: () => unknown | Promise<unknown>;
    oncancel?: () => void;
    errorText?: string;
    children?: Snippet;
  }
  let {
    open = $bindable(false),
    title,
    tone = 'primary',
    confirmLabel = '确定',
    cancelLabel = '取消',
    warning,
    confirmText,
    onconfirm,
    oncancel,
    errorText,
    children,
  }: Props = $props();

  let busy = $state(false);
  let typed = $state('');
  const ready = $derived(!confirmText || typed.trim() === confirmText);

  $effect(() => {
    if (open) typed = '';
  });

  async function confirm() {
    if (!ready || busy) return;
    busy = true;
    try {
      await onconfirm();
      open = false;
    } catch {
      /* 留在对话框：错误文案由调用方通过 errorText 传入 */
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open {title} size="sm" dismissible={!busy} onclose={() => !busy && oncancel?.()}>
  <div class="stack">
    {#if warning}
      <div class="warn" role="note">
        <Icon name="alert" size={18} />
        <span>{warning}</span>
      </div>
    {/if}
    {#if children}<div class="msg">{@render children()}</div>{/if}
    {#if confirmText}
      <Input label="输入「{confirmText}」以确认" bind:value={typed} autocomplete="off" spellcheck={false} />
    {/if}
    {#if errorText}<p class="err" role="alert">{errorText}</p>{/if}
  </div>
  {#snippet footer()}
    <Button variant="plain" disabled={busy} onclick={() => (open = false)}>{cancelLabel}</Button>
    <Button variant={tone} loading={busy} disabled={!ready} onclick={confirm}>{confirmLabel}</Button>
  {/snippet}
</Dialog>

<style>
  .stack {
    --stack-gap: 14px;
  }
  .warn {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 12px;
    background: var(--warn-soft);
    color: var(--warn-text);
    font-weight: var(--fw-medium);
  }
  .warn :global(svg) {
    margin-top: 2px;
  }
  .msg {
    color: var(--text-2);
  }
  .err {
    color: var(--bad-text);
    font-size: var(--fs-sm);
  }
</style>
