<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Dialog · 模态对话框（原生 <dialog>.showModal：顶层、焦点陷阱、Esc、还焦点）
  ───────────────────────────────────────────────────────────────
  <Dialog bind:open title="新建用户" onclose={reset}>
    ……表单……
    {#snippet footer()}<Button onclick={() => (open = false)}>取消</Button>{/snippet}
  </Dialog>

  dismissible=false：点遮罩与 Esc 不关闭（提交中、必须做选择时）
  size  sm 420 | md 560 | lg 720
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import IconButton from './IconButton.svelte';

  interface Props {
    open?: boolean;
    title: string;
    description?: string;
    size?: 'sm' | 'md' | 'lg';
    dismissible?: boolean;
    onclose?: () => void;
    children?: Snippet;
    footer?: Snippet;
    /** 标题前的装饰（图标、表情） */
    lead?: Snippet;
  }
  let {
    open = $bindable(false),
    title,
    description,
    size = 'md',
    dismissible = true,
    onclose,
    children,
    footer,
    lead,
  }: Props = $props();

  const uid = $props.id();
  let dlg: HTMLDialogElement;

  $effect(() => {
    if (open && !dlg.open) {
      dlg.showModal();
      requestAnimationFrame(() => {
        if (!dlg?.open) return;
        const target = dlg.querySelector<HTMLElement>(
          '.body [autofocus]:not([disabled]), .body input:not([disabled]):not([type="hidden"])',
        );
        target?.focus();
      });
    } else if (!open && dlg.open) {
      dlg.close();
    }
  });

  function handleClose() {
    open = false;
    onclose?.();
  }
  function oncancel(e: Event) {
    if (!dismissible) e.preventDefault();
  }
  /* 点在 <dialog> 自身（即遮罩区域）上才关闭；内容区由 .panel 承接 */
  function onclick(e: MouseEvent) {
    if (dismissible && e.target === dlg) open = false;
  }
</script>

<dialog
  bind:this={dlg}
  class="dlg {size}"
  aria-labelledby="{uid}-t"
  aria-describedby={description ? `${uid}-d` : undefined}
  onclose={handleClose}
  {oncancel}
  {onclick}
>
  <div class="panel">
    <header>
      {#if lead}{@render lead()}{/if}
      <div class="titles">
        <h2 id="{uid}-t">{title}</h2>
        {#if description}<p id="{uid}-d">{description}</p>{/if}
      </div>
      {#if dismissible}<IconButton icon="x" label="关闭" size="sm" onclick={() => (open = false)} />{/if}
    </header>
    {#if children}<div class="body">{@render children()}</div>{/if}
    {#if footer}<footer>{@render footer()}</footer>{/if}
  </div>
</dialog>

<style>
  .dlg {
    width: min(560px, calc(100vw - 32px));
    max-height: min(86vh, 900px);
    padding: 0;
    border: 0;
    border-radius: var(--r-xl);
    background: var(--surface);
    box-shadow: var(--shadow-3);
    overflow: visible;
  }
  .sm {
    width: min(420px, calc(100vw - 32px));
  }
  .lg {
    width: min(720px, calc(100vw - 32px));
  }
  .dlg[open] {
    animation: qwq-rise-in var(--dur-3) var(--ease-out);
  }
  .dlg::backdrop {
    background: var(--scrim);
    backdrop-filter: blur(2px);
  }
  .dlg[open]::backdrop {
    animation: qwq-fade-in var(--dur-2) var(--ease);
  }
  .panel {
    display: flex;
    flex-direction: column;
    max-height: inherit;
  }
  header {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: var(--s-5) var(--s-5) 0;
  }
  .titles {
    flex: 1;
    min-width: 0;
  }
  h2 {
    font-size: var(--fs-xl);
    font-weight: var(--fw-semibold);
  }
  header p {
    margin-top: 2px;
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .body {
    padding: var(--s-4) var(--s-5);
    overflow: auto;
  }
  footer {
    display: flex;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: 8px;
    padding: var(--s-3) var(--s-5) var(--s-5);
  }
  @media (max-width: 860px) {
    .dlg {
      margin: auto 0 0;
      width: 100vw;
      max-width: 100vw;
      border-radius: var(--r-xl) var(--r-xl) 0 0;
    }
  }
</style>
