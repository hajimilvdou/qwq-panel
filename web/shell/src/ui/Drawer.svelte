<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Drawer · 侧边抽屉（≤860 的会话列表、筛选面板等）
  ───────────────────────────────────────────────────────────────
  <Drawer bind:open title="会话" side="left">……</Drawer>
  基于原生 <dialog>，行为同 Dialog（Esc、点遮罩关闭、焦点陷阱）。
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import IconButton from './IconButton.svelte';
  import { registerModalDialog, unregisterModalDialog } from './toplayer';

  interface Props {
    open?: boolean;
    title: string;
    side?: 'left' | 'right';
    size?: 'sm' | 'md' | 'lg';
    onclose?: () => void;
    children: Snippet;
  }
  let { open = $bindable(false), title, side = 'right', size = 'sm', onclose, children }: Props = $props();

  const uid = $props.id();
  let dlg: HTMLDialogElement;

  $effect(() => {
    const el = dlg;
    if (!el) return;
    if (open && !el.open) {
      el.showModal();
      registerModalDialog(el);
    } else if (!open && el.open) {
      unregisterModalDialog(el);
      el.close();
    }
  });

  $effect(() => {
    const el = dlg;
    return () => {
      if (el) unregisterModalDialog(el);
    };
  });
</script>

<dialog
  bind:this={dlg}
  class="drawer {side} sz-{size}"
  aria-labelledby="{uid}-t"
  onclose={() => {
    unregisterModalDialog(dlg);
    open = false;
    onclose?.();
  }}
  onclick={(e) => e.target === dlg && (open = false)}
>
  <div class="panel">
    <header>
      <h2 id="{uid}-t">{title}</h2>
      <IconButton icon="x" label="关闭" size="sm" onclick={() => (open = false)} />
    </header>
    <div class="body">{@render children()}</div>
  </div>
</dialog>

<style>
  .drawer {
    margin: 0;
    width: min(360px, 90vw);
    max-width: none;
    height: 100dvh;
    max-height: none;
    padding: 0;
    border: 0;
    background: var(--surface);
    box-shadow: var(--shadow-3);
  }
  .drawer.sz-md { width: min(500px, 92vw); }
  .drawer.sz-lg { width: min(640px, 94vw); }
  .right {
    margin-left: auto;
  }
  .drawer[open].left {
    animation: slide-l var(--dur-3) var(--ease-out);
  }
  .drawer[open].right {
    animation: slide-r var(--dur-3) var(--ease-out);
  }
  .drawer::backdrop {
    background: var(--scrim);
  }
  .panel {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--s-4) var(--s-4) var(--s-2) var(--s-5);
  }
  h2 {
    font-size: var(--fs-lg);
  }
  .body {
    flex: 1;
    overflow: auto;
    padding: 0 var(--s-3) var(--s-4);
  }
  @keyframes slide-l {
    from {
      transform: translateX(-100%);
    }
  }
  @keyframes slide-r {
    from {
      transform: translateX(100%);
    }
  }
</style>
