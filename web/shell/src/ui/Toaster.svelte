<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Toaster · Toast 容器（顶部居中，aria-live=polite）
  ───────────────────────────────────────────────────────────────
  纯展示：数据与生命周期由调用方（lib/toast）管理，ui 不依赖 lib。
  <Toaster items={toasts.items} ondismiss={(id) => toasts.dismiss(id)} />
-->
<script lang="ts">
  import Icon from './Icon.svelte';
  import IconButton from './IconButton.svelte';
  import type { IconName } from './icons';

  export interface ToastItem {
    id: number;
    kind: 'info' | 'success' | 'warn' | 'error';
    text: string;
    detail?: string;
    action?: { label: string; run: () => void };
  }

  interface Props {
    items: readonly ToastItem[];
    ondismiss: (id: number) => void;
  }
  let { items, ondismiss }: Props = $props();

  const ICON: Record<ToastItem['kind'], IconName> = {
    info: 'info',
    success: 'check-circle',
    warn: 'alert',
    error: 'alert',
  };
</script>

<div class="toaster" aria-live="polite" aria-relevant="additions">
  {#each items as t (t.id)}
    <div class="toast {t.kind}" role={t.kind === 'error' ? 'alert' : 'status'}>
      <span class="ic"><Icon name={ICON[t.kind]} size={18} /></span>
      <div class="text">
        <span>{t.text}</span>
        {#if t.detail}<small class="mono">{t.detail}</small>{/if}
      </div>
      {#if t.action}
        <button
          type="button"
          class="act"
          onclick={() => {
            t.action?.run();
            ondismiss(t.id);
          }}>{t.action.label}</button
        >
      {/if}
      <IconButton icon="x" label="关闭提示" size="sm" onclick={() => ondismiss(t.id)} />
    </div>
  {/each}
</div>

<style>
  .toaster {
    position: fixed;
    top: 16px;
    left: 50%;
    z-index: var(--z-toast);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    width: min(480px, calc(100vw - 24px));
    transform: translateX(-50%);
    pointer-events: none;
  }
  .toast {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 8px 8px 14px;
    border-radius: var(--r-md);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-2);
    pointer-events: auto;
    animation: qwq-rise-in var(--dur-3) var(--ease-out);
  }
  .ic {
    display: grid;
    color: var(--info-text);
  }
  .success .ic {
    color: var(--ok-text);
  }
  .warn .ic {
    color: var(--warn-text);
  }
  .error {
    border-color: color-mix(in oklab, var(--bad) 35%, var(--line));
  }
  .error .ic {
    color: var(--bad-text);
  }
  .text {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    font-weight: var(--fw-medium);
    overflow-wrap: anywhere;
  }
  small {
    color: var(--text-3);
    font-weight: var(--fw-regular);
  }
  .act {
    padding: 4px 10px;
    border-radius: 8px;
    color: var(--accent-text);
    font-weight: var(--fw-semibold);
  }
  .act:hover {
    background: var(--accent-soft);
  }
</style>
