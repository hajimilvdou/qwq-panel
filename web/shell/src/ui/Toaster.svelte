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
  import {
    getTopModalDialog,
    hideToasterFromTopLayer,
    onTopLayerChanged,
    promoteToasterToTopLayer,
  } from './toplayer';

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

  let anchorEl = $state<HTMLSpanElement>();
  let hostEl = $state<HTMLDivElement>();
  let lastMaxId = 0;

  function syncMountTarget(wantPortal: boolean): boolean {
    if (!hostEl) return false;
    const modal = wantPortal ? getTopModalDialog() : null;
    if (modal) {
      if (hostEl.parentElement !== modal) {
        modal.appendChild(hostEl);
        return true;
      }
      return false;
    }
    const anchor = anchorEl;
    const home = anchor?.parentElement;
    if (anchor && home && hostEl.parentElement !== home) {
      home.insertBefore(hostEl, anchor.nextSibling);
      return true;
    }
    return false;
  }

  function isPopoverOpen(el: HTMLElement): boolean {
    try {
      return el.matches(':popover-open');
    } catch {
      return false;
    }
  }

  $effect(() => {
    const count = items.length;
    let maxId = 0;
    for (const item of items) {
      if (item.id > maxId) maxId = item.id;
    }
    if (!hostEl) return;
    if (count > 0) {
      const moved = syncMountTarget(true);
      const hasNew = maxId > lastMaxId;
      if (moved || hasNew || !isPopoverOpen(hostEl)) {
        promoteToasterToTopLayer(hostEl);
      }
      if (maxId > lastMaxId) lastMaxId = maxId;
    } else {
      lastMaxId = 0;
      hideToasterFromTopLayer(hostEl);
      syncMountTarget(false);
    }
  });

  $effect(() => {
    const off = onTopLayerChanged(() => {
      if (!hostEl) return;
      if (items.length > 0) {
        syncMountTarget(true);
        promoteToasterToTopLayer(hostEl);
      } else {
        syncMountTarget(false);
      }
    });
    return () => {
      off();
      if (hostEl) {
        hideToasterFromTopLayer(hostEl);
        syncMountTarget(false);
      }
    };
  });

  const ICON: Record<ToastItem['kind'], IconName> = {
    info: 'info',
    success: 'check-circle',
    warn: 'alert',
    error: 'alert',
  };
</script>

<span bind:this={anchorEl} hidden></span>
<div bind:this={hostEl} class="toaster" popover="manual" aria-live="polite" aria-relevant="additions">
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
    inset: 68px auto auto 50%;
    margin: 0;
    padding: 0;
    border: 0;
    background: transparent;
    color: inherit;
    overflow: visible;
    z-index: var(--z-toast);
    flex-direction: column;
    align-items: center;
    gap: 8px;
    width: min(480px, calc(100vw - 24px));
    transform: translateX(-50%);
    pointer-events: none;
  }
  .toaster:popover-open {
    display: flex;
  }
  .toaster:not(:popover-open) {
    display: none;
  }
  @supports not selector(:popover-open) {
    .toaster {
      display: flex;
    }
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
