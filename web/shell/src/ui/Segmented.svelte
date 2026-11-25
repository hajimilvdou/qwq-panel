<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Segmented · 分段选择（radiogroup，←→ 切换，Tab 只停在选中项）
  ───────────────────────────────────────────────────────────────
  <Segmented label="主题" bind:value={theme}
    options={[{ value: 'light', label: '浅色' }, { value: 'dark', label: '深色' }]} />
  禁用项写 hint 作为原因（悬停与读屏可见）。
-->
<script lang="ts" generics="V extends string">
  import type { Option } from './types';

  interface Props {
    value: V;
    options: readonly Option<V>[];
    label: string;
    size?: 'sm' | 'md';
    wide?: boolean;
    onchange?: (v: V) => void;
  }
  let { value = $bindable(), options, label, size = 'md', wide = false, onchange }: Props = $props();

  let group: HTMLDivElement;

  function pick(v: V) {
    if (v === value) return;
    value = v;
    onchange?.(v);
  }

  function onkeydown(e: KeyboardEvent) {
    const step = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const enabled = options.filter((o) => !o.disabled);
    const i = enabled.findIndex((o) => o.value === value);
    const next = enabled[(i + step + enabled.length) % enabled.length];
    if (!next) return;
    pick(next.value);
    group.querySelector<HTMLElement>(`[data-v="${CSS.escape(next.value)}"]`)?.focus();
  }
</script>

<div bind:this={group} class="seg {size}" class:wide role="radiogroup" aria-label={label} tabindex="-1" {onkeydown}>
  {#each options as o (o.value)}
    <button
      type="button"
      role="radio"
      data-v={o.value}
      aria-checked={o.value === value}
      tabindex={o.value === value ? 0 : -1}
      disabled={o.disabled}
      title={o.hint}
      onclick={() => pick(o.value)}
    >
      {o.label}
    </button>
  {/each}
</div>

<style>
  .seg {
    display: inline-flex;
    gap: 2px;
    padding: 3px;
    border-radius: 12px;
    background: var(--surface-3);
  }
  .wide {
    display: flex;
  }
  .wide button {
    flex: 1;
  }
  button {
    height: calc(var(--ctl-md) - 6px);
    padding: 0 14px;
    border-radius: 9px;
    color: var(--text-2);
    font-weight: var(--fw-medium);
    white-space: nowrap;
    transition:
      background var(--dur-2) var(--ease),
      color var(--dur-2) var(--ease),
      box-shadow var(--dur-2) var(--ease);
  }
  .sm button {
    height: calc(var(--ctl-sm) - 6px);
    padding: 0 10px;
    font-size: var(--fs-sm);
  }
  button:hover:not(:disabled) {
    color: var(--text);
  }
  button[aria-checked='true'] {
    background: var(--surface);
    color: var(--text);
    font-weight: var(--fw-semibold);
    box-shadow: var(--shadow-1);
  }
  button:disabled {
    opacity: 0.45;
  }
</style>
