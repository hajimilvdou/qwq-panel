<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Tabs · 选项卡（role=tablist，←→ Home End 切换，自动激活）
  ───────────────────────────────────────────────────────────────
  <Tabs label="应用详情" tabs={[{ id: 'overview', label: '概览' }, …]} bind:value={tab}
        onchange={(t) => router.setQuery({ tab: t })}>
    {#snippet children(active)}
      {#if active === 'overview'}…{/if}
    {/snippet}
  </Tabs>
  选中项建议写进 URL query（可分享），由调用方在 onchange 里做。
-->
<script lang="ts" generics="T extends string">
  import type { Snippet } from 'svelte';

  interface Tab {
    id: T;
    label: string;
    /** 计数徽标（中性色，不表示紧急） */
    count?: number;
    hidden?: boolean;
  }
  interface Props {
    tabs: readonly Tab[];
    value: T;
    label: string;
    onchange?: (id: T) => void;
    children?: Snippet<[T]>;
  }
  let { tabs, value = $bindable(), label, onchange, children }: Props = $props();

  const uid = $props.id();
  const visible = $derived(tabs.filter((t) => !t.hidden));
  let list: HTMLDivElement;

  function select(id: T, focus = false) {
    if (id !== value) {
      value = id;
      onchange?.(id);
    }
    if (focus) list.querySelector<HTMLElement>(`#${uid}-${id}`)?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    const i = visible.findIndex((t) => t.id === value);
    const n = visible.length;
    const to =
      e.key === 'ArrowRight' ? (i + 1) % n : e.key === 'ArrowLeft' ? (i - 1 + n) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    select(visible[to]!.id, true);
  }
</script>

<div bind:this={list} class="tabs" role="tablist" aria-label={label} tabindex="-1" {onkeydown}>
  {#each visible as t (t.id)}
    <button
      type="button"
      role="tab"
      id="{uid}-{t.id}"
      aria-selected={t.id === value}
      aria-controls="{uid}-panel"
      tabindex={t.id === value ? 0 : -1}
      onclick={() => select(t.id)}
    >
      {t.label}
      {#if t.count !== undefined}<span class="count num">{t.count}</span>{/if}
    </button>
  {/each}
</div>
{#if children}
  <div id="{uid}-panel" role="tabpanel" aria-labelledby="{uid}-{value}" class="panel">
    {@render children(value)}
  </div>
{/if}

<style>
  .tabs {
    display: flex;
    gap: 4px;
    border-bottom: 1px solid var(--line);
    overflow-x: auto;
    scrollbar-width: none;
  }
  button {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: var(--ctl-md);
    padding: 0 12px;
    color: var(--text-2);
    font-weight: var(--fw-medium);
    white-space: nowrap;
    transition: color var(--dur-1) var(--ease);
  }
  button:hover {
    color: var(--text);
  }
  button[aria-selected='true'] {
    color: var(--text);
    font-weight: var(--fw-semibold);
  }
  button[aria-selected='true']::after {
    content: '';
    position: absolute;
    left: 10px;
    right: 10px;
    bottom: -1px;
    height: 2px;
    border-radius: 2px;
    background: var(--accent);
  }
  .count {
    min-width: 20px;
    padding: 0 6px;
    border-radius: var(--r-pill);
    background: var(--surface-3);
    color: var(--text-2);
    font-size: var(--fs-2xs);
    line-height: 18px;
    text-align: center;
  }
  .panel {
    padding-top: var(--s-5);
  }
</style>
