<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  IconButton · 只有图标的按钮（必须给 label，作为 aria-label 与悬停提示）
  ───────────────────────────────────────────────────────────────
  <IconButton icon="sun" label="切换主题" onclick={toggle} />
  variant  plain（默认）| ghost；size sm 32 | md 40
-->
<script lang="ts">
  import type { HTMLButtonAttributes } from 'svelte/elements';
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';

  interface Props extends Omit<HTMLButtonAttributes, 'children'> {
    icon: IconName;
    label: string;
    variant?: 'plain' | 'ghost';
    size?: 'sm' | 'md';
    href?: string;
    pressed?: boolean;
  }
  let {
    icon,
    label,
    variant = 'plain',
    size = 'md',
    href,
    pressed,
    type = 'button',
    class: cls = '',
    ...rest
  }: Props = $props();
</script>

{#if href}
  <a {href} class="ib {variant} {size} {cls}" aria-label={label} title={label}>
    <Icon name={icon} size={size === 'sm' ? 16 : 20} />
  </a>
{:else}
  <button {type} class="ib {variant} {size} {cls}" aria-label={label} title={label} aria-pressed={pressed} {...rest}>
    <Icon name={icon} size={size === 'sm' ? 16 : 20} />
  </button>
{/if}

<style>
  .ib {
    display: inline-grid;
    place-items: center;
    flex: none;
    width: var(--ctl-md);
    height: var(--ctl-md);
    border-radius: var(--r-pill);
    color: var(--text-2);
    transition:
      background var(--dur-1) var(--ease),
      color var(--dur-1) var(--ease);
  }
  .sm {
    width: var(--ctl-sm);
    height: var(--ctl-sm);
  }
  .ghost {
    background: var(--surface-3);
  }
  .ib:hover:not(:disabled) {
    background: var(--surface-3);
    color: var(--text);
  }
  .ghost:hover:not(:disabled) {
    background: var(--line);
  }
  .ib[aria-pressed='true'] {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .ib:disabled {
    opacity: 0.5;
  }
</style>
