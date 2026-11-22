<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Button · 按钮
  ───────────────────────────────────────────────────────────────
  variant  primary（主题色实底）| soft | ghost | plain | danger | ok | ai | warn
  size     sm 32 | md 40 | lg 44
  href     传入则渲染为 <a>（站内链接由路由拦截）
  loading  显示转圈并禁用（按钮宽度不跳动）
  icon / iconRight  图标名

  <Button variant="primary" icon="plus" onclick={add}>安装应用</Button>
  <Button variant="danger" loading={busy}>卸载</Button>
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';

  type Variant = 'primary' | 'soft' | 'ghost' | 'plain' | 'danger' | 'ok' | 'ai' | 'warn';

  interface Props extends Omit<HTMLButtonAttributes, 'children'> {
    variant?: Variant;
    size?: 'sm' | 'md' | 'lg';
    href?: string;
    loading?: boolean;
    icon?: IconName;
    iconRight?: IconName;
    wide?: boolean;
    children?: Snippet;
  }
  let {
    variant = 'ghost',
    size = 'md',
    href,
    loading = false,
    icon,
    iconRight,
    wide = false,
    type = 'button',
    disabled,
    children,
    class: cls = '',
    ...rest
  }: Props = $props();

  const iconSize = $derived(size === 'sm' ? 16 : 18);
</script>

{#snippet body()}
  {#if loading}
    <span class="spin loop" aria-hidden="true"></span>
  {:else if icon}
    <Icon name={icon} size={iconSize} />
  {/if}
  {#if children}<span class="label">{@render children()}</span>{/if}
  {#if iconRight && !loading}<Icon name={iconRight} size={iconSize} />{/if}
{/snippet}

{#if href && !disabled}
  <a {href} class="btn {variant} {size} {cls}" class:wide aria-busy={loading || undefined}>{@render body()}</a>
{:else}
  <button
    {type}
    class="btn {variant} {size} {cls}"
    class:wide
    disabled={disabled || loading}
    aria-busy={loading || undefined}
    {...rest}
  >
    {@render body()}
  </button>
{/if}

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    height: var(--ctl-md);
    padding: 0 16px;
    border-radius: 12px;
    font-weight: var(--fw-semibold);
    white-space: nowrap;
    text-decoration: none;
    user-select: none;
    transition:
      transform var(--dur-1) var(--ease),
      background var(--dur-1) var(--ease),
      box-shadow var(--dur-1) var(--ease),
      color var(--dur-1) var(--ease);
  }
  .btn:active:not(:disabled) {
    transform: scale(0.97);
  }
  .btn:disabled {
    opacity: 0.55;
  }
  .sm {
    height: var(--ctl-sm);
    padding: 0 12px;
    border-radius: 10px;
    font-size: var(--fs-sm);
  }
  .lg {
    height: var(--ctl-lg);
    padding: 0 20px;
    font-size: var(--fs-lg);
  }
  .wide {
    width: 100%;
  }
  .label {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .primary {
    background: var(--accent-strong);
    color: var(--on-accent);
    box-shadow: 0 6px 16px color-mix(in oklab, var(--accent) 28%, transparent);
  }
  .primary:hover:not(:disabled) {
    background: color-mix(in oklab, var(--accent-strong) 88%, black);
  }
  .soft {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .soft:hover:not(:disabled) {
    background: var(--accent-soft-2);
  }
  .ghost {
    background: var(--surface-3);
    color: var(--text);
  }
  .ghost:hover:not(:disabled) {
    background: var(--line);
  }
  .plain {
    background: transparent;
    color: var(--text-2);
  }
  .plain:hover:not(:disabled) {
    background: var(--surface-3);
    color: var(--text);
  }
  .danger {
    background: var(--bad-strong);
    color: var(--on-strong);
  }
  .danger:hover:not(:disabled) {
    background: color-mix(in oklab, var(--bad-strong) 88%, black);
  }
  .ok {
    background: var(--ok-strong);
    color: var(--on-strong);
  }
  .warn {
    background: var(--warn-strong);
    color: var(--on-warn);
  }
  .ai {
    background: var(--ai-btn);
    color: var(--on-strong);
    box-shadow: 0 6px 16px color-mix(in oklab, var(--ai-2) 26%, transparent);
  }
  .ai:hover:not(:disabled) {
    filter: brightness(1.06);
  }

  .spin {
    width: 1em;
    height: 1em;
    border: 2px solid currentColor;
    border-right-color: transparent;
    border-radius: 50%;
    animation: qwq-spin 0.8s linear infinite;
  }
</style>
