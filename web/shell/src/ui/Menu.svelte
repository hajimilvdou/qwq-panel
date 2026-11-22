<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Menu · 下拉菜单（头像菜单、行内"更多"）
  ───────────────────────────────────────────────────────────────
  <Menu label="账户菜单" items={[
    { label: '账户', icon: 'user', href: '/settings/account' },
    { label: '登出', icon: 'logout', tone: 'danger', onselect: logout },
  ]}>
    {#snippet trigger(props)}<button {...props}><Avatar name="Alice" /></button>{/snippet}
  </Menu>

  键盘：Enter/Space/↓ 打开并聚焦首项，↑↓ 移动，Esc 关闭并还焦点，Tab 关闭。
  点外部关闭。align：菜单靠右（end，默认）或靠左（start）。
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';

  export interface MenuItem {
    label: string;
    icon?: IconName;
    href?: string;
    onselect?: () => void;
    tone?: 'danger';
    disabled?: boolean;
  }
  interface TriggerProps {
    'aria-haspopup': 'menu';
    'aria-expanded': boolean;
    'aria-controls': string;
    'aria-label': string;
    onclick: () => void;
    onkeydown: (e: KeyboardEvent) => void;
  }
  interface Props {
    label: string;
    items: readonly MenuItem[];
    align?: 'start' | 'end';
    trigger: Snippet<[TriggerProps]>;
  }
  let { label, items, align = 'end', trigger }: Props = $props();

  const uid = $props.id();
  let open = $state(false);
  let root: HTMLDivElement;
  let menu = $state<HTMLDivElement>();

  const focusables = () => [...(menu?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([aria-disabled="true"])') ?? [])];

  function show(focusFirst: boolean) {
    open = true;
    if (focusFirst) queueMicrotask(() => focusables()[0]?.focus());
  }
  function hide(restore = true) {
    open = false;
    if (restore) root.querySelector<HTMLElement>('[aria-haspopup]')?.focus();
  }
  function pick(it: MenuItem) {
    if (it.disabled) return;
    hide(!it.href);
    it.onselect?.();
  }

  const triggerProps: TriggerProps = {
    'aria-haspopup': 'menu',
    get 'aria-expanded'() {
      return open;
    },
    'aria-controls': `${uid}-menu`,
    get 'aria-label'() {
      return label;
    },
    onclick: () => (open ? hide() : show(false)),
    onkeydown: (e) => {
      if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        show(true);
      }
    },
  };

  function onMenuKey(e: KeyboardEvent) {
    const els = focusables();
    const i = els.indexOf(document.activeElement as HTMLElement);
    if (e.key === 'Escape') {
      e.preventDefault();
      hide();
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const d = e.key === 'ArrowDown' ? 1 : -1;
      els[(i + d + els.length) % els.length]?.focus();
    } else if (e.key === 'Tab') {
      hide(false);
    }
  }

  $effect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      if (!root.contains(e.target as Node)) hide(false);
    };
    document.addEventListener('pointerdown', onDown);
    return () => document.removeEventListener('pointerdown', onDown);
  });
</script>

<div class="menu-root" bind:this={root}>
  {@render trigger(triggerProps)}
  {#if open}
    <div bind:this={menu} id="{uid}-menu" class="menu {align}" role="menu" aria-label={label} tabindex="-1" onkeydown={onMenuKey}>
      {#each items as it (it.label)}
        {#if it.href && !it.disabled}
          <a role="menuitem" href={it.href} class:danger={it.tone === 'danger'} onclick={() => pick(it)}>
            {#if it.icon}<Icon name={it.icon} size={18} />{/if}{it.label}
          </a>
        {:else}
          <button
            type="button"
            role="menuitem"
            class:danger={it.tone === 'danger'}
            aria-disabled={it.disabled || undefined}
            onclick={() => pick(it)}
          >
            {#if it.icon}<Icon name={it.icon} size={18} />{/if}{it.label}
          </button>
        {/if}
      {/each}
    </div>
  {/if}
</div>

<style>
  .menu-root {
    position: relative;
    display: inline-flex;
  }
  .menu {
    position: absolute;
    top: calc(100% + 6px);
    z-index: var(--z-dialog);
    display: flex;
    flex-direction: column;
    min-width: 180px;
    padding: 6px;
    border-radius: var(--r-md);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-3);
    animation: qwq-rise-in var(--dur-2) var(--ease-out);
  }
  .end {
    right: 0;
  }
  .start {
    left: 0;
  }
  a,
  button {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 38px;
    padding: 0 10px;
    border-radius: 9px;
    color: var(--text);
    font-weight: var(--fw-medium);
    text-align: left;
    white-space: nowrap;
  }
  a:hover,
  button:hover,
  a:focus-visible,
  button:focus-visible {
    background: var(--surface-3);
    outline: none;
  }
  .danger {
    color: var(--bad-text);
  }
  [aria-disabled='true'] {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
