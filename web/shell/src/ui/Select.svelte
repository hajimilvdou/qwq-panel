<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Select · 与面板浅/深色主题完全同步的下拉选择器
  ───────────────────────────────────────────────────────────────
  <Select label="角色" bind:value={role} options={[{ value: 'admin', label: '管理员' }, …]} />
  · 消除 Windows / Linux 原生 <select> 的丑陋灰底系统弹窗，弹出层严格沿用面板表面与描边令牌
  · 保留隐藏原生 <select> 以完全兼容表单提交、required 与 onchange(Event) 契约
  · 支持键盘 ↑/↓/Home/End/Enter/Escape、自动向上翻转防贴底裁切与选中勾选态
-->
<script lang="ts" generics="V extends string">
  import type { HTMLSelectAttributes } from 'svelte/elements';
  import Field from './Field.svelte';
  import Icon from './Icon.svelte';
  import type { Option } from './types';

  interface Props extends Omit<HTMLSelectAttributes, 'value' | 'children'> {
    value?: V | '';
    options: readonly Option<V>[];
    label?: string;
    hint?: string;
    error?: string;
    hideLabel?: boolean;
    placeholder?: string;
  }
  let {
    value = $bindable(''),
    options,
    label,
    hint,
    error,
    hideLabel = false,
    placeholder,
    required,
    disabled,
    id,
    class: cls = '',
    ...rest
  }: Props = $props();

  const uid = $props.id();
  let open = $state(false);
  let openUp = $state(false);
  let root = $state<HTMLDivElement>();
  let triggerEl = $state<HTMLButtonElement>();
  let listEl = $state<HTMLDivElement>();
  let nativeEl = $state<HTMLSelectElement>();

  interface DisplayOption {
    value: string;
    label: string;
    hint?: string;
    disabled?: boolean;
  }

  const allOptions = $derived<DisplayOption[]>([
    ...(placeholder ? [{ value: '', label: placeholder, disabled: !!required }] : []),
    ...options.map((o) => ({ value: o.value, label: o.label, hint: o.hint, disabled: o.disabled })),
  ]);

  const currentOpt = $derived(
    options.find((o) => o.value === value) ?? (placeholder ? { value: '', label: placeholder } : undefined),
  );
  const isPlaceholder = $derived(!options.some((o) => o.value === value));

  const optionEls = () => [...(listEl?.querySelectorAll<HTMLButtonElement>('[role="option"]:not([disabled])') ?? [])];

  function computeUp(): boolean {
    if (!root || typeof window === 'undefined') return false;
    const rect = root.getBoundingClientRect();
    const estH = Math.min(allOptions.length * 38 + 16, 280);
    const spaceBelow = window.innerHeight - rect.bottom - 12;
    const spaceAbove = rect.top - 12;
    return spaceBelow < estH && spaceAbove > spaceBelow;
  }

  function show(focusList: boolean) {
    if (disabled) return;
    openUp = computeUp();
    open = true;
    if (focusList) {
      queueMicrotask(() => {
        const els = optionEls();
        const active = els.find((el) => el.getAttribute('aria-selected') === 'true') ?? els[0];
        active?.focus();
      });
    }
  }

  function hide(restoreFocus = true) {
    open = false;
    if (restoreFocus) triggerEl?.focus();
  }

  function choose(next: string) {
    if (disabled) return;
    const changed = value !== next;
    value = next as V | '';
    if (nativeEl) {
      nativeEl.value = next;
      if (changed) {
        nativeEl.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }
    hide(true);
  }

  function onTriggerKey(e: KeyboardEvent) {
    if (disabled) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      show(true);
    }
  }

  function onListKey(e: KeyboardEvent) {
    const els = optionEls();
    if (!els.length) return;
    const i = els.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === 'Escape') {
      e.preventDefault();
      hide(true);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      els[(i + 1 + els.length) % els.length]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      els[(i - 1 + els.length) % els.length]?.focus();
    } else if (e.key === 'Home') {
      e.preventDefault();
      els[0]?.focus();
    } else if (e.key === 'End') {
      e.preventDefault();
      els[els.length - 1]?.focus();
    } else if (e.key === 'Tab') {
      hide(false);
    }
  }

  $effect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      if (root && !root.contains(e.target as Node)) hide(false);
    };
    document.addEventListener('pointerdown', onDown);
    return () => document.removeEventListener('pointerdown', onDown);
  });
</script>

<Field {label} {hint} {error} {hideLabel} required={!!required} id={id ?? undefined}>
  {#snippet children({ id: fieldId, describedby, invalid })}
    <div class="box {cls}" class:invalid class:open bind:this={root}>
      <!-- 隐藏原生 select：确保 onchange 事件签名、form 提交与单元测试 100% 兼容 -->
      <select
        bind:this={nativeEl}
        bind:value
        class="native-sr"
        tabindex="-1"
        aria-hidden="true"
        aria-invalid={invalid || undefined}
        required={required ?? undefined}
        {disabled}
        {...rest}
      >
        {#if placeholder}<option value="" disabled={!!required}>{placeholder}</option>{/if}
        {#each options as o (o.value)}
          <option value={o.value} disabled={o.disabled} title={o.hint}>{o.label}</option>
        {/each}
      </select>

      <button
        bind:this={triggerEl}
        type="button"
        id={fieldId}
        class="trigger"
        class:placeholder={isPlaceholder}
        {disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls="{uid}-list"
        aria-describedby={describedby}
        aria-label={rest['aria-label'] ?? undefined}
        onclick={() => (open ? hide(false) : show(false))}
        onkeydown={onTriggerKey}
      >
        <span class="trigger-text">{currentOpt?.label ?? '请选择'}</span>
        <span class="chev" class:rot={open}><Icon name="chevron-down" size={16} /></span>
      </button>

      {#if open}
        <div
          bind:this={listEl}
          id="{uid}-list"
          class="pop"
          class:up={openUp}
          role="listbox"
          tabindex="-1"
          onkeydown={onListKey}
        >
          {#each allOptions as o (o.value)}
            {@const selected = value === o.value}
            <button
              type="button"
              role="option"
              class="opt"
              class:selected
              disabled={o.disabled}
              aria-selected={selected}
              title={o.hint}
              onclick={() => choose(o.value)}
            >
              <span class="opt-body">
                <span class="opt-label">{o.label}</span>
                {#if o.hint}<small class="opt-hint">{o.hint}</small>{/if}
              </span>
              {#if selected}<span class="opt-ck"><Icon name="check" size={14} /></span>{/if}
            </button>
          {/each}
        </div>
      {/if}
    </div>
  {/snippet}
</Field>

<style>
  .box {
    position: relative;
    display: flex;
    align-items: center;
    width: 100%;
  }
  .native-sr {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
    pointer-events: none;
  }
  .trigger {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    width: 100%;
    height: var(--ctl-md);
    padding: 0 12px 0 13px;
    border: 1px solid var(--line-input);
    border-radius: 12px;
    background: var(--surface-2);
    color: var(--text);
    font-size: var(--fs-md);
    text-align: left;
    cursor: pointer;
    transition:
      border-color var(--dur-1) var(--ease),
      background-color var(--dur-1) var(--ease),
      box-shadow var(--dur-1) var(--ease);
  }
  .trigger:hover:not(:disabled) {
    border-color: var(--line-strong);
    background: var(--surface);
  }
  .box.open .trigger,
  .trigger:focus-visible {
    outline: none;
    border-color: var(--accent);
    background: var(--surface);
    box-shadow: var(--ring);
  }
  .trigger:disabled {
    cursor: not-allowed;
    color: var(--text-3);
    opacity: 0.7;
  }
  .trigger.placeholder {
    color: var(--text-3);
  }
  .trigger-text {
    flex: 1;
    min-width: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .invalid .trigger {
    border-color: var(--bad);
  }
  .chev {
    flex: none;
    display: grid;
    color: var(--text-3);
    transition: transform var(--dur-1) var(--ease);
  }
  .chev.rot {
    transform: rotate(180deg);
    color: var(--accent-text);
  }
  .pop {
    position: absolute;
    left: 0;
    right: 0;
    top: calc(100% + 6px);
    z-index: var(--z-dialog);
    display: flex;
    flex-direction: column;
    gap: 2px;
    max-height: min(280px, 50dvh);
    overflow-y: auto;
    padding: 6px;
    border-radius: var(--r-md);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-3);
    animation: qwq-rise-in var(--dur-1) var(--ease-out);
  }
  .pop.up {
    top: auto;
    bottom: calc(100% + 6px);
  }
  .opt {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    width: 100%;
    min-height: 36px;
    padding: 6px 10px;
    border-radius: 9px;
    color: var(--text);
    text-align: left;
    transition: background-color var(--dur-1) var(--ease);
  }
  .opt:hover:not(:disabled),
  .opt:focus-visible {
    background: var(--surface-2);
    outline: none;
  }
  .opt.selected {
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: var(--fw-semibold);
  }
  .opt:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .opt-body {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .opt-label {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: var(--fs-sm);
  }
  .opt-hint {
    color: var(--text-3);
    font-size: var(--fs-2xs);
  }
  .opt-ck {
    flex: none;
    display: grid;
    color: var(--accent-text);
  }
</style>
