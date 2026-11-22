<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Select · 原生下拉（键盘、读屏、移动端都最可靠）
  ───────────────────────────────────────────────────────────────
  <Select label="角色" bind:value={role} options={[{ value: 'admin', label: '管理员' }, …]} />
  placeholder：首项为空值提示（必选时不可再选回）
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
    id,
    class: cls = '',
    ...rest
  }: Props = $props();
</script>

<Field {label} {hint} {error} {hideLabel} required={!!required} id={id ?? undefined}>
  {#snippet children({ id, describedby, invalid })}
    <div class="box {cls}" class:invalid>
      <select
        bind:value
        {id}
        required={required ?? undefined}
        aria-describedby={describedby}
        aria-invalid={invalid || undefined}
        {...rest}
      >
        {#if placeholder}<option value="" disabled={!!required}>{placeholder}</option>{/if}
        {#each options as o (o.value)}
          <option value={o.value} disabled={o.disabled} title={o.hint}>{o.label}</option>
        {/each}
      </select>
      <span class="chev"><Icon name="chevron-down" size={16} /></span>
    </div>
  {/snippet}
</Field>

<style>
  .box {
    position: relative;
    display: flex;
    align-items: center;
  }
  select {
    width: 100%;
    height: var(--ctl-md);
    padding: 0 36px 0 12px;
    border: 1px solid var(--line-input);
    border-radius: 12px;
    background: var(--surface);
    appearance: none;
    cursor: pointer;
    transition:
      border-color var(--dur-1) var(--ease),
      box-shadow var(--dur-1) var(--ease);
  }
  select:hover {
    border-color: var(--text-3);
  }
  select:focus-visible {
    outline: none;
    border-color: var(--accent);
    box-shadow: var(--ring);
  }
  select:disabled {
    cursor: not-allowed;
    color: var(--text-3);
  }
  .invalid select {
    border-color: var(--bad);
  }
  .chev {
    position: absolute;
    right: 12px;
    display: grid;
    color: var(--text-3);
    pointer-events: none;
  }
</style>
