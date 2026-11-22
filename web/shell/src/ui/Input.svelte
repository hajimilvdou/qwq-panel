<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Input · 文本输入（含 Field：标签、提示、错误）
  ───────────────────────────────────────────────────────────────
  <Input label="用户名" bind:value={username} required autocomplete="username" />
  <Input label="密码" type="password" bind:value={pw} error={errs['/password']} />
  <Input label="备注" multiline rows={3} bind:value={note} />
  <Input label="搜索" hideLabel icon="search" placeholder="搜索…" bind:value={q} />
  mono：等宽（ID、指纹、密钥）
-->
<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';
  import Field from './Field.svelte';
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';

  interface Props extends Omit<HTMLInputAttributes, 'value' | 'children'> {
    value?: string;
    label?: string;
    hint?: string;
    error?: string;
    hideLabel?: boolean;
    icon?: IconName;
    multiline?: boolean;
    rows?: number;
    mono?: boolean;
    /** 取到底层元素（聚焦等） */
    el?: HTMLInputElement | HTMLTextAreaElement | null;
  }
  let {
    value = $bindable(''),
    el = $bindable(null),
    label,
    hint,
    error,
    hideLabel = false,
    icon,
    multiline = false,
    rows = 3,
    mono = false,
    required,
    id,
    class: cls = '',
    ...rest
  }: Props = $props();
</script>

<Field {label} {hint} {error} {hideLabel} required={!!required} id={id ?? undefined}>
  {#snippet children({ id, describedby, invalid })}
    <div class="box {cls}" class:mono class:has-icon={!!icon} class:invalid class:multi={multiline}>
      {#if icon}<span class="lead"><Icon name={icon} size={18} /></span>{/if}
      {#if multiline}
        <textarea
          bind:this={el}
          bind:value
          {id}
          {rows}
          required={required ?? undefined}
          aria-describedby={describedby}
          aria-invalid={invalid || undefined}
          placeholder={rest.placeholder}
          disabled={rest.disabled}
          readonly={rest.readonly}
          name={rest.name}
          maxlength={rest.maxlength}
        ></textarea>
      {:else}
        <input
          bind:this={el}
          bind:value
          {id}
          required={required ?? undefined}
          aria-describedby={describedby}
          aria-invalid={invalid || undefined}
          {...rest}
        />
      {/if}
    </div>
  {/snippet}
</Field>

<style>
  .box {
    position: relative;
    display: flex;
    align-items: center;
    min-height: var(--ctl-md);
    border: 1px solid var(--line-input);
    border-radius: 12px;
    background: var(--surface);
    transition:
      border-color var(--dur-1) var(--ease),
      box-shadow var(--dur-1) var(--ease);
  }
  .box:hover {
    border-color: var(--text-3);
  }
  .box:focus-within {
    border-color: var(--accent);
    box-shadow: var(--ring);
  }
  .box.invalid {
    border-color: var(--bad);
  }
  input,
  textarea {
    flex: 1;
    min-width: 0;
    width: 100%;
    height: calc(var(--ctl-md) - 2px);
    padding: 0 12px;
    border: 0;
    border-radius: inherit;
    background: transparent;
    outline: none;
  }
  textarea {
    height: auto;
    padding: 9px 12px;
    resize: vertical;
    line-height: 1.55;
  }
  input::placeholder,
  textarea::placeholder {
    color: var(--text-3);
  }
  input:disabled,
  textarea:disabled {
    cursor: not-allowed;
    color: var(--text-3);
  }
  .has-icon input {
    padding-left: 38px;
  }
  .lead {
    position: absolute;
    left: 12px;
    display: grid;
    color: var(--text-3);
    pointer-events: none;
  }
  .mono input,
  .mono textarea {
    font-family: var(--font-mono);
    font-size: 0.92em;
  }
</style>
