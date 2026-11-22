<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  OtpInput · 6 位验证码（单个原生 input + 6 个视觉格子）
  ───────────────────────────────────────────────────────────────
  一个真实 input 保证粘贴、自动填充（autocomplete=one-time-code）、读屏都正常；
  格子只是背景装饰。输满 6 位触发 oncomplete。

  <OtpInput label="两步验证码" bind:value={code} oncomplete={submit} error={err} />
-->
<script lang="ts">
  import Field from './Field.svelte';

  interface Props {
    value?: string;
    label?: string;
    length?: number;
    error?: string;
    disabled?: boolean;
    autofocus?: boolean;
    oncomplete?: (code: string) => void;
  }
  let {
    value = $bindable(''),
    label = '验证码',
    length = 6,
    error,
    disabled = false,
    autofocus = false,
    oncomplete,
  }: Props = $props();

  let el = $state<HTMLInputElement>();
  $effect(() => {
    if (autofocus) el?.focus();
  });

  /* 只保留数字（粘贴 "123 456" 也能用）；回写到 DOM，避免显示非数字 */
  function oninput(e: Event & { currentTarget: HTMLInputElement }) {
    value = e.currentTarget.value.replace(/\D/g, '').slice(0, length);
    e.currentTarget.value = value;
    if (value.length === length) oncomplete?.(value);
  }
</script>

<Field {label} {error}>
  {#snippet children({ id, describedby, invalid })}
    <div class="otp" class:invalid>
      <input
        bind:this={el}
        {value}
        {id}
        {disabled}
        {oninput}
        inputmode="numeric"
        autocomplete="one-time-code"
        pattern="[0-9]*"
        maxlength={length}
        aria-describedby={describedby}
        aria-invalid={invalid || undefined}
        spellcheck="false"
      />
      <div class="cells" aria-hidden="true">
        {#each Array.from({ length }, (_, i) => i) as i (i)}
          <span class:filled={i < value.length} class:caret={i === value.length}>{value[i] ?? ''}</span>
        {/each}
      </div>
    </div>
  {/snippet}
</Field>

<style>
  .otp {
    position: relative;
    width: max-content;
  }
  input {
    position: absolute;
    inset: 0;
    width: 100%;
    opacity: 0;
    font-size: 16px;
    cursor: text;
  }
  .cells {
    display: flex;
    gap: 8px;
    pointer-events: none;
  }
  span {
    display: grid;
    place-items: center;
    width: 44px;
    height: 52px;
    border: 1px solid var(--line-input);
    border-radius: 12px;
    background: var(--surface);
    font-family: var(--font-mono);
    font-size: var(--fs-2xl);
    font-weight: var(--fw-semibold);
    transition: border-color var(--dur-1) var(--ease);
  }
  .otp:focus-within .caret {
    border-color: var(--accent);
    box-shadow: var(--ring);
  }
  .invalid span {
    border-color: var(--bad);
  }
  @media (max-width: 400px) {
    span {
      width: 38px;
      height: 46px;
    }
  }
</style>
