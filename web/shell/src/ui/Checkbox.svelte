<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Checkbox · 复选框（安装向导的敏感能力逐项勾选、"已保存恢复码"等）
  <Checkbox bind:checked={saved} label="我已保存恢复码" />
-->
<script lang="ts">
  interface Props {
    checked?: boolean;
    label: string;
    hint?: string;
    disabled?: boolean;
    onchange?: (checked: boolean) => void;
  }
  let { checked = $bindable(false), label, hint, disabled = false, onchange }: Props = $props();
</script>

<label class="cb" class:disabled>
  <input type="checkbox" bind:checked {disabled} onchange={() => onchange?.(checked)} />
  <span class="box" aria-hidden="true">
    <svg viewBox="0 0 24 24"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg>
  </span>
  <span class="text">
    <span>{label}</span>
    {#if hint}<small>{hint}</small>{/if}
  </span>
</label>

<style>
  .cb {
    position: relative;
    display: inline-flex;
    align-items: flex-start;
    gap: 10px;
    min-height: 32px;
    padding: 4px 0;
    cursor: pointer;
  }
  .disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }
  input {
    position: absolute;
    opacity: 0;
    width: 20px;
    height: 20px;
    margin: 2px 0 0;
  }
  .box {
    display: grid;
    place-items: center;
    flex: none;
    width: 20px;
    height: 20px;
    margin-top: 2px;
    border: 1.5px solid var(--line-input);
    border-radius: 6px;
    background: var(--surface);
    transition:
      background var(--dur-1) var(--ease),
      border-color var(--dur-1) var(--ease);
  }
  svg {
    width: 14px;
    height: 14px;
    fill: none;
    stroke: #fff;
    stroke-width: 3;
    stroke-linecap: round;
    stroke-linejoin: round;
    opacity: 0;
  }
  input:checked + .box {
    background: var(--accent-strong);
    border-color: var(--accent-strong);
  }
  input:checked + .box svg {
    opacity: 1;
  }
  input:focus-visible + .box {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .text {
    display: flex;
    flex-direction: column;
  }
  small {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
</style>
