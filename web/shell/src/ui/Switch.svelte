<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Switch · 开关（role="switch"；状态不只靠颜色：滑块位置 + 可选文字）
  ───────────────────────────────────────────────────────────────
  <Switch label="开启两步验证" bind:checked={on} hint="登录时需要验证码" />
  onchange(checked) 在用户切换后调用（bind 已更新）
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
  const uid = $props.id();

  function toggle() {
    if (disabled) return;
    checked = !checked;
    onchange?.(checked);
  }
</script>

<div class="row">
  <div class="text">
    <span id="{uid}-l" class="label">{label}</span>
    {#if hint}<span id="{uid}-h" class="hint">{hint}</span>{/if}
  </div>
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    aria-labelledby="{uid}-l"
    aria-describedby={hint ? `${uid}-h` : undefined}
    {disabled}
    class="sw"
    onclick={toggle}
  >
    <span class="knob"></span>
  </button>
</div>

<style>
  .row {
    display: flex;
    align-items: center;
    gap: var(--s-4);
    min-height: var(--ctl-md);
  }
  .text {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }
  .label {
    font-weight: var(--fw-medium);
  }
  .hint {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .sw {
    position: relative;
    flex: none;
    width: 44px;
    height: 26px;
    border-radius: var(--r-pill);
    background: var(--line-strong);
    transition: background var(--dur-2) var(--ease);
  }
  .sw[aria-checked='true'] {
    background: var(--accent-strong);
  }
  .knob {
    position: absolute;
    top: 3px;
    left: 3px;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 1px 3px rgb(0 0 0 / 0.25);
    transition: transform var(--dur-2) var(--ease-soft);
  }
  .sw[aria-checked='true'] .knob {
    transform: translateX(18px);
  }
  .sw:disabled {
    opacity: 0.5;
  }
</style>
