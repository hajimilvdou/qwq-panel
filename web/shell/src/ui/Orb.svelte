<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Orb · AI 极光小球（悬浮窗、AI 头像、AI 发起的审批）
  ───────────────────────────────────────────────────────────────
  state  rest（慢呼吸光，reduced/off 档关闭）| working（外环转动）| still（静止）
  size   像素，默认 24
-->
<script lang="ts">
  interface Props {
    size?: number;
    state?: 'rest' | 'working' | 'still';
    label?: string;
  }
  let { size = 24, state = 'still', label }: Props = $props();
</script>

<span
  class="orb {state}"
  class:loop={state !== 'still'}
  style:--size="{size}px"
  role={label ? 'img' : undefined}
  aria-label={label}
  aria-hidden={label ? undefined : 'true'}
></span>

<style>
  .orb {
    position: relative;
    display: inline-block;
    flex: none;
    width: var(--size);
    height: var(--size);
    border-radius: 50%;
    background:
      radial-gradient(circle at 32% 28%, rgb(255 255 255 / 0.55), transparent 44%),
      var(--ai-gradient);
    box-shadow: 0 4px 12px color-mix(in oklab, var(--ai-1) 28%, transparent);
  }
  .rest {
    animation: breathe 3.6s var(--ease) infinite;
  }
  .working::after {
    content: '';
    position: absolute;
    inset: -4px;
    border-radius: 50%;
    border: 2px solid transparent;
    border-top-color: var(--ai-1);
    border-right-color: var(--ai-2);
    animation: qwq-spin 1.1s linear infinite;
  }
  :global(:root[data-motion='reduced']) .rest,
  :global(:root[data-motion='off']) .rest {
    animation: none;
  }
  @keyframes breathe {
    50% {
      box-shadow: 0 4px 18px color-mix(in oklab, var(--ai-1) 42%, transparent);
    }
  }
</style>
