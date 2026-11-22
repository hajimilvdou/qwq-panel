<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Mood · qwq 品牌表情（只用于主页问候区、侧栏服务器卡、空/错误态）
  ───────────────────────────────────────────────────────────────
  mood  ok（开心，主题色）| warn（平静，琥珀）| bad（难过，红）
  size  sm 28 | md 40 | lg 60
  装饰性元素：外层已有文字说明状态，表情本身 aria-hidden。
-->
<script lang="ts">
  import type { Mood } from './types';

  interface Props {
    mood?: Mood;
    size?: 'sm' | 'md' | 'lg';
  }
  let { mood = 'ok', size = 'lg' }: Props = $props();
</script>

<span class="mood {mood} {size}" aria-hidden="true">
  <svg viewBox="0 0 40 40">
    {#if mood === 'ok'}
      <path d="M10.6 18.6q3.1-4.4 6.2 0M23.2 18.6q3.1-4.4 6.2 0" />
      <path d="M14.6 25q2.7 3.6 5.4 0q2.7 3.6 5.4 0" />
    {:else if mood === 'warn'}
      <circle class="fill" cx="13.8" cy="17.6" r="2.4" />
      <circle class="fill" cx="26.2" cy="17.6" r="2.4" />
      <path d="M15.5 25.5q2.25 3 4.5 0q2.25 3 4.5 0" />
    {:else}
      <circle cx="13.4" cy="16.8" r="3.6" />
      <circle cx="26.6" cy="16.8" r="3.6" />
      <path d="M15.4 19.6l2.6 3M28.6 19.6l2.6 3" />
      <path d="M16 27.4q2 2.6 4 0q2 2.6 4 0" />
    {/if}
  </svg>
</span>

<style>
  .mood {
    display: inline-grid;
    place-items: center;
    flex: none;
    width: 60px;
    height: 60px;
    border-radius: 20px;
    color: #fff;
    background: var(--mood-ok);
    box-shadow: 0 10px 24px color-mix(in oklab, var(--accent) 30%, transparent);
    transition:
      background var(--dur-3) var(--ease),
      box-shadow var(--dur-3) var(--ease);
  }
  .md {
    width: 40px;
    height: 40px;
    border-radius: 13px;
    box-shadow: none;
  }
  .sm {
    width: 28px;
    height: 28px;
    border-radius: 9px;
    box-shadow: none;
  }
  .warn {
    background: var(--mood-warn);
  }
  .bad {
    background: var(--mood-bad);
  }
  .lg.warn {
    box-shadow: 0 10px 24px rgb(240 146 15 / 0.3);
  }
  .lg.bad {
    box-shadow: 0 10px 24px rgb(229 72 77 / 0.3);
  }
  svg {
    width: 72%;
    height: 72%;
    fill: none;
    stroke: currentColor;
    stroke-width: 2.4;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .fill {
    fill: currentColor;
    stroke: none;
  }
</style>
