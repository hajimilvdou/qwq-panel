<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Chip · 状态标签 / 徽章
  ───────────────────────────────────────────────────────────────
  tone  neutral | ok | warn | bad | info | ai | accent（-soft 底 + -text 字）
  dot   前置圆点（默认开；纯标签用 dot={false}）
  solid 实底（仅 bad：--bad-strong 白字），用于极少数强调

  <Chip tone="ok">运行中</Chip>
  <Chip tone="warn" dot={false}>不可撤销</Chip>
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { Tone } from './types';

  interface Props {
    tone?: Tone;
    dot?: boolean;
    solid?: boolean;
    size?: 'sm' | 'md';
    title?: string;
    children: Snippet;
  }
  let { tone = 'neutral', dot = true, solid = false, size = 'md', title, children }: Props = $props();
</script>

<span class="chip {tone} {size}" class:dot class:solid {title}>{@render children()}</span>

<style>
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 26px;
    padding: 0 10px;
    border-radius: var(--r-pill);
    background: var(--surface-3);
    color: var(--text-2);
    font-size: var(--fs-xs);
    font-weight: var(--fw-semibold);
    white-space: nowrap;
    vertical-align: middle;
  }
  .sm {
    height: 22px;
    padding: 0 8px;
    font-size: var(--fs-2xs);
  }
  .dot::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
  }
  .ok { background: var(--ok-soft); color: var(--ok-text); }
  .warn { background: var(--warn-soft); color: var(--warn-text); }
  .bad { background: var(--bad-soft); color: var(--bad-text); }
  .info { background: var(--info-soft); color: var(--info-text); }
  .ai { background: var(--ai-soft); color: var(--ai-text); }
  .accent { background: var(--accent-soft); color: var(--accent-text); }
  .bad.solid { background: var(--bad-strong); color: var(--on-strong); }
</style>
