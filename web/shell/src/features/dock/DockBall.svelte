<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  DockBall · 悬浮窗收起态（SPEC §4）
  ───────────────────────────────────────────────────────────────
  rest 呼吸球 / working 环形转动 + "第 n/m 步" / reach 向左伸出胶囊 / 离线置灰。
  open 时只隐藏（visibility），保持布局与焦点还原目标稳定。
-->
<script lang="ts">
  import { Orb } from '$ui';
  import { approvals } from '$lib/ai/approvals.svelte';
  import { dock } from '$lib/ai/dock.svelte';
  import { reachText } from '$lib/ai/decide';
  import { events } from '$lib/events.svelte';

  interface Props {
    /** 当前对话进度（turnProgress） */
    progress: { done: number; total: number };
    onopen: () => void;
  }
  let { progress, onopen }: Props = $props();

  const mode = $derived(dock.mode);
  const firstUnseen = $derived(approvals.unseen[0]);
  const openFromBall = () => onopen();
  const ballLabel = $derived(
    mode === 'reach'
      ? `有 ${approvals.unseen.length} 项等你确认，打开 AI 助手`
      : mode === 'working'
        ? `AI 正在处理${progress.total ? `，第 ${Math.min(progress.done + 1, progress.total)}/${progress.total} 步` : ''}，打开 AI 助手`
        : '打开 AI 助手',
  );
  const tip = $derived(
    events.offline
      ? '连接中断，正在重连'
      : mode === 'working'
        ? progress.total
          ? `第 ${Math.min(progress.done + 1, progress.total)}/${progress.total} 步`
          : 'AI 正在处理'
        : '',
  );
</script>

<div class="dock" class:hidden={mode === 'open'} class:offline={events.offline}>
  {#if mode === 'reach' && firstUnseen}
    <button type="button" class="reach" onclick={openFromBall} aria-label={ballLabel}>
      <span class="reach-text">{reachText(firstUnseen)}</span>
      {#if approvals.unseen.length > 1}<span class="more">+{approvals.unseen.length - 1}</span>{/if}
      <span class="look">看一下</span>
    </button>
  {/if}
  <button type="button" class="ball {mode}" onclick={openFromBall} aria-label={ballLabel} aria-haspopup="dialog">
    <Orb size={56} state={mode === 'working' ? 'working' : mode === 'reach' ? 'still' : 'rest'} />
    {#if mode === 'reach'}<span class="badge" aria-hidden="true">{approvals.unseen.length}</span>{/if}
  </button>
  {#if tip}<span class="tip" role="status">{tip}</span>{/if}
</div>

<style>
  /* ------------------------------------------------------------ 球 */
  .dock {
    position: fixed;
    right: 24px;
    bottom: 24px;
    z-index: var(--z-dock);
    display: flex;
    align-items: center;
    justify-content: flex-end;
    pointer-events: none;
  }
  .dock > * {
    pointer-events: auto;
  }
  .hidden {
    visibility: hidden;
  }
  .ball {
    position: relative;
    display: grid;
    place-items: center;
    width: 56px;
    height: 56px;
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: none;
    cursor: pointer;
    transition: transform var(--dur-2) var(--ease);
  }
  .ball:hover {
    transform: scale(1.06);
  }
  .ball:active {
    transform: scale(0.96);
  }
  .offline .ball {
    filter: grayscale(0.7);
    opacity: 0.75;
  }
  .badge {
    position: absolute;
    top: -2px;
    right: -2px;
    min-width: 20px;
    height: 20px;
    padding: 0 5px;
    border-radius: var(--r-pill);
    border: 2px solid var(--surface);
    background: var(--bad-strong);
    color: var(--on-strong);
    font-size: var(--fs-2xs);
    font-weight: var(--fw-bold);
    line-height: 16px;
    text-align: center;
  }
  .tip {
    position: absolute;
    right: 0;
    bottom: calc(100% + 8px);
    padding: 4px 10px;
    border-radius: var(--r-sm);
    background: var(--text);
    color: var(--surface);
    font-size: var(--fs-xs);
    white-space: nowrap;
    opacity: 0;
    transform: translateY(4px);
    transition:
      opacity var(--dur-1) var(--ease),
      transform var(--dur-1) var(--ease);
    pointer-events: none;
  }
  .ball:hover ~ .tip,
  .ball:focus-visible ~ .tip,
  .offline .tip {
    opacity: 1;
    transform: none;
  }

  /* 胶囊：从球左侧伸出，弹性展开；减弱动效时直接出现 */
  .reach {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    max-width: min(360px, calc(100vw - 112px));
    height: 48px;
    margin-right: -28px;
    padding: 0 calc(28px + var(--s-3)) 0 var(--s-4);
    border: 1px solid var(--line);
    border-radius: var(--r-pill);
    background: var(--surface);
    box-shadow: var(--shadow-2);
    color: var(--text);
    font: inherit;
    font-size: var(--fs-sm);
    cursor: pointer;
    transform-origin: right center;
    animation: reach-out var(--dur-3) cubic-bezier(0.34, 1.56, 0.64, 1);
  }
  .reach:hover {
    border-color: var(--line-strong);
  }
  .reach-text {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .more {
    flex: none;
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .look {
    flex: none;
    color: var(--ai-text);
    font-weight: var(--fw-semibold);
  }
  @keyframes reach-out {
    from {
      clip-path: inset(0 0 0 100% round 24px);
      opacity: 0.4;
    }
    to {
      clip-path: inset(0 0 0 0 round 24px);
      opacity: 1;
    }
  }
  :global(:root[data-motion='reduced']) .reach {
    animation: qwq-fade-in var(--dur-1) linear;
  }
</style>
