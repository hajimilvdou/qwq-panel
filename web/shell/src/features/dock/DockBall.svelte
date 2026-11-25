<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  DockBall · 悬浮窗收起态（SPEC §4）
  ───────────────────────────────────────────────────────────────
  不同 AI 状态对应不同表情球与提示文案：
    idle      常驻微笑 (^‿^)
    thinking  思考推演 (•̀ᴗ•́) + 外环转动 + "第 n/m 步"
    streaming 正在流式输出 (◕‿◕)
    tool      工具执行中 (>‿<)
    approval  待人工确认 (⊙_⊙)? + 红色数量徽标（所有未处理审批始终显示角标）
    error     API / 对话出错 (×_×)
    offline   连接中断 (-_- )z
    paused    已暂停 (・_・)
-->
<script lang="ts">
  import { Orb } from '$ui';
  import type { OrbState } from '$ui/Orb.svelte';
  import { approvals } from '$lib/ai/approvals.svelte';
  import { dock } from '$lib/ai/dock.svelte';
  import { reachText } from '$lib/ai/decide';
  import { events } from '$lib/events.svelte';

  interface Props {
    /** 当前对话进度（turnProgress） */
    progress: { done: number; total: number };
    /** 当前实时 AI 表情态 */
    aiState?: OrbState;
    onopen: () => void;
  }
  let { progress, aiState = 'idle', onopen }: Props = $props();

  const mode = $derived(dock.mode);
  const pendingCount = $derived(approvals.pending.length);
  const firstUnseen = $derived(approvals.unseen[0]);
  const openFromBall = () => onopen();

  const effectiveOrbState = $derived.by<OrbState>(() => {
    if (events.offline) return 'offline';
    if (pendingCount > 0) return 'approval';
    if (aiState === 'error') return 'error';
    if (aiState === 'tool') return 'tool';
    if (aiState === 'streaming') return 'streaming';
    if (aiState === 'thinking' || aiState === 'working' || mode === 'working') return 'thinking';
    if (aiState === 'paused') return 'paused';
    if (aiState === 'done') return 'done';
    return 'rest';
  });

  const ballLabel = $derived(
    pendingCount > 0
      ? `有 ${pendingCount} 项待确认操作，打开 AI 助手`
      : effectiveOrbState === 'error'
        ? 'AI 上一轮接口或执行出错，点击查看'
        : effectiveOrbState === 'tool'
          ? 'AI 正在调用工具，打开 AI 助手'
          : effectiveOrbState === 'streaming'
            ? 'AI 正在回复，打开 AI 助手'
            : effectiveOrbState === 'thinking'
              ? `AI 正在思考${progress.total ? `，第 ${Math.min(progress.done + 1, progress.total)}/${progress.total} 步` : ''}，打开 AI 助手`
              : '打开 AI 助手',
  );

  const tip = $derived.by(() => {
    if (events.offline) return '连接中断，正在重连';
    if (pendingCount > 0) return `${pendingCount} 项操作待你确认`;
    if (effectiveOrbState === 'error') return 'AI 请求出错，点击查看详情';
    if (effectiveOrbState === 'tool') return progress.total ? `工具执行中 · 第 ${Math.min(progress.done + 1, progress.total)}/${progress.total} 步` : '正在调用工具';
    if (effectiveOrbState === 'streaming') return '正在输出回复…';
    if (effectiveOrbState === 'thinking') {
      return progress.total ? `思考中 · 第 ${Math.min(progress.done + 1, progress.total)}/${progress.total} 步` : 'AI 正在思考…';
    }
    if (effectiveOrbState === 'paused') return '对话已暂停';
    return 'AI 助手';
  });
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
    <Orb size={56} state={effectiveOrbState} />
    {#if pendingCount > 0}<span class="badge" aria-hidden="true">{pendingCount}</span>{/if}
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
    opacity: 0.85;
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
  @media (max-width: 860px) {
    .dock {
      right: 16px;
      bottom: calc(var(--tabbar-h) + env(safe-area-inset-bottom) + 16px);
    }
  }
</style>
