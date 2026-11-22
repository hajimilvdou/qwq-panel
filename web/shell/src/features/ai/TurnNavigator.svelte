<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  TurnNavigator · 会话轮次圆点时间轴导航（查看会话 / 快速定位）
  ───────────────────────────────────────────────────────────────
  还原简洁高密度圆点导航轴：
  - 每一轮用户提问对应一个小圆点，当前视口所在轮次自动高亮；
  - 悬停或聚焦任意圆点时，在其侧边弹出预览卡片（2 行内容预览 + 第 X / N 轮 + HH:MM 时间）；
  - 点击圆点平滑滚动到对应消息并短暂高亮；
  - 顶部附带「会话目录」展开按钮，支持搜索筛选长对话所有轮次。
-->
<script lang="ts">
  import { Icon } from '$ui';
  import type { TranscriptItem } from '$lib/ai/transcript';

  interface Props {
    items: readonly TranscriptItem[];
    scroller: HTMLElement | null;
  }
  let { items, scroller }: Props = $props();

  type TurnEntry = {
    id: string;
    index: number;
    text: string;
    time: string;
  };

  function formatHHMM(iso: string): string {
    if (!iso) return '';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  }

  const turns = $derived<TurnEntry[]>(
    items
      .filter((m): m is Extract<TranscriptItem, { kind: 'user' }> => m.kind === 'user')
      .map((m, index) => ({
        id: m.id,
        index,
        text: m.text.replace(/\s+/g, ' ').trim() || '（空消息）',
        time: formatHHMM(m.at),
      })),
  );

  let activeIdx = $state(0);
  let hoverIdx = $state<number | null>(null);
  let hoverTop = $state(0);
  let listOpen = $state(false);
  let query = $state('');
  let railEl = $state<HTMLElement | null>(null);

  const filteredTurns = $derived(
    query.trim()
      ? turns.filter((t) => t.text.toLowerCase().includes(query.trim().toLowerCase()) || String(t.index + 1) === query.trim())
      : turns,
  );

  /* 滚动时自动高亮当前视口对应的提问轮次 */
  $effect(() => {
    const el = scroller;
    const total = turns.length;
    if (!el || total === 0) return;

    const updateActive = () => {
      const nodes = el.querySelectorAll<HTMLElement>('[data-turn-idx]');
      if (!nodes.length) return;
      const boxTop = el.getBoundingClientRect().top;
      let best = 0;
      for (const n of nodes) {
        const idx = Number(n.dataset.turnIdx ?? 0);
        const relTop = n.getBoundingClientRect().top - boxTop;
        if (relTop <= 140) best = idx;
        else break;
      }
      if (el.scrollHeight - el.scrollTop - el.clientHeight < 24) {
        best = total - 1;
      }
      activeIdx = best;
    };

    updateActive();
    el.addEventListener('scroll', updateActive, { passive: true });
    return () => el.removeEventListener('scroll', updateActive);
  });

  function onDotEnter(idx: number, e: MouseEvent | FocusEvent) {
    hoverIdx = idx;
    const target = e.currentTarget as HTMLElement | null;
    if (target && railEl) {
      const tr = target.getBoundingClientRect();
      const rr = railEl.getBoundingClientRect();
      hoverTop = tr.top - rr.top + tr.height / 2;
    }
  }

  function jumpTo(idx: number) {
    activeIdx = idx;
    listOpen = false;
    hoverIdx = null;
    const el = scroller;
    if (!el) return;
    const node = el.querySelector<HTMLElement>(`[data-turn-idx="${idx}"]`);
    if (!node) return;
    node.scrollIntoView({ behavior: 'smooth', block: 'start' });
    node.classList.remove('qwq-turn-flash');
    void node.offsetWidth;
    node.classList.add('qwq-turn-flash');
    window.setTimeout(() => node.classList.remove('qwq-turn-flash'), 1200);
  }
</script>

{#if turns.length > 0}
  <aside class="nav-wrap" aria-label="查看会话轮次导航">
    <button
      type="button"
      class="toc-btn"
      class:on={listOpen}
      title="查看全部会话轮次（共 {turns.length} 轮）"
      aria-expanded={listOpen}
      onclick={() => (listOpen = !listOpen)}
    >
      <Icon name="menu" size={13} />
      <span>{activeIdx + 1}/{turns.length}</span>
    </button>

    <div
      class="rail"
      bind:this={railEl}
      role="navigation"
      aria-label="对话时间轴"
      onmouseleave={() => (hoverIdx = null)}
    >
      {#each turns as t (t.id)}
        <button
          type="button"
          class="dot-btn"
          class:active={t.index === activeIdx}
          class:hovered={t.index === hoverIdx}
          aria-label="跳转到第 {t.index + 1} 轮：{t.text.slice(0, 40)}"
          onclick={() => jumpTo(t.index)}
          onmouseenter={(e) => onDotEnter(t.index, e)}
          onfocus={(e) => onDotEnter(t.index, e)}
          onblur={() => (hoverIdx = null)}
        >
          <span class="dot"></span>
        </button>
      {/each}

      {#if hoverIdx !== null}
        {@const item = turns[hoverIdx]}
        {#if item}
          <div class="preview-card" style:top="{hoverTop}px" role="tooltip">
            <p class="preview-text">{item.text}</p>
            <div class="preview-meta">
              <span>{item.index + 1} of {turns.length}</span>
              {#if item.time}<time>{item.time}</time>{/if}
            </div>
          </div>
        {/if}
      {/if}
    </div>

    {#if listOpen}
      <div class="toc-pop" role="dialog" aria-label="会话目录">
        <header class="toc-head">
          <span>查看会话（共 {turns.length} 轮）</span>
          <button type="button" class="toc-x" aria-label="关闭会话目录" onclick={() => (listOpen = false)}>
            <Icon name="x" size={14} />
          </button>
        </header>
        {#if turns.length >= 4}
          <div class="toc-search">
            <input type="search" placeholder="搜索提问关键词或轮次号…" bind:value={query} />
          </div>
        {/if}
        <ol class="toc-list">
          {#each filteredTurns as t (t.id)}
            <li>
              <button type="button" class="toc-row" class:active={t.index === activeIdx} onclick={() => jumpTo(t.index)}>
                <span class="toc-num">#{t.index + 1}</span>
                <span class="toc-txt">{t.text}</span>
                {#if t.time}<time class="toc-time">{t.time}</time>{/if}
              </button>
            </li>
          {:else}
            <li class="toc-empty">没有匹配的提问</li>
          {/each}
        </ol>
      </div>
    {/if}
  </aside>
{/if}

<style>
  .nav-wrap {
    position: absolute;
    top: 50%;
    right: 14px;
    transform: translateY(-50%);
    z-index: 15;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    pointer-events: none;
  }
  .toc-btn,
  .rail,
  .toc-pop {
    pointer-events: auto;
  }
  .toc-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 24px;
    padding: 0 8px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: color-mix(in oklab, var(--surface) 88%, transparent);
    backdrop-filter: blur(8px);
    color: var(--text-3);
    font-size: 11px;
    font-variant-numeric: tabular-nums;
    cursor: pointer;
    transition: color var(--dur-1) var(--ease), border-color var(--dur-1) var(--ease);
  }
  .toc-btn:hover,
  .toc-btn.on {
    color: var(--text);
    border-color: var(--line-strong);
    background: var(--surface);
  }
  .rail {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    max-height: min(56vh, 360px);
    overflow-y: auto;
    scrollbar-width: none;
    padding: 6px 4px;
    border-radius: var(--r-pill);
    background: color-mix(in oklab, var(--surface-2) 72%, transparent);
    backdrop-filter: blur(8px);
    border: 1px solid color-mix(in oklab, var(--line) 75%, transparent);
  }
  .rail::-webkit-scrollbar {
    display: none;
  }
  .dot-btn {
    display: grid;
    place-items: center;
    width: 18px;
    height: 15px;
    padding: 0;
    border: 0;
    background: transparent;
    cursor: pointer;
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: color-mix(in oklab, var(--text-3) 55%, transparent);
    transition:
      transform var(--dur-1) var(--ease),
      background var(--dur-1) var(--ease),
      box-shadow var(--dur-1) var(--ease);
  }
  .dot-btn:hover .dot,
  .dot-btn.hovered .dot {
    background: var(--text-2);
    transform: scale(1.45);
  }
  .dot-btn.active .dot {
    width: 7px;
    height: 7px;
    background: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in oklab, var(--accent) 24%, transparent);
  }
  .preview-card {
    position: absolute;
    right: calc(100% + 12px);
    transform: translateY(-50%);
    width: 286px;
    padding: 12px 14px;
    border-radius: 14px;
    background: color-mix(in oklab, var(--surface) 96%, black 4%);
    border: 1px solid var(--line-strong);
    box-shadow: var(--shadow-3);
    pointer-events: none;
    display: grid;
    gap: 8px;
    animation: qwq-fade-in 0.12s var(--ease-out);
  }
  .preview-text {
    margin: 0;
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    line-height: 1.45;
    color: var(--text);
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    overflow-wrap: anywhere;
  }
  .preview-meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: var(--fs-xs);
    color: var(--text-3);
    font-variant-numeric: tabular-nums;
  }
  .toc-pop {
    position: absolute;
    right: calc(100% + 12px);
    top: 50%;
    transform: translateY(-50%);
    width: 310px;
    max-height: min(65vh, 420px);
    display: flex;
    flex-direction: column;
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line-strong);
    box-shadow: var(--shadow-3);
    overflow: hidden;
  }
  .toc-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    border-bottom: 1px solid var(--line);
    font-size: var(--fs-xs);
    font-weight: var(--fw-semibold);
    color: var(--text-2);
  }
  .toc-x {
    display: grid;
    place-items: center;
    width: 24px;
    height: 24px;
    border-radius: var(--r-pill);
    color: var(--text-3);
    cursor: pointer;
  }
  .toc-x:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .toc-search {
    padding: 8px 10px 4px;
  }
  .toc-search input {
    width: 100%;
    height: 30px;
    padding: 0 10px;
    border-radius: var(--r-sm);
    border: 1px solid var(--line);
    background: var(--surface-2);
    color: var(--text);
    font: inherit;
    font-size: var(--fs-xs);
  }
  .toc-list {
    margin: 0;
    padding: 6px;
    list-style: none;
    overflow-y: auto;
    display: grid;
    gap: 2px;
  }
  .toc-row {
    display: grid;
    grid-template-columns: auto 1fr auto;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 7px 8px;
    border-radius: var(--r-sm);
    text-align: left;
    font-size: var(--fs-xs);
    color: var(--text-2);
    cursor: pointer;
  }
  .toc-row:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .toc-row.active {
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: var(--fw-medium);
  }
  .toc-num {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-3);
  }
  .toc-row.active .toc-num {
    color: var(--accent-text);
  }
  .toc-txt {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .toc-time {
    font-size: 11px;
    color: var(--text-3);
    font-variant-numeric: tabular-nums;
  }
  .toc-empty {
    padding: 16px;
    text-align: center;
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  @media (max-width: 860px) {
    .nav-wrap {
      top: 10px;
      right: 10px;
      transform: none;
    }
    .rail {
      display: none;
    }
    .toc-pop {
      top: calc(100% + 6px);
      right: 0;
      transform: none;
      width: min(300px, calc(100vw - 24px));
    }
  }
</style>
