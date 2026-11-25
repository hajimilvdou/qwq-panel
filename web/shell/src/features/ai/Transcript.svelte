<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Transcript · 会话消息流（Agent 页与悬浮窗共用）
  ───────────────────────────────────────────────────────────────
  用户气泡 · 助手 Markdown 子集 · 工具调用折叠行 · 内联审批卡（inlineApprovals）
  贴底跟随：用户停在底部附近时新内容自动滚到底；往上翻时不打扰。
  滚动容器由外层提供（scroller），本组件只负责内容。
-->
<script lang="ts">
  import { tick } from 'svelte';
  import { CopyButton, Icon, Markdown, Orb } from '$ui';
  import ApprovalCard from '$lib/ai/ApprovalCard.svelte';
  import { approvals } from '$lib/ai/approvals.svelte';
  import type { SessionStream } from '$lib/ai/session-stream.svelte';
  import ToolRow from './ToolRow.svelte';

  interface Props {
    stream: SessionStream;
    scroller?: HTMLElement | null;
    inlineApprovals?: boolean;
  }
  let { stream, scroller = null, inlineApprovals = true }: Props = $props();

  const items = $derived(stream.transcript.items);
  const turnIndexById = $derived.by(() => {
    const map = new Map<string, number>();
    let n = 0;
    for (const m of items) {
      if (m.kind === 'user') map.set(m.id, n++);
    }
    return map;
  });
  const thinking = $derived(
    stream.transcript.status === 'running' && !items.some((x) => x.kind === 'assistant' && x.streaming),
  );

  /* 贴底跟随 */
  let stick = true;
  $effect(() => {
    const el = scroller;
    if (!el) return;
    const onscroll = () => (stick = el.scrollHeight - el.scrollTop - el.clientHeight < 80);
    el.addEventListener('scroll', onscroll, { passive: true });
    return () => el.removeEventListener('scroll', onscroll);
  });
  $effect(() => {
    void items;
    void thinking;
    if (!scroller || !stick) return;
    void tick().then(() => scroller?.scrollTo({ top: scroller.scrollHeight }));
  });

  const ERROR_TEXT: Record<string, string> = {
    UNAVAILABLE: 'AI 服务暂时不可用',
    TIMEOUT: 'AI 想太久了，这一轮已停止',
    PERMISSION_DENIED: 'AI 服务拒绝了请求',
  };
</script>

<ol class="flow" aria-label="对话内容">
  {#if stream.truncated}
    <li class="note">仅显示最近的消息</li>
  {/if}

  {#each items as m (m.kind + m.id)}
    {#if m.kind === 'user'}
      <li class="user" data-turn-idx={turnIndexById.get(m.id)}>
        <div class="bubble" class:failed={m.state === 'failed'} class:sending={m.state === 'sending'}>{m.text}</div>
        <div class="msg-tools">
          <CopyButton text={m.text} label="复制提问" />
          {#if m.state === 'failed'}
            <button type="button" class="retry" onclick={() => stream.retry(m.id).catch(() => {})}>
              <Icon name="alert" size={14} /> 没发出去 · 重试
            </button>
          {/if}
        </div>
      </li>
    {:else if m.kind === 'reasoning'}
      <li class="reason">
        <details open={m.streaming}>
          <summary>
            <Icon name="ai" size={14} />
            <span>{m.streaming ? '正在思考推演…' : '已思考过程'}</span>
          </summary>
          <p class="reason-body">{m.text}</p>
        </details>
      </li>
    {:else if m.kind === 'command'}
      <li class="cmd" class:bad={!m.ok}>
        <span class="cmd-tag">{m.command}</span>
        <span>{m.text}</span>
      </li>
    {:else if m.kind === 'assistant'}
      <li class="ai">
        <Orb size={24} state={m.streaming ? 'streaming' : 'idle'} />
        <div class="text">
          <Markdown source={m.text} />
          {#if !m.streaming && m.text}
            <div class="msg-tools ai-tools"><CopyButton text={m.text} label="复制回复" /></div>
          {/if}
        </div>
      </li>
    {:else if m.kind === 'tool'}
      {@const pending = m.approvalId ? approvals.get(m.approvalId) : undefined}
      <li class="tool">
        {#if pending && inlineApprovals}
          <ApprovalCard approval={pending} />
        {:else}
          <ToolRow item={m} />
        {/if}
      </li>
    {:else}
      <li class="err" role="alert">
        <Orb size={22} state="error" />
        <span>{ERROR_TEXT[m.code] ?? '这一轮出错了'}{m.detail ? `：${m.detail}` : ''}</span>
      </li>
    {/if}
  {/each}

  {#if thinking}
    <li class="ai thinking" aria-live="polite">
      <Orb size={24} state="thinking" />
      <span class="dots" aria-label="AI 正在思考"><i></i><i></i><i></i></span>
    </li>
  {/if}
</ol>

<style>
  .flow {
    display: grid;
    gap: var(--s-4);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .note {
    justify-self: center;
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .user {
    display: grid;
    justify-items: end;
    gap: 4px;
    scroll-margin-top: 20px;
  }
  .user:global(.qwq-turn-flash) .bubble {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in oklab, var(--accent) 26%, transparent);
  }
  .msg-tools {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    opacity: 0;
    transition: opacity var(--dur-1) var(--ease);
  }
  .user:hover .msg-tools,
  .user:focus-within .msg-tools,
  .ai:hover .ai-tools,
  .ai:focus-within .ai-tools {
    opacity: 1;
  }
  .ai-tools {
    margin-top: 4px;
  }
  .bubble {
    max-width: min(76%, 640px);
    padding: 10px 16px;
    border-radius: 18px 18px 6px 18px;
    background: var(--surface-2);
    border: 1px solid var(--line);
    color: var(--text);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    line-height: 1.65;
    animation: qwq-rise-in var(--dur-2) var(--ease-out);
  }
  .bubble.sending {
    opacity: 0.7;
  }
  .bubble.failed {
    background: var(--bad-soft);
    color: var(--bad-text);
  }
  .retry {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    min-height: 32px;
    padding: 0 var(--s-2);
    border: 0;
    background: none;
    color: var(--bad-text);
    font: inherit;
    font-size: var(--fs-xs);
    cursor: pointer;
  }
  .ai {
    display: grid;
    grid-template-columns: 22px 1fr;
    gap: var(--s-3);
    align-items: start;
  }
  .ai :global(.orb) {
    margin-top: 2px;
  }
  .text {
    min-width: 0;
    animation: qwq-fade-in var(--dur-2) var(--ease-out);
  }
  .tool {
    padding-left: calc(22px + var(--s-3));
  }
  .reason {
    padding-left: calc(22px + var(--s-3));
  }
  .reason details {
    border: 1px solid var(--line);
    border-radius: var(--r-md);
    background: var(--surface-2);
    padding: 8px 12px;
    font-size: var(--fs-sm);
  }
  .reason summary {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    color: var(--text-2);
    font-weight: var(--fw-medium);
  }
  .reason-body {
    margin: 8px 0 0;
    color: var(--text-3);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    line-height: 1.6;
  }
  .cmd {
    display: flex;
    align-items: baseline;
    gap: 8px;
    margin-left: calc(22px + var(--s-3));
    padding: 8px 12px;
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .cmd.bad {
    background: var(--bad-soft);
    border-color: transparent;
    color: var(--bad-text);
  }
  .cmd-tag {
    flex: none;
    padding: 1px 7px;
    border-radius: var(--r-pill);
    background: var(--surface);
    border: 1px solid var(--line);
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--accent-text);
  }
  .err {
    display: flex;
    gap: var(--s-2);
    align-items: center;
    padding: var(--s-2) var(--s-3);
    border-radius: var(--r-md);
    background: var(--bad-soft);
    color: var(--bad-text);
    font-size: var(--fs-sm);
  }
  .dots {
    display: inline-flex;
    gap: 4px;
    align-items: center;
    height: 24px;
  }
  .dots i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--ai-2);
    animation: blink 1.2s var(--ease) infinite;
  }
  .dots i:nth-child(2) {
    animation-delay: 0.15s;
  }
  .dots i:nth-child(3) {
    animation-delay: 0.3s;
  }
  @keyframes blink {
    0%,
    80%,
    100% {
      opacity: 0.25;
    }
    40% {
      opacity: 1;
    }
  }
  :global(:root[data-motion='reduced']) .dots i,
  :global(:root[data-motion='off']) .dots i {
    animation: none;
    opacity: 0.6;
  }
</style>
