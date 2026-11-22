<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Composer · 对话输入框（Agent 页与悬浮窗共用）
  ───────────────────────────────────────────────────────────────
  Enter 发送 · Shift+Enter 换行 · 输入法组字中不发送
  接近 32768 字节时显示计数，超出禁用发送；忙时按钮变"停止"。
  onsend 返回 Promise：成功才清空（失败保留文字，气泡另有重试）。
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Icon, Spinner } from '$ui';
  import { byteLength, MESSAGE_MAX_BYTES } from '$lib/ai/session-stream.svelte';

  interface Props {
    value?: string;
    busy?: boolean;
    disabled?: boolean;
    disabledReason?: string;
    placeholder?: string;
    el?: HTMLTextAreaElement | null;
    onsend: (text: string) => Promise<unknown> | void;
    onstop?: () => void;
    /** 输入框下方左侧的附加控件（模式标签、会话切换） */
    tools?: Snippet;
  }
  let {
    value = $bindable(''),
    busy = false,
    disabled = false,
    disabledReason,
    placeholder = '想让 AI 帮你做什么？',
    el = $bindable(null),
    onsend,
    onstop,
    tools,
  }: Props = $props();

  const uid = $props.id();
  let sending = $state(false);
  let stopping = $state(false);

  const bytes = $derived(byteLength(value));
  const near = $derived(bytes > MESSAGE_MAX_BYTES * 0.8);
  const over = $derived(bytes > MESSAGE_MAX_BYTES);
  const canSend = $derived(!disabled && !sending && !busy && !over && value.trim().length > 0);

  /* 随内容增高，最多 8 行 */
  $effect(() => {
    void value;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 8 * 22 + 20) + 'px';
  });

  async function send() {
    if (!canSend) return;
    const text = value.trim();
    sending = true;
    try {
      await onsend(text);
      value = '';
    } catch {
      /* 调用方已提示；保留文字 */
    } finally {
      sending = false;
      el?.focus();
    }
  }

  async function stop() {
    if (!onstop || stopping) return;
    stopping = true;
    try {
      await onstop();
    } finally {
      stopping = false;
    }
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key !== 'Enter' || e.shiftKey || e.isComposing || e.keyCode === 229) return;
    e.preventDefault();
    void send();
  }
</script>

<div class="composer" class:disabled>
  <label class="sr-only" for="{uid}-in">给 AI 的消息</label>
  <textarea
    bind:this={el}
    bind:value
    id="{uid}-in"
    rows="1"
    placeholder={disabled ? (disabledReason ?? placeholder) : placeholder}
    {disabled}
    aria-describedby={near ? `${uid}-count` : undefined}
    {onkeydown}
  ></textarea>
  <div class="row">
    <div class="tools">{@render tools?.()}</div>
    {#if near}
      <span id="{uid}-count" class="count" class:over aria-live="polite">
        {over ? '太长了，' : ''}{bytes.toLocaleString()} / {MESSAGE_MAX_BYTES.toLocaleString()} 字节
      </span>
    {/if}
    {#if busy && onstop}
      <button type="button" class="btn stop" onclick={stop} disabled={stopping} aria-label="停止">
        {#if stopping}<Spinner size={16} />{:else}<Icon name="stop" size={16} />{/if}
        <span>停止</span>
      </button>
    {:else}
      <button type="button" class="btn send" onclick={send} disabled={!canSend} aria-label="发送">
        {#if sending}<Spinner size={16} />{:else}<Icon name="send" size={18} />{/if}
      </button>
    {/if}
  </div>
</div>

<style>
  .composer {
    display: grid;
    gap: var(--s-2);
    padding: var(--s-3) var(--s-3) var(--s-2) var(--s-4);
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line-input);
    transition: border-color var(--dur-1) var(--ease);
  }
  .composer:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .disabled {
    background: var(--surface-2);
  }
  textarea {
    width: 100%;
    min-height: 26px;
    max-height: 196px;
    padding: 2px 0;
    border: 0;
    outline: 0;
    resize: none;
    background: none;
    color: var(--text);
    font: inherit;
    font-size: var(--fs-md);
    line-height: 22px;
  }
  textarea::placeholder {
    color: var(--text-3);
  }
  .row {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    min-height: 36px;
  }
  .tools {
    display: flex;
    align-items: center;
    gap: var(--s-1);
    flex: 1;
    min-width: 0;
  }
  .count {
    font-size: var(--fs-xs);
    color: var(--text-3);
    white-space: nowrap;
  }
  .count.over {
    color: var(--bad-text);
  }
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    height: 40px;
    min-width: 40px;
    border: 0;
    border-radius: var(--r-pill);
    font: inherit;
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    cursor: pointer;
    transition:
      transform var(--dur-1) var(--ease),
      opacity var(--dur-1) var(--ease);
  }
  .send {
    background: var(--ai-btn);
    color: #fff;
  }
  .send:disabled {
    background: var(--surface-3);
    color: var(--text-3);
    cursor: default;
  }
  .send:not(:disabled):active {
    transform: scale(0.94);
  }
  .stop {
    padding: 0 var(--s-4);
    background: var(--surface-3);
    color: var(--text);
  }
  .stop:hover {
    background: var(--line);
  }
</style>
