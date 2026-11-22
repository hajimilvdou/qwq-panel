<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  SessionList · 会话列表（状态点、未读、最后消息预览；顶部"新对话"）
-->
<script lang="ts">
  import { Button, ErrorState, Skeleton } from '$ui';
  import type { AgentSession } from '$api/types';
  import { readMarks, statusMeta } from '$lib/ai/agent-sessions.svelte';
  import type { Resource } from '$lib/resource.svelte';
  import { describeError } from '$lib/errors';
  import { relativeTime } from '$lib/format';

  interface Props {
    list: Resource<AgentSession[]>;
    current?: string;
    onpick?: () => void;
  }
  let { list, current, onpick }: Props = $props();

  const items = $derived(list.data ?? []);
</script>

<nav class="list" aria-label="会话">
  <div class="top">
    <Button variant="primary" icon="plus" wide href="/agent" onclick={onpick}>新建运维对话</Button>
  </div>

  {#if list.status === 'loading' && !list.data}
    <div class="pad"><Skeleton lines={4} height={44} /></div>
  {:else if list.status === 'error' && !list.data}
    <ErrorState compact message={describeError(list.error).message} onretry={list.refresh} />
  {:else if !items.length}
    <p class="none">还没有对话。</p>
  {:else}
    <ul>
      {#each items as s (s.session_id)}
        {@const st = statusMeta(s.status)}
        {@const unread = s.session_id !== current && readMarks?.unread(s)}
        <li>
          <a
            href="/agent/{encodeURIComponent(s.session_id)}"
            aria-current={s.session_id === current ? 'page' : undefined}
            onclick={onpick}
          >
            <span class="dot {st.tone}" title={st.label}></span>
            <span class="body">
              <span class="title">{s.title || '新的对话'}</span>
              {#if s.last_message_preview}<span class="preview">{s.last_message_preview}</span>{/if}
            </span>
            <span class="meta">
              <time datetime={s.last_message_at ?? s.created_at}>{relativeTime(s.last_message_at ?? s.created_at)}</time>
              {#if s.status === 'waiting_approval' || s.status === 'running' || s.status === 'failed'}
                <span class="st {st.tone}">{st.label}</span>
              {:else if unread}
                <span class="unread">新消息</span>
              {/if}
            </span>
          </a>
        </li>
      {/each}
    </ul>
  {/if}
</nav>

<style>
  .list {
    display: flex;
    flex-direction: column;
    min-height: 0;
    height: 100%;
  }
  .top {
    padding: var(--s-3);
  }
  .pad {
    padding: 0 var(--s-3);
  }
  .none {
    padding: var(--s-4);
    color: var(--text-3);
    font-size: var(--fs-sm);
  }
  ul {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    margin: 0;
    padding: 0 var(--s-2) var(--s-3);
    list-style: none;
  }
  a {
    display: grid;
    grid-template-columns: 8px 1fr auto;
    gap: var(--s-3);
    align-items: start;
    padding: var(--s-3);
    border-radius: var(--r-md);
    color: inherit;
    text-decoration: none;
  }
  a:hover {
    background: var(--surface-2);
  }
  a[aria-current='page'] {
    background: var(--surface);
    border: 1px solid color-mix(in oklab, var(--accent) 28%, var(--line));
    box-shadow: var(--shadow-1);
  }
  .dot {
    width: 8px;
    height: 8px;
    margin-top: 7px;
    border-radius: 50%;
    background: var(--line-strong);
  }
  .dot.ai {
    background: var(--ai-gradient);
  }
  .dot.warn {
    background: var(--warn);
  }
  .dot.bad {
    background: var(--bad);
  }
  .body {
    display: grid;
    gap: 2px;
    min-width: 0;
  }
  .title {
    font-weight: var(--fw-medium);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .preview {
    font-size: var(--fs-sm);
    color: var(--text-3);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .meta {
    display: grid;
    justify-items: end;
    gap: 4px;
    font-size: var(--fs-xs);
    color: var(--text-3);
    white-space: nowrap;
  }
  .st.warn {
    color: var(--warn-text);
  }
  .st.bad {
    color: var(--bad-text);
  }
  .st.ai {
    color: var(--ai-text);
  }
  .unread {
    color: var(--accent-text);
    font-weight: var(--fw-medium);
  }
</style>
