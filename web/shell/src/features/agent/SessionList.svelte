<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  SessionList · 会话列表（状态点、未读、最后消息预览；支持单条导出 Markdown/JSON 与删除）
-->
<script lang="ts">
  import { Button, ConfirmDialog, ErrorState, Icon, IconButton, Menu, Skeleton } from '$ui';
  import { agent } from '$api/endpoints';
  import type { AgentSession } from '$api/types';
  import { lastSession, readMarks, statusMeta } from '$lib/ai/agent-sessions.svelte';
  import { resources, type Resource } from '$lib/resource.svelte';
  import { describeError } from '$lib/errors';
  import { relativeTime } from '$lib/format';
  import { navigate } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';

  interface Props {
    list: Resource<AgentSession[]>;
    current?: string;
    exchangeOpen?: boolean;
    onpick?: () => void;
    onopenworkspace?: (tab?: 'prompts' | 'skills' | 'mcp' | 'registry') => void;
    onopenexchange?: () => void;
  }
  let { list, current, exchangeOpen = false, onpick, onopenworkspace, onopenexchange }: Props = $props();

  const canWrite = $derived(session.can('host.agent_sessions:write'));

  let query = $state('');
  let deleteTarget = $state<AgentSession | null>(null);
  let deleteOpen = $state(false);
  let deleteError = $state<string>();

  const allItems = $derived(list.data ?? []);
  const items = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return allItems;
    return allItems.filter(
      (s) =>
        (s.title || '新的对话').toLowerCase().includes(q) ||
        (s.last_message_preview || '').toLowerCase().includes(q),
    );
  });

  function downloadSession(s: AgentSession, format: 'markdown' | 'json') {
    const a = document.createElement('a');
    a.href = agent.exportUrl(s.session_id, format);
    a.download = '';
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    toasts.info(`正在导出「${s.title || '新的对话'}」(${format === 'json' ? 'JSON' : 'Markdown'})`);
  }

  function askDelete(s: AgentSession) {
    deleteTarget = s;
    deleteError = undefined;
    deleteOpen = true;
  }

  async function confirmDelete() {
    const target = deleteTarget;
    if (!target) return;
    deleteError = undefined;
    try {
      await agent.remove(target.session_id);
      readMarks?.forget(target.session_id);
      if (lastSession.get() === target.session_id) lastSession.set(null);
      resources.invalidate('agent-sessions');
      toasts.success(`已删除对话「${target.title || '新的对话'}」`);
      if (current === target.session_id) {
        navigate('/agent', { replace: true });
      }
      deleteTarget = null;
    } catch (err) {
      deleteError = describeError(err).message;
      throw err;
    }
  }

  function menuItemsFor(s: AgentSession) {
    return [
      { label: '导出 Markdown (.md)', icon: 'download' as const, onselect: () => downloadSession(s, 'markdown') },
      { label: '导出 JSON (.json)', icon: 'file' as const, onselect: () => downloadSession(s, 'json') },
      ...(canWrite
        ? [{ label: '删除对话', icon: 'trash' as const, tone: 'danger' as const, onselect: () => askDelete(s) }]
        : []),
    ];
  }
</script>

<nav class="list" aria-label="会话">
  <div class="top">
    <Button variant="primary" icon="plus" wide href="/agent" onclick={onpick}>新建运维对话</Button>
    <div class="top-tools">
      {#if onopenexchange}
        <Button
          variant={exchangeOpen ? 'primary' : 'soft'}
          size="sm"
          icon="folder"
          wide
          onclick={() => {
            onpick?.();
            onopenexchange();
          }}
        >
          交互文件夹
        </Button>
      {/if}
      {#if onopenworkspace}
        <Button
          variant="soft"
          size="sm"
          icon="apps"
          wide
          onclick={() => {
            onpick?.();
            onopenworkspace('prompts');
          }}
        >
          MCP · 技能 · 提示词
        </Button>
      {/if}
    </div>
    {#if allItems.length > 0}
      <div class="search-box">
        <Icon name="search" size={14} />
        <input
          type="search"
          class="search-in"
          placeholder="搜索历史对话…"
          aria-label="搜索历史对话"
          bind:value={query}
        />
      </div>
    {/if}
  </div>

  {#if list.status === 'loading' && !list.data}
    <div class="pad"><Skeleton lines={4} height={44} /></div>
  {:else if list.status === 'error' && !list.data}
    <ErrorState compact message={describeError(list.error).message} onretry={list.refresh} />
  {:else if !allItems.length}
    <p class="none">还没有对话。</p>
  {:else if !items.length}
    <p class="none">没有匹配“{query}”的对话。</p>
  {:else}
    <ul>
      {#each items as s (s.session_id)}
        {@const st = statusMeta(s.status)}
        {@const unread = s.session_id !== current && readMarks?.unread(s)}
        <li class="row" class:active={s.session_id === current}>
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
          <div class="row-menu">
            <Menu label="操作 {s.title || '新的对话'}" items={menuItemsFor(s)} align="end">
              {#snippet trigger(props)}
                <IconButton icon="more" size="sm" variant="plain" label="导出或删除对话" {...props} />
              {/snippet}
            </Menu>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</nav>

<ConfirmDialog
  bind:open={deleteOpen}
  title="删除对话「{deleteTarget?.title || '新的对话'}」？"
  tone="danger"
  confirmLabel="删除"
  errorText={deleteError}
  onconfirm={confirmDelete}
>
  对话记录会一并删除；进行中的一轮会被取消。已经执行的操作不受影响，可在"动态"里查看。
</ConfirmDialog>

<style>
  .list {
    display: flex;
    flex-direction: column;
    min-height: 0;
    height: 100%;
  }
  .top {
    display: grid;
    gap: var(--s-2);
    padding: var(--s-3);
  }
  .top-tools {
    display: grid;
    gap: 6px;
  }
  .search-box {
    display: flex;
    align-items: center;
    gap: 6px;
    height: 32px;
    padding: 0 10px;
    border-radius: var(--r-md);
    background: var(--surface);
    border: 1px solid var(--line);
    color: var(--text-3);
  }
  .search-box:focus-within {
    border-color: var(--accent);
    color: var(--text);
  }
  .search-in {
    flex: 1;
    min-width: 0;
    border: 0;
    outline: 0;
    background: transparent;
    color: var(--text);
    font: inherit;
    font-size: var(--fs-xs);
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
    display: grid;
    align-content: start;
    gap: 2px;
  }
  .row {
    position: relative;
    display: flex;
    align-items: center;
    border-radius: var(--r-md);
  }
  .row:hover {
    background: color-mix(in oklab, var(--surface) 60%, var(--surface-2));
  }
  .row.active {
    background: var(--surface);
    border: 1px solid color-mix(in oklab, var(--accent) 28%, var(--line));
    box-shadow: var(--shadow-1);
  }
  a {
    flex: 1;
    min-width: 0;
    display: grid;
    grid-template-columns: 8px 1fr auto;
    gap: var(--s-2);
    align-items: start;
    padding: 10px 6px 10px 10px;
    border-radius: var(--r-md);
    color: inherit;
    text-decoration: none;
  }
  .row-menu {
    flex: none;
    padding-right: 4px;
    opacity: 0;
    transition: opacity var(--dur-1) var(--ease);
  }
  .row:hover .row-menu,
  .row:focus-within .row-menu,
  .row.active .row-menu {
    opacity: 1;
  }
  @media (hover: none) {
    .row-menu {
      opacity: 1;
    }
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
