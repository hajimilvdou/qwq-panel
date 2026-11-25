<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  原生 Agent 页（SPEC §3.3）
  ───────────────────────────────────────────────────────────────
  三栏自适应：左 238 会话列表 · 中 对话或新建面板 · 右 可折叠 356 交互文件夹；
  ≤860 会话列表收进左抽屉，≤1180 交互文件夹收进右抽屉。
  在本页时悬浮窗只保留球形提醒（dock.chatSuppressed），避免同屏两个输入框。
  会话切换时 Conversation 以 id 为 key 重建：各自的流互不串线。
-->
<script lang="ts">
  import { Drawer } from '$ui';
  import { dock } from '$lib/ai/dock.svelte';
  import { sessionsResource } from '$lib/ai/agent-sessions.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import Conversation from './Conversation.svelte';
  import NewSession from './NewSession.svelte';
  import SessionList from './SessionList.svelte';

  type WorkspaceTab = 'prompts' | 'skills' | 'mcp' | 'registry';

  let { params }: { params: Record<string, string> } = $props();

  const list = useResource(sessionsResource);
  const id = $derived(params.sessionId);
  const isAdmin = $derived(session.role === 'admin');
  const canReadAgent = $derived(session.can('host.agent_sessions:read'));

  let drawer = $state(false);
  let narrow = $state(false);
  let compactExchange = $state(false);
  let workspaceOpen = $state(false);
  let workspaceTab = $state<WorkspaceTab>('prompts');
  let exchangeOpen = $state(false);
  let exchangeTick = $state(0);
  let insertSeq = 0;
  let pendingInsert = $state<{ seq: number; text: string } | null>(null);

  function openWorkspace(tab: WorkspaceTab = 'prompts') {
    if (!isAdmin) return;
    workspaceTab = tab;
    workspaceOpen = true;
  }
  const workspaceTrigger = $derived(isAdmin ? openWorkspace : undefined);

  function toggleExchange() {
    if (!canReadAgent) return;
    exchangeOpen = !exchangeOpen;
    if (exchangeOpen) exchangeTick++;
  }
  const exchangeTrigger = $derived(canReadAgent ? toggleExchange : undefined);

  function handleInsertRef(refText: string) {
    insertSeq += 1;
    pendingInsert = { seq: insertSeq, text: refText };
    if (compactExchange) exchangeOpen = false;
  }

  $effect(() => {
    dock.chatSuppressed = true;
    return () => (dock.chatSuppressed = false);
  });

  $effect(() => {
    const mqNarrow = matchMedia('(max-width: 860px)');
    const mqCompact = matchMedia('(max-width: 1180px)');
    narrow = mqNarrow.matches;
    compactExchange = mqCompact.matches;
    const onNarrow = () => (narrow = mqNarrow.matches);
    const onCompact = () => (compactExchange = mqCompact.matches);
    mqNarrow.addEventListener('change', onNarrow);
    mqCompact.addEventListener('change', onCompact);
    return () => {
      mqNarrow.removeEventListener('change', onNarrow);
      mqCompact.removeEventListener('change', onCompact);
    };
  });
</script>

<div class="agent" class:with-exchange={exchangeOpen && !compactExchange && canReadAgent}>
  {#if !narrow}
    <aside class="side">
      <SessionList
        {list}
        current={id}
        {exchangeOpen}
        onopenworkspace={workspaceTrigger}
        onopenexchange={exchangeTrigger}
      />
    </aside>
  {/if}
  <div class="main">
    {#key id}
      {#if id}
        <Conversation
          {id}
          {exchangeOpen}
          {pendingInsert}
          onmenu={narrow ? () => (drawer = true) : undefined}
          onopenworkspace={workspaceTrigger}
          ontoggleexchange={exchangeTrigger}
          onturnsettled={() => {
            if (exchangeOpen) exchangeTick++;
          }}
        />
      {:else}
        {#if narrow}
          <div class="mobile-bar">
            <button type="button" class="open-list" onclick={() => (drawer = true)}>历史对话</button>
            {#if canReadAgent}
              <button type="button" class="open-list" onclick={toggleExchange}>交互文件夹</button>
            {/if}
            {#if isAdmin}
              <button type="button" class="open-list" onclick={() => openWorkspace('prompts')}>MCP · 技能 · 提示词</button>
            {/if}
          </div>
        {/if}
        <NewSession {pendingInsert} ontoggleexchange={exchangeTrigger} />
      {/if}
    {/key}
  </div>

  {#if exchangeOpen && !compactExchange && canReadAgent}
    <aside class="exchange-side">
      {#await import('./ExchangePanel.svelte') then mod}
        <mod.default
          refreshTick={exchangeTick}
          oninsertref={handleInsertRef}
          onclose={() => (exchangeOpen = false)}
        />
      {/await}
    </aside>
  {/if}
</div>

{#if narrow}
  <Drawer bind:open={drawer} title="对话" side="left">
    <SessionList
      {list}
      current={id}
      {exchangeOpen}
      onpick={() => (drawer = false)}
      onopenworkspace={workspaceTrigger}
      onopenexchange={exchangeTrigger}
    />
  </Drawer>
{/if}

{#if compactExchange && canReadAgent && exchangeOpen}
  <Drawer bind:open={exchangeOpen} title="交互文件夹" side="right">
    {#await import('./ExchangePanel.svelte') then mod}
      <mod.default
        refreshTick={exchangeTick}
        oninsertref={handleInsertRef}
      />
    {/await}
  </Drawer>
{/if}

{#if isAdmin && workspaceOpen}
  {#await import('./AgentWorkspaceModal.svelte') then mod}
    <mod.default bind:open={workspaceOpen} initialTab={workspaceTab} />
  {/await}
{/if}

<style>
  /* 占满宽屏工作区（支持三栏协同：会话列表 + 对话 + 交互文件夹） */
  .agent {
    display: grid;
    grid-template-columns: 238px 1fr;
    height: calc(100dvh - var(--top-h) - var(--s-5));
    min-height: 520px;
    border-radius: var(--r-xl);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    overflow: hidden;
  }
  .agent.with-exchange {
    grid-template-columns: 238px minmax(0, 1fr) 356px;
  }
  .side {
    min-height: 0;
    border-right: 1px solid var(--line);
    background: var(--surface-2);
  }
  .exchange-side {
    min-width: 0;
    min-height: 0;
    border-left: 1px solid var(--line);
    background: var(--surface);
  }
  .main {
    position: relative;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow-y: auto;
  }
  .mobile-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s-2);
    margin: var(--s-3) var(--s-3) 0;
  }
  .open-list {
    align-self: flex-start;
    min-height: 36px;
    padding: 0 var(--s-3);
    border: 1px solid var(--line);
    border-radius: var(--r-pill);
    background: var(--surface);
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-sm);
    cursor: pointer;
  }
  @media (max-width: 860px) {
    .agent {
      grid-template-columns: 1fr;
      height: calc(100dvh - var(--top-h) - var(--tabbar-h) - var(--s-4));
      border-radius: var(--r-lg);
    }
  }
</style>
