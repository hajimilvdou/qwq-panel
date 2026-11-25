<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  原生 Agent 页（宽屏三栏自适应：会话列表 + 对话 + 交互文件夹）
-->
<script lang="ts">
  import { Drawer } from '$ui';
  import { dock } from '$lib/ai/dock.svelte';
  import { sessionsResource } from '$lib/ai/agent-sessions.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import type { ComposerCitation } from '../ai/Composer.svelte';
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
  let citations = $state<ComposerCitation[]>([]);

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

  function handleInsertRef(ref: ComposerCitation) {
    if (!citations.some((c) => c.path === ref.path)) {
      citations = [...citations, ref];
    }
    if (compactExchange) exchangeOpen = false;
  }

  function removeCitation(path: string) {
    citations = citations.filter((c) => c.path !== path);
  }

  function clearCitations() {
    citations = [];
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
          {citations}
          onremovecitation={removeCitation}
          onclearcitations={clearCitations}
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
        <NewSession {citations} onremovecitation={removeCitation} onclearcitations={clearCitations} />
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
      <mod.default refreshTick={exchangeTick} oninsertref={handleInsertRef} />
    {/await}
  </Drawer>
{/if}

{#if isAdmin && workspaceOpen}
  {#await import('./AgentWorkspaceModal.svelte') then mod}
    <mod.default bind:open={workspaceOpen} initialTab={workspaceTab} />
  {/await}
{/if}

<style>
  .agent {
    display: grid;
    grid-template-columns: 224px minmax(0, 1fr);
    height: calc(100dvh - var(--top-h) - 38px);
    min-height: 540px;
    border-radius: var(--r-xl);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    overflow: hidden;
  }
  .agent.with-exchange {
    grid-template-columns: 220px minmax(0, 1fr) 336px;
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
    font-size: var(--fs-sm);
  }
  @media (max-width: 860px) {
    .agent {
      grid-template-columns: 1fr;
      height: calc(100dvh - var(--top-h) - var(--tabbar-h) - var(--s-5));
      border-radius: var(--r-lg);
    }
  }
</style>
