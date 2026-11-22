<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  原生 Agent 页（SPEC §3.3）
  ───────────────────────────────────────────────────────────────
  双栏：左 280 会话列表，右对话或新建面板；≤860 列表收进抽屉。
  在本页时悬浮窗只保留球形提醒（dock.chatSuppressed），避免同屏两个输入框。
  会话切换时 Conversation 以 id 为 key 重建：各自的流互不串线。
-->
<script lang="ts">
  import { Drawer } from '$ui';
  import { dock } from '$lib/ai/dock.svelte';
  import { sessionsResource } from '$lib/ai/agent-sessions.svelte';
  import { useResource } from '$lib/resource.svelte';
  import Conversation from './Conversation.svelte';
  import NewSession from './NewSession.svelte';
  import SessionList from './SessionList.svelte';

  let { params }: { params: Record<string, string> } = $props();

  const list = useResource(sessionsResource);
  const id = $derived(params.sessionId);
  let drawer = $state(false);
  let narrow = $state(false);

  $effect(() => {
    dock.chatSuppressed = true;
    return () => (dock.chatSuppressed = false);
  });

  $effect(() => {
    const mq = matchMedia('(max-width: 860px)');
    narrow = mq.matches;
    const on = () => (narrow = mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  });
</script>

<div class="agent">
  {#if !narrow}
    <aside class="side"><SessionList {list} current={id} /></aside>
  {/if}
  <div class="main">
    {#key id}
      {#if id}
        <Conversation {id} onmenu={narrow ? () => (drawer = true) : undefined} />
      {:else}
        {#if narrow}
          <button type="button" class="open-list" onclick={() => (drawer = true)}>历史对话</button>
        {/if}
        <NewSession />
      {/if}
    {/key}
  </div>
</div>

{#if narrow}
  <Drawer bind:open={drawer} title="对话" side="left">
    <SessionList {list} current={id} onpick={() => (drawer = false)} />
  </Drawer>
{/if}

<style>
  /* 占满宽屏工作区（定稿 v4 DSH 布局，减少留白） */
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
  .side {
    min-height: 0;
    border-right: 1px solid var(--line);
    background: var(--surface-2);
  }
  .main {
    position: relative;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow-y: auto;
  }
  .open-list {
    align-self: flex-start;
    margin: var(--s-3) var(--s-3) 0;
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
