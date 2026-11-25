<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  AiDock · AI 悬浮窗（SPEC §4）
  ───────────────────────────────────────────────────────────────
  状态（数据面在 $lib/ai/dock.svelte）：
    rest     56 极光小球，慢呼吸光
    working  球上环形转动；悬停提示"第 n/m 步"
    reach    球向左伸出胶囊："AI 想创建用户 bob · 看一下"，直到被查看
    open     <dialog> 顶层：上方聊天窗 + 下方输入窗 + 遮罩；点外部 / Esc 收回

  布局：两窗水平居中同宽；聊天窗右上角可拖拽缩放（dock-layout.ts），尺寸存 localStorage。
  在 /agent 页（dock.chatSuppressed）：只保留球形提醒；展开时只有待确认，没有输入窗。
  焦点：showModal 自带焦点陷阱；收回时还给展开前的元素。输入框草稿收回后保留。
-->
<script lang="ts">
  import { tick } from 'svelte';
  import { Icon, IconButton, Menu, Orb, registerModalDialog, unregisterModalDialog } from '$ui';
  import type { OrbState } from '$ui/Orb.svelte';
  import { approvals } from '$lib/ai/approvals.svelte';
  import { dock } from '$lib/ai/dock.svelte';
  import { dockSession } from '$lib/ai/dock-session.svelte';
  import { BUSY, MODE_META, sessionsResource } from '$lib/ai/agent-sessions.svelte';
  import { pauseSession, takeOver } from '$lib/ai/controls';
  import { loadSize, saveSize, sizeFromPointer, type DockSize } from '$lib/ai/dock-layout';
  import { turnProgress } from '$lib/ai/transcript';
  import { reportError } from '$lib/errors';
  import { events } from '$lib/events.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { navigate } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import Composer from '../ai/Composer.svelte';
  import Transcript from '../ai/Transcript.svelte';
  import ApprovalStack from './ApprovalStack.svelte';
  import DockBall from './DockBall.svelte';

  const sessions = useResource(sessionsResource);
  dockSession.init();

  let dlg = $state<HTMLDialogElement>();
  let chatEl = $state<HTMLElement | null>(null);
  let scroller = $state<HTMLElement | null>(null);
  let inputH = $state(0);
  let draft = $state('');
  let inputEl = $state<HTMLTextAreaElement | null>(null);
  let returnFocus: HTMLElement | null = null;
  let size = $state<DockSize | null>(loadSize());
  let approvalsOpen = $state(true);

  const canChat = $derived(session.can('host.agent_sessions:write'));
  const canApprove = $derived(session.can('host.approvals:approve'));
  const pending = $derived(approvals.pending);
  const firstUnseen = $derived(approvals.unseen[0]);
  const stream = $derived(dockSession.stream);
  const chat = $derived(canChat && !dock.chatSuppressed);
  const showDock = $derived(canChat || (canApprove && pending.length > 0));
  const progress = $derived(stream ? turnProgress(stream.transcript) : { done: 0, total: 0 });
  const current = $derived(sessions.data?.find((s) => s.session_id === dockSession.id));
  const sessionBusy = $derived(stream?.busy ?? (current ? BUSY.has(current.status) : false));

  /* 实时推导 AI 表情态（覆盖离线/待审批/API出错/工具调用/流式回复/思考/暂停/常驻） */
  const liveAiState = $derived.by<OrbState>(() => {
    if (events.offline) return 'offline';
    if (pending.length > 0) return 'approval';
    const items = stream?.transcript.items ?? [];
    const last = items[items.length - 1];
    const st = stream?.transcript.status ?? current?.status;
    if (st === 'failed' || last?.kind === 'error' || sessions.data?.some((s) => s.status === 'failed' && s.session_id === dockSession.id)) {
      return 'error';
    }
    if (items.some((x) => x.kind === 'tool' && x.status === 'running')) return 'tool';
    if (items.some((x) => x.kind === 'assistant' && x.streaming)) return 'streaming';
    if (st === 'running' || dock.busy) return 'thinking';
    if (st === 'cancelled') return 'paused';
    return 'idle';
  });

  /* 有新审批到来或带 focusApprovalId 打开时自动展开顶置审批区 */
  $effect(() => {
    if (dock.expanded && (dock.focusApprovalId || pending.length > 0)) {
      approvalsOpen = true;
    }
  });

  /* working：任一会话在跑（全局流 agent.session.updated 刷新列表） */
  $effect(() => {
    dock.busy = canChat && !!sessions.data?.some((s) => s.status === 'running');
  });

  /* 展开或当前会话在跑时才保持会话流；在 Agent 页或只读角色不需要 */
  $effect(() => {
    const want = chat && (dock.expanded || (current?.status === 'running'));
    if (want) dockSession.attach();
    else dockSession.detach();
  });

  $effect(() => {
    if (stream?.phase === 'gone') dockSession.forgetIfGone();
  });

  /* 登出卸载：关流，不把上一个用户的会话带进下一次登录 */
  $effect(() => () => dockSession.reset());

  /* 打开 / 收回 <dialog> */
  $effect(() => {
    const el = dlg;
    if (!el) return;
    if (dock.expanded && showDock && !el.open) {
      returnFocus = document.activeElement as HTMLElement | null;
      el.showModal();
      registerModalDialog(el);
      if (dock.prompt) {
        draft = dock.prompt;
        dock.prompt = '';
      }
      void tick().then(() => {
        if (chat && !dock.focusApprovalId && !approvals.unseen.length) inputEl?.focus();
      });
    } else if ((!dock.expanded || !showDock) && el.open) {
      unregisterModalDialog(el);
      el.close();
    }
  });

  $effect(() => {
    const el = dlg;
    return () => {
      if (el) unregisterModalDialog(el);
    };
  });

  function onDialogClose() {
    unregisterModalDialog(dlg);
    if (dock.expanded) dock.close();
    returnFocus?.focus?.();
    returnFocus = null;
  }

  /* 点遮罩收回：点到 dialog 本身（两窗之外的透明区）才算 */
  function onDialogClick(e: MouseEvent) {
    if (e.target === dlg) dock.close();
  }

  function openFromBall() {
    dock.open({ approvalId: firstUnseen?.approval_id });
  }

  async function send(text: string) {
    try {
      await dockSession.send(text);
    } catch (err) {
      reportError(err, '消息没有发出去');
      throw err;
    }
  }

  /* ---------------------------------------------------------------- 缩放 */
  function startResize(e: PointerEvent) {
    if (!chatEl) return;
    e.preventDefault();
    const handle = e.currentTarget as HTMLElement;
    handle.setPointerCapture(e.pointerId);
    const r = chatEl.getBoundingClientRect();
    const box = { centerX: r.left + r.width / 2, bottom: r.bottom, top: 24 };
    const move = (ev: PointerEvent) => (size = sizeFromPointer({ x: ev.clientX, y: ev.clientY }, box, innerWidth, innerHeight));
    const up = () => {
      handle.removeEventListener('pointermove', move);
      handle.removeEventListener('pointerup', up);
      handle.removeEventListener('pointercancel', up);
      saveSize(size);
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', up);
    handle.addEventListener('pointercancel', up);
  }

  function resetSize() {
    size = null;
    saveSize(null);
  }

  /* ---------------------------------------------------------------- 会话切换菜单 */
  const sessionItems = $derived([
    { label: '新对话', icon: 'plus' as const, onselect: () => dockSession.switchTo(null) },
    ...(sessions.data ?? []).slice(0, 8).map((s) => ({
      label: (s.session_id === dockSession.id ? '✓ ' : '') + (s.title || '新的对话'),
      onselect: () => dockSession.switchTo(s.session_id),
    })),
    {
      label: '在 AI 助手页打开',
      icon: 'external' as const,
      onselect: () => {
        dock.close();
        navigate(dockSession.id ? `/agent/${encodeURIComponent(dockSession.id)}` : '/agent');
      },
    },
  ]);
</script>

<!-- ============================================================ 球 + 胶囊 -->
{#if showDock}
  <DockBall {progress} aiState={liveAiState} onopen={openFromBall} />
{/if}

<!-- ============================================================ 展开 -->
<dialog
  bind:this={dlg}
  class="sheet"
  class:with-size={!!size}
  aria-label="AI 助手"
  onclose={onDialogClose}
  onclick={onDialogClick}
  style:--input-h="{chat ? inputH : 0}px"
  style:--dock-w={size ? `${size.w}px` : null}
  style:--chat-h={size ? `${size.h}px` : null}
>
  {#if dock.expanded}
    <section class="chat" bind:this={chatEl} aria-label="AI 对话">
      <header class="chat-head">
        <Orb size={22} state={liveAiState} />
        <h2>{chat ? (current?.title ?? 'AI 助手') : '待确认'}</h2>
        {#if pending.length}
          <button
            type="button"
            class="count"
            aria-expanded={approvalsOpen}
            onclick={() => (approvalsOpen = !approvalsOpen)}
            title={approvalsOpen ? '收起待确认面板' : '展开待确认面板'}
          >
            待确认 {pending.length}
            <Icon name={approvalsOpen ? 'chevron-down' : 'chevron-right'} size={12} />
          </button>
        {/if}
        <span class="grow"></span>
        {#if size}<IconButton icon="undo" label="恢复默认大小" size="sm" variant="plain" onclick={resetSize} />{/if}
        <IconButton icon="x" label="收起" size="sm" variant="plain" onclick={() => dock.close()} />
        <button type="button" class="grip" aria-label="拖拽改变大小" title="拖拽改变大小" onpointerdown={startResize}>
          <Icon name="resize" size={14} />
        </button>
      </header>

      <!-- 独立置顶审批区：不与消息流共用滚动容器，彻底解决聊天加载滚底导致审批卡片闪现消失的问题 -->
      {#if pending.length && approvalsOpen}
        <section class="approval-tray" class:only={!chat} aria-label="待确认操作">
          <div class="tray-bar">
            <span class="tray-title">有 {pending.length} 项操作等待你确认</span>
            {#if chat}
              <button type="button" class="tray-toggle" onclick={() => (approvalsOpen = false)}>先看对话</button>
            {/if}
          </div>
          <div class="tray-scroll">
            <ApprovalStack focusId={dock.focusApprovalId} active={dock.expanded && approvalsOpen} />
          </div>
        </section>
      {/if}

      {#if chat || !pending.length}
        <div class="chat-body" bind:this={scroller}>
          {#if chat}
            {#if stream && stream.phase !== 'loading'}
              <Transcript {stream} {scroller} inlineApprovals={false} />
            {:else if !dockSession.id && !pending.length}
              <div class="hello">
                <Orb size={44} state="idle" />
                <p>有什么可以帮你？我会先说明要做什么，重要操作会先问你。</p>
              </div>
            {/if}
          {:else if !pending.length}
            <p class="quiet">没有需要确认的事。</p>
          {/if}
        </div>
      {/if}
    </section>

    {#if chat}
      <section class="input" bind:clientHeight={inputH} aria-label="给 AI 发消息">
        <Composer
          bind:value={draft}
          bind:el={inputEl}
          busy={sessionBusy}
          disabled={events.offline}
          disabledReason="连接中断，恢复后再发"
          onsend={send}
          onstop={stream && stream.transcript.status === 'running' ? () => pauseSession(stream) : undefined}
        >
          {#snippet tools()}
            <Menu label="切换对话" items={sessionItems} align="start">
              {#snippet trigger(props)}
                <button type="button" class="tag" {...props}>
                  <Icon name="clock" size={14} />
                  <span class="tag-t">{dockSession.id ? (current?.title ?? '当前对话') : '新对话'}</span>
                </button>
              {/snippet}
            </Menu>
            {#if current}
              <span class="tag mode" class:danger={current.permission_mode === 'full'} title="权限模式">
                <Icon name="shield" size={14} />{MODE_META[current.permission_mode]?.short}
              </span>
            {/if}
            {#if stream && stream.transcript.status === 'running'}
              <button type="button" class="tag" onclick={() => pauseSession(stream)}><Icon name="pause" size={14} />暂停</button>
            {/if}
            {#if stream && current}
              <button type="button" class="tag" onclick={() => takeOver(stream)} title="停下 AI 并切为只读">
                <Icon name="hand" size={14} />接管
              </button>
            {/if}
          {/snippet}
        </Composer>
      </section>
    {/if}
  {/if}
</dialog>

<style>
  /* ------------------------------------------------------------ 展开 */
  .sheet {
    --gap: 24px;
    --w: var(--dock-w, min(720px, calc(100vw - 32px)));
    position: fixed;
    inset: 0;
    width: 100vw;
    height: 100dvh;
    max-width: none;
    max-height: none;
    margin: 0;
    padding: 0;
    border: 0;
    background: transparent;
    color: var(--text);
    overflow: hidden;
  }
  .sheet::backdrop {
    background: var(--scrim);
    backdrop-filter: blur(2px);
  }
  .sheet[open]::backdrop {
    animation: qwq-fade-in var(--dur-2) var(--ease);
  }
  .chat,
  .input {
    position: absolute;
    left: 50%;
    width: var(--w);
    translate: -50% 0;
  }
  .chat {
    top: var(--gap);
    bottom: calc(var(--gap) + var(--input-h) + 16px);
    display: flex;
    flex-direction: column;
    border-radius: var(--r-xl);
    background: var(--surface);
    box-shadow: var(--shadow-3);
    overflow: hidden;
    animation: from-top var(--dur-3) var(--ease-out);
  }
  .with-size .chat {
    top: auto;
    height: min(var(--chat-h), calc(100dvh - 2 * var(--gap) - var(--input-h) - 16px));
  }
  .input {
    bottom: var(--gap);
    padding: 0;
    border-radius: var(--r-lg);
    background: var(--surface);
    box-shadow: var(--shadow-3);
    animation: from-bottom var(--dur-3) var(--ease-out);
  }
  .input :global(.composer) {
    border-color: var(--line-strong);
  }
  .input :global(.composer:focus-within) {
    box-shadow: none;
  }
  @keyframes from-top {
    from {
      opacity: 0;
      transform: translateY(-32px);
    }
  }
  @keyframes from-bottom {
    from {
      opacity: 0;
      transform: translateY(32px);
    }
  }
  :global(:root[data-motion='reduced']) .chat,
  :global(:root[data-motion='reduced']) .input {
    animation: qwq-fade-in var(--dur-1) linear;
  }

  .chat-head {
    position: relative;
    display: flex;
    align-items: center;
    gap: var(--s-2);
    padding: var(--s-3) var(--s-6) var(--s-3) var(--s-4);
    border-bottom: 1px solid var(--line);
  }
  .chat-head h2 {
    margin: 0;
    min-width: 0;
    font-size: var(--fs-md);
    font-weight: var(--fw-semibold);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .count {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border: 0;
    border-radius: var(--r-pill);
    background: var(--warn-soft);
    color: var(--warn-text);
    font: inherit;
    font-size: var(--fs-xs);
    font-weight: var(--fw-medium);
    cursor: pointer;
  }
  .approval-tray {
    flex: none;
    display: flex;
    flex-direction: column;
    max-height: 54%;
    border-bottom: 1px solid var(--line);
    background: color-mix(in oklab, var(--warn-soft) 22%, var(--surface-2));
  }
  .approval-tray.only {
    flex: 1;
    max-height: none;
    border-bottom: 0;
  }
  .tray-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-2);
    padding: 8px var(--s-4);
    border-bottom: 1px solid color-mix(in oklab, var(--line) 75%, transparent);
    font-size: var(--fs-xs);
  }
  .tray-title {
    font-weight: var(--fw-semibold);
    color: var(--warn-text);
  }
  .tray-toggle {
    border: 0;
    background: none;
    padding: 2px 6px;
    border-radius: var(--r-sm);
    color: var(--text-2);
    font: inherit;
    cursor: pointer;
  }
  .tray-toggle:hover {
    background: var(--surface);
    color: var(--text);
  }
  .tray-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    overscroll-behavior: contain;
    padding: var(--s-3) var(--s-4);
  }
  .grow {
    flex: 1;
  }
  .grip {
    position: absolute;
    top: 0;
    right: 0;
    display: grid;
    place-items: start end;
    width: 28px;
    height: 28px;
    padding: 6px;
    border: 0;
    background: none;
    color: var(--text-3);
    cursor: nesw-resize;
    touch-action: none;
  }
  .grip:hover {
    color: var(--text);
  }
  .chat-body {
    flex: 1;
    min-height: 0;
    display: grid;
    align-content: start;
    gap: var(--s-4);
    padding: var(--s-4);
    overflow-y: auto;
    overscroll-behavior: contain;
  }
  .hello {
    display: grid;
    justify-items: center;
    gap: var(--s-3);
    padding: var(--s-7) var(--s-4);
    text-align: center;
    color: var(--text-2);
  }
  .hello p {
    margin: 0;
    max-width: 320px;
  }
  .quiet {
    margin: var(--s-6) 0;
    text-align: center;
    color: var(--text-3);
  }

  .tag {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 30px;
    max-width: 180px;
    padding: 0 var(--s-2);
    border: 0;
    border-radius: var(--r-pill);
    background: var(--surface-2);
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-xs);
    white-space: nowrap;
  }
  button.tag {
    cursor: pointer;
  }
  button.tag:hover {
    background: var(--surface-3);
  }
  .tag-t {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .tag.danger {
    color: var(--bad-text);
  }

  /* ------------------------------------------------------------ 窄屏 */
  @media (max-width: 860px) {
    .sheet {
      --gap: 12px;
      --w: calc(100vw - 24px);
    }
    .with-size .chat {
      top: var(--gap);
      height: auto;
    }
    .grip {
      display: none;
    }
    .input {
      bottom: calc(var(--gap) + env(keyboard-inset-height, 0px));
    }
  }
</style>
