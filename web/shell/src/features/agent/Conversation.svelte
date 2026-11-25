<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Conversation · 会话右栏：会话头 + 消息流 + 输入 + 常驻遥测条
-->
<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { Button, Checkbox, Chip, ConfirmDialog, Dialog, EmptyState, ErrorState, IconButton, Input, Menu, Select, Skeleton, Icon } from '$ui';
  import type { Option } from '$ui';
  import { agent, ai } from '$api/endpoints';
  import type { PermissionMode } from '$api/types';
  import type { AiProvider, ReasoningEffort } from '$api/additions';
  import {
    BUILTIN_SKILLS,
    coreLabel,
    MODE_META,
    MODES,
    SLASH_COMMANDS,
    statusMeta,
    lastSession,
  } from '$lib/ai/agent-sessions.svelte';
  import ContextField from '../ai/ContextField.svelte';
  import EffortField from '../ai/EffortField.svelte';
  import TelemetryStrip from '../ai/TelemetryStrip.svelte';
  import { changeMode, pauseSession, takeOver } from '$lib/ai/controls';
  import { SessionStream } from '$lib/ai/session-stream.svelte';
  import { describeError, reportError } from '$lib/errors';
  import { page } from '$lib/page.svelte';
  import { navigate } from '$lib/router.svelte';
  import { resources } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';
  import Composer, { type ComposerCitation } from '../ai/Composer.svelte';
  import Transcript from '../ai/Transcript.svelte';
  import TurnNavigator from '../ai/TurnNavigator.svelte';

  interface Props {
    id: string;
    exchangeOpen?: boolean;
    citations?: readonly ComposerCitation[];
    onremovecitation?: (path: string) => void;
    onclearcitations?: () => void;
    onmenu?: () => void;
    onopenworkspace?: (tab?: 'prompts' | 'skills' | 'mcp' | 'registry') => void;
    ontoggleexchange?: () => void;
    onturnsettled?: () => void;
  }
  let {
    id,
    exchangeOpen = false,
    citations = [],
    onremovecitation,
    onclearcitations,
    onmenu,
    onopenworkspace,
    ontoggleexchange,
    onturnsettled,
  }: Props = $props();

  const stream = new SessionStream(untrack(() => id));
  stream.start();
  lastSession.set(stream.id);
  onDestroy(() => stream.stop());

  let scroller = $state<HTMLElement | null>(null);
  let text = $state('');
  let editing = $state(false);
  let titleDraft = $state('');
  let confirmFull = $state(false);
  let confirmDelete = $state(false);
  let deleteError = $state<string>();
  let planOpen = $state(false);
  let cmdOpen = $state(false);

  /* 会话实时运行参数弹窗 */
  let cfgOpen = $state(false);
  let cfgSaving = $state(false);
  let cfgModel = $state('');
  let cfgEffort = $state<ReasoningEffort>('');
  let cfgMaxCtx = $state('0');
  let cfgPlan = $state(false);
  let cfgProviders = $state<AiProvider[]>([]);

  const isAdmin = $derived(session.role === 'admin');
  const canWriteAgent = $derived(session.can('host.agent_sessions:write'));
  const s = $derived(stream.session);
  const st = $derived(statusMeta(stream.transcript.status));
  const running = $derived(stream.transcript.status === 'running');
  const plan = $derived(stream.transcript.plan);
  const planDone = $derived(plan ? plan.steps.filter((x) => x.status === 'completed').length : 0);
  const planTotal = $derived(plan?.steps.length ?? 0);
  const planPct = $derived(planTotal > 0 ? Math.round((planDone / planTotal) * 100) : 0);
  const tel = $derived(stream.transcript.telemetry);

  const sessionCfg = $derived((s?.config ?? {}) as Record<string, unknown>);
  const selectedProvider = $derived.by(() => {
    const pid = typeof sessionCfg.provider_id === 'string' ? sessionCfg.provider_id : '';
    return cfgProviders.find((x) => x.provider_id === pid) ?? cfgProviders.find((x) => x.is_default);
  });
  const activeModelName = $derived(typeof sessionCfg.model === 'string' ? sessionCfg.model : '');
  const effectiveModelName = $derived(activeModelName.trim() || tel?.model || selectedProvider?.model || '');
  const activeEffort = $derived(
    typeof sessionCfg.reasoning_effort === 'string' ? (sessionCfg.reasoning_effort as ReasoningEffort) : '',
  );
  const activeMaxCtx = $derived(
    typeof sessionCfg.max_context_tokens === 'number' ? sessionCfg.max_context_tokens : 0,
  );
  const activePlan = $derived(Boolean(sessionCfg.plan_mode));

  const cfgModelOptions = $derived.by<Option[]>(() => {
    const p = selectedProvider;
    const set = new Set<string>();
    if (p?.model) set.add(p.model);
    for (const m of p?.models ?? []) set.add(m);
    if (cfgModel.trim()) set.add(cfgModel.trim());
    return [
      { value: '', label: p ? `跟随服务默认 (${p.model})` : '跟随默认模型' },
      ...Array.from(set).map((m) => ({ value: m, label: m })),
    ];
  });

  async function openConfigDialog() {
    if (!canWriteAgent) return;
    cfgModel = activeModelName;
    cfgEffort = activeEffort;
    cfgMaxCtx = String(activeMaxCtx || 0);
    cfgPlan = activePlan;
    cfgOpen = true;
    if (!cfgProviders.length) {
      try {
        const res = await ai.providers();
        cfgProviders = res.items;
      } catch {
        /* 仅在有权限时加载提供方列表 */
      }
    }
  }

  async function saveConfigDialog() {
    if (!canWriteAgent) return;
    cfgSaving = true;
    try {
      const ctxNum = Number(cfgMaxCtx) || 0;
      await stream.updateConfig({
        model: cfgModel.trim(),
        reasoning_effort: cfgEffort,
        max_context_tokens: ctxNum,
        plan_mode: cfgPlan,
      });
      toasts.success('已更新会话模型与运行参数');
      cfgOpen = false;
    } catch (err) {
      reportError(err, '更新会话参数失败');
    } finally {
      cfgSaving = false;
    }
  }

  const slashQuery = $derived(text.startsWith('/') ? text.slice(1).trim().toLowerCase() : '');
  const showSlash = $derived(canWriteAgent && (cmdOpen || text.startsWith('/')));
  const filteredCmds = $derived(
    SLASH_COMMANDS.filter((c) => !slashQuery || c.cmd.toLowerCase().includes(slashQuery) || c.label.includes(slashQuery)),
  );
  const filteredSkills = $derived(
    BUILTIN_SKILLS.filter((k) => !slashQuery || k.id.includes(slashQuery) || k.label.toLowerCase().includes(slashQuery)),
  );

  function pickSlash(cmd: string, instant?: boolean) {
    if (!canWriteAgent) return;
    cmdOpen = false;
    if (instant && stream.phase === 'ready' && !stream.busy) {
      text = '';
      void send(cmd);
      return;
    }
    text = cmd + ' ';
  }

  function pickSkill(prompt: string) {
    if (!canWriteAgent) return;
    cmdOpen = false;
    text = prompt;
  }

  $effect(() => {
    if (s?.title) page.setTitle(s.title);
  });

  let wasRunning = false;
  $effect(() => {
    const curRunning = stream.transcript.status === 'running';
    if (wasRunning && !curRunning) onturnsettled?.();
    wasRunning = curRunning;
  });

  function exportTranscript(format: 'markdown' | 'json') {
    const a = document.createElement('a');
    a.href = agent.exportUrl(stream.id, format);
    a.download = '';
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    toasts.info(`正在导出当前会话 (${format === 'json' ? 'JSON' : 'Markdown'})`);
  }

  const exportItems = [
    { label: '导出 Markdown (.md)', icon: 'download' as const, onselect: () => exportTranscript('markdown') },
    { label: '导出 JSON (.json)', icon: 'file' as const, onselect: () => exportTranscript('json') },
  ];

  let savingOrCancelled = false;
  function startEdit() {
    if (!canWriteAgent) return;
    savingOrCancelled = false;
    titleDraft = s?.title ?? '';
    editing = true;
  }
  function cancelEdit() {
    savingOrCancelled = true;
    editing = false;
  }
  async function saveTitle() {
    if (savingOrCancelled || !canWriteAgent) return;
    savingOrCancelled = true;
    editing = false;
    const t = titleDraft.trim();
    if (!t || t === s?.title) return;
    try {
      await stream.rename(t.slice(0, 80));
      resources.invalidate('agent-sessions');
    } catch (err) {
      reportError(err, '改名没有成功');
    }
  }

  function pickMode(m: PermissionMode) {
    if (!canWriteAgent || m === s?.permission_mode) return;
    if (m === 'full') confirmFull = true;
    else void changeMode(stream, m);
  }

  async function send(t: string) {
    if (!canWriteAgent) return;
    try {
      await stream.send(t);
    } catch (err) {
      reportError(err, '消息没有发出去');
    }
  }

  async function remove() {
    if (!canWriteAgent) return;
    deleteError = undefined;
    try {
      await stream.remove();
      lastSession.set(null);
      resources.invalidate('agent-sessions');
      navigate('/agent', { replace: true });
    } catch (err) {
      deleteError = describeError(err).message;
      throw err;
    }
  }

  const modeItems = $derived(
    MODES.map((m) => ({
      label: (m === s?.permission_mode ? '✓ ' : '') + MODE_META[m].label + (m === 'full' && !isAdmin ? '（仅管理员）' : ''),
      disabled: m === 'custom' || (m === 'full' && !isAdmin) || !canWriteAgent,
      tone: MODE_META[m].danger ? ('danger' as const) : undefined,
      onselect: () => pickMode(m),
    })),
  );
</script>

<section class="conv" aria-label="对话">
  {#if stream.phase === 'gone'}
    <div class="center">
      <EmptyState title="这个对话已不存在" description="可能已在别处被删除。">
        {#snippet action()}<Button variant="primary" href="/agent">开始新对话</Button>{/snippet}
      </EmptyState>
    </div>
  {:else if stream.phase === 'error'}
    <div class="center">
      <ErrorState message={describeError(stream.error).message} onretry={stream.reload} />
    </div>
  {:else}
    <header class="head">
      {#if onmenu}<IconButton icon="menu" label="会话列表" variant="plain" onclick={onmenu} />{/if}
      <div class="ttl">
        {#if !s}
          <Skeleton width="200px" height={20} />
        {:else if editing}
          <!-- svelte-ignore a11y_autofocus -->
          <input
            class="title-in"
            aria-label="对话标题"
            maxlength={80}
            bind:value={titleDraft}
            autofocus
            onblur={() => void saveTitle()}
            onkeydown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                void saveTitle();
              } else if (e.key === 'Escape') {
                e.preventDefault();
                cancelEdit();
              }
            }}
          />
        {:else if canWriteAgent}
          <button type="button" class="title" onclick={startEdit} title="点击改名">
            <span>{s.title || '新的对话'}</span><Icon name="edit" size={14} />
          </button>
        {:else}
          <span class="title-static">{s.title || '新的对话'}</span>
        {/if}
        {#if s}
          <Chip size="sm" tone={st.tone}>{st.label}</Chip>
          <span class="core-badge">{coreLabel(s.core)}</span>
        {/if}
      </div>

      {#if s}
        <div class="acts">
          {#if ontoggleexchange}
            <Button size="sm" variant={exchangeOpen ? 'soft' : 'ghost'} icon="folder" onclick={ontoggleexchange} title="打开交互文件夹">
              文件
            </Button>
          {/if}
          {#if onopenworkspace && canWriteAgent}
            <Button size="sm" variant="ghost" icon="apps" onclick={() => onopenworkspace('prompts')} title="管理 MCP、技能与提示词">
              资源
            </Button>
          {/if}
          <Menu label="导出对话" items={exportItems} align="end">
            {#snippet trigger(props)}
              <IconButton icon="download" label="导出对话" variant="plain" {...props} />
            {/snippet}
          </Menu>
          {#if canWriteAgent}
            <Menu label="权限模式" items={modeItems}>
              {#snippet trigger(props)}
                <button type="button" class="mode" class:danger={s.permission_mode === 'full'} {...props}>
                  <Icon name="shield" size={15} />
                  {MODE_META[s.permission_mode]?.short ?? s.permission_mode}
                </button>
              {/snippet}
            </Menu>
            {#if running}
              <Button size="sm" variant="soft" icon="pause" onclick={() => pauseSession(stream)}>暂停</Button>
            {/if}
            <Button size="sm" variant="ghost" icon="hand" onclick={() => takeOver(stream)} title="停下 AI 并切为只读">接管</Button>
            <IconButton icon="trash" label="删除对话" variant="plain" onclick={() => (confirmDelete = true)} />
          {:else}
            <span class="mode readonly" class:danger={s.permission_mode === 'full'}>
              <Icon name="shield" size={15} />
              {MODE_META[s.permission_mode]?.short ?? s.permission_mode}
            </span>
          {/if}
        </div>
      {/if}
    </header>

    {#if stream.link === 'reconnecting'}
      <p class="link" role="status">对话连接中断，正在重连…</p>
    {/if}

    <div class="scroll-host">
      <div class="scroll" bind:this={scroller}>
        <div class="inner">
          {#if stream.phase === 'loading'}
            <Skeleton lines={4} height={48} />
          {:else}
            <Transcript {stream} {scroller} />
          {/if}
        </div>
      </div>
      {#if stream.phase !== 'loading'}
        <TurnNavigator items={stream.transcript.items} {scroller} />
      {/if}
    </div>

    <div class="foot">
      {#if planTotal > 0 && plan}
        {#if planOpen}
          <section class="task-sheet" aria-label="任务执行清单">
            <header class="task-head">
              <div class="task-title">
                <Icon name="menu" size={15} />
                <span>任务执行清单</span>
                <span class="task-pill" class:all-done={planDone === planTotal}>{planDone}/{planTotal} 已完成</span>
              </div>
              <button type="button" class="task-close" aria-label="收起任务清单" onclick={() => (planOpen = false)}>
                <Icon name="x" size={15} />
              </button>
            </header>
            <div class="task-bar"><span class="task-fill" style:width="{planPct}%"></span></div>
            <ol class="task-list">
              {#each plan.steps as step, idx (step.id)}
                <li class="task-item {step.status}">
                  <span class="task-dot">
                    {#if step.status === 'completed'}✓{:else if step.status === 'in_progress'}●{:else}○{/if}
                  </span>
                  <span>{idx + 1}. {step.content}</span>
                </li>
              {/each}
            </ol>
          </section>
        {:else}
          <button type="button" class="task-bar-btn" onclick={() => (planOpen = true)}>
            <span class="tb-l">
              <Icon name="menu" size={14} />
              <span>任务 {planDone}/{planTotal} 已完成</span>
            </span>
            <span class="tb-r">查看清单</span>
          </button>
        {/if}
      {/if}

      {#if showSlash && (filteredCmds.length > 0 || filteredSkills.length > 0)}
        <div class="slash-pop" role="listbox" aria-label="快捷指令与运维技能">
          {#if filteredCmds.length}
            <div class="slash-group">快捷指令</div>
            {#each filteredCmds as c (c.cmd)}
              <button type="button" class="slash-row" onclick={() => pickSlash(c.cmd, c.instant)}>
                <code class="slash-cmd">{c.cmd}</code>
                <span class="slash-lbl">{c.label}</span>
                <span class="slash-desc">{c.desc}</span>
              </button>
            {/each}
          {/if}
          {#if filteredSkills.length}
            <div class="slash-group">运维技能</div>
            {#each filteredSkills as k (k.id)}
              <button type="button" class="slash-row" onclick={() => pickSkill(k.prompt)}>
                <span class="slash-lbl">{k.label}</span>
                <span class="slash-desc">{k.desc}</span>
                <span class="slash-tag">内置</span>
              </button>
            {/each}
          {/if}
        </div>
      {/if}

      <Composer
        bind:value={text}
        {citations}
        {onremovecitation}
        {onclearcitations}
        allowUpload={canWriteAgent}
        busy={stream.busy}
        disabled={stream.phase !== 'ready' || !canWriteAgent}
        placeholder={!canWriteAgent
          ? '当前角色仅可查看，无法发送消息或修改会话'
          : stream.transcript.status === 'waiting_approval'
            ? '先处理上面的确认，再继续对话'
            : '输入运维需求或问题，输入 / 调用快捷指令，支持拖拽或粘贴文件…'}
        onsend={async (t) => {
          cmdOpen = false;
          await send(t);
        }}
        onstop={canWriteAgent && running ? () => pauseSession(stream) : undefined}
      >
        {#snippet tools()}
          {#if canWriteAgent}
            <button type="button" class="c-pill" class:active={showSlash} onclick={() => (cmdOpen = !cmdOpen)}>
              / 快捷指令
            </button>
            {#if s}
              <button
                type="button"
                class="c-pill"
                class:active={activePlan || Boolean(activeEffort)}
                onclick={openConfigDialog}
                title="调整当前会话的模型、思考挡位、上下文大小与计划模式"
              >
                <Icon name="settings" size={13} />
                <span>
                  {activeModelName || '默认模型'}{activeEffort ? ` · ${activeEffort}` : ''}{activePlan ? ' · Plan' : ''}
                </span>
              </button>
              <Menu label="权限模式" items={modeItems} align="start" placement="up">
                {#snippet trigger(props)}
                  <button type="button" class="c-pill" class:danger={s.permission_mode === 'full'} {...props}>
                    <Icon name="shield" size={13} />
                    <span>{MODE_META[s.permission_mode]?.label ?? s.permission_mode}</span>
                    <Icon name="chevron-down" size={12} />
                  </button>
                {/snippet}
              </Menu>
            {/if}
          {:else if s}
            <span class="c-pill">
              <Icon name="shield" size={13} />
              <span>只读查看</span>
            </span>
          {/if}
        {/snippet}
      </Composer>

      <TelemetryStrip telemetry={tel} model={effectiveModelName} maxContextTokens={activeMaxCtx} />
    </div>
  {/if}
</section>

<ConfirmDialog
  bind:open={confirmFull}
  title="让 AI 按授权直接做？"
  tone="danger"
  confirmLabel="切换"
  warning="包括可能影响连接的操作，例如改防火墙、重启 SSH。AI 不会再逐项问你。"
  onconfirm={() => changeMode(stream, 'full')}
>
  随时可以在这里切回"重要操作先问我"。
</ConfirmDialog>

<ConfirmDialog
  bind:open={confirmDelete}
  title="删除这个对话？"
  tone="danger"
  confirmLabel="删除"
  errorText={deleteError}
  onconfirm={remove}
>
  对话记录会一并删除；进行中的一轮会被取消。已经执行的操作不受影响，可在"动态"里查看。
</ConfirmDialog>

<Dialog bind:open={cfgOpen} title="会话模型与运行参数" size="sm">
  <div class="cfg-form">
    {#if cfgModelOptions.length > 1}
      <Select label="快速选择模型" options={cfgModelOptions} bind:value={cfgModel} />
    {/if}
    <Input
      label="模型名称（留空则跟随服务或核心默认）"
      bind:value={cfgModel}
      placeholder="如 claude-sonnet-4-6 / gpt-5 / deepseek-reasoner"
    />
    <EffortField label="思考挡位（Effort，可自由填写）" model={cfgModel.trim() || effectiveModelName} bind:value={cfgEffort} />
    <ContextField label="上下文窗口大小（自动识别主流模型）" model={cfgModel.trim() || effectiveModelName} bind:value={cfgMaxCtx} />
    <Checkbox bind:checked={cfgPlan} label="计划模式（Plan Mode）：先列步骤再执行，适合高风险变更" />
    <p class="cfg-tip">也可在对话框输入 <code>/effort max</code>、<code>/context 200k</code>、<code>/model 名称</code> 或 <code>/plan on</code> 快速生效。</p>
  </div>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (cfgOpen = false)}>取消</Button>
    <Button variant="primary" loading={cfgSaving} onclick={saveConfigDialog}>保存并生效</Button>
  {/snippet}
</Dialog>

<style>
  .conv {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    height: 100%;
  }
  .center {
    display: grid;
    place-items: center;
    flex: 1;
  }
  .head {
    display: flex;
    align-items: center;
    gap: var(--s-3);
    padding: var(--s-3) var(--s-5);
    border-bottom: 1px solid var(--line);
    min-height: 58px;
  }
  .ttl {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    flex: 1;
    min-width: 0;
  }
  .title {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
    min-height: 36px;
    padding: 0 var(--s-2);
    margin-left: calc(-1 * var(--s-2));
    border-radius: var(--r-sm);
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
    cursor: text;
  }
  .title span,
  .title-static {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .title-static {
    min-width: 0;
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .mode.readonly {
    cursor: default;
  }
  .title :global(svg) {
    flex: none;
    color: var(--text-3);
    opacity: 0;
    transition: opacity var(--dur-1) var(--ease);
  }
  .title:hover {
    background: var(--surface-2);
  }
  .title:hover :global(svg),
  .title:focus-visible :global(svg) {
    opacity: 1;
  }
  .title-in {
    flex: 1;
    min-width: 0;
    height: 36px;
    padding: 0 var(--s-2);
    border: 1px solid var(--accent);
    border-radius: var(--r-sm);
    background: var(--surface);
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .acts {
    display: flex;
    align-items: center;
    gap: var(--s-2);
  }
  .mode {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 32px;
    padding: 0 var(--s-3);
    border: 1px solid var(--line);
    border-radius: var(--r-pill);
    background: var(--surface);
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .mode:hover {
    border-color: var(--line-strong);
  }
  .mode.danger {
    color: var(--bad-text);
    border-color: var(--bad-soft);
  }
  .link {
    padding: 6px var(--s-5);
    font-size: var(--fs-xs);
    background: var(--warn-soft);
    color: var(--warn-text);
  }
  .scroll-host {
    position: relative;
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
  }
  .scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    overscroll-behavior: contain;
  }
  .inner {
    width: min(1160px, 100%);
    margin: 0 auto;
    padding: var(--s-5) 48px var(--s-5) var(--s-6);
  }
  .cfg-form {
    display: grid;
    gap: var(--s-3);
  }
  .cfg-tip {
    font-size: var(--fs-xs);
    color: var(--text-3);
    line-height: 1.5;
  }
  .foot {
    position: relative;
    width: min(1160px, 100%);
    margin: 0 auto;
    padding: 0 var(--s-6) var(--s-3);
    display: grid;
    gap: 8px;
  }
  .core-badge {
    padding: 2px 9px;
    border-radius: var(--r-pill);
    background: var(--surface-2);
    border: 1px solid var(--line);
    color: var(--text-2);
    font-size: var(--fs-2xs);
    font-weight: var(--fw-medium);
    white-space: nowrap;
  }
  .task-bar-btn {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    padding: 8px 14px;
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
    color: var(--text-2);
    font-size: var(--fs-xs);
  }
  .task-bar-btn:hover {
    border-color: var(--line-strong);
    color: var(--text);
  }
  .tb-l {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: var(--fw-medium);
  }
  .tb-r {
    color: var(--text-3);
  }
  .task-sheet {
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-2);
    overflow: hidden;
    animation: qwq-rise-in var(--dur-2) var(--ease-out);
  }
  .task-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    background: var(--surface-2);
  }
  .task-title {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
  }
  .task-pill {
    padding: 2px 9px;
    border-radius: var(--r-pill);
    background: var(--accent-soft);
    color: var(--accent-text);
    font-size: var(--fs-2xs);
    font-weight: var(--fw-semibold);
  }
  .task-pill.all-done {
    background: var(--ok-soft);
    color: var(--ok-text);
  }
  .task-close {
    display: inline-grid;
    place-items: center;
    width: 26px;
    height: 26px;
    border-radius: var(--r-pill);
    color: var(--text-3);
  }
  .task-close:hover {
    background: var(--surface-3);
    color: var(--text);
  }
  .task-bar {
    height: 3px;
    background: var(--surface-3);
  }
  .task-fill {
    display: block;
    height: 100%;
    background: var(--ok);
    transition: width var(--dur-2) var(--ease);
  }
  .task-list {
    display: grid;
    gap: 6px;
    padding: 12px 16px;
    font-size: var(--fs-sm);
  }
  .task-item {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-2);
  }
  .task-item.completed {
    color: var(--text-3);
  }
  .task-item.in_progress {
    color: var(--text);
    font-weight: var(--fw-medium);
  }
  .task-dot {
    width: 18px;
    text-align: center;
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .task-item.completed .task-dot {
    color: var(--ok);
  }
  .task-item.in_progress .task-dot {
    color: var(--accent);
  }
  .slash-pop {
    position: absolute;
    left: var(--s-6);
    right: var(--s-6);
    bottom: calc(100% + 4px);
    z-index: 20;
    max-height: 300px;
    overflow-y: auto;
    padding: 6px;
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line-strong);
    box-shadow: var(--shadow-3);
    display: grid;
    gap: 2px;
  }
  .slash-group {
    padding: 6px 10px 3px;
    font-size: var(--fs-2xs);
    font-weight: var(--fw-semibold);
    color: var(--text-3);
  }
  .slash-row {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 10px;
    border-radius: var(--r-sm);
    text-align: left;
    font-size: var(--fs-sm);
  }
  .slash-row:hover {
    background: var(--surface-2);
  }
  .slash-cmd {
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    color: var(--accent-text);
    font-weight: var(--fw-semibold);
  }
  .slash-lbl {
    font-weight: var(--fw-medium);
    white-space: nowrap;
  }
  .slash-desc {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .slash-tag {
    font-size: var(--fs-2xs);
    color: var(--text-3);
  }
  .c-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 30px;
    padding: 0 10px;
    border-radius: var(--r-pill);
    background: var(--surface-2);
    border: 1px solid var(--line);
    color: var(--text-2);
    font-size: var(--fs-xs);
    white-space: nowrap;
  }
  .c-pill:hover,
  .c-pill.active {
    background: var(--surface-3);
    color: var(--text);
    border-color: var(--line-strong);
  }
  .c-pill.danger {
    color: var(--bad-text);
    border-color: var(--bad-soft);
  }
  @media (max-width: 860px) {
    .head {
      padding: var(--s-2) var(--s-3);
    }
    .inner,
    .foot {
      padding-inline: var(--s-3);
    }
    .slash-pop {
      left: var(--s-3);
      right: var(--s-3);
    }
  }
</style>
