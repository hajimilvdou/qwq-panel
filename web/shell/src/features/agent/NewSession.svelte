<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  NewSession · 新建会话面板（SPEC §3.3 / ADR-0028）
  ───────────────────────────────────────────────────────────────────────────────
  支持：
  - 核心选择（内置原生 / Claude Code / Codex / OpenCode）
  - 外部 CLI 明确区分「官方登录态」与「自定义 API 服务（URL/Key）」，互不串线
  - 选择具体模型（自动带出该服务已拉取的模型列表，也支持手填）、思考挡位（Effort）、
    上下文窗口大小（Max Context）与计划模式（Plan Mode）
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { Checkbox, Chip, Icon, Input, Orb, Segmented, Select, Skeleton } from '$ui';
  import type { Option } from '$ui';
  import { agent, ai } from '$api/endpoints';
  import { newIdempotencyKey } from '$api/client';
  import type { AgentCore, PermissionMode } from '$api/types';
  import type { ReasoningEffort } from '$api/additions';
  import { coreLabel, MODE_META, MODES } from '$lib/ai/agent-sessions.svelte';
  import ContextField from '../ai/ContextField.svelte';
  import EffortField from '../ai/EffortField.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { reportError } from '$lib/errors';
  import { navigate } from '$lib/router.svelte';
  import { resources } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import Composer from '../ai/Composer.svelte';

  let {
    prompt = '',
    pendingInsert = null,
    ontoggleexchange,
  }: {
    prompt?: string;
    pendingInsert?: { seq: number; text: string } | null;
    ontoggleexchange?: () => void;
  } = $props();

  const cores = useResource({ key: 'agent-cores', load: () => agent.cores().then((r) => r.items) });
  const coreAuth = useResource({ key: 'agent.core-auth', load: () => agent.coreAuth().then((r) => r.items) });
  const providers = useResource({ key: 'ai-providers', load: () => ai.providers().then((r) => r.items), subjects: ['ai_providers/'] });

  let core = $state<AgentCore>('native');
  let authMode = $state<'oauth' | 'provider'>('oauth');
  let mode = $state<PermissionMode>('safe');
  let providerId = $state('');
  let modelOverride = $state('');
  let effort = $state<ReasoningEffort>('');
  let maxContext = $state('0');
  let planMode = $state(false);
  let text = $state(untrack(() => prompt));
  let lastInsertSeq = 0;

  $effect(() => {
    if (!pendingInsert || pendingInsert.seq === lastInsertSeq) return;
    lastInsertSeq = pendingInsert.seq;
    const prefix = text.trim() ? `${text.trimEnd()}\n` : '';
    text = `${prefix}${pendingInsert.text} `;
  });

  const isAdmin = $derived(session.role === 'admin');
  const canWriteAgent = $derived(session.can('host.agent_sessions:write'));
  const isExternalCli = $derived(core !== 'native');
  const activeCoreAuth = $derived(coreAuth.data?.find((c) => c.core === core) ?? null);
  const activeProvider = $derived(providers.data?.find((p) => p.provider_id === providerId) ?? null);

  const coreOptions = $derived<Option<AgentCore>[]>(
    (cores.data ?? [{ core: 'native' as const, available: true }]).map((c) => {
      const restricted = c.core !== 'native' && !isAdmin;
      return {
        value: c.core,
        label: coreLabel(c.core),
        disabled: !c.available || restricted,
        hint: restricted ? '外部 CLI 核心仅限管理员使用' : c.available ? undefined : (c.reason ?? '暂不可用'),
      };
    }),
  );

  $effect(() => {
    if (!isAdmin && core !== 'native') core = 'native';
    if (!isAdmin && mode === 'full') mode = 'safe';
  });
  const providerOptions = $derived<Option[]>(
    (providers.data ?? []).map((p) => ({
      value: p.provider_id,
      label: `${p.name} · ${p.model}${p.is_default ? '（默认）' : ''}${p.has_api_key ? '' : '（未设置 Key）'}`,
    })),
  );
  const modelOptions = $derived.by<Option[]>(() => {
    const list = new Set<string>();
    if (activeProvider?.model) list.add(activeProvider.model);
    for (const m of activeProvider?.models ?? []) list.add(m);
    return [{ value: '', label: activeProvider ? `跟随服务默认 (${activeProvider.model})` : '跟随核心默认' }, ...Array.from(list).map((m) => ({ value: m, label: m }))];
  });
  const noProvider = $derived(providers.status === 'ready' && !providers.data?.length);
  const unavailableReason = $derived(cores.data?.find((c) => c.core === core && !c.available)?.reason);
  const needsProvider = $derived(core === 'native' || authMode === 'provider');

  /* 默认选中默认提供方 */
  $effect(() => {
    if (!providerId && providers.data?.length)
      providerId = (providers.data.find((p) => p.is_default) ?? providers.data[0]!).provider_id;
  });

  /* 切换外部 CLI 核心时：若已登录官方账号默认选官方登录，否则若配了自定义服务则默认自定义 Key */
  $effect(() => {
    if (!isExternalCli) return;
    if (activeCoreAuth?.logged_in) authMode = 'oauth';
    else if (providers.data?.length) authMode = 'provider';
  });

  async function start(first: string) {
    try {
      const cfg: Record<string, unknown> = {};
      if (core === 'native') {
        if (providerId) cfg.provider_id = providerId;
        cfg.stream = true;
        cfg.enable_plan_tool = true;
      } else {
        cfg.auth_mode = authMode;
        if (authMode === 'provider' && providerId) {
          cfg.provider_id = providerId;
        }
      }
      if (modelOverride.trim()) cfg.model = modelOverride.trim();
      if (effort) cfg.reasoning_effort = effort;
      const ctxNum = Number.parseInt(maxContext, 10) || 0;
      if (ctxNum > 0) cfg.max_context_tokens = ctxNum;
      if (planMode) cfg.plan_mode = true;

      const s = await agent.create({
        title: first.replace(/\s+/g, ' ').slice(0, 40),
        core,
        permission_mode: mode,
        config: cfg,
      });
      await agent.send(s.session_id, first, newIdempotencyKey());
      resources.invalidate('agent-sessions');
      navigate(`/agent/${encodeURIComponent(s.session_id)}`);
    } catch (err) {
      reportError(err, '没能开始对话');
      throw err;
    }
  }
</script>

<div class="new">
  <header class="hero">
    <div class="hero-orb"><Orb size={58} state="idle" /></div>
    <h2>你好{session.user?.display_name ? `，${session.user.display_name}` : ''}，想让我做点什么？</h2>
    <p>我可以执行服务器命令、读写排查配置、原生管理面板插件，也能通过右侧「交互文件夹」和你双向交换文件。</p>
  </header>

  <section class="opts" aria-label="对话设置">
    <div class="row">
      <span class="lbl">核心</span>
      {#if cores.status === 'loading' && !cores.data}
        <Skeleton width="320px" height={36} />
      {:else}
        <Segmented label="核心" options={coreOptions} bind:value={core} />
      {/if}
    </div>
    {#if unavailableReason}<p class="hint">{unavailableReason}</p>{/if}

    {#if isExternalCli}
      <div class="row">
        <span class="lbl">认证</span>
        <div class="auth-switch">
          <button type="button" class="pill" class:on={authMode === 'oauth'} onclick={() => (authMode = 'oauth')}>
            官方登录态
            {#if activeCoreAuth}
              <Chip size="sm" tone={activeCoreAuth.logged_in ? 'ok' : 'warn'}>
                {activeCoreAuth.logged_in ? '已登录' : '未登录'}
              </Chip>
            {/if}
          </button>
          <button type="button" class="pill" class:on={authMode === 'provider'} onclick={() => (authMode = 'provider')}>
            自定义 API 服务（自备 URL / Key）
          </button>
          {#if authMode === 'oauth' && activeCoreAuth && !activeCoreAuth.logged_in && session.can('host.ai_providers:create')}
            <a class="go-link" href="/settings/ai">去面板登录官方账号 →</a>
          {/if}
        </div>
      </div>
    {/if}

    {#if needsProvider}
      <div class="row">
        <span class="lbl">AI 服务</span>
        {#if noProvider}
          <p class="hint">
            还没有可用的 AI 服务。{#if session.can('host.ai_providers:create')}<a href="/settings/ai">去添加</a>{:else}请联系管理员添加。{/if}
          </p>
        {:else}
          <div class="sel">
            <Select label="AI 服务" hideLabel options={providerOptions} bind:value={providerId} />
          </div>
        {/if}
      </div>
    {/if}

    <div class="row top">
      <span class="lbl">参数</span>
      <div class="params-stack">
        {#if needsProvider && (activeProvider?.models?.length ?? 0) > 0}
          <Select label="模型" options={modelOptions} bind:value={modelOverride} />
        {:else}
          <Input label="模型覆盖（可选）" placeholder={activeProvider ? `默认 ${activeProvider.model}` : '留空使用核心默认模型'} mono bind:value={modelOverride} />
        {/if}
        <EffortField
          label="思考挡位（Effort，可自定义或自动匹配清单）"
          model={modelOverride.trim() || activeProvider?.model || ''}
          bind:value={effort}
        />
        <ContextField
          label="上下文窗口大小（自动识别主流模型）"
          model={modelOverride.trim() || activeProvider?.model || ''}
          bind:value={maxContext}
        />
      </div>
    </div>

    <div class="row">
      <span class="lbl">计划</span>
      <Checkbox label="开启计划模式（先输出只读排查与步骤清单，确认后再动手）" bind:checked={planMode} />
    </div>

    <div class="row top">
      <span class="lbl" id="new-mode-l">权限</span>
      <div class="modes" role="radiogroup" aria-labelledby="new-mode-l">
        {#each MODES as m (m)}
          {@const meta = MODE_META[m]}
          {@const restricted = m === 'full' && !isAdmin}
          <label class="mode" class:on={mode === m} class:off={m === 'custom' || restricted}>
            <input type="radio" name="mode" value={m} bind:group={mode} disabled={m === 'custom' || restricted} />
            <span class="mt">
              {meta.label}
              {#if m === 'safe'}<span class="rec">推荐</span>{/if}
            </span>
            {#if restricted}
              <span class="mn">仅管理员可开启完全授权模式</span>
            {:else if meta.note}
              <span class="mn" class:danger={meta.danger}>{meta.note}</span>
            {/if}
            {#if mode === m}<span class="tick"><Icon name="check" size={16} /></span>{/if}
          </label>
        {/each}
      </div>
    </div>
  </section>

  <div class="compose">
    <Composer
      bind:value={text}
      onsend={start}
      disabled={!canWriteAgent || (needsProvider && noProvider) || !!unavailableReason}
      disabledReason={!canWriteAgent ? '当前角色仅支持只读查看，无法发起 AI 会话' : '先选一个可用的核心或 AI 服务'}
    >
      {#snippet tools()}
        {#if ontoggleexchange}
          <button type="button" class="pill" onclick={ontoggleexchange}>
            <Icon name="folder" size={14} /> 交互文件夹（上传/查看文件）
          </button>
        {/if}
      {/snippet}
    </Composer>
  </div>
</div>

<style>
  .new {
    display: flex;
    flex-direction: column;
    gap: var(--s-5);
    width: min(880px, 100%);
    margin: 0 auto;
    padding: var(--s-6) var(--s-5) var(--s-5);
  }
  .hero {
    display: grid;
    justify-items: center;
    gap: var(--s-2);
    text-align: center;
  }
  .hero-orb {
    margin-bottom: var(--s-1);
    animation: qwq-rise-in var(--dur-3) var(--ease-out);
  }
  h2 {
    margin: 0;
    font-size: var(--fs-2xl);
    font-weight: var(--fw-semibold);
  }
  .hero p {
    margin: 0;
    color: var(--text-2);
  }
  .opts {
    display: grid;
    gap: var(--s-4);
  }
  .row {
    display: flex;
    align-items: center;
    gap: var(--s-4);
    flex-wrap: wrap;
  }
  .lbl {
    width: 58px;
    flex: none;
    padding: 0;
    font-size: var(--fs-sm);
    color: var(--text-2);
  }
  .sel {
    flex: 1;
    min-width: 220px;
  }
  .auth-switch {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface);
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-xs);
    cursor: pointer;
  }
  .pill.on {
    border-color: var(--accent);
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: var(--fw-medium);
  }
  .go-link {
    font-size: var(--fs-xs);
    color: var(--accent-text);
    text-decoration: none;
  }
  .params-stack {
    flex: 1;
    display: grid;
    gap: var(--s-3);
    min-width: 0;
  }
  .hint {
    margin: 0;
    font-size: var(--fs-sm);
    color: var(--text-3);
  }
  .hint a {
    color: var(--accent-text);
  }
  .row.top {
    align-items: start;
  }
  .row.top .lbl {
    padding-top: var(--s-2);
  }
  .modes {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--s-2);
  }
  .mode {
    position: relative;
    display: grid;
    gap: 2px;
    padding: var(--s-3) var(--s-4);
    border-radius: var(--r-md);
    border: 1px solid var(--line);
    background: var(--surface);
    cursor: pointer;
    transition:
      border-color var(--dur-1) var(--ease),
      background var(--dur-1) var(--ease);
  }
  .mode:hover {
    border-color: var(--line-strong);
  }
  .mode.on {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .mode.off {
    cursor: not-allowed;
    opacity: 0.55;
  }
  .mode:has(input:focus-visible) {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .mode input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }
  .mt {
    font-weight: var(--fw-medium);
  }
  .rec {
    margin-left: 6px;
    font-size: var(--fs-xs);
    color: var(--accent-text);
    font-weight: var(--fw-regular);
  }
  .mn {
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .mn.danger {
    color: var(--bad-text);
  }
  .tick {
    position: absolute;
    top: var(--s-3);
    right: var(--s-3);
    color: var(--accent-text);
  }
  .compose {
    margin-top: auto;
  }
  @media (max-width: 860px) {
    .modes {
      grid-template-columns: 1fr;
    }
  }
</style>
