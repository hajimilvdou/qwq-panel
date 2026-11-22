<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  NewSession · 新建会话面板（SPEC §3.3）
  ───────────────────────────────────────────────────────────────
  核心（segmented，不可用的写明原因）→ AI 服务（只读列表，管理在设置）→ 权限模式四选一
  → 第一句话。发送即创建会话、发出消息、进入会话页。
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { Segmented, Select, Skeleton, Icon } from '$ui';
  import type { Option } from '$ui';
  import { agent, ai } from '$api/endpoints';
  import { newIdempotencyKey } from '$api/client';
  import type { AgentCore, PermissionMode } from '$api/types';
  import { coreLabel, MODE_META, MODES } from '$lib/ai/agent-sessions.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { reportError } from '$lib/errors';
  import { navigate } from '$lib/router.svelte';
  import { resources } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import Composer from '../ai/Composer.svelte';

  let { prompt = '' }: { prompt?: string } = $props();

  const cores = useResource({ key: 'agent-cores', load: () => agent.cores().then((r) => r.items) });
  const providers = useResource({ key: 'ai-providers', load: () => ai.providers().then((r) => r.items), subjects: ['ai_providers/'] });

  let core = $state<AgentCore>('native');
  let mode = $state<PermissionMode>('safe');
  let providerId = $state('');
  let text = $state(untrack(() => prompt));

  const coreOptions = $derived<Option<AgentCore>[]>(
    (cores.data ?? [{ core: 'native' as const, available: true }]).map((c) => ({
      value: c.core,
      label: coreLabel(c.core),
      disabled: !c.available,
      hint: c.available ? undefined : (c.reason ?? '暂不可用'),
    })),
  );
  const providerOptions = $derived<Option[]>(
    (providers.data ?? []).map((p) => ({
      value: p.provider_id,
      label: `${p.name} · ${p.model}${p.is_default ? '（默认）' : ''}${p.has_api_key ? '' : '（未设置 Key）'}`,
    })),
  );
  const noProvider = $derived(providers.status === 'ready' && !providers.data?.length);
  const unavailableReason = $derived(cores.data?.find((c) => c.core === core && !c.available)?.reason);

  /* 默认选中默认提供方 */
  $effect(() => {
    if (!providerId && providers.data?.length)
      providerId = (providers.data.find((p) => p.is_default) ?? providers.data[0]!).provider_id;
  });

  async function start(first: string) {
    try {
      const cfg: Record<string, unknown> = providerId ? { provider_id: providerId } : {};
      if (core === 'native') {
        cfg.stream = true;
        cfg.enable_plan_tool = true;
      }
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
    <span class="orb-big" aria-hidden="true"></span>
    <h2>你好{session.user?.display_name ? `，${session.user.display_name}` : ''}，想让我做点什么？</h2>
    <p>我可以查看服务器状态、排查问题，也能在你允许的范围内动手处理。</p>
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

    <div class="row top">
      <span class="lbl" id="new-mode-l">权限</span>
      <div class="modes" role="radiogroup" aria-labelledby="new-mode-l">
      {#each MODES as m (m)}
        {@const meta = MODE_META[m]}
        <label class="mode" class:on={mode === m} class:off={m === 'custom'}>
          <input type="radio" name="mode" value={m} bind:group={mode} disabled={m === 'custom'} />
          <span class="mt">
            {meta.label}
            {#if m === 'safe'}<span class="rec">推荐</span>{/if}
          </span>
          {#if meta.note}<span class="mn" class:danger={meta.danger}>{meta.note}</span>{/if}
          {#if mode === m}<span class="tick"><Icon name="check" size={16} /></span>{/if}
        </label>
      {/each}
      </div>
    </div>
  </section>

  <div class="compose">
    <Composer bind:value={text} onsend={start} disabled={(core === 'native' && noProvider) || !!unavailableReason} disabledReason="先选一个可用的核心或 AI 服务" />
  </div>
</div>

<style>
  .new {
    display: flex;
    flex-direction: column;
    gap: var(--s-6);
    width: min(860px, 100%);
    margin: 0 auto;
    padding: var(--s-7) var(--s-5) var(--s-5);
  }
  .hero {
    display: grid;
    justify-items: center;
    gap: var(--s-2);
    text-align: center;
  }
  .orb-big {
    width: 60px;
    height: 60px;
    margin-bottom: var(--s-2);
    border-radius: 50%;
    background:
      radial-gradient(circle at 32% 28%, rgb(255 255 255 / 0.55), transparent 44%),
      var(--ai-gradient);
    box-shadow: 0 10px 26px color-mix(in oklab, var(--ai-1) 28%, transparent);
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
    width: 64px;
    flex: none;
    padding: 0;
    font-size: var(--fs-sm);
    color: var(--text-2);
  }
  .sel {
    flex: 1;
    min-width: 220px;
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
    padding-top: var(--s-3);
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
