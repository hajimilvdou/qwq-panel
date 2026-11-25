<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置 · AI 服务与外部 CLI 官方登录（SPEC §7 / GAPS 缺口 2 / ADR-0028，仅管理员）
  ───────────────────────────────────────────────────────────────────────────────
  1. AI 模型服务（自定义 URL + API Key）：
     - 支持 OpenAI 兼容 & Anthropic 兼容两种协议
     - 支持填写 URL + Key 后一键「拉取模型列表」并勾选默认模型
     - 支持配置默认思考深度（Reasoning Effort）与默认上下文窗口大小
     - API Key 走独立机密只写路由（PUT/DELETE /ai/providers/{id}/api-key）
  2. 外部 CLI Agent 官方登录（Codex / Claude Code / OpenCode）：
     - 自动检测 CLI 安装状态与独立隔离凭据目录（<DataDir>/agent-homes/<core>）登录态
     - 支持「官方设备码 / OAuth 登录」（面板内提取授权链接与设备码）与「粘贴 Setup Token / Auth JSON」
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Alert, Button, Card, Checkbox, Chip, ConfirmDialog, CopyButton, Dialog, EmptyState, ErrorState, IconButton, Input, Menu, Select, Skeleton } from '$ui';
  import { safeExternalHref } from '$ui/safe-url';
  import { agent, ai } from '$api/endpoints';
  import type {
    AgentCoreAuthStatus,
    AiProvider,
    AiProviderKind,
    AiProviderTestResult,
    ExternalCliCore,
    ReasoningEffort,
  } from '$api/additions';
  import { effortLabel, formatContextSize } from '$lib/ai/agent-sessions.svelte';
  import ContextField from '../ai/ContextField.svelte';
  import EffortField from '../ai/EffortField.svelte';
  import { describeError, reportError, type ErrorView } from '$lib/errors';
  import { createIntent, runIntent, type Intent } from '$lib/ops';
  import { useResource } from '$lib/resource.svelte';
  import { toasts } from '$lib/toast.svelte';

  const list = useResource({ key: 'ai.providers', load: () => ai.providers().then((r) => r.items), subjects: ['ai_providers/'] });
  const coreAuth = useResource({ key: 'agent.core-auth', load: () => agent.coreAuth().then((r) => r.items) });

  const CATEGORY: Record<NonNullable<AiProviderTestResult['category']>, string> = {
    auth: 'Key 不对或没有权限',
    network: '连不上这个地址',
    denied: '这个地址不在允许的出站范围内',
    '4xx': '服务拒绝了请求',
    '5xx': '服务出错了',
  };

  const KIND_OPTIONS = [
    { value: 'openai_compatible', label: 'OpenAI 兼容接口（/chat/completions）' },
    { value: 'anthropic_compatible', label: 'Anthropic 兼容接口（/v1/messages · Claude）' },
  ];

  /* ---------------------------------------------------------------- 新建 / 编辑 AI 服务 */
  let editOpen = $state(false);
  let editing = $state<AiProvider | null>(null);
  let form = $state({
    name: '',
    kind: 'openai_compatible' as AiProviderKind,
    base_url: '',
    model: '',
    models: [] as string[],
    reasoning_effort: '' as ReasoningEffort,
    max_context_tokens: '0',
    is_default: false,
    api_key: '',
  });
  let editBusy = $state(false);
  let editErr = $state<ErrorView | null>(null);
  let editIntent: Intent = createIntent();
  let fetchingModels = $state(false);
  let fetchNote = $state('');

  function openEdit(p: AiProvider | null) {
    editing = p;
    fetchNote = '';
    form = p
      ? {
          name: p.name,
          kind: p.kind ?? 'openai_compatible',
          base_url: p.base_url ?? '',
          model: p.model,
          models: [...(p.models ?? [])],
          reasoning_effort: (p.reasoning_effort ?? '') as ReasoningEffort,
          max_context_tokens: String(p.max_context_tokens ?? 0),
          is_default: p.is_default,
          api_key: '',
        }
      : {
          name: '',
          kind: 'openai_compatible',
          base_url: '',
          model: '',
          models: [],
          reasoning_effort: '',
          max_context_tokens: '0',
          is_default: !(list.data ?? []).length,
          api_key: '',
        };
    editErr = null;
    editIntent = createIntent();
    editOpen = true;
  }

  async function fetchModelList() {
    if (fetchingModels) return;
    if (!form.base_url.trim() && !editing) return;
    fetchingModels = true;
    fetchNote = '';
    try {
      const res = await ai.fetchModels({
        provider_id: editing && !form.api_key.trim() && form.base_url.trim() === (editing.base_url ?? '') ? editing.provider_id : undefined,
        kind: form.kind,
        base_url: form.base_url.trim(),
        api_key: form.api_key.trim() || undefined,
      });
      if (!res.ok) {
        fetchNote = `获取模型失败：${res.category ? CATEGORY[res.category] : '原因未知'}`;
        return;
      }
      form.models = res.models;
      if (res.models.length > 0 && !form.model.trim()) {
        form.model = res.models[0]!;
      }
      fetchNote = res.models.length
        ? `已拉取 ${res.models.length} 个可用模型${res.latency_ms !== undefined ? `（${res.latency_ms} ms）` : ''}`
        : '连接成功，但接口返回的模型列表为空，请手动输入模型名称';
    } catch (err) {
      fetchNote = `获取模型失败：${describeError(err).message}`;
    } finally {
      fetchingModels = false;
    }
  }

  async function submitEdit(e?: SubmitEvent) {
    e?.preventDefault();
    if (editBusy || !form.name.trim() || !form.base_url.trim() || !form.model.trim()) return;
    editBusy = true;
    editErr = null;
    const maxCtx = Math.max(0, Number.parseInt(form.max_context_tokens, 10) || 0);
    const mergedModels = form.models.includes(form.model.trim())
      ? form.models
      : [form.model.trim(), ...form.models].slice(0, 500);
    const body = {
      name: form.name.trim(),
      kind: form.kind,
      base_url: form.base_url.trim(),
      model: form.model.trim(),
      models: mergedModels,
      reasoning_effort: form.reasoning_effort,
      max_context_tokens: maxCtx,
      is_default: form.is_default,
    };
    try {
      if (editing) {
        const p = editing;
        await runIntent(editIntent, (key) => ai.updateProvider(p.provider_id, { expected_revision: p.revision!, ...body }, key), {
          label: `修改 AI 服务 ${body.name}`,
        });
        if (form.api_key.trim()) {
          await ai.setKey(p.provider_id, form.api_key.trim(), createIntent().key);
        }
      } else {
        const r = await runIntent(editIntent, (key) => ai.createProvider(body, key), { label: `添加 AI 服务 ${body.name}` });
        const created = r.op.result as AiProvider | undefined;
        if (form.api_key.trim() && r.kind === 'done' && created?.provider_id) {
          await ai.setKey(created.provider_id, form.api_key.trim(), createIntent().key);
        } else if (form.api_key.trim()) {
          toasts.info('服务创建完成后，请在它的菜单里设置 API Key');
        }
      }
      form.api_key = '';
      editOpen = false;
      void list.refresh();
    } catch (err) {
      editErr = describeError(err);
    } finally {
      editBusy = false;
    }
  }

  /* ---------------------------------------------------------------- API Key（只写） */
  let keyTarget = $state<AiProvider | null>(null);
  let keyValue = $state('');
  let keyBusy = $state(false);
  let keyErr = $state('');
  let keyIntent: Intent = createIntent();

  function openKey(p: AiProvider) {
    keyTarget = p;
    keyValue = '';
    keyErr = '';
    keyIntent = createIntent();
  }
  function closeKey() {
    keyTarget = null;
    keyValue = '';
  }

  async function submitKey() {
    const p = keyTarget;
    if (!p || !keyValue.trim() || keyBusy) return;
    keyBusy = true;
    keyErr = '';
    try {
      await ai.setKey(p.provider_id, keyValue.trim(), keyIntent.key);
      closeKey();
      toasts.success(`已保存「${p.name}」的 API Key`);
      void list.refresh();
    } catch (err) {
      keyErr = describeError(err).message;
    } finally {
      keyBusy = false;
    }
  }

  async function clearKey(p: AiProvider) {
    try {
      await ai.clearKey(p.provider_id, createIntent().key);
      toasts.success(`已清除「${p.name}」的 API Key`);
      void list.refresh();
    } catch (err) {
      reportError(err, '清除失败');
    }
  }

  /* ---------------------------------------------------------------- 测试 / 默认 / 删除 */
  let testing = $state<Record<string, boolean>>({});
  let results = $state<Record<string, AiProviderTestResult>>({});

  async function test(p: AiProvider) {
    testing[p.provider_id] = true;
    try {
      results[p.provider_id] = await ai.testProvider(p.provider_id, createIntent().key);
    } catch (err) {
      reportError(err, '测试失败');
    } finally {
      testing[p.provider_id] = false;
    }
  }

  async function makeDefault(p: AiProvider) {
    try {
      await runIntent(createIntent(), (key) => ai.updateProvider(p.provider_id, { expected_revision: p.revision!, is_default: true }, key), {
        label: `把 ${p.name} 设为默认`,
      });
      void list.refresh();
    } catch (err) {
      reportError(err, '设置默认失败');
    }
  }

  let removeTarget = $state<AiProvider | null>(null);
  let removeOpen = $state(false);
  let removeErr = $state('');
  let removeIntent: Intent = createIntent();

  function openRemove(p: AiProvider) {
    removeTarget = p;
    removeErr = '';
    removeIntent = createIntent();
    removeOpen = true;
  }
  async function submitRemove() {
    const p = removeTarget!;
    try {
      await runIntent(removeIntent, (key) => ai.removeProvider(p.provider_id, p.revision!, key), { label: `删除 AI 服务 ${p.name}`, preConfirmed: true });
      void list.refresh();
    } catch (err) {
      const v = describeError(err);
      removeErr = v.code === 'STATE_CONFLICT' ? '它是默认服务，请先把别的服务设为默认' : v.message;
      throw err;
    }
  }

  function menuFor(p: AiProvider) {
    return [
      { label: '编辑与拉取模型', icon: 'settings' as const, onselect: () => openEdit(p) },
      { label: p.has_api_key ? '替换 API Key' : '设置 API Key', icon: 'key' as const, onselect: () => openKey(p) },
      ...(p.has_api_key ? [{ label: '清除 API Key', icon: 'x' as const, onselect: () => clearKey(p) }] : []),
      ...(!p.is_default ? [{ label: '设为默认', icon: 'check' as const, onselect: () => makeDefault(p) }] : []),
      { label: '删除', icon: 'trash' as const, tone: 'danger' as const, onselect: () => openRemove(p) },
    ];
  }

  /* ---------------------------------------------------------------- 外部 CLI 官方登录 */
  let loginTarget = $state<ExternalCliCore | null>(null);
  let loginMode = $state<'device' | 'token'>('device');
  let loginToken = $state('');
  let loginBusy = $state(false);
  let loginErr = $state('');
  let pollTimer: number | null = null;

  const activeCoreStatus = $derived<AgentCoreAuthStatus | null>(
    loginTarget ? (coreAuth.data?.find((c) => c.core === loginTarget) ?? null) : null,
  );

  function stopPoll() {
    if (pollTimer !== null) {
      window.clearInterval(pollTimer);
      pollTimer = null;
    }
  }
  onDestroy(stopPoll);

  $effect(() => {
    const hasPending = (coreAuth.data ?? []).some((c) => c.active_login?.state === 'pending');
    if (hasPending && pollTimer === null) {
      pollTimer = window.setInterval(() => void coreAuth.refresh(), 3000);
    } else if (!hasPending && pollTimer !== null) {
      stopPoll();
    }
  });

  function openCoreLogin(c: AgentCoreAuthStatus) {
    loginTarget = c.core;
    loginMode = c.installed ? 'device' : 'token';
    loginToken = '';
    loginErr = '';
  }

  function closeCoreLogin() {
    loginTarget = null;
    loginToken = '';
    loginErr = '';
  }

  async function triggerCoreLogin() {
    if (!loginTarget || loginBusy) return;
    if (loginMode === 'token' && !loginToken.trim()) return;
    loginBusy = true;
    loginErr = '';
    try {
      const st = await agent.startCoreLogin(loginTarget, {
        mode: loginMode,
        token: loginMode === 'token' ? loginToken.trim() : undefined,
      });
      await coreAuth.refresh();
      if (loginMode === 'token' && st.logged_in) {
        toasts.success(`${st.display_name} 凭据已导入并生效`);
        closeCoreLogin();
      } else {
        toasts.info(`已启动 ${st.display_name} 官方登录流程，请按下方指引完成授权`);
      }
    } catch (err) {
      loginErr = describeError(err).message;
    } finally {
      loginBusy = false;
    }
  }

  async function logoutCore(c: AgentCoreAuthStatus) {
    try {
      await agent.logoutCore(c.core);
      toasts.success(`已清除 ${c.display_name} 的官方登录态`);
      await coreAuth.refresh();
    } catch (err) {
      reportError(err, '退出登录失败');
    }
  }
</script>

<div class="sections">
  <!-- 卡片 1：自定义 URL + API Key 模型服务 -->
  <Card title="AI 模型服务（自备 URL 与 Key）" icon="ai" color="indigo" subtitle="支持 OpenAI 兼容与 Anthropic 兼容接口；内置核心与外部 CLI 均可直接调用">
    {#snippet actions()}
      <Button variant="primary" size="sm" icon="plus" onclick={() => openEdit(null)}>添加服务</Button>
    {/snippet}

    {#if list.status === 'loading'}
      <Skeleton lines={3} height={56} />
    {:else if list.status === 'error' && !list.data}
      <ErrorState compact message={describeError(list.error).message} requestId={describeError(list.error).requestId} onretry={list.refresh} />
    {:else if !(list.data ?? []).length}
      <EmptyState compact title="还没有配置 AI 服务" description="填写中转或官方 URL 与 API Key，可自动拉取可用模型并设置思考挡位与上下文大小。">
        {#snippet action()}<Button variant="soft" icon="plus" onclick={() => openEdit(null)}>添加服务</Button>{/snippet}
      </EmptyState>
    {:else}
      <ul class="providers">
        {#each list.data ?? [] as p (p.provider_id)}
          {@const r = results[p.provider_id]}
          <li>
            <div class="main">
              <div class="title">
                <span class="strong">{p.name}</span>
                <Chip size="sm" tone="neutral">{p.kind === 'anthropic_compatible' ? 'Anthropic' : 'OpenAI'}</Chip>
                {#if p.is_default}<Chip size="sm" tone="accent" dot={false}>默认</Chip>{/if}
                <Chip size="sm" tone={p.has_api_key ? 'ok' : 'warn'}>{p.has_api_key ? 'Key 已设置' : '未设置 Key'}</Chip>
              </div>
              <div class="small muted meta-line">
                <span class="mono">{p.model}</span>
                {#if (p.models?.length ?? 0) > 1}<span>· 共 {p.models?.length} 个模型</span>{/if}
                <span>· 思考：{effortLabel(p.reasoning_effort)}</span>
                <span>· 上下文：{formatContextSize(p.max_context_tokens, p.model)}</span>
                {#if p.base_url}<span>·</span><span class="mono ellipsis">{p.base_url}</span>{/if}
              </div>
              {#if r}
                <p class="small result" class:ok={r.ok} role="status">
                  {r.ok ? `连接正常${r.latency_ms !== undefined ? `，响应 ${r.latency_ms} ms` : ''}` : `连接失败：${r.category ? CATEGORY[r.category] : '原因未知'}`}
                </p>
              {/if}
            </div>
            <div class="ops">
              <Button variant="soft" size="sm" loading={testing[p.provider_id]} onclick={() => test(p)}>测试</Button>
              <Menu label="{p.name} 的操作" items={menuFor(p)}>
                {#snippet trigger(t)}<IconButton icon="more" label="{p.name} 的操作" size="sm" {...t} />{/snippet}
              </Menu>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </Card>

  <!-- 卡片 2：外部 CLI Agent 官方登录管理 -->
  <Card title="外部 CLI Agent 官方登录" icon="shield" color="teal" subtitle="Codex / Claude Code / OpenCode 独立隔离凭据目录，支持官方设备码 OAuth 登录或粘贴 Setup Token；若不走官方登录，也可在新建会话时选择上方的自定义 API 服务">
    {#snippet actions()}
      <Button variant="plain" size="sm" onclick={() => void coreAuth.refresh()}>刷新状态</Button>
    {/snippet}

    {#if coreAuth.status === 'loading' && !coreAuth.data}
      <Skeleton lines={3} height={56} />
    {:else if coreAuth.status === 'error' && !coreAuth.data}
      <ErrorState compact message={describeError(coreAuth.error).message} onretry={coreAuth.refresh} />
    {:else}
      <ul class="providers">
        {#each coreAuth.data ?? [] as c (c.core)}
          <li>
            <div class="main">
              <div class="title">
                <span class="strong">{c.display_name}</span>
                <Chip size="sm" tone={c.installed ? 'ok' : 'neutral'}>{c.installed ? `已安装 (${c.binary})` : '未安装'}</Chip>
                <Chip size="sm" tone={c.logged_in ? 'ok' : c.active_login?.state === 'pending' ? 'accent' : 'warn'}>
                  {c.logged_in ? (c.auth_method === 'token' ? '已登录 (Token)' : '已登录 (官方 OAuth)') : c.active_login?.state === 'pending' ? '等待浏览器授权…' : '未登录官方账号'}
                </Chip>
              </div>
              {#if !c.installed}
                <div class="small muted meta-line">
                  <span>安装命令：</span>
                  <code class="mono">{c.install_hint}</code>
                  <CopyButton text={c.install_hint} label="复制安装命令" />
                </div>
              {:else if c.active_login?.state === 'pending'}
                <p class="small result ok">正在等待授权完成，点击右侧「查看授权码」继续。</p>
              {:else}
                <p class="small muted meta-line">
                  {c.logged_in ? '面板内新建该核心会话时可直接勾选「使用官方登录态」。' : '支持在面板内直接发起官方 OAuth 登录，或改为绑定上方自定义 API 服务。'}
                </p>
              {/if}
            </div>
            <div class="ops">
              <Button variant={c.logged_in ? 'soft' : 'primary'} size="sm" onclick={() => openCoreLogin(c)}>
                {c.active_login?.state === 'pending' ? '查看授权码' : c.logged_in ? '重新登录' : '官方登录'}
              </Button>
              {#if c.logged_in || c.active_login?.state === 'pending'}
                <Button variant="plain" size="sm" onclick={() => void logoutCore(c)}>退出</Button>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </Card>
</div>

<!-- ---------------------------------------------------------------- 新建 / 编辑 AI 服务 -->
<Dialog bind:open={editOpen} title={editing ? '编辑 AI 服务' : '添加 AI 服务'} size="md" onclose={() => (form.api_key = '')}>
  <form id="aip-edit" class="stack" onsubmit={submitEdit} novalidate>
    <div class="grid-2">
      <Input label="名称" required maxlength={64} autocomplete="off" bind:value={form.name} error={editErr?.fields['/name']} />
      <Select label="接口协议" options={KIND_OPTIONS} bind:value={form.kind} />
    </div>
    <Input
      label="接口地址（Base URL）"
      hint={form.kind === 'anthropic_compatible' ? '例如 https://api.anthropic.com 或 Claude 中转地址' : '例如 https://api.openai.com/v1 或 OpenAI 兼容中转地址'}
      type="url"
      required
      mono
      autocomplete="off"
      bind:value={form.base_url}
      error={editErr?.fields['/base_url']}
    />
    <Input
      label={editing ? 'API Key（留空保持不变）' : 'API Key'}
      hint="加密保存、永不回显；填写后可立即点下方「获取模型」自动拉取列表"
      type="password"
      autocomplete="new-password"
      bind:value={form.api_key}
    />

    <div class="model-row">
      <div class="model-in">
        <Input label="默认模型" required mono autocomplete="off" bind:value={form.model} error={editErr?.fields['/model']} />
      </div>
      <div class="model-btn">
        <Button
          variant="soft"
          loading={fetchingModels}
          disabled={!form.base_url.trim()}
          onclick={() => void fetchModelList()}
        >
          获取模型
        </Button>
      </div>
    </div>

    {#if fetchNote}
      <p class="small muted fetch-note" role="status">{fetchNote}</p>
    {/if}

    {#if form.models.length > 0}
      <div class="model-picker">
        <span class="small muted">已获取的模型（点击设为默认，全部模型都会保存供会话内快速切换）：</span>
        <div class="chips">
          {#each form.models.slice(0, 40) as m (m)}
            <button type="button" class="m-chip" class:on={form.model === m} onclick={() => (form.model = m)}>{m}</button>
          {/each}
        </div>
      </div>
    {/if}

    <EffortField
      label="默认思考挡位（Effort，可自由填写或点选）"
      model={form.model}
      error={editErr?.fields['/reasoning_effort']}
      bind:value={form.reasoning_effort}
    />

    <ContextField
      label="默认上下文窗口大小（自动识别模型）"
      model={form.model}
      error={editErr?.fields['/max_context_tokens']}
      bind:value={form.max_context_tokens}
    />

    <Checkbox label="设为默认服务" bind:checked={form.is_default} disabled={editing?.is_default} />
    {#if editErr && !Object.keys(editErr.fields).length}<Alert>{editErr.message}</Alert>{/if}
  </form>
  {#snippet footer()}
    <Button variant="plain" onclick={() => (editOpen = false)}>取消</Button>
    <Button
      type="submit"
      form="aip-edit"
      variant="primary"
      loading={editBusy}
      disabled={!form.name.trim() || !form.base_url.trim() || !form.model.trim()}
    >
      {editing ? '保存' : '添加'}
    </Button>
  {/snippet}
</Dialog>

<!-- ---------------------------------------------------------------- 外部 CLI 官方登录对话框 -->
<Dialog
  open={!!loginTarget}
  title={activeCoreStatus ? `${activeCoreStatus.display_name} 官方登录` : '官方登录'}
  description="凭据仅保存在当前面板的独立隔离目录（0700），不会读取或污染宿主机 /root 凭据。"
  size="md"
  onclose={closeCoreLogin}
>
  {#if activeCoreStatus}
    <div class="stack">
      <div class="mode-tabs">
        <button type="button" class="m-chip" class:on={loginMode === 'device'} onclick={() => (loginMode = 'device')}>
          方式一：官方设备码 / OAuth 登录
        </button>
        <button type="button" class="m-chip" class:on={loginMode === 'token'} onclick={() => (loginMode = 'token')}>
          方式二：粘贴 Setup Token / Auth JSON
        </button>
      </div>

      {#if loginMode === 'device'}
        {#if !activeCoreStatus.installed}
          <Alert>
            当前服务器尚未安装 <code>{activeCoreStatus.binary}</code>。请先在终端运行：<code>{activeCoreStatus.install_hint}</code>，或改用「方式二」预先导入凭据。
          </Alert>
        {:else}
          <p class="small muted">
            点击下方「发起官方登录」后，面板会自动在后台拉起 <code>{activeCoreStatus.binary}</code> 官方登录流程并提取浏览器授权链接与一次性设备码（无需在服务器安装桌面浏览器）。
          </p>
        {/if}

        {#if activeCoreStatus.active_login}
          {@const al = activeCoreStatus.active_login}
          <div class="login-box">
            <div class="title">
              <Chip size="sm" tone={al.state === 'succeeded' ? 'ok' : al.state === 'pending' ? 'accent' : 'bad'}>
                {al.state === 'pending' ? '等待浏览器授权' : al.state === 'succeeded' ? '登录成功' : al.state === 'expired' ? '已超时' : '未完成'}
              </Chip>
              <span class="small">{al.message}</span>
            </div>
            {#if al.verification_url}
              {@const verifyHref = safeExternalHref(al.verification_url)}
              {#if verifyHref}
                <div class="auth-row">
                  <a class="auth-url" href={verifyHref} target="_blank" rel="noopener noreferrer">{verifyHref}</a>
                  <CopyButton text={verifyHref} label="复制链接" />
                </div>
              {/if}
            {/if}
            {#if al.user_code}
              <div class="auth-row">
                <span class="small muted">一次性设备码：</span>
                <code class="device-code">{al.user_code}</code>
                <CopyButton text={al.user_code} label="复制设备码" />
              </div>
            {/if}
            {#if al.output_tail?.length}
              <pre class="login-log">{al.output_tail.join('\n')}</pre>
            {/if}
          </div>
        {/if}
      {:else}
        <p class="small muted">
          适用于无头 VPS 无法自动回调 OAuth 时：在本地电脑执行 <code>claude setup-token</code> 或复制已登录的 <code>auth.json</code> / <code>.credentials.json</code> 粘贴到下方（以 0600 加密权限落盘，永不回显）。
        </p>
        <textarea
          class="tok-area"
          rows="5"
          placeholder="粘贴 OAuth Setup Token（如 sk-ant-oat01-...）或完整 auth.json 内容…"
          bind:value={loginToken}
        ></textarea>
      {/if}

      {#if loginErr}<Alert>{loginErr}</Alert>{/if}
    </div>
  {/if}
  {#snippet footer()}
    <Button variant="plain" onclick={closeCoreLogin}>关闭</Button>
    <Button
      variant="primary"
      loading={loginBusy}
      disabled={(loginMode === 'device' && !activeCoreStatus?.installed) || (loginMode === 'token' && !loginToken.trim())}
      onclick={() => void triggerCoreLogin()}
    >
      {loginMode === 'device' ? '发起官方登录' : '导入并保存凭据'}
    </Button>
  {/snippet}
</Dialog>

<!-- ---------------------------------------------------------------- API Key -->
<Dialog
  open={!!keyTarget}
  title={keyTarget?.has_api_key ? '替换 API Key' : '设置 API Key'}
  description="Key 加密保存，只用于调用这个服务；保存后任何人都看不到明文。"
  size="sm"
  onclose={closeKey}
>
  <form
    id="aip-key"
    class="stack"
    onsubmit={(e) => {
      e.preventDefault();
      void submitKey();
    }}
  >
    <Input label="API Key" type="password" autocomplete="new-password" required bind:value={keyValue} />
    {#if keyErr}<Alert>{keyErr}</Alert>{/if}
  </form>
  {#snippet footer()}
    <Button variant="plain" onclick={closeKey}>取消</Button>
    <Button type="submit" form="aip-key" variant="primary" loading={keyBusy} disabled={!keyValue.trim()}>保存</Button>
  {/snippet}
</Dialog>

<!-- ---------------------------------------------------------------- 删除 -->
<ConfirmDialog
  bind:open={removeOpen}
  title="删除 AI 服务"
  tone="danger"
  confirmLabel="删除"
  warning="使用它的 AI 会话将无法继续，已保存的 API Key 也会一并删除。"
  confirmText={removeTarget?.name}
  errorText={removeErr}
  onconfirm={submitRemove}
/>

<style>
  .sections {
    display: grid;
    gap: var(--s-5);
  }
  .stack {
    display: grid;
    gap: var(--s-4);
  }
  .grid-2 {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--s-3);
  }
  .providers {
    display: flex;
    flex-direction: column;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  li {
    display: flex;
    align-items: center;
    gap: var(--s-4);
    padding: var(--s-4) 0;
  }
  li + li {
    border-top: 1px solid var(--line);
  }
  .main {
    display: flex;
    flex: 1;
    flex-direction: column;
    gap: 5px;
    min-width: 0;
  }
  .meta-line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin: 0;
    min-width: 0;
  }
  .title {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .result {
    margin: 0;
    color: var(--bad-text);
  }
  .result.ok {
    color: var(--ok-text);
  }
  .ops {
    display: flex;
    flex: none;
    align-items: center;
    gap: 6px;
  }
  .model-row {
    display: flex;
    align-items: flex-end;
    gap: var(--s-2);
  }
  .model-in {
    flex: 1;
    min-width: 0;
  }
  .model-btn {
    flex: none;
  }
  .fetch-note {
    margin: -6px 0 0;
  }
  .model-picker {
    display: grid;
    gap: 6px;
  }
  .chips,
  .mode-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .chips {
    max-height: 120px;
    overflow-y: auto;
  }
  .m-chip {
    padding: 4px 10px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface-2);
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-xs);
    cursor: pointer;
  }
  .m-chip.on {
    border-color: var(--accent);
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: var(--fw-medium);
  }
  .login-box {
    display: grid;
    gap: 10px;
    padding: 12px;
    border-radius: var(--r-md);
    border: 1px solid var(--line);
    background: var(--surface-2);
  }
  .auth-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .auth-url {
    color: var(--accent-text);
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    word-break: break-all;
  }
  .device-code {
    padding: 4px 12px;
    border-radius: var(--r-sm);
    background: var(--surface);
    border: 1px solid var(--accent);
    font-family: var(--font-mono);
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
    letter-spacing: 0.08em;
    color: var(--text);
  }
  .login-log {
    margin: 0;
    padding: 8px 10px;
    border-radius: var(--r-sm);
    background: var(--surface);
    border: 1px solid var(--line);
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-3);
    max-height: 120px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .tok-area {
    width: 100%;
    padding: 10px 12px;
    border-radius: var(--r-md);
    border: 1px solid var(--line);
    background: var(--surface-2);
    color: var(--text);
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
  }
  @media (max-width: 680px) {
    .grid-2 {
      grid-template-columns: 1fr;
    }
  }
</style>
