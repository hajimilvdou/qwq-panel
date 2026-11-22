<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置 · AI 服务（SPEC §7 / GAPS 缺口 2，仅管理员）
  ───────────────────────────────────────────────────────────────
  提供方增删改走 operation（args 不含 Key）；API Key 只写：
    PUT    /ai/providers/{id}/api-key   设置 / 替换（机密例外，不进 operation）
    DELETE /ai/providers/{id}/api-key   清除
  界面只知道 has_api_key，永远拿不到 Key 明文。
  测试只回 ok / latency_ms / category，不回显地址与响应体（AGT-03）。
-->
<script lang="ts">
  import { Alert, Button, Card, Checkbox, Chip, ConfirmDialog, Dialog, EmptyState, ErrorState, IconButton, Input, Menu, Skeleton } from '$ui';
  import { ai } from '$api/endpoints';
  import type { AiProvider, AiProviderTestResult } from '$api/additions';
  import { describeError, reportError, type ErrorView } from '$lib/errors';
  import { createIntent, runIntent, type Intent } from '$lib/ops';
  import { useResource } from '$lib/resource.svelte';
  import { toasts } from '$lib/toast.svelte';

  const list = useResource({ key: 'ai.providers', load: () => ai.providers().then((r) => r.items), subjects: ['ai_providers/'] });

  const CATEGORY: Record<NonNullable<AiProviderTestResult['category']>, string> = {
    auth: 'Key 不对或没有权限',
    network: '连不上这个地址',
    denied: '这个地址不在允许的出站范围内',
    '4xx': '服务拒绝了请求',
    '5xx': '服务出错了',
  };

  /* ---------------------------------------------------------------- 新建 / 编辑 */
  let editOpen = $state(false);
  let editing = $state<AiProvider | null>(null);
  let form = $state({ name: '', base_url: '', model: '', is_default: false, api_key: '' });
  let editBusy = $state(false);
  let editErr = $state<ErrorView | null>(null);
  let editIntent: Intent = createIntent();

  function openEdit(p: AiProvider | null) {
    editing = p;
    form = p
      ? { name: p.name, base_url: p.base_url ?? '', model: p.model, is_default: p.is_default, api_key: '' }
      : { name: '', base_url: '', model: '', is_default: !(list.data ?? []).length, api_key: '' };
    editErr = null;
    editIntent = createIntent();
    editOpen = true;
  }

  async function submitEdit(e?: SubmitEvent) {
    e?.preventDefault();
    if (editBusy || !form.name.trim() || !form.base_url.trim() || !form.model.trim()) return;
    editBusy = true;
    editErr = null;
    const body = { name: form.name.trim(), base_url: form.base_url.trim(), model: form.model.trim(), is_default: form.is_default };
    try {
      if (editing) {
        const p = editing;
        await runIntent(editIntent, (key) => ai.updateProvider(p.provider_id, { expected_revision: p.revision!, ...body }, key), {
          label: `修改 AI 服务 ${body.name}`,
        });
      } else {
        const r = await runIntent(editIntent, (key) => ai.createProvider(body, key), { label: `添加 AI 服务 ${body.name}` });
        const created = r.op.result as AiProvider | undefined;
        if (form.api_key && r.kind === 'done' && created?.provider_id) {
          await ai.setKey(created.provider_id, form.api_key, createIntent().key);
        } else if (form.api_key) {
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

  /* ---------------------------------------------------------------- 测试 / 默认 */
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

  /* ---------------------------------------------------------------- 删除 */
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
      await runIntent(removeIntent, (key) => ai.removeProvider(p.provider_id, p.revision!, key), { label: `删除 AI 服务 ${p.name}` });
      void list.refresh();
    } catch (err) {
      const v = describeError(err);
      removeErr = v.code === 'STATE_CONFLICT' ? '它是默认服务，请先把别的服务设为默认' : v.message;
      throw err;
    }
  }

  function menuFor(p: AiProvider) {
    return [
      { label: '编辑', icon: 'settings' as const, onselect: () => openEdit(p) },
      { label: p.has_api_key ? '替换 API Key' : '设置 API Key', icon: 'key' as const, onselect: () => openKey(p) },
      ...(p.has_api_key ? [{ label: '清除 API Key', icon: 'x' as const, onselect: () => clearKey(p) }] : []),
      ...(!p.is_default ? [{ label: '设为默认', icon: 'check' as const, onselect: () => makeDefault(p) }] : []),
      { label: '删除', icon: 'trash' as const, tone: 'danger' as const, onselect: () => openRemove(p) },
    ];
  }
</script>

<Card title="AI 服务" icon="ai" color="indigo" subtitle="内置 AI 助手调用的模型服务（OpenAI 兼容接口）">
  {#snippet actions()}
    <Button variant="primary" size="sm" icon="plus" onclick={() => openEdit(null)}>添加服务</Button>
  {/snippet}

  {#if list.status === 'loading'}
    <Skeleton lines={3} height={56} />
  {:else if list.status === 'error' && !list.data}
    <ErrorState compact message={describeError(list.error).message} requestId={describeError(list.error).requestId} onretry={list.refresh} />
  {:else if !(list.data ?? []).length}
    <EmptyState compact title="还没有 AI 服务" description="添加一个服务，AI 助手才能工作。">
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
              {#if p.is_default}<Chip size="sm" tone="accent" dot={false}>默认</Chip>{/if}
              <Chip size="sm" tone={p.has_api_key ? 'ok' : 'warn'}>{p.has_api_key ? 'Key 已设置' : '未设置 Key'}</Chip>
            </div>
            <div class="small muted">
              <span class="mono">{p.model}</span>
              {#if p.base_url}<span aria-hidden="true"> · </span><span class="mono ellipsis">{p.base_url}</span>{/if}
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

<!-- ---------------------------------------------------------------- 新建 / 编辑 -->
<Dialog bind:open={editOpen} title={editing ? '编辑 AI 服务' : '添加 AI 服务'} onclose={() => (form.api_key = '')}>
  <form id="aip-edit" class="stack" onsubmit={submitEdit} novalidate>
    <Input label="名称" required maxlength={64} autocomplete="off" bind:value={form.name} error={editErr?.fields['/name']} />
    <Input
      label="接口地址"
      hint="OpenAI 兼容的 base URL，例如 https://api.openai.com/v1"
      type="url"
      required
      mono
      autocomplete="off"
      bind:value={form.base_url}
      error={editErr?.fields['/base_url']}
    />
    <Input label="模型" required mono autocomplete="off" bind:value={form.model} error={editErr?.fields['/model']} />
    {#if !editing}
      <Input
        label="API Key"
        hint="可选，也可以之后再设置；保存后不会再显示"
        type="password"
        autocomplete="new-password"
        bind:value={form.api_key}
      />
    {/if}
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
  .stack {
    gap: var(--s-4);
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
    gap: 4px;
    min-width: 0;
  }
  .main > .small {
    display: flex;
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
</style>
