<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ConfigTab · 插件设置（SPEC §3.4 / §8 编辑冲突）
  ───────────────────────────────────────────────────────────────
  GET config-schema + GET config → SchemaForm；PUT /config（expected_revision）
  · 密文字段显示"已设置 · 替换"
  · x-qwq-hot-apply=false：提示保存后需重启，保存成功给"立即重启"
  · 冲突：REVISION_CONFLICT，或编辑期间 plugin.config_revision 变了（别处保存）
    → 顶部条"已在别处修改"，按钮"重新加载"，不静默覆盖
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { Alert, Button, Card, EmptyState, ErrorState, SchemaForm, Skeleton } from '$ui';
  import { draftOf, fieldsOf, hotApply, initialValues, toPayload, validate, type FormValues, type SchemaField } from '$ui';
  import { plugins } from '$api/endpoints';
  import type { Plugin, PluginConfig } from '$api/types';
  import { registerDraft, takeDraft } from '$lib/drafts';
  import { describeError, type ErrorView } from '$lib/errors';
  import { createIntent, type Intent } from '$lib/ops';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';

  interface Props {
    plugin: Plugin;
    onrestart: () => void;
  }
  let { plugin, onrestart }: Props = $props();

  const pid = untrack(() => plugin.plugin_id);
  const canEdit = $derived(session.can('host.plugins:config'));

  let status = $state<'loading' | 'ready' | 'error'>('loading');
  let loadErr = $state<unknown>(null);
  let schema = $state<Record<string, unknown>>({});
  let fields = $state<SchemaField[]>([]);
  let values = $state<FormValues>({});
  let config = $state<PluginConfig | null>(null);
  let errors = $state<Record<string, string>>({});
  let saveErr = $state<ErrorView | null>(null);
  let saving = $state(false);
  let needsRestart = $state(false);
  let intent: Intent = createIntent();
  /* 本表单见过的配置版本（加载的 + 自己保存的）：插件快照落后时不误报冲突 */
  let known = new Set<string>();

  async function load() {
    status = 'loading';
    saveErr = null;
    errors = {};
    try {
      const [s, c] = await Promise.all([plugins.configSchema(pid), plugins.getConfig(pid)]);
      schema = s;
      fields = fieldsOf(s);
      config = c;
      known = new Set([c.revision]);
      const draft = takeDraft<Record<string, unknown>>(`plugin-config:${pid}`);
      values = { ...initialValues(fields, c.config), ...(draft as FormValues | null) };
      intent = createIntent();
      status = 'ready';
    } catch (err) {
      loadErr = err;
      status = 'error';
    }
  }
  void load();

  $effect(() => registerDraft(`plugin-config:${pid}`, () => draftOf(fields, values)));

  /* 编辑期间别处保存过：插件快照出现了本表单没见过的 config_revision */
  const conflict = $derived(
    saveErr?.code === 'REVISION_CONFLICT' ||
      (status === 'ready' && !!config && !!plugin.config_revision && !known.has(plugin.config_revision)),
  );
  const hot = $derived(hotApply(schema));

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!config || saving || conflict) return;
    errors = validate(fields, values);
    if (Object.keys(errors).length) return;
    saving = true;
    saveErr = null;
    try {
      const next = await plugins.putConfig(pid, toPayload(fields, values), config.revision, intent.key);
      config = next;
      known.add(next.revision);
      values = initialValues(fields, next.config);
      intent = createIntent();
      needsRestart = !hot;
      toasts.success(hot ? '设置已保存并生效' : '设置已保存，重启后生效');
    } catch (err) {
      saveErr = describeError(err);
      errors = { ...saveErr.fields };
    } finally {
      saving = false;
    }
  }
</script>

<Card title="设置" icon="settings" color="slate">
  {#if status === 'loading'}
    <Skeleton lines={4} height={36} />
  {:else if status === 'error'}
    {@const v = describeError(loadErr)}
    {#if v.code === 'NOT_FOUND'}
      <EmptyState compact title="这个应用没有可调的设置" />
    {:else}
      <ErrorState compact message={v.message} requestId={v.requestId} onretry={load} />
    {/if}
  {:else if !fields.length}
    <EmptyState compact title="这个应用没有可调的设置" />
  {:else}
    <form class="stack" onsubmit={save} novalidate>
      {#if conflict}
        <Alert tone="warn" title="设置已在别处修改">
          为避免覆盖别人的改动，请先重新加载。
          {#snippet actions()}<Button size="sm" variant="soft" icon="refresh" onclick={load}>重新加载</Button>{/snippet}
        </Alert>
      {/if}
      {#if !hot}<Alert tone="info">修改这些设置后需要重启应用才会生效。</Alert>{/if}
      {#if needsRestart}
        <Alert tone="warn" title="新设置还没生效">
          {#snippet actions()}<Button size="sm" variant="soft" icon="refresh" onclick={() => ((needsRestart = false), onrestart())}>立即重启</Button>{/snippet}
        </Alert>
      {/if}
      <SchemaForm {fields} bind:values {errors} disabled={!canEdit || saving} />
      {#if saveErr && !conflict && !Object.keys(saveErr.fields).length}
        <Alert>{saveErr.fromPlugin ? `来自插件：${saveErr.fromPlugin}` : saveErr.message}</Alert>
      {/if}
      {#if canEdit}
        <div class="actions">
          <Button type="submit" variant="primary" loading={saving} disabled={conflict}>保存</Button>
        </div>
      {/if}
    </form>
  {/if}
</Card>

<style>
  .stack {
    gap: var(--s-4);
    max-width: 560px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
  }
</style>
