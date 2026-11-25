<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ConfigTab · 插件设置与可调资源上限（SPEC §3.4）
  ───────────────────────────────────────────────────────────────
  1. 资源上限配置卡片（内存 / CPU 配额 / 进程数 / 文件句柄 / 磁盘建议）：
     随时可修改或恢复默认，调用 PUT /api/v1/plugins/{id}/resources 持久化并实时同步 systemd cgroup。
  2. 插件业务参数表单（SchemaForm）：模块级缓存实现切换即显零闪烁。
-->
<script module lang="ts">
  import type { PluginConfig } from '$api/types';
  const cfgCache = new Map<string, { schema: Record<string, unknown>; config: PluginConfig }>();
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import { Alert, Button, Card, ErrorState, Input, SchemaForm, Skeleton } from '$ui';
  import { draftOf, fieldsOf, hotApply, initialValues, toPayload, validate, type FormValues, type SchemaField } from '$ui';
  import { plugins } from '$api/endpoints';
  import type { Plugin } from '$api/types';
  import { registerDraft, takeDraft } from '$lib/drafts';
  import { describeError, type ErrorView } from '$lib/errors';
  import { createIntent, type Intent } from '$lib/ops';
  import { resources as resCache } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';
  import { guideForPlugin } from './catalog-guides';

  interface Props {
    plugin: Plugin;
    onrestart: () => void;
    onupdated?: () => void;
  }
  let { plugin, onrestart, onupdated }: Props = $props();

  const pid = untrack(() => plugin.plugin_id);
  const canEdit = $derived(session.can('host.plugins:config'));
  const guide = $derived(guideForPlugin(plugin.plugin_id));

  /* ---------------------------------------------------------------- 资源上限配置 */
  let memMb = $state(String(untrack(() => plugin.resources?.memory_max_mb ?? guideForPlugin(pid)?.defaults.memory_max_mb ?? 64)));
  let cpuPct = $state(String(untrack(() => plugin.resources?.cpu_quota_percent ?? guideForPlugin(pid)?.defaults.cpu_quota_percent ?? 50)));
  let pidsMax = $state(String(untrack(() => plugin.resources?.pids_max ?? guideForPlugin(pid)?.defaults.pids_max ?? 32)));
  let fdsMax = $state(String(untrack(() => plugin.resources?.fds_max ?? guideForPlugin(pid)?.defaults.fds_max ?? 256)));
  let diskMb = $state(String(untrack(() => plugin.resources?.disk_max_mb ?? guideForPlugin(pid)?.defaults.disk_max_mb ?? 64)));
  let resSaving = $state(false);
  let resResetting = $state(false);
  let resErr = $state('');

  $effect(() => {
    const r = plugin.resources;
    if (!r) return;
    memMb = String(r.memory_max_mb);
    cpuPct = String(r.cpu_quota_percent);
    pidsMax = String(r.pids_max);
    fdsMax = String(r.fds_max);
    diskMb = String(r.disk_max_mb);
  });

  async function saveResources(e: SubmitEvent) {
    e.preventDefault();
    if (!canEdit || resSaving) return;
    const m = Number.parseInt(memMb, 10);
    const c = Number.parseInt(cpuPct, 10);
    const p = Number.parseInt(pidsMax, 10);
    const f = Number.parseInt(fdsMax, 10);
    const d = Number.parseInt(diskMb, 10);
    if (!Number.isFinite(m) || m < 16 || m > 65536) {
      resErr = '内存上限必须在 16 ~ 65536 MB 之间';
      return;
    }
    if (!Number.isFinite(c) || c < 1 || c > 100000) {
      resErr = 'CPU 配额必须在 1 ~ 100000 % 之间';
      return;
    }
    if (!Number.isFinite(p) || p < 1 || p > 4096) {
      resErr = '最大进程数必须在 1 ~ 4096 之间';
      return;
    }
    if (!Number.isFinite(f) || f < 16 || f > 65536) {
      resErr = '最大文件句柄必须在 16 ~ 65536 之间';
      return;
    }
    resSaving = true;
    resErr = '';
    try {
      await plugins.putResources(pid, {
        memory_max_mb: m,
        cpu_quota_percent: c,
        pids_max: p,
        fds_max: f,
        ...(Number.isFinite(d) && d > 0 ? { disk_max_mb: d } : {}),
      });
      resCache.invalidate('plugins');
      resCache.invalidate(`plugin:${pid}`);
      onupdated?.();
      toasts.success('资源上限已保存并同步生效');
    } catch (err) {
      resErr = describeError(err).message;
    } finally {
      resSaving = false;
    }
  }

  async function resetResources() {
    if (!canEdit || resResetting) return;
    resResetting = true;
    resErr = '';
    try {
      const updated = await plugins.putResources(pid, {
        memory_max_mb: guide?.defaults.memory_max_mb ?? 64,
        cpu_quota_percent: guide?.defaults.cpu_quota_percent ?? 50,
        reset_default: true,
      });
      if (updated.resources) {
        memMb = String(updated.resources.memory_max_mb);
        cpuPct = String(updated.resources.cpu_quota_percent);
        pidsMax = String(updated.resources.pids_max);
        fdsMax = String(updated.resources.fds_max);
        diskMb = String(updated.resources.disk_max_mb);
      }
      resCache.invalidate('plugins');
      resCache.invalidate(`plugin:${pid}`);
      onupdated?.();
      toasts.success('已恢复插件默认资源上限');
    } catch (err) {
      resErr = describeError(err).message;
    } finally {
      resResetting = false;
    }
  }

  /* ---------------------------------------------------------------- 插件参数配置 */
  const hit = untrack(() => cfgCache.get(pid));
  const initialHasConfig = untrack(() => plugin.has_config !== false);
  let status = $state<'loading' | 'ready' | 'error'>(hit || !initialHasConfig ? 'ready' : 'loading');
  let loadErr = $state<unknown>(null);
  let schema = $state<Record<string, unknown>>(hit?.schema ?? {});
  let fields = $state<SchemaField[]>(hit ? fieldsOf(hit.schema) : []);
  let values = $state<FormValues>(hit ? initialValues(fieldsOf(hit.schema), hit.config.config) : {});
  let config = $state<PluginConfig | null>(hit?.config ?? null);
  let errors = $state<Record<string, string>>({});
  let saveErr = $state<ErrorView | null>(null);
  let saving = $state(false);
  let needsRestart = $state(false);
  let intent: Intent = createIntent();
  let known = new Set<string>(hit ? [hit.config.revision] : []);

  async function load(silent = false) {
    if (plugin.has_config === false) {
      status = 'ready';
      fields = [];
      return;
    }
    if (!silent && !config) status = 'loading';
    saveErr = null;
    errors = {};
    try {
      const [s, c] = await Promise.all([plugins.configSchema(pid), plugins.getConfig(pid)]);
      cfgCache.set(pid, { schema: s, config: c });
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
      if (!config) status = 'error';
    }
  }
  void load(Boolean(hit));

  $effect(() => registerDraft(`plugin-config:${pid}`, () => draftOf(fields, values)));

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
      cfgCache.set(pid, { schema, config: next });
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

<div class="cfg-grid">
  <!-- 1. 插件业务参数（有参数才突出展示，无参数时仅简洁提示，不喧宾夺主） -->
  {#if status === 'loading'}
    <Card title="运行参数" icon="settings" color="slate">
      <Skeleton lines={3} height={36} />
    </Card>
  {:else if status === 'error'}
    {@const v = describeError(loadErr)}
    {#if v.code !== 'NOT_FOUND'}
      <Card title="运行参数" icon="settings" color="slate">
        <ErrorState compact message={v.message} requestId={v.requestId} onretry={() => void load(false)} />
      </Card>
    {/if}
  {:else if fields.length > 0}
    <Card title="运行参数" subtitle="修改该应用的基础配置" icon="settings" color="slate">
      <form class="stack" onsubmit={save} novalidate>
        {#if conflict}
          <Alert tone="warn" title="设置已在别处修改">
            为避免覆盖别人的改动，请先重新加载。
            {#snippet actions()}<Button size="sm" variant="soft" icon="refresh" onclick={() => void load(false)}>重新加载</Button>{/snippet}
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
            <Button type="submit" variant="primary" loading={saving} disabled={conflict}>保存参数</Button>
          </div>
        {/if}
      </form>
    </Card>
  {:else}
    <p class="no-param-note">该应用的功能设置均已在主界面中直接管理，此处无需额外配置参数。</p>
  {/if}

  <!-- 2. 高级资源限额默认折叠收纳，避免将一堆底层 cgroup 数值塞在显眼处 -->
  <details class="adv-res">
    <summary>
      <span>高级 · 容器资源上限</span>
      <span class="adv-hint num">内存 {memMb} MB · CPU {cpuPct}%</span>
    </summary>
    <form class="res-form" onsubmit={saveResources} novalidate>
      <p class="res-desc">仅在内存紧张或需要限制单插件资源时调整；保存后自动同步 systemd 限额。</p>
      <div class="res-fields">
        <Input label="内存上限 (MB)" type="number" min="16" max="65536" mono bind:value={memMb} disabled={!canEdit || resSaving} />
        <Input label="CPU 配额 (%)" type="number" min="1" max="100000" mono bind:value={cpuPct} disabled={!canEdit || resSaving} hint="100% 表示单核" />
        <Input label="最大进程数" type="number" min="1" max="4096" mono bind:value={pidsMax} disabled={!canEdit || resSaving} />
        <Input label="最大文件句柄" type="number" min="16" max="65536" mono bind:value={fdsMax} disabled={!canEdit || resSaving} />
        <Input label="磁盘上限 (MB)" type="number" min="1" max="1048576" mono bind:value={diskMb} disabled={!canEdit || resSaving} />
      </div>
      {#if resErr}<Alert tone="bad">{resErr}</Alert>{/if}
      {#if canEdit}
        <div class="actions">
          <Button type="button" variant="ghost" size="sm" loading={resResetting} disabled={resSaving} onclick={resetResources}>
            恢复默认
          </Button>
          <Button type="submit" variant="primary" size="sm" loading={resSaving} disabled={resResetting}>
            保存限额
          </Button>
        </div>
      {/if}
    </form>
  </details>
</div>

<style>
  .cfg-grid {
    display: grid;
    gap: var(--s-4);
  }
  .no-param-note {
    padding: 12px 14px;
    border-radius: var(--r-md);
    background: var(--surface-2);
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .adv-res {
    border-radius: var(--r-lg);
    border: 1px solid var(--line);
    background: var(--surface-2);
    padding: 12px 14px;
  }
  .adv-res summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    cursor: pointer;
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
    color: var(--text);
    list-style: none;
  }
  .adv-res summary::-webkit-details-marker {
    display: none;
  }
  .adv-hint {
    font-size: var(--fs-xs);
    font-weight: var(--fw-regular);
    color: var(--text-3);
  }
  .res-desc {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .res-form {
    display: grid;
    gap: var(--s-3);
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid var(--line);
  }
  .res-fields {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
    gap: var(--s-3);
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--s-2);
  }
</style>
