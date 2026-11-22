<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  安装向导 /apps/install（SPEC §3.4）
  ───────────────────────────────────────────────────────────────
    upload ──POST /plugin-packages（XHR 进度，≤64 MiB）──▶ GET /plugin-packages/{id}
    check  ──blockers() 为空才可下一步（签名 / 兼容 / 内存 / 磁盘）
    grant  ──全部能力已同意才可安装（敏感能力逐项勾）
    install──POST /plugins 或 /plugins/{id}/update（已装同插件自动走更新）
             跟随 plugin.{install,update}.step 事件（每条表示该步已完成）；commit 即完成
  install 用同一意图键：网络失败后"重试"不会重复安装。
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Alert, Button, Card, Icon, Spinner } from '$ui';
  import { plugins } from '$api/endpoints';
  import type { PluginPackageInspection } from '$api/additions';
  import { describeError, type ErrorView } from '$lib/errors';
  import { events } from '$lib/events.svelte';
  import { bytes } from '$lib/format';
  import { createIntent, type Intent } from '$lib/ops';
  import { resources } from '$lib/resource.svelte';
  import { navigate } from '$lib/router.svelte';
  import GrantStep from './GrantStep.svelte';
  import InspectionView from './InspectionView.svelte';
  import {
    ROLLOUT_STEPS,
    WIZARD_STEPS,
    acceptedList,
    allAccepted,
    blockers,
    defaultAccepted,
    fileProblem,
    stepIndex,
    type WizardStep,
  } from './install';

  let { params: _params }: { params: Record<string, string> } = $props();

  let step = $state<WizardStep>('upload');
  const stepNo = $derived(WIZARD_STEPS.findIndex((s) => s.id === step));

  /* ---------------------------------------------------------------- 上传 */
  let file = $state<File | null>(null);
  let progress = $state(0);
  let uploading = $state(false);
  let uploadErr = $state('');
  let dragging = $state(false);
  let ctrl: AbortController | null = null;
  let picker = $state<HTMLInputElement>();

  async function take(f: File | undefined | null) {
    if (!f || uploading) return;
    uploadErr = fileProblem(f) ?? '';
    if (uploadErr) return;
    file = f;
    uploading = true;
    progress = 0;
    ctrl = new AbortController();
    try {
      const up = await plugins.upload(f, (l, t) => (progress = t ? l / t : 0), ctrl.signal);
      progress = 1;
      ins = await plugins.inspect(up.upload_id);
      accepted = defaultAccepted(ins.manifest?.capabilities ?? []);
      step = 'check';
    } catch (err) {
      const v = describeError(err);
      if (v.code !== 'ABORTED') uploadErr = v.code === 'PAYLOAD_TOO_LARGE' ? '安装包不能超过 64 MiB' : v.message;
      file = null;
    } finally {
      uploading = false;
      ctrl = null;
    }
  }

  function ondrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    void take(e.dataTransfer?.files[0]);
  }

  onDestroy(() => ctrl?.abort());

  /* ---------------------------------------------------------------- 检查 / 授权 */
  let ins = $state<PluginPackageInspection | null>(null);
  let accepted = $state(new Set<string>());
  const problems = $derived(ins ? blockers(ins) : []);
  const caps = $derived(ins?.manifest?.capabilities ?? []);
  const isUpdate = $derived(!!ins?.installed);
  const verb = $derived(isUpdate ? '更新' : '安装');

  function restart() {
    step = 'upload';
    ins = null;
    file = null;
    uploadErr = '';
    installErr = null;
    current = -1;
    finished = false;
    intent = createIntent();
  }

  /* ---------------------------------------------------------------- 安装 */
  let intent: Intent = createIntent();
  let installing = $state(false);
  let installErr = $state<ErrorView | null>(null);
  let current = $state(-1);
  let finished = $state(false);
  let off: (() => void) | null = null;
  onDestroy(() => off?.());

  async function install() {
    const m = ins?.manifest;
    if (!ins || !m || installing) return;
    step = 'install';
    installing = true;
    installErr = null;
    off?.();
    off = events.on('plugin.*', (e) => {
      const p = e.payload as { plugin_id?: string; step?: string };
      if (p.plugin_id !== m.id || !p.step || !/^plugin\.(install|update)\.step$/.test(e.type)) return;
      current = Math.max(current, stepIndex(p.step));
      if (p.step === 'commit') {
        finished = true;
        off?.();
        off = null;
      }
    });
    try {
      const body = { upload_id: ins.upload_id, accepted_capabilities: acceptedList(caps, accepted) };
      if (ins.installed) await plugins.update(m.id, { ...body, expected_revision: ins.installed.revision }, intent.key);
      else await plugins.install(body, intent.key);
      current = ROLLOUT_STEPS.length - 1;
      finished = true;
      off?.();
      off = null;
      resources.invalidate('plugins');
    } catch (err) {
      off?.();
      off = null;
      installErr = describeError(err);
    } finally {
      installing = false;
    }
  }
</script>

<!-- ---------------------------------------------------------------- 步骤条 -->
<ol class="stepper" aria-label="安装步骤">
  {#each WIZARD_STEPS as s, i (s.id)}
    <li class:done={i < stepNo} class:now={i === stepNo} aria-current={i === stepNo ? 'step' : undefined}>
      <span class="n">{#if i < stepNo}<Icon name="check" size={14} />{:else}{i + 1}{/if}</span>
      <span>{s.id === 'install' ? verb : s.label}</span>
    </li>
  {/each}
</ol>

<Card padding="md" class="wizard">
  {#if step === 'upload'}
    <h2 class="sr-only">上传安装包</h2>
    <div
      class="drop"
      class:dragging
      role="group"
      aria-label="安装包拖放区"
      ondragover={(e) => {
        e.preventDefault();
        dragging = true;
      }}
      ondragleave={() => (dragging = false)}
      {ondrop}
    >
      {#if uploading && file}
        <Spinner />
        <p class="strong">正在上传 {file.name}</p>
        <div class="bar" role="progressbar" aria-label="上传进度" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress * 100)}>
          <span style:width="{progress * 100}%"></span>
        </div>
        <p class="small muted">{bytes(file.size * progress)} / {bytes(file.size)}{progress >= 1 ? ' · 正在检查…' : ''}</p>
        <Button variant="plain" size="sm" onclick={() => ctrl?.abort()}>取消</Button>
      {:else}
        <span class="up"><Icon name="upload" size={28} /></span>
        <p class="strong">把安装包拖到这里</p>
        <p class="small muted">.qwqpkg 文件，不超过 64 MiB</p>
        <Button variant="soft" onclick={() => picker?.click()}>选择文件</Button>
      {/if}
      <input bind:this={picker} type="file" accept=".qwqpkg,application/octet-stream" hidden onchange={(e) => take(e.currentTarget.files?.[0])} />
    </div>
    {#if uploadErr}<Alert>{uploadErr}</Alert>{/if}
  {:else if step === 'check' && ins}
    <h2 class="sr-only">安装前检查</h2>
    <InspectionView {ins} {problems} />
  {:else if step === 'grant' && ins?.manifest}
    <h2 class="title">{ins.manifest.name} 需要这些权限</h2>
    <GrantStep manifest={ins.manifest} bind:accepted />
  {:else if step === 'install' && ins?.manifest}
    <h2 class="title">{finished ? `${ins.manifest.name} 已${verb}` : `正在${verb} ${ins.manifest.name}`}</h2>
    <ol class="rollout" aria-live="polite">
      {#each ROLLOUT_STEPS as s, i (s.id)}
        {@const done = finished || i <= current}
        {@const now = !done && !installErr && i === current + 1}
        <li class:done class:now>
          <span class="dot">
            {#if done}<Icon name="check" size={14} />{:else if now}<Spinner size={14} />{/if}
          </span>
          {s.label}
        </li>
      {/each}
    </ol>
    {#if installErr}
      <Alert title="{verb}没有成功">
        {installErr.fromPlugin ? `来自插件：${installErr.fromPlugin}` : installErr.message}
        {#if installErr.requestId}<span class="mono tiny"> · {installErr.requestId}</span>{/if}
      </Alert>
    {/if}
  {/if}

  <!-- -------------------------------------------------------------- 底部按钮 -->
  <footer>
    {#if step === 'check'}
      <Button variant="plain" onclick={restart}>换一个包</Button>
      <Button variant="primary" iconRight="chevron-right" disabled={problems.length > 0} onclick={() => (step = 'grant')}>下一步</Button>
    {:else if step === 'grant'}
      <Button variant="plain" onclick={() => (step = 'check')}>上一步</Button>
      <Button variant="primary" disabled={!allAccepted(caps, accepted)} onclick={install}>同意并{verb}</Button>
    {:else if step === 'install'}
      {#if installErr}
        <Button variant="plain" onclick={restart}>重新上传</Button>
        <Button variant="primary" icon="refresh" loading={installing} onclick={install}>重试</Button>
      {:else if finished && ins?.manifest}
        <Button variant="plain" href="/apps">返回应用中心</Button>
        <Button variant="primary" onclick={() => navigate(`/apps/${encodeURIComponent(ins!.manifest!.id)}`)}>查看应用</Button>
      {/if}
    {/if}
  </footer>
</Card>

<style>
  .stepper {
    display: flex;
    gap: var(--s-2);
    margin: 0 0 var(--s-5);
    padding: 0;
    list-style: none;
  }
  .stepper li {
    display: flex;
    flex: 1;
    align-items: center;
    gap: 8px;
    padding-bottom: 10px;
    border-bottom: 3px solid var(--line);
    color: var(--text-3);
    font-weight: var(--fw-medium);
  }
  .stepper li.done {
    border-color: var(--accent);
    color: var(--text-2);
  }
  .stepper li.now {
    border-color: var(--accent);
    color: var(--text);
  }
  .n {
    display: grid;
    place-items: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--surface-3);
    font-size: var(--fs-xs);
  }
  .done .n,
  .now .n {
    background: var(--accent-strong);
    color: var(--on-accent);
  }
  :global(.wizard) {
    max-width: 760px;
  }
  .title {
    margin: 0 0 var(--s-4);
    font-size: var(--fs-xl);
  }
  .drop {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--s-2);
    padding: var(--s-8) var(--s-5);
    border: 2px dashed var(--line-input);
    border-radius: var(--r-lg);
    text-align: center;
    transition:
      border-color var(--dur-2) var(--ease),
      background var(--dur-2) var(--ease);
  }
  .drop.dragging {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .drop p {
    margin: 0;
  }
  .drop + :global(.alert) {
    margin-top: var(--s-4);
  }
  .up {
    display: grid;
    place-items: center;
    width: 56px;
    height: 56px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .bar {
    width: min(360px, 100%);
    height: 6px;
    overflow: hidden;
    border-radius: var(--r-pill);
    background: var(--surface-3);
  }
  .bar span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: var(--accent);
    transition: width var(--dur-2) var(--ease);
  }
  .rollout {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
    margin: 0 0 var(--s-4);
    padding: 0;
    list-style: none;
    color: var(--text-3);
  }
  .rollout li {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .rollout li.done {
    color: var(--text-2);
  }
  .rollout li.now {
    color: var(--text);
    font-weight: var(--fw-medium);
  }
  .dot {
    display: grid;
    place-items: center;
    width: 22px;
    height: 22px;
    border: 1.5px solid var(--line-input);
    border-radius: 50%;
  }
  .done .dot {
    border-color: var(--ok-text);
    background: var(--ok-soft);
    color: var(--ok-text);
  }
  footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: var(--s-5);
  }
  footer:empty {
    display: none;
  }
  @media (max-width: 860px) {
    .stepper li span:last-child {
      display: none;
    }
    .stepper li.now span:last-child {
      display: inline;
    }
  }
</style>
