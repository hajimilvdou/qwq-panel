<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  InspectionView · 向导"检查"步（GAPS 缺口 4）
  签名、兼容性、内存、磁盘逐项打勾；不过的项由父级 blockers() 汇总并禁用下一步。
-->
<script lang="ts">
  import type { PluginPackageInspection } from '$api/additions';
  import { Alert, Icon } from '$ui';
  import { bytes } from '$lib/format';

  interface Props {
    ins: PluginPackageInspection;
    problems: readonly string[];
  }
  let { ins, problems }: Props = $props();

  const m = $derived(ins.manifest);
  const rows = $derived([
    {
      label: '签名',
      ok: ins.signature.valid && ins.signature.trusted,
      text: !ins.signature.valid ? '无效' : ins.signature.trusted ? `有效 · 发布者 ${ins.signature.publisher_id}` : `有效，但发布者 ${ins.signature.publisher_id} 不受信任`,
    },
    {
      label: '兼容性',
      ok: ins.compatibility.ok,
      text: ins.compatibility.ok ? (m ? `${m.target} · ABI ${m.abi}` : '兼容') : '不兼容',
    },
    { label: '内存', ok: ins.memory.ok, text: `需要 ${ins.memory.required_mb} MB · 可用 ${ins.memory.available_mb} MB` },
    { label: '磁盘', ok: ins.disk.ok, text: `需要 ${ins.disk.required_mb} MB · 可用 ${ins.disk.available_mb} MB` },
  ]);
</script>

{#if m}
  <div class="who">
    <h3>{m.name} <span class="ver mono">v{m.version}</span></h3>
    <p class="muted">{m.summary}</p>
    {#if m.description}<p class="small">{m.description}</p>{/if}
    {#if ins.installed}
      <Alert tone="info">已安装 v{ins.installed.version}，这次会<strong>更新</strong>到 v{m.version}，数据和设置保留。</Alert>
    {/if}
  </div>
{/if}

<ul class="checks" aria-label="安装前检查">
  {#each rows as r (r.label)}
    <li class:bad={!r.ok}>
      <span class="ic"><Icon name={r.ok ? 'check-circle' : 'alert'} size={18} /></span>
      <span class="label">{r.label}</span>
      <span class="text">{r.text}</span>
      <span class="sr-only">{r.ok ? '通过' : '未通过'}</span>
    </li>
  {/each}
</ul>

{#if problems.length}
  <Alert title="暂时不能安装">
    <ul class="reasons">
      {#each problems as p (p)}<li>{p}</li>{/each}
    </ul>
  </Alert>
{/if}

<p class="tiny faint mono hash">{bytes(ins.size)} · sha256 {ins.sha256.slice(0, 16)}…</p>

<style>
  .who h3 {
    margin: 0;
    font-size: var(--fs-xl);
  }
  .ver {
    color: var(--text-3);
    font-size: var(--fs-sm);
    font-weight: var(--fw-regular);
  }
  .who p {
    margin: 4px 0 0;
  }
  .who :global(.alert) {
    margin-top: var(--s-3);
  }
  .checks {
    display: flex;
    flex-direction: column;
    margin: var(--s-5) 0;
    padding: 0;
    list-style: none;
    border: 1px solid var(--line);
    border-radius: var(--r-md);
  }
  li {
    display: grid;
    grid-template-columns: 24px 64px minmax(0, 1fr);
    align-items: center;
    gap: 8px;
    padding: 12px var(--s-4);
  }
  li + li {
    border-top: 1px solid var(--line);
  }
  .ic {
    display: grid;
    color: var(--ok-text);
  }
  li.bad .ic,
  li.bad .text {
    color: var(--bad-text);
  }
  .label {
    font-weight: var(--fw-medium);
  }
  .text {
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  .reasons {
    margin: 4px 0 0;
    padding-left: 1.2em;
  }
  .hash {
    margin: var(--s-4) 0 0;
  }
</style>
