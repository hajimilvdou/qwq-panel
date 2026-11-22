<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  GrantStep · 向导"授权"步（SPEC §3.4）
  ───────────────────────────────────────────────────────────────
  能力逐项列出 scope 与 reason；普通能力默认勾选，sensitive 能力单独成组、
  必须逐个手动勾选。另列 connect_sources、资源预算、可能影响连接的操作。
  插件文本一律纯文本渲染（x-qwq-untrusted）。
-->
<script lang="ts">
  import type { PluginPackageInspection } from '$api/additions';
  import { Alert, Checkbox, Chip } from '$ui';
  import { capKey } from './install';
  import { RISK_LABEL } from './runtime';

  type Manifest = NonNullable<PluginPackageInspection['manifest']>;
  interface Props {
    manifest: Manifest;
    accepted: Set<string>;
  }
  let { manifest, accepted = $bindable() }: Props = $props();

  const normal = $derived(manifest.capabilities.filter((c) => !c.sensitive));
  const sensitive = $derived(manifest.capabilities.filter((c) => c.sensitive));
  const reach = $derived(manifest.operations.filter((o) => o.reachability));
  const r = $derived(manifest.resources);

  function set(key: string, on: boolean) {
    const next = new Set(accepted);
    if (on) next.add(key);
    else next.delete(key);
    accepted = next;
  }
</script>

{#snippet cap(c: Manifest['capabilities'][number])}
  <li>
    <Checkbox label="{c.name} · {c.scope}" hint={c.reason} checked={accepted.has(capKey(c))} onchange={(on) => set(capKey(c), on)} />
  </li>
{/snippet}

{#if !manifest.capabilities.length}
  <p class="muted">这个应用不需要额外权限。</p>
{/if}

{#if normal.length}
  <section>
    <h3>需要的权限</h3>
    <ul class="caps">{#each normal as c (capKey(c))}{@render cap(c)}{/each}</ul>
  </section>
{/if}

{#if sensitive.length}
  <section class="sensitive">
    <h3>敏感权限 <Chip size="sm" tone="warn">需逐项确认</Chip></h3>
    <p class="small muted">这些权限能读取机密或改动系统关键配置。只勾选你信任这个应用去做的。</p>
    <ul class="caps">{#each sensitive as c (capKey(c))}{@render cap(c)}{/each}</ul>
  </section>
{/if}

{#if reach.length}
  <Alert tone="warn" title="有些操作可能导致无法连接服务器">
    {reach.map((o) => o.summary).join('、')}——执行前一定会先问你。
  </Alert>
{/if}

<section>
  <h3>联网与资源</h3>
  <dl class="kv">
    <dt>可访问的外部地址</dt>
    <dd>
      {#if manifest.connect_sources.length}
        {#each manifest.connect_sources as s (s)}<code class="mono">{s}</code>{/each}
      {:else}
        <span class="muted">不联网</span>
      {/if}
    </dd>
    {#if r}
      <dt>资源上限</dt>
      <dd class="small">内存 {r.memory_max_mb} MB · CPU {r.cpu_quota_percent}% · 磁盘 {r.disk_max_mb} MB · 进程 {r.pids_max}</dd>
    {/if}
    <dt>操作</dt>
    <dd class="small">
      {manifest.operations.length} 项{#if manifest.operations.some((o) => o.risk === 'high')}，含{RISK_LABEL.high}操作{/if}
    </dd>
  </dl>
</section>

<style>
  section + section,
  section + :global(.alert),
  :global(.alert) + section {
    margin-top: var(--s-5);
  }
  h3 {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0 0 var(--s-2);
    font-size: var(--fs-md);
  }
  .caps {
    display: flex;
    flex-direction: column;
    gap: var(--s-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .sensitive {
    padding: var(--s-4);
    border-radius: var(--r-md);
    background: color-mix(in oklab, var(--warn-soft) 60%, transparent);
  }
  .sensitive p {
    margin: 0 0 var(--s-3);
  }
  .kv {
    display: grid;
    grid-template-columns: 140px minmax(0, 1fr);
    gap: var(--s-2) var(--s-4);
    margin: 0;
  }
  dt {
    color: var(--text-3);
    font-size: var(--fs-sm);
  }
  dd {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 0;
  }
  dd code {
    padding: 1px 6px;
    border-radius: var(--r-xs);
    background: var(--surface-3);
    font-size: var(--fs-xs);
  }
</style>
