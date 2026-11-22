<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  OverviewTab · 描述、运行状况、权限、操作、资源（插件文本一律纯文本，x-qwq-untrusted）
-->
<script lang="ts">
  import type { Plugin } from '$api/types';
  import { Card, Chip } from '$ui';
  import { bytes, dateTime, relativeTime } from '$lib/format';
  import { EFFECT_LABEL, RISK_LABEL, runtimeOf } from './runtime';

  interface Props {
    plugin: Plugin;
  }
  let { plugin: p }: Props = $props();

  const st = $derived(runtimeOf(p));
  const homepage = $derived(p.homepage && /^https:\/\//.test(p.homepage) ? p.homepage : undefined);
  const memPct = $derived(
    p.runtime?.memory_bytes && p.runtime.memory_max_bytes ? Math.round((p.runtime.memory_bytes / p.runtime.memory_max_bytes) * 100) : undefined,
  );
</script>

<div class="grid">
  <Card title="介绍" icon="info" color="blue" class="span-2">
    <p class="desc">{p.description || p.summary}</p>
    <dl class="kv">
      <dt>发布者</dt><dd>{p.publisher_id}</dd>
      {#if p.license}<dt>许可证</dt><dd class="mono">{p.license}</dd>{/if}
      <dt>运行位置</dt><dd>{p.placement === 'controller' ? '控制节点' : '每个节点'}</dd>
      {#if homepage}<dt>主页</dt><dd><a href={homepage} target="_blank" rel="noopener noreferrer">{homepage}</a></dd>{/if}
      {#if p.dependencies?.length}<dt>依赖</dt><dd class="mono">{p.dependencies.join('、')}</dd>{/if}
    </dl>
  </Card>

  <Card title="运行状况" icon="cpu" color="teal">
    <dl class="kv">
      <dt>状态</dt><dd><Chip size="sm" tone={st.tone}>{st.label}</Chip></dd>
      {#if p.runtime?.since}<dt>持续</dt><dd title={dateTime(p.runtime.since)}>自 {relativeTime(p.runtime.since)}</dd>{/if}
      {#if p.runtime?.restarts !== undefined}<dt>重启次数</dt><dd class="num">{p.runtime.restarts}</dd>{/if}
      {#if p.runtime?.memory_bytes !== undefined}
        <dt>内存</dt>
        <dd class="num">{bytes(p.runtime.memory_bytes)}{#if p.runtime.memory_max_bytes} / {bytes(p.runtime.memory_max_bytes)}（{memPct}%）{/if}</dd>
      {/if}
      {#if p.runtime?.detail}<dt>说明</dt><dd>{p.runtime.detail}</dd>{/if}
    </dl>
  </Card>

  {#if p.capabilities?.length}
    <Card title="权限" icon="shield" color="amber" class="span-2">
      <ul class="list">
        {#each p.capabilities as c (`${c.name} ${c.scope}`)}
          <li>
            <div class="line">
              <span class="mono strong">{c.name}</span><span class="mono faint">{c.scope}</span>
              {#if c.sensitive}<Chip size="sm" tone="warn">敏感</Chip>{/if}
            </div>
            <p class="small muted">{c.reason}</p>
          </li>
        {/each}
      </ul>
    </Card>
  {/if}

  {#if p.resources}
    <Card title="资源上限" icon="memory" color="slate">
      <dl class="kv">
        <dt>内存</dt><dd class="num">{p.resources.memory_max_mb} MB</dd>
        <dt>CPU</dt><dd class="num">{p.resources.cpu_quota_percent}%</dd>
        <dt>磁盘</dt><dd class="num">{p.resources.disk_max_mb} MB</dd>
        <dt>进程 / 文件</dt><dd class="num">{p.resources.pids_max} / {p.resources.fds_max}</dd>
      </dl>
    </Card>
  {/if}

  {#if p.operations?.length}
    <Card title="能做的事" icon="activity" color="violet" class="span-3">
      <ul class="list ops">
        {#each p.operations as o (o.id)}
          <li>
            <span>{o.summary}</span>
            <span class="tags">
              <Chip size="sm" tone="neutral" dot={false}>{EFFECT_LABEL[o.effect] ?? o.effect}</Chip>
              {#if o.effect !== 'read'}<Chip size="sm" tone={o.risk === 'high' ? 'bad' : o.risk === 'medium' ? 'warn' : 'neutral'}>{RISK_LABEL[o.risk] ?? o.risk}</Chip>{/if}
              {#if o.reachability}<Chip size="sm" tone="warn">可能影响连接</Chip>{/if}
            </span>
          </li>
        {/each}
      </ul>
    </Card>
  {/if}
</div>

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: var(--s-5);
    align-items: start;
  }
  .grid > :global(.span-2) {
    grid-column: span 2;
  }
  .grid > :global(.span-3) {
    grid-column: 1 / -1;
  }
  @media (max-width: 1180px) {
    .grid {
      grid-template-columns: minmax(0, 1fr);
    }
    .grid > :global(*) {
      grid-column: auto !important;
    }
  }
  .desc {
    margin: 0 0 var(--s-4);
    white-space: pre-line;
  }
  .kv {
    display: grid;
    grid-template-columns: 88px minmax(0, 1fr);
    gap: var(--s-2) var(--s-4);
    margin: 0;
  }
  dt {
    color: var(--text-3);
  }
  dd {
    margin: 0;
    word-break: break-word;
  }
  .list {
    display: flex;
    flex-direction: column;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .list li {
    padding: 10px 0;
  }
  .list li + li {
    border-top: 1px solid var(--line);
  }
  .list p {
    margin: 2px 0 0;
  }
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .ops li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .tags {
    display: flex;
    gap: 6px;
  }
</style>
