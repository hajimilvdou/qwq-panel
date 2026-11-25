<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  HeadlessPluginPane · 引擎类插件（如 core.xray）的原生直达工作台
  ──────────────────────────────────────────────────────────────────────────────
  当已安装插件未提供独立 iframe 页面时，直接在左侧栏点击即可进入本工作台，
  查看实时运行状态、大白话能力说明与推荐图形化前端入口，不再缺失侧栏入口。
-->
<script lang="ts">
  import type { Plugin } from '$api/types';
  import { bytes } from '$lib/format';
  import { Button, Card, Chip, Icon } from '$ui';
  import { guideForPlugin } from '../apps/catalog-guides';
  import { runtimeOf } from '../apps/runtime';

  interface Props {
    plugin: Plugin;
    allPlugins: readonly Plugin[];
  }
  let { plugin, allPlugins }: Props = $props();

  const guide = $derived(guideForPlugin(plugin.plugin_id));
  const st = $derived(runtimeOf(plugin));
  const isXray = $derived(plugin.plugin_id === 'core.xray');
  const proxyApp = $derived(allPlugins.find((x) => x.plugin_id === 'proxy.advanced'));
</script>

<div class="engine-grid">
  <Card title={guide?.title || plugin.name} subtitle={guide?.tagline || plugin.summary} icon="shield" color="orange">
    <p class="desc">{guide?.whatItDoes || plugin.description || plugin.summary}</p>
    {#if guide?.highlights?.length}
      <ul class="hl">
        {#each guide.highlights as h (h)}
          <li><Icon name="check" size={14} /><span>{h}</span></li>
        {/each}
      </ul>
    {/if}

    {#if isXray}
      <div class="xray-cta">
        {#if proxyApp}
          <div class="cta-text">
            <strong>可视化节点与订阅工作台已就绪</strong>
            <span>可通过「高级代理与订阅中心」图形化新建 VLESS Reality / Hysteria2 / Trojan 节点并生成 Clash / sing-box 订阅。</span>
          </div>
          <Button variant="primary" icon="external" href="/plugins/proxy.advanced/proxy">打开高级代理工作台</Button>
        {:else}
          <div class="cta-text">
            <strong>需要可视化搭建节点与多用户订阅？</strong>
            <span>当前仅安装了底层 Xray 核心引擎；前往应用中心一键安装「高级代理与订阅中心」即可获得图形化节点向导、流量限速与客户端订阅链接。</span>
          </div>
          <Button variant="primary" icon="apps" href="/apps">前往应用中心安装「高级代理」</Button>
        {/if}
      </div>
    {/if}
  </Card>

  <Card title="运行状态与当前配额" icon="cpu" color="teal">
    <dl class="kv">
      <dt>运行状态</dt><dd><Chip size="sm" tone={st.tone}>{st.label}</Chip></dd>
      {#if plugin.active_version}
        <dt>当前版本</dt><dd class="mono">v{plugin.active_version}</dd>
      {/if}
      {#if plugin.runtime?.memory_bytes !== undefined}
        <dt>当前内存</dt>
        <dd class="num">
          {bytes(plugin.runtime.memory_bytes)}
          {#if plugin.resources?.memory_max_mb} / {plugin.resources.memory_max_mb} MB{/if}
        </dd>
      {/if}
      {#if plugin.resources}
        <dt>CPU 配额</dt><dd class="num">{plugin.resources.cpu_quota_percent}%</dd>
        <dt>进程 / 句柄</dt><dd class="num">{plugin.resources.pids_max} / {plugin.resources.fds_max}</dd>
      {/if}
    </dl>
    <p class="tiny faint tip-note">如需调整内存或 CPU 上限，请切换到上方「设置与资源」标签直接修改。</p>
  </Card>
</div>

<style>
  .engine-grid {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(260px, 1fr);
    gap: var(--s-5);
    align-items: start;
  }
  .desc {
    margin: 0 0 var(--s-4);
    color: var(--text-2);
    line-height: 1.65;
  }
  .hl {
    display: grid;
    gap: 8px;
    margin-bottom: var(--s-4);
  }
  .hl li {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: var(--fs-sm);
    color: var(--text);
  }
  .hl li :global(svg) {
    margin-top: 3px;
    color: var(--ok);
    flex: none;
  }
  .xray-cta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: var(--s-4);
    padding: var(--s-4);
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
  }
  .cta-text {
    display: grid;
    gap: 4px;
    flex: 1;
    min-width: 220px;
  }
  .cta-text strong {
    font-size: var(--fs-sm);
  }
  .cta-text span {
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .kv {
    display: grid;
    grid-template-columns: 92px minmax(0, 1fr);
    gap: 10px 14px;
  }
  dt {
    color: var(--text-3);
    font-size: var(--fs-sm);
  }
  dd {
    margin: 0;
    font-size: var(--fs-sm);
  }
  .tip-note {
    margin-top: var(--s-4);
  }
  @media (max-width: 960px) {
    .engine-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
