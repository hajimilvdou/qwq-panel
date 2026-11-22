<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  AppsCard · 主页"我的应用"（复用侧栏的 pluginsResource，状态点 + 版本）
-->
<script lang="ts">
  import type { Plugin } from '$api/types';
  import { pluginLook } from '../../app/nav';
  import { session } from '$lib/session.svelte';
  import { Button, Card, Tile, type Tone } from '$ui';

  interface Props {
    plugins: readonly Plugin[];
  }
  let { plugins }: Props = $props();

  type RuntimeState = NonNullable<Plugin['runtime']>['state'];
  const STATE: Record<RuntimeState, { label: string; tone: Tone }> = {
    running: { label: '运行中', tone: 'ok' },
    starting: { label: '启动中', tone: 'info' },
    stopped: { label: '已停止', tone: 'neutral' },
    crashed: { label: '出错了', tone: 'bad' },
    quarantined: { label: '已隔离', tone: 'bad' },
    unknown: { label: '状态未知', tone: 'neutral' },
  };
  const stateOf = (p: Plugin) => STATE[p.runtime?.state ?? 'unknown'] ?? STATE.unknown;
  const running = $derived(plugins.filter((p) => p.runtime?.state === 'running').length);
</script>

<Card
  title="我的应用"
  subtitle={plugins.length ? `${running} 个应用正在运行` : '还没有安装应用'}
  icon="apps"
  color="violet"
>
  {#snippet actions()}
    <Button variant="plain" size="sm" href="/apps">应用中心</Button>
  {/snippet}

  <ul class="apps">
    {#each plugins as p (p.plugin_id)}
      {@const look = pluginLook(p)}
      {@const st = stateOf(p)}
      <li>
        <a class="app" href="/apps/{encodeURIComponent(p.plugin_id)}">
          <Tile icon={look.icon} color={look.color} size="lg" />
          <span class="text">
            <b class="ellipsis">{p.name}</b>
            <small><i class="dot t-{st.tone}" aria-hidden="true"></i>{st.label}{p.active_version ? ` · ${p.active_version}` : ''}</small>
          </span>
        </a>
      </li>
    {/each}
    {#if session.can('host.plugins:install')}
      <li>
        <a class="app add" href="/apps/install">
          <Tile icon="plus" size="lg" />
          <span class="text"><b>添加应用</b><small>从文件安装</small></span>
        </a>
      </li>
    {/if}
  </ul>
</Card>

<style>
  .apps {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }
  .app {
    display: flex;
    align-items: center;
    gap: 12px;
    height: 100%;
    padding: 12px;
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid transparent;
    color: inherit;
    text-decoration: none;
    transition:
      border-color var(--dur-1) var(--ease),
      transform var(--dur-1) var(--ease);
  }
  .app:hover {
    border-color: var(--line-strong);
    transform: translateY(-1px);
  }
  .app.add {
    background: transparent;
    border: 1.5px dashed var(--line-strong);
    color: var(--text-2);
  }
  .text {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.4;
  }
  b {
    font-weight: var(--fw-semibold);
  }
  small {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--text-3);
  }
  .dot.t-ok { background: var(--ok); }
  .dot.t-info { background: var(--info); }
  .dot.t-bad { background: var(--bad); }

  @media (max-width: 560px) {
    .apps {
      grid-template-columns: minmax(0, 1fr);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .app:hover {
      transform: none;
    }
  }
</style>
