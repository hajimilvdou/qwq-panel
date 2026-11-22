<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  PluginFrame · 单个插件 iframe + 宿主桥（ENG §9）
  ───────────────────────────────────────────────────────────────
  attempt 每 +1：重建 <iframe>（{#key}）并重新 attach，等于全新握手。
  设置变化（主题 / 动效 / 密度 / 可见性）即推 ui.settings；path 变化推 ui.route。
-->
<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { Button, ErrorState, Skeleton } from '$ui';
  import type { Plugin } from '$api/types';
  import { PluginBridge, HEIGHT_MIN } from '$lib/plugin-host';
  import { bridgeDeps, hostSettings, pluginFrameSrc } from '$lib/plugin-host/wiring';
  import { prefs } from '$lib/prefs.svelte';
  import { navigate } from '$lib/router.svelte';
  import { toasts } from '$lib/toast.svelte';

  interface Props {
    plugin: Plugin;
    path: string;
  }
  let { plugin, path }: Props = $props();

  /* Shell 固定策略：插件不能影响 sandbox 取值 */
  const SANDBOX = 'allow-scripts allow-forms allow-downloads';

  const p = untrack(() => plugin);
  let phase = $state<'loading' | 'ready' | 'timeout'>('loading');
  let height = $state(Math.max(HEIGHT_MIN, 560));
  let attempt = $state(0);
  let visible = $state(typeof document === 'undefined' || document.visibilityState === 'visible');
  let frame = $state<HTMLIFrameElement>();

  const bridge = new PluginBridge(
    bridgeDeps(p, {
      onReady: () => (phase = 'ready'),
      onResize: (h) => (height = h),
      onToast: (text) => toasts.info(`${p.name}：${text}`),
      onNavigate: (to) => navigate(`/plugins/${encodeURIComponent(p.plugin_id)}${to === '/' ? '' : to}`),
      onTimeout: () => (phase = 'timeout'),
    }),
  );

  /* 首帧 src 只在每次重建时计算一次；之后的路径变化走 ui.route，不重载 iframe */
  const src = $derived.by(() => {
    void attempt;
    return untrack(() => pluginFrameSrc(p.ui!.entry_url, hostSettings(), path));
  });

  /*
   * iframe 一插入 DOM 就 attach（不能等 load 事件：插件脚本在 load 之前就会发
   * hello）。contentWindow 是稳定的 WindowProxy，从 about:blank 导航到 entry 不变。
   */
  $effect(() => {
    void attempt;
    if (frame) bridge.attach(frame.contentWindow);
  });

  function retry() {
    phase = 'loading';
    attempt++;
  }

  /* 主题等变化 → ui.settings（读这些响应式值即建立依赖） */
  $effect(() => {
    void prefs.resolvedTheme;
    void prefs.resolvedMotion;
    void prefs.density;
    void prefs.accent;
    void visible;
    untrack(() => bridge.settings({ ...hostSettings(), visible }));
  });

  /* 浏览器前进后退 / 插件内导航回写后的路径 → ui.route */
  let lastPath = untrack(() => path);
  $effect(() => {
    if (path === lastPath) return;
    lastPath = path;
    bridge.route(path);
  });

  const onVisibility = () => (visible = document.visibilityState === 'visible');
  window.addEventListener('message', bridge.onWindowMessage);
  document.addEventListener('visibilitychange', onVisibility);
  onDestroy(() => {
    window.removeEventListener('message', bridge.onWindowMessage);
    document.removeEventListener('visibilitychange', onVisibility);
    bridge.dispose();
  });
</script>

<div class="host" class:ready={phase === 'ready'}>
  {#if phase === 'timeout'}
    <div class="state">
      <ErrorState message="{p.name} 的页面没有响应" />
      <Button variant="soft" icon="refresh" onclick={retry}>重试</Button>
    </div>
  {:else}
    {#if phase === 'loading'}
      <div class="skeleton" aria-hidden="true"><Skeleton height={height} radius={20} label="正在打开 {p.name}" /></div>
    {/if}
    {#key attempt}
      <iframe
        bind:this={frame}
        title={p.name}
        {src}
        sandbox={SANDBOX}
        referrerpolicy="no-referrer"
        allow=""
        loading="eager"
        style:height="{height}px"
      ></iframe>
    {/key}
  {/if}
</div>

<style>
  .host {
    position: relative;
    min-height: 240px;
  }
  iframe {
    display: block;
    width: 100%;
    border: 0;
    border-radius: var(--r-lg);
    background: var(--surface);
    box-shadow: var(--shadow-1);
    opacity: 0;
    transition: opacity var(--dur-2) var(--ease);
  }
  .ready iframe {
    opacity: 1;
  }
  .skeleton {
    position: absolute;
    inset: 0;
    pointer-events: none;
  }
  .state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--s-3);
    padding: var(--s-6);
    border-radius: var(--r-lg);
    background: var(--surface);
  }
</style>
