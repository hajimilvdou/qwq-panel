<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  PluginFrame · 单个插件 iframe + 宿主桥（ENG §9 + STEP-16 + Keep-Alive）
  ───────────────────────────────────────────────────────────────
  支持保活驻留：active=false 时隐藏且向插件下发 visible=false，切回时 0ms 显现。
  attempt / reloadTick 递增时重建 <iframe> 并重新握手。
  沙箱内 ui.confirm 由本宿主组件弹出统一风格的 <ConfirmDialog>，绝不开启 allow-modals。
-->
<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { Button, ConfirmDialog, ErrorState, Spinner } from '$ui';
  import { system } from '$api/endpoints';
  import type { Plugin } from '$api/types';
  import { PluginBridge, HEIGHT_MIN, type BridgeConfirmRequest, type HostViewport } from '$lib/plugin-host';
  import { bridgeDeps, hostSettings, pluginFrameSrc } from '$lib/plugin-host/wiring';
  import { prefs } from '$lib/prefs.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { navigate } from '$lib/router.svelte';
  import { toasts } from '$lib/toast.svelte';
  import { pluginFramePool } from './plugin-frame-pool.svelte';

  interface Props {
    plugin: Plugin;
    path: string;
    active?: boolean;
    reloadTick?: number;
  }
  let { plugin, path, active = true, reloadTick = 0 }: Props = $props();

  /* Shell 固定策略：插件不能影响 sandbox 取值 */
  const SANDBOX = 'allow-scripts allow-forms allow-downloads';

  const p = untrack(() => plugin);
  const sysInfo = useResource({
    key: 'system.info',
    load: () => system.info(),
  });
  let phase = $state<'loading' | 'ready' | 'timeout'>('loading');
  let height = $state(Math.max(HEIGHT_MIN, 420));
  let attempt = $state(0);
  let modalOpen = $state(false);
  let docVisible = $state(typeof document === 'undefined' || document.visibilityState === 'visible');
  let frame = $state<HTMLIFrameElement>();

  const effectiveVisible = $derived(docVisible && active);
  const activeModal = $derived(modalOpen && active);

  $effect(() => {
    const open = activeModal;
    untrack(() => pluginFramePool.setModalOpen(open));
  });

  function dismissModal() {
    bridge.dismissModal();
  }

  /* 宿主受控确认弹窗（代理沙箱内 ui.confirm） */
  interface PendingConfirm extends BridgeConfirmRequest {
    resolve: (ok: boolean) => void;
  }
  let confirmOpen = $state(false);
  let confirmReq = $state<PendingConfirm | null>(null);

  function settleConfirm(ok: boolean) {
    const req = confirmReq;
    confirmReq = null;
    confirmOpen = false;
    req?.resolve(ok);
  }

  $effect(() => {
    if (!confirmOpen && confirmReq) {
      const req = confirmReq;
      confirmReq = null;
      req.resolve(false);
    }
  });

  const bridge = new PluginBridge(
    bridgeDeps(p, {
      onReady: () => (phase = 'ready'),
      onResize: (h) => (height = Math.max(HEIGHT_MIN, h + 12)),
      onModal: (open) => (modalOpen = open),
      onToast: (text) => toasts.info(`${p.name}：${text}`),
      onNavigate: (to) => navigate(`/plugins/${encodeURIComponent(p.plugin_id)}${to === '/' ? '' : to}`),
      onOpenPlugin: (targetPid, subPath) =>
        navigate(`/plugins/${encodeURIComponent(targetPid)}${subPath && subPath !== '/' ? subPath : ''}`),
      onTimeout: () => (phase = 'timeout'),
      onConfirm: (req) =>
        new Promise<boolean>((resolve) => {
          confirmReq = { ...req, resolve };
          confirmOpen = true;
        }),
    }),
  );

  /* 外部主动触发重载（如强制接管/恢复安全管理器后刷新安全插件） */
  let lastReloadTick = untrack(() => reloadTick);
  $effect(() => {
    if (reloadTick === lastReloadTick) return;
    lastReloadTick = reloadTick;
    untrack(() => retry());
  });

  /* 首帧 src 只在每次重建时计算一次；之后的路径变化走 ui.route，不重载 iframe */
  const src = $derived.by(() => {
    void attempt;
    return untrack(() => pluginFrameSrc(p.ui!.entry_url, hostSettings(), path));
  });

  $effect(() => {
    void attempt;
    if (frame) bridge.attach(frame.contentWindow);
  });

  function retry() {
    settleConfirm(false);
    phase = 'loading';
    attempt++;
  }

  /* 主题与可见性变化 → ui.settings */
  $effect(() => {
    void prefs.resolvedTheme;
    void prefs.resolvedMotion;
    void prefs.density;
    void prefs.accent;
    const vis = effectiveVisible;
    void sysInfo.data;
    untrack(() => bridge.settings({ ...hostSettings(), visible: vis }));
  });

  /* 浏览器前进后退 / 插件内导航回写后的路径 → ui.route */
  let lastPath = untrack(() => path);
  $effect(() => {
    if (path === lastPath) return;
    lastPath = path;
    bridge.route(path);
  });

  /* 跨 iframe 视口同步 */
  function computeViewport(el: HTMLIFrameElement): HostViewport {
    const rect = el.getBoundingClientRect();
    const winH = window.innerHeight || document.documentElement.clientHeight || 720;
    const winW = window.innerWidth || document.documentElement.clientWidth || 1024;
    const offsetTopPx = Math.max(0, Math.round(-rect.top));
    const visTop = Math.max(0, rect.top);
    const visBot = Math.min(winH, rect.bottom);
    const visibleTop = offsetTopPx;
    const visibleHeight = Math.max(
      0,
      Math.min(Math.round(visBot - visTop), Math.max(0, Math.round(rect.height - offsetTopPx))),
    );
    const visibleCenterY = visibleTop + Math.round(visibleHeight / 2);
    return {
      offsetTopPx,
      viewportHeightPx: visibleHeight,
      visibleTop,
      visibleHeight,
      visibleCenterY,
      scroll_top: offsetTopPx,
      visible_height: visibleHeight,
      viewport_width: Math.round(winW),
    };
  }

  let vpRaf = 0;
  let lastVpKey = '';
  function syncViewport(force = false) {
    if (!frame || !active) return;
    const vp = computeViewport(frame);
    const key = `${vp.offsetTopPx}:${vp.viewportHeightPx}:${vp.viewport_width}`;
    if (!force && key === lastVpKey) return;
    lastVpKey = key;
    bridge.viewport(vp);
  }
  function scheduleViewportSync() {
    if (vpRaf || !active) return;
    vpRaf = requestAnimationFrame(() => {
      vpRaf = 0;
      syncViewport(false);
    });
  }

  $effect(() => {
    void height;
    const isAct = active;
    if (phase === 'ready' && isAct && frame) {
      untrack(() => requestAnimationFrame(() => syncViewport(true)));
    }
  });

  const onVisibility = () => (docVisible = document.visibilityState === 'visible');
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Escape' && activeModal) dismissModal();
  };
  window.addEventListener('message', bridge.onWindowMessage);
  window.addEventListener('scroll', scheduleViewportSync, { passive: true });
  window.addEventListener('resize', scheduleViewportSync, { passive: true });
  window.addEventListener('keydown', onKeyDown);
  document.addEventListener('visibilitychange', onVisibility);
  onDestroy(() => {
    if (vpRaf) cancelAnimationFrame(vpRaf);
    if (modalOpen) pluginFramePool.setModalOpen(false);
    settleConfirm(false);
    window.removeEventListener('message', bridge.onWindowMessage);
    window.removeEventListener('scroll', scheduleViewportSync);
    window.removeEventListener('resize', scheduleViewportSync);
    window.removeEventListener('keydown', onKeyDown);
    document.removeEventListener('visibilitychange', onVisibility);
    bridge.dispose();
  });
</script>

{#if activeModal}
  <div class="p-scrim" role="presentation" onclick={dismissModal}></div>
{/if}

<div class="host" class:ready={phase === 'ready'} class:modal-open={activeModal}>
  {#if phase === 'timeout'}
    <div class="state">
      <ErrorState message="{p.name} 的页面没有响应" />
      <Button variant="soft" icon="refresh" onclick={retry}>重试</Button>
    </div>
  {:else}
    {#if phase === 'loading'}
      <div class="frame-loader" role="status">
        <Spinner size={20} />
        <span class="small muted">正在加载 {p.name}…</span>
      </div>
    {/if}
    {#key attempt}
      <iframe
        bind:this={frame}
        title={p.name}
        {src}
        sandbox={SANDBOX}
        referrerpolicy="no-referrer"
        allow=""
        scrolling="no"
        loading="eager"
        style:height="{height}px"
      ></iframe>
    {/key}
  {/if}
</div>

<ConfirmDialog
  bind:open={confirmOpen}
  title={confirmReq?.title ?? '确认操作'}
  tone={confirmReq?.danger ? 'danger' : 'primary'}
  confirmLabel={confirmReq?.confirmLabel || '确定'}
  onconfirm={() => settleConfirm(true)}
  oncancel={() => settleConfirm(false)}
>
  {#if confirmReq?.body}<p class="confirm-body">{confirmReq.body}</p>{/if}
</ConfirmDialog>

<style>
  .p-scrim {
    position: fixed;
    inset: 0;
    z-index: 44;
    background: rgb(21 18 16 / 0.5);
  }
  .host {
    position: relative;
    min-height: 220px;
  }
  .host.modal-open {
    z-index: 45;
  }
  iframe {
    display: block;
    width: 100%;
    border: 0;
    overflow: hidden;
    background: var(--bg);
    opacity: 0;
    transition: opacity var(--dur-2) var(--ease);
  }
  .ready iframe {
    opacity: 1;
  }
  .frame-loader {
    position: absolute;
    inset: 0 0 auto 0;
    height: 220px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
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
  .confirm-body {
    margin: 0;
    white-space: pre-line;
  }
</style>
