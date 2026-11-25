<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Outlet · 渲染当前路由的页面（零白屏闪烁 + 空闲预加载核心路由 chunk）
-->
<script lang="ts">
  import { tick, type Component } from 'svelte';
  import { Skeleton } from '$ui';
  import { page } from '$lib/page.svelte';
  import { router, type Match } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { routes } from './routes';

  let errorMod: Promise<typeof import('$ui/ErrorState.svelte')> | null = null;
  const loadErrorState = () => (errorMod ??= import('$ui/ErrorState.svelte'));

  interface Props {
    match: Match;
  }
  let { match }: Props = $props();

  type PageComp = Component<{ params: Record<string, string> }>;
  const cache = new Map<string, PageComp>();
  let rendered = $state<{ pattern: string; params: Record<string, string>; Comp: PageComp } | null>(null);
  let loadFailed = $state(false);
  let preloaded = false;

  const allowed = $derived(session.can(match.route.perm));

  $effect.pre(() => {
    page.routeTitle = match.route.title;
    page.setTitle(null);
  });

  /* 首屏渲染完成后空闲预取高频核心路由，切页时 0ms 直接命中 cache */
  $effect(() => {
    if (preloaded || !session.user) return;
    preloaded = true;
    const warmPatterns = ['/', '/activity', '/agent', '/apps', '/plugins/:pluginId/*', '/settings/:section'];
    const run = () => {
      for (const pat of warmPatterns) {
        if (cache.has(pat)) continue;
        const def = routes.find((r) => r.pattern === pat);
        if (!def || !session.can(def.perm)) continue;
        void def.load().then(
          (m) => cache.set(pat, m.default),
          () => {},
        );
      }
    };
    const w = window as Window & { requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => number };
    if (typeof w.requestIdleCallback === 'function') w.requestIdleCallback(run, { timeout: 1500 });
    else setTimeout(run, 400);
  });

  $effect(() => {
    const route = match.route;
    const params = match.params;
    const version = router.version;
    loadFailed = false;
    const hit = cache.get(route.pattern);
    if (hit) {
      rendered = { pattern: route.pattern, params, Comp: hit };
      void tick().then(() => router.version === version && router.settle());
      return;
    }
    /* 不再清空 rendered：保留上一页直到新 chunk 就绪，彻底消灭先白屏后弹字 */
    route.load().then(
      (m) => {
        cache.set(route.pattern, m.default);
        if (router.version !== version) return;
        rendered = { pattern: route.pattern, params, Comp: m.default };
        void tick().then(() => router.settle());
      },
      () => {
        if (router.version === version) loadFailed = true;
      },
    );
  });

  function retryLoad() {
    loadFailed = false;
    router.navigate(router.path + router.search, { replace: true });
  }
</script>

{#if !allowed}
  {#await loadErrorState() then mod}<mod.default kind="permission" />{/await}
{:else if loadFailed}
  {#await loadErrorState() then mod}<mod.default message="页面没能加载，可能是网络问题或面板刚升级" onretry={retryLoad} />{/await}
{:else if rendered}
  {#key rendered.pattern}
    <div class="route-view">
      <svelte:boundary>
        <rendered.Comp params={rendered.params} />
        {#snippet failed(_error, reset)}
          {#await loadErrorState() then mod}<mod.default message="这个页面出错了" onretry={reset} />{/await}
        {/snippet}
      </svelte:boundary>
    </div>
  {/key}
{:else}
  <div class="loading"><Skeleton height={28} width="40%" /><Skeleton lines={4} /></div>
{/if}

<style>
  .route-view {
    animation: qwq-fade-in 140ms var(--ease-out);
  }
  .loading {
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding-top: 8px;
  }
</style>
