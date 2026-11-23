<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Outlet · 渲染当前路由的页面
  ───────────────────────────────────────────────────────────────
  - 动态 import 页面组件（模块缓存），加载中显示骨架
  - perm 不满足：渲染权限态（不跳走，SPEC §7）
  - <svelte:boundary> 兜底：页面渲染抛错时显示 ErrorState，可重试
  - 渲染完成后 router.settle()：恢复/归顶滚动、焦点移到标题
  页面组件收到 props：{ params }（路由参数，如 { pluginId, rest }）
-->
<script lang="ts">
  import { tick, type Component } from 'svelte';
  import { Skeleton } from '$ui';
  import { page } from '$lib/page.svelte';
  import { router, type Match } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';

  let errorMod: Promise<typeof import('$ui/ErrorState.svelte')> | null = null;
  const loadErrorState = () => (errorMod ??= import('$ui/ErrorState.svelte'));

  interface Props {
    match: Match;
  }
  let { match }: Props = $props();

  const cache = new Map<string, Component<{ params: Record<string, string> }>>();
  let Page = $state<Component<{ params: Record<string, string> }> | null>(null);
  let loadFailed = $state(false);

  const allowed = $derived(session.can(match.route.perm));

  /* 新页面挂载前复位标题，页面初始化时可再 page.setTitle() 覆盖 */
  $effect.pre(() => {
    page.routeTitle = match.route.title;
    page.setTitle(null);
  });

  $effect(() => {
    const route = match.route;
    const version = router.version;
    loadFailed = false;
    const hit = cache.get(route.pattern);
    if (hit) {
      Page = hit;
      void tick().then(() => router.version === version && router.settle());
      return;
    }
    Page = null;
    route.load().then(
      (m) => {
        cache.set(route.pattern, m.default);
        if (router.version !== version) return;
        Page = m.default;
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
{:else if Page}
  {#key match.route.pattern}
    <svelte:boundary>
      <Page params={match.params} />
      {#snippet failed(_error, reset)}
        {#await loadErrorState() then mod}<mod.default message="这个页面出错了" onretry={reset} />{/await}
      {/snippet}
    </svelte:boundary>
  {/key}
{:else}
  <div class="loading"><Skeleton height={28} width="40%" /><Skeleton lines={4} /></div>
{/if}

<style>
  .loading {
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding-top: 8px;
  }
</style>
