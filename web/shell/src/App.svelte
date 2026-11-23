<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  App · 根组件：偏好落到 <html>、启动画面、路由守卫、布局选择
  ───────────────────────────────────────────────────────────────
  守卫顺序（ENG §2）：bootstrap 完成 → 重定向 → public 放行 → 未登录去
  /login?next= → perm 不满足渲染权限态（在 Outlet 里）。
-->
<script lang="ts">
  import Outlet from './app/Outlet.svelte';
  import Splash from './app/Splash.svelte';
  import { page } from '$lib/page.svelte';
  import { prefs } from '$lib/prefs.svelte';
  import { loginUrl, navigate, router, safeNext } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';

  $effect(() => prefs.apply());

  const match = $derived(router.match);
  const route = $derived(match?.route);

  /* 守卫：只决定"要不要跳走"；渲染分支见下方模板 */
  $effect(() => {
    if (!route || session.status === 'booting' || session.status === 'error') return;
    const here = router.path + router.search;
    const st = session.status;

    if (route.redirect) return navigate(route.redirect, { replace: true });
    if (st === 'uninitialized') {
      if (router.path !== '/setup') navigate('/setup' + location.hash, { replace: true });
      return;
    }
    if (router.path === '/setup') return navigate(st === 'authenticated' ? '/' : '/login', { replace: true });
    if (route.public) {
      if (st === 'authenticated' && router.path === '/login') navigate(safeNext(router.query.get('next')), { replace: true });
      return;
    }
    if (st !== 'authenticated') navigate(loginUrl(here), { replace: true });
  });

  $effect(() => {
    document.title = page.title ? `${page.title} · qwq` : 'qwq';
  });

  /* 登录后再加载主壳：匿名登录页 / 启动画面不拉取侧栏、顶栏与悬浮浮层 */
  let shellPromise: Promise<typeof import('./app/AppShell.svelte')> | null = null;
  const loadShell = () => (shellPromise ??= import('./app/AppShell.svelte'));
  let errorStatePromise: Promise<typeof import('$ui/ErrorState.svelte')> | null = null;
  const loadErrorState = () => (errorStatePromise ??= import('$ui/ErrorState.svelte'));
  let toasterPromise: Promise<typeof import('$ui/Toaster.svelte')> | null = null;
  const loadToaster = () => (toasterPromise ??= import('$ui/Toaster.svelte'));

  const ready = $derived(
    !!route &&
      !route.redirect &&
      (route.public ? session.status !== 'booting' : session.status === 'authenticated'),
  );
</script>

{#if session.status === 'error'}
  <main class="center">
    {#await loadErrorState() then mod}
      <mod.default message="连不上服务器" onretry={() => location.reload()} />
    {/await}
  </main>
{:else if !ready || !match}
  <Splash />
{:else if match.route.bare}
  <Outlet {match} />
{:else}
  {#await loadShell()}
    <Splash />
  {:then shell}
    <shell.default>
      <Outlet {match} />
    </shell.default>
  {/await}
{/if}

{#if toasts.items.length > 0}
  {#await loadToaster() then mod}
    <mod.default items={toasts.items} ondismiss={(id) => toasts.dismiss(id)} />
  {/await}
{/if}

<style>
  .center {
    display: grid;
    place-items: center;
    min-height: 100dvh;
  }
</style>
