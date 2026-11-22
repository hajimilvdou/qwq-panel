<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- TabBar · ≤860 的底部快捷导航（5 项） -->
<script lang="ts">
  import { router } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { Icon } from '$ui';
  import { isActive, TABS } from './nav';

  const tabs = $derived(TABS.filter((t) => session.can(t.perm)));
</script>

<nav class="tabbar" aria-label="快捷导航">
  {#each tabs as t (t.href)}
    <a href={t.href} aria-current={isActive(t.href, router.path) ? 'page' : undefined}>
      <Icon name={t.icon} size={22} />
      <span>{t.label}</span>
    </a>
  {/each}
</nav>

<style>
  .tabbar {
    display: none;
  }
  @media (max-width: 860px) {
    .tabbar {
      position: fixed;
      inset: auto 0 0 0;
      z-index: var(--z-sticky);
      display: flex;
      height: calc(var(--tabbar-h) + env(safe-area-inset-bottom));
      padding-bottom: env(safe-area-inset-bottom);
      background: color-mix(in oklab, var(--surface) 88%, transparent);
      backdrop-filter: blur(14px) saturate(1.4);
      border-top: 1px solid var(--line);
    }
    a {
      display: flex;
      flex: 1;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 2px;
      color: var(--text-3);
      font-size: var(--fs-2xs);
      font-weight: var(--fw-medium);
    }
    a[aria-current='page'] {
      color: var(--accent-text);
      font-weight: var(--fw-semibold);
    }
  }
</style>
