<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置（SPEC §7）
  ───────────────────────────────────────────────────────────────
  左侧二级导航（sections.ts，无权分项隐藏）；右侧按 :section 懒加载分项组件。
  ≤860：导航收为顶部横向滚动的分项条（/settings 恒重定向到 account，无独立列表页）。
  直接访问无权分项 → 权限态；未知分项 → 404 态。
-->
<script lang="ts">
  import type { Component } from 'svelte';
  import { ErrorState, Skeleton } from '$ui';
  import { page } from '$lib/page.svelte';
  import { session } from '$lib/session.svelte';
  import { SETTINGS_SECTIONS } from './sections';

  let { params }: { params: Record<string, string> } = $props();

  type SectionId = (typeof SETTINGS_SECTIONS)[number]['id'];
  const LOADERS: Record<SectionId, () => Promise<{ default: Component }>> = {
    account: () => import('./AccountSection.svelte'),
    appearance: () => import('./AppearanceSection.svelte'),
    users: () => import('./UsersSection.svelte'),
    delegations: () => import('./DelegationsSection.svelte'),
    ai: () => import('./AiSection.svelte'),
    system: () => import('./SystemSection.svelte'),
  };

  const visible = $derived(SETTINGS_SECTIONS.filter((s) => !('perm' in s) || session.can(s.perm)));
  const current = $derived(SETTINGS_SECTIONS.find((s) => s.id === params.section));
  const allowed = $derived(!!current && (!('perm' in current) || session.can(current.perm)));

  $effect(() => {
    if (current) page.setTitle(`设置 · ${current.title}`);
  });
</script>

<div class="settings">
  <nav class="side" aria-label="设置分项">
    <ul>
      {#each visible as s (s.id)}
        <li>
          <a href="/settings/{s.id}" aria-current={s.id === params.section ? 'page' : undefined}>{s.title}</a>
        </li>
      {/each}
    </ul>
  </nav>

  <section class="content" aria-label={current?.title ?? '设置'}>
    {#if !current}
      <ErrorState kind="notfound" message="没有这个设置项" />
    {:else if !allowed}
      <ErrorState kind="permission" role={current.id === 'ai' ? '管理员' : undefined} />
    {:else}
      {#key current.id}
        {#await LOADERS[current.id]()}
          <Skeleton lines={4} height={18} />
        {:then mod}
          <mod.default />
        {:catch}
          <ErrorState message="这个设置页没能加载" onretry={() => location.reload()} />
        {/await}
      {/key}
    {/if}
  </section>
</div>

<style>
  .settings {
    display: grid;
    grid-template-columns: 200px minmax(0, 1fr);
    gap: var(--s-6);
    align-items: start;
    max-width: 1040px;
  }
  .side {
    position: sticky;
    top: calc(var(--top-h) + var(--s-5));
  }
  ul {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  a {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 40px;
    padding: 0 12px;
    border-radius: var(--r-sm);
    color: var(--text-2);
    font-weight: var(--fw-medium);
    text-decoration: none;
  }
  a:hover {
    background: var(--surface-3);
    color: var(--text);
  }
  a[aria-current='page'] {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .content {
    display: flex;
    flex-direction: column;
    gap: var(--s-5);
    min-width: 0;
  }

  /* 窄屏：分项条横向滚动 */
  @media (max-width: 860px) {
    .settings {
      grid-template-columns: 1fr;
      gap: var(--s-4);
    }
    .side {
      position: static;
      margin: 0 calc(var(--s-4) * -1);
      overflow-x: auto;
    }
    ul {
      flex-direction: row;
      padding: 0 var(--s-4);
    }
    a {
      white-space: nowrap;
    }
  }
</style>
