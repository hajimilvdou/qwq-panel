<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  AuthLayout · 登录类页面外壳（SPEC §6）：单栏居中 420 卡片、环境光、大表情
  ───────────────────────────────────────────────────────────────
  <AuthLayout title="欢迎回来" subtitle="登录 qwq 面板">…表单…</AuthLayout>
  标题即页面 h1（#page-title，路由切换后焦点落在这里）。
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Mood, type MoodKind } from '$ui';

  interface Props {
    title: string;
    subtitle?: string;
    mood?: MoodKind;
    children: Snippet;
    footer?: Snippet;
  }
  let { title, subtitle, mood = 'ok', children, footer }: Props = $props();
</script>

<div class="ambient" aria-hidden="true"></div>
<main class="auth">
  <div class="card">
    <header>
      <Mood {mood} size="lg" />
      <h1 id="page-title" tabindex="-1">{title}</h1>
      {#if subtitle}<p class="sub">{subtitle}</p>{/if}
    </header>
    {@render children()}
  </div>
  {#if footer}<footer>{@render footer()}</footer>{/if}
</main>

<style>
  .auth {
    position: relative;
    z-index: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--s-4);
    min-height: 100dvh;
    padding: var(--s-6) var(--s-4);
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: var(--s-5);
    width: min(420px, 100%);
    padding: var(--s-7) var(--s-6) var(--s-6);
    border: 1px solid color-mix(in oklab, var(--line) 70%, transparent);
    border-radius: var(--r-xl);
    background: var(--surface);
    box-shadow: var(--shadow-2);
    animation: qwq-rise-in var(--dur-3) var(--ease-out);
  }
  header {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--s-2);
    text-align: center;
  }
  h1 {
    margin: var(--s-2) 0 0;
    font-size: var(--fs-2xl);
    font-weight: var(--fw-bold);
    outline: none;
  }
  .sub {
    margin: 0;
    color: var(--text-2);
  }
  footer {
    color: var(--text-3);
    font-size: var(--fs-xs);
    text-align: center;
  }
</style>
