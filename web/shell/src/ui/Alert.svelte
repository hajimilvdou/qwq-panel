<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Alert · 行内提示条（表单错误、冲突条、警示）
  ───────────────────────────────────────────────────────────────
  <Alert tone="bad">用户名或密码不对</Alert>
  <Alert tone="warn" title="已被 Alice 修改">{#snippet actions()}<Button …/>{/snippet}</Alert>
  tone=bad 时 role=alert（读屏立即播报），其余 role=status。
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';

  interface Props {
    tone?: 'bad' | 'warn' | 'info' | 'ok';
    title?: string;
    children?: Snippet;
    actions?: Snippet;
  }
  let { tone = 'bad', title, children, actions }: Props = $props();

  const ICONS: Record<NonNullable<Props['tone']>, IconName> = { bad: 'alert', warn: 'alert', info: 'info', ok: 'check-circle' };
</script>

<div class="alert {tone}" role={tone === 'bad' ? 'alert' : 'status'}>
  <span class="ic"><Icon name={ICONS[tone]} size={16} /></span>
  <div class="body">
    {#if title}<strong>{title}</strong>{/if}
    {#if children}<div>{@render children()}</div>{/if}
  </div>
  {#if actions}<div class="actions">{@render actions()}</div>{/if}
</div>

<style>
  .alert {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border-radius: var(--r-sm);
    font-size: var(--fs-sm);
    line-height: 1.5;
  }
  .ic {
    display: grid;
    flex: none;
    padding-top: 2px;
  }
  .body {
    display: flex;
    flex: 1;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .actions {
    display: flex;
    flex: none;
    gap: 6px;
    align-self: center;
  }
  .bad {
    background: var(--bad-soft);
    color: var(--bad-text);
  }
  .warn {
    background: var(--warn-soft);
    color: var(--warn-text);
  }
  .info {
    background: var(--info-soft);
    color: var(--info-text);
  }
  .ok {
    background: var(--ok-soft);
    color: var(--ok-text);
  }
</style>
