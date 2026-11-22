<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ErrorState · 区域错误 / 权限 / 404（SPEC §8）
  ───────────────────────────────────────────────────────────────
  kind       error（sad 表情 + 重试）| permission（不提供重试）| notfound（回主页）
  message    人话（来自 lib/errors 的 describeError(err).message）
  requestId  5xx 时可复制
  fromPlugin 插件原文（纯文本，标"来自插件"）

  {:else if r.error}
    {@const v = describeError(r.error)}
    <ErrorState message={v.message} requestId={v.requestId} onretry={r.refresh} />
-->
<script lang="ts">
  import Button from './Button.svelte';
  import CopyButton from './CopyButton.svelte';
  import Mood from './Mood.svelte';

  interface Props {
    kind?: 'error' | 'permission' | 'notfound';
    message?: string;
    /** permission：所需角色名，如"管理员" */
    role?: string;
    requestId?: string;
    fromPlugin?: string;
    onretry?: () => void;
    compact?: boolean;
  }
  let { kind = 'error', message, role, requestId, fromPlugin, onretry, compact = false }: Props = $props();

  const text = $derived(
    message ??
      (kind === 'permission'
        ? `这里需要${role ?? '更高'}权限`
        : kind === 'notfound'
          ? '这里什么也没有'
          : '加载失败了'),
  );
</script>

<div class="err" class:compact role={kind === 'error' ? 'alert' : undefined}>
  <Mood mood={kind === 'error' ? 'bad' : 'warn'} size={compact ? 'md' : 'lg'} />
  <p class="title">{text}</p>
  {#if fromPlugin}
    <p class="plugin"><span class="tag">来自插件</span>{fromPlugin}</p>
  {/if}
  {#if requestId}
    <p class="rid">请求编号 <span class="mono">{requestId}</span><CopyButton text={requestId} label="复制请求编号" /></p>
  {/if}
  {#if kind === 'error' && onretry}
    <Button variant="ghost" icon="refresh" onclick={onretry}>重试</Button>
  {:else if kind === 'notfound'}
    <Button variant="primary" href="/">回主页</Button>
  {/if}
</div>

<style>
  .err {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: var(--s-8) var(--s-5);
    text-align: center;
  }
  .compact {
    padding: var(--s-5) var(--s-4);
  }
  .title {
    margin-top: 8px;
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .plugin {
    max-width: 520px;
    color: var(--text-2);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .tag {
    margin-right: 6px;
    padding: 1px 6px;
    border-radius: 6px;
    background: var(--surface-3);
    color: var(--text-3);
    font-size: var(--fs-2xs);
    font-weight: var(--fw-semibold);
  }
  .rid {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
</style>
