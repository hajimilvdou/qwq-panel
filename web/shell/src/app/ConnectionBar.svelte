<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- ConnectionBar · 宿主断线超过 5 秒：顶栏下细条"连接中断，正在重连…"；恢复后消失 -->
<script lang="ts">
  import { events } from '$lib/events.svelte';
</script>

{#if events.offline}
  <div class="bar" role="status">
    <span class="dot loop" aria-hidden="true"></span>
    {events.degraded ? '打开的页面太多，实时更新已改为定时刷新' : '连接中断，正在重连…'}
    {#if !events.degraded}
      <button type="button" onclick={() => events.reconnectNow()}>立即重试</button>
    {/if}
  </div>
{/if}

<style>
  .bar {
    position: sticky;
    top: var(--top-h);
    z-index: var(--z-sticky);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    height: 32px;
    background: var(--warn-soft);
    color: var(--warn-text);
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--warn);
    animation: pulse 1.4s var(--ease) infinite;
  }
  button {
    text-decoration: underline;
    font-weight: var(--fw-semibold);
  }
  @keyframes pulse {
    50% {
      opacity: 0.35;
    }
  }
</style>
