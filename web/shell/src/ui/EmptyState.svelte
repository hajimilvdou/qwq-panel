<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  EmptyState · 空状态（表情 + 一句话 + 至多一个动作）
  ───────────────────────────────────────────────────────────────
  <EmptyState title="还没有安装应用" description="装上系统监控，主页就能看到服务器状态">
    {#snippet action()}<Button variant="primary" href="/apps">去应用中心</Button>{/snippet}
  </EmptyState>
  compact：卡片内的小号版本
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import Mood from './Mood.svelte';
  import type { Mood as MoodT } from './types';

  interface Props {
    title: string;
    description?: string;
    mood?: MoodT;
    compact?: boolean;
    action?: Snippet;
  }
  let { title, description, mood = 'ok', compact = false, action }: Props = $props();
</script>

<div class="empty" class:compact>
  <Mood {mood} size={compact ? 'md' : 'lg'} />
  <p class="title">{title}</p>
  {#if description}<p class="desc">{description}</p>{/if}
  {#if action}<div class="act">{@render action()}</div>{/if}
</div>

<style>
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    padding: var(--s-8) var(--s-5);
    text-align: center;
  }
  .compact {
    padding: var(--s-6) var(--s-4);
  }
  .title {
    margin-top: 10px;
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .desc {
    max-width: 420px;
    color: var(--text-2);
  }
  .act {
    margin-top: 12px;
  }
</style>
