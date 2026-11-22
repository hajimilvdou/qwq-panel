<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Skeleton · 骨架屏（首次加载；150ms 内不出现，避免快速请求闪一下）
  ───────────────────────────────────────────────────────────────
  <Skeleton lines={3} />                        文本段落
  <Skeleton width="100%" height={120} radius={20} />  卡片块
  形状尽量贴合真实内容。动效 off 档时为静态色块。
-->
<script lang="ts">
  interface Props {
    width?: string;
    height?: number;
    radius?: number;
    lines?: number;
    delay?: number;
    label?: string;
  }
  let { width = '100%', height = 14, radius = 8, lines = 1, delay = 150, label = '加载中' }: Props = $props();

  let shown = $state(false);
  $effect(() => {
    const t = setTimeout(() => (shown = true), delay);
    return () => clearTimeout(t);
  });
</script>

<div class="sk" class:shown role="status" aria-label={label} aria-busy="true">
  {#each Array.from({ length: lines }, (_, i) => i) as i (i)}
    <span
      class="bar loop"
      style:width={lines > 1 && i === lines - 1 ? '62%' : width}
      style:height="{height}px"
      style:border-radius="{radius}px"
    ></span>
  {/each}
</div>

<style>
  .sk {
    display: flex;
    flex-direction: column;
    gap: 10px;
    visibility: hidden;
  }
  .shown {
    visibility: visible;
  }
  .bar {
    display: block;
    max-width: 100%;
    background: linear-gradient(
      90deg,
      var(--surface-3) 25%,
      color-mix(in oklab, var(--surface-3) 55%, var(--surface)) 50%,
      var(--surface-3) 75%
    );
    background-size: 200% 100%;
    animation: qwq-shimmer 1.4s linear infinite;
  }
</style>
