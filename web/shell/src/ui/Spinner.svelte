<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Spinner · 小型转圈（按钮内、行内加载）。整页加载请用 Skeleton。
  <Spinner label="正在加载" />
-->
<script lang="ts">
  interface Props {
    size?: number;
    label?: string;
  }
  let { size = 18, label = '加载中' }: Props = $props();
</script>

<span class="sp loop" style:--size="{size}px" role="status" aria-label={label}></span>

<style>
  .sp {
    display: inline-block;
    flex: none;
    width: var(--size);
    height: var(--size);
    border: 2px solid color-mix(in oklab, currentColor 25%, transparent);
    border-top-color: currentColor;
    border-radius: 50%;
    color: var(--accent);
    animation: qwq-spin 0.8s linear infinite;
  }
</style>
