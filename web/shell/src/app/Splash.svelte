<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Splash · 启动中（bootstrap 未完成）：只有品牌表情，150ms 后才出现 -->
<script lang="ts">
  import { Mood } from '$ui';

  let shown = $state(false);
  $effect(() => {
    const t = setTimeout(() => (shown = true), 150);
    return () => clearTimeout(t);
  });
</script>

<div class="splash" class:shown role="status" aria-label="正在启动">
  <Mood size="lg" />
</div>

<style>
  .splash {
    display: grid;
    place-items: center;
    min-height: 100dvh;
    opacity: 0;
    transition: opacity var(--dur-3) var(--ease);
  }
  .shown {
    opacity: 1;
  }
</style>
