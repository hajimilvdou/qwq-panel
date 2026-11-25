<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  PluginDetail · 旧 /apps/:pluginId 路由兼容重定向
  ───────────────────────────────────────────────────────────────
  概览页已移除，设置与日志统一归入 /plugins/:pluginId 工作区标签页。
-->
<script lang="ts">
  import { navigate, router } from '$lib/router.svelte';

  let { id }: { id: string } = $props();

  $effect(() => {
    const rawTab = router.query.get('tab');
    const suffix = rawTab === 'settings' || rawTab === 'logs' ? `?tab=${rawTab}` : '';
    navigate(`/plugins/${encodeURIComponent(id)}${suffix}`, { replace: true });
  });
</script>
