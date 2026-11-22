<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  应用详情 /apps/:pluginId（SPEC §3.4）——按 pluginId 重建子树，避免跨应用串状态
-->
<script lang="ts">
  import PluginDetail from './PluginDetail.svelte';

  let { params }: { params: Record<string, string> } = $props();
</script>

{#key params.pluginId}
  <PluginDetail id={params.pluginId ?? ''} />
{/key}
