<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  操作详情 `/activity/:operationId`（SPEC §3.2）
  Outlet 只按路由模式重建页面；这里按 id 重建详情，保证每个 operation 一份干净的状态。
-->
<script lang="ts">
  import OperationDetail from './OperationDetail.svelte';

  let { params }: { params: Record<string, string> } = $props();
</script>

{#key params.operationId}
  <OperationDetail id={params.operationId ?? ''} />
{/key}
