<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ApprovalStack · 全部待审批依序堆叠（不限本会话：外部委托、人工发起也在内）
  ───────────────────────────────────────────────────────────────
  批完一张自动聚焦下一张；focusId 变化时滚动并聚焦对应卡片。
  进入视野即视为"已看过"（驱动球的 reach 态收回）。
-->
<script lang="ts">
  import { tick } from 'svelte';
  import ApprovalCard from '$lib/ai/ApprovalCard.svelte';
  import { approvals } from '$lib/ai/approvals.svelte';
  import { nextFocus } from '$lib/ai/decide';

  let { focusId = null }: { focusId?: string | null } = $props();

  let root = $state<HTMLElement>();
  const list = $derived(approvals.pending);

  async function focusCard(id: string | null) {
    if (!id) return;
    await tick();
    const card = root?.querySelector<HTMLElement>(`[data-approval="${CSS.escape(id)}"]`);
    card?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    card?.querySelector<HTMLElement>('[data-primary], button')?.focus({ preventScroll: true });
  }

  $effect(() => {
    void focusCard(focusId);
  });

  /* 展开即看到：全部标记已看过 */
  $effect(() => {
    for (const a of list) approvals.markSeen(a.approval_id);
  });

  function decided(id: string) {
    const ids = list.map((a) => a.approval_id);
    void focusCard(nextFocus(ids, id));
  }
</script>

{#if list.length}
  <section class="stack" bind:this={root} aria-label="待确认">
    {#each list as a (a.approval_id)}
      <ApprovalCard approval={a} ondecided={decided} />
    {/each}
  </section>
{/if}

<style>
  .stack {
    display: grid;
    gap: var(--s-3);
  }
  .stack > :global(*) {
    animation: qwq-rise-in var(--dur-2) var(--ease-out);
  }
</style>
