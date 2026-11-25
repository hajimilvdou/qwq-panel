<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  HumanApprovalDialog · 人工操作独立确认弹窗（绝不混入 AI 助手对话界面）
  ───────────────────────────────────────────────────────────────
  复用统一 <Dialog> 与 <ApprovalCard>，仅在人工直接操作确需二次确认或输入 2FA 验证码时弹出。
-->
<script lang="ts">
  import { Dialog } from '$ui';
  import ApprovalCard from '$lib/ai/ApprovalCard.svelte';
  import { humanApproval } from '$lib/ai/human-approval.svelte';

  function onDecided(_id: string, decision?: 'approve' | 'reject') {
    humanApproval.settle(decision === 'reject' ? 'rejected' : 'approved');
  }
</script>

<Dialog
  open={humanApproval.openState && humanApproval.current !== null}
  title="确认执行操作"
  size="md"
  onclose={() => {
    if (humanApproval.openState) humanApproval.settle('dismissed');
  }}
>
  {#if humanApproval.current}
    <ApprovalCard approval={humanApproval.current} ondecided={onDecided} />
  {/if}
</Dialog>
