// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 人工发起操作的独立确认模态与已确认自动批准
 * --------------------------------------------------------------------------
 * 人工在页面或插件里直接点击触发的确认/二次验证绝不跳转到 AI 助手对话窗：
 *   · tryAutoApproveHuman()  刚在宿主 ConfirmDialog 中明确点过确认且无需额外 MFA 时，
 *                            透明提交批准并继续等待真实结果，避免二次弹窗与 AI 弹窗干扰。
 *   · humanApproval.open()   确需二次确认（如 2FA 验证码、可达性警示或未预确认的 confirm 操作）
 *                            时弹出干净的原生确认弹窗（仅展示操作信息与确认按钮，无 AI 对话 UI）。
 * ========================================================================== */
import { newIdempotencyKey } from '$api/client';
import { approvals as approvalsApi } from '$api/endpoints';
import type { Approval } from '$api/types';
import { session } from '../session.svelte';
import { approvals } from './approvals.svelte';

export type HumanApprovalOutcome = 'approved' | 'rejected' | 'dismissed';

interface PendingModal {
  approval: Approval;
  resolve: (outcome: HumanApprovalOutcome) => void;
}

class HumanApprovalController {
  current = $state<Approval | null>(null);
  openState = $state(false);
  #queue: PendingModal[] = [];
  #active: PendingModal | null = null;

  /** 打开独立原生确认弹窗（不打开 AI 助手）；返回用户决定 */
  async open(approvalId: string): Promise<HumanApprovalOutcome> {
    approvals.markSeen(approvalId);
    let a = approvals.get(approvalId);
    if (!a) {
      try {
        a = await approvalsApi.get(approvalId);
      } catch {
        return 'dismissed';
      }
    }
    if (a.status !== 'PENDING') {
      return a.status === 'APPROVED' ? 'approved' : 'rejected';
    }
    approvals.markSeen(a.approval_id);
    return new Promise<HumanApprovalOutcome>((resolve) => {
      const item: PendingModal = { approval: a!, resolve };
      if (this.#active) {
        this.#queue.push(item);
      } else {
        this.#show(item);
      }
    });
  }

  /** 由 HumanApprovalDialog 在 ApprovalCard 提交决定或用户关闭弹窗时调用 */
  settle(outcome: HumanApprovalOutcome): void {
    const active = this.#active;
    this.#active = null;
    this.openState = false;
    this.current = null;
    active?.resolve(outcome);
    const next = this.#queue.shift();
    if (next) this.#show(next);
  }

  #show(item: PendingModal): void {
    this.#active = item;
    this.current = item.approval;
    this.openState = true;
  }
}

export const humanApproval = new HumanApprovalController();

/**
 * 当人工管理员刚刚在宿主原生 ConfirmDialog / 表单中明确确认了本操作时，
 * 若账户未开启 2FA（或已提供 mfaCode），直接透明完成后端批准步骤，避免二次弹窗或跳进 AI 助手。
 * 返回 true 表示已成功提交批准；返回 false 表示仍需人工弹窗（例如需要输入 6 位两步验证码）。
 */
export async function tryAutoApproveHuman(approvalId: string, mfaCode?: string): Promise<boolean> {
  if (!approvalId || !session.can('host.approvals:approve')) return false;
  approvals.suppress(approvalId);
  try {
    const a = await approvalsApi.get(approvalId);
    if (a.status !== 'PENDING') return a.status === 'APPROVED';
    const by = a.facts.requested_by;
    if (by.kind !== 'human' || (session.user?.user_id && by.id !== session.user.user_id)) {
      return false;
    }
    if (a.requires_mfa && Boolean(session.user?.mfa_enabled) && !mfaCode) {
      return false;
    }
    const decided = await approvalsApi.decide(
      a.approval_id,
      {
        decision: 'approve',
        expected_revision: a.revision,
        ...(mfaCode ? { mfa_code: mfaCode } : {}),
      },
      newIdempotencyKey(),
    );
    approvals.upsert(decided);
    return decided.status === 'APPROVED';
  } catch {
    return false;
  } finally {
    approvals.unsuppress(approvalId);
  }
}
