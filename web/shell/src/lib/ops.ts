// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 写操作封装（ENG §6 / SPEC §8）
 * --------------------------------------------------------------------------
 * 每个"用户意图"一个 Idempotency-Key：网络重试、用户点"重试"都复用它，
 * 意图结束（成功或用户放弃）后再建新的。
 *
 *   const intent = createIntent();                     // 表单打开 / 按钮首次点击
 *   const r = await runIntent(intent, (key) => api.users.create(body, key), {
 *     label: '创建用户 bob',
 *   });
 *   r.kind: 'done' | 'running' | 'awaiting'
 *
 *   done      200 已完成（SUCCEEDED / FAILED 等终态）
 *   running   202 RUNNING：Toast"已开始"，终态时再 Toast 结果（可点进详情）
 *   awaiting  202 AWAITING_APPROVAL：自动打开悬浮窗并定位到该审批卡
 *
 * 失败（ApiError / NetworkError）原样抛出：调用方决定行内显示或 reportError()。
 * ========================================================================== */
import { newIdempotencyKey, TERMINAL, type OpResult } from '$api/client';
import { operations as opsApi } from '$api/endpoints';
import { humanApproval, tryAutoApproveHuman } from './ai/human-approval.svelte';
import { liveOps } from './operations.svelte';
import { toasts } from './toast.svelte';
import { navigate } from './router.svelte';

export interface Intent {
  readonly key: string;
}

export function createIntent(): Intent {
  return { key: newIdempotencyKey() };
}

/**
 * 表单级自适应幂等意图（P0-FE-04）：
 *   - 相同载荷因网络/5xx/429 重试时复用同一 Idempotency-Key；
 *   - 载荷发生修改或收到 400/409/422 校验/冲突错误后自动轮换新 Key，根除 422 死锁。
 */
export interface FormIntent {
  keyFor(payload: unknown): string;
  onError(status?: number): void;
  reset(): void;
}

export function createFormIntent(): FormIntent {
  let key = newIdempotencyKey();
  let lastFp: string | null = null;
  return {
    keyFor(payload: unknown): string {
      const fp = JSON.stringify(payload) ?? '';
      if (lastFp !== null && fp !== lastFp) key = newIdempotencyKey();
      lastFp = fp;
      return key;
    },
    onError(status?: number): void {
      if (status === 400 || status === 409 || status === 422) {
        key = newIdempotencyKey();
        lastFp = null;
      }
    },
    reset(): void {
      key = newIdempotencyKey();
      lastFp = null;
    },
  };
}

export type IntentResult =
  | { kind: 'done'; op: OpResult }
  | { kind: 'running'; op: OpResult }
  | { kind: 'awaiting'; op: OpResult };

export interface RunOptions {
  /** 人话描述，用于 Toast："已开始：重启 系统监控" */
  label: string;
  /** 进行中的操作结束时回调（成功或失败） */
  onSettled?: (status: OpResult['status']) => void;
  /** 不弹"已开始"等 Toast（调用方自己展示进度） */
  quiet?: boolean;
  /** 人工已在宿主确认弹窗/表单中明确确认此操作，无需再弹二次确认（开启 2FA 时仍走验证） */
  preConfirmed?: boolean;
  /** 已收集的 6 位两步验证码（如卸载清理数据时） */
  mfaCode?: string;
}

export async function runIntent(
  intent: Intent,
  call: (key: string) => Promise<OpResult>,
  opts: RunOptions,
): Promise<IntentResult> {
  let op = await call(intent.key);

  if (op.status === 'AWAITING_APPROVAL' && op.approvalId) {
    let approved = false;
    if (opts.preConfirmed) {
      approved = await tryAutoApproveHuman(op.approvalId, opts.mfaCode);
    }
    if (!approved) {
      const outcome = await humanApproval.open(op.approvalId);
      approved = outcome === 'approved';
      if (!approved) return { kind: 'awaiting', op };
    }
    if (op.operationId) {
      try {
        const latest = await opsApi.get(op.operationId);
        op = {
          operationId: latest.operation_id,
          status: latest.status,
          approvalId: latest.approval_id,
          result: latest.result,
          error: latest.error,
          operation: latest,
        };
      } catch {
        /* 保持后续跟踪 */
      }
    }
  }
  if (op.status === 'AWAITING_APPROVAL') {
    return { kind: 'awaiting', op };
  }
  if (TERMINAL.has(op.status)) {
    if (op.status !== 'SUCCEEDED' && !opts.quiet) toasts.error(`${opts.label}没有成功`);
    return { kind: 'done', op };
  }

  /* 进行中：跟随 operation.updated 到终态 */
  if (!opts.quiet) toasts.info(`已开始：${opts.label}`);
  const detail = { label: '查看', run: () => navigate(`/activity/${encodeURIComponent(op.operationId)}`) };
  liveOps.watch(op.operationId, (p) => {
    opts.onSettled?.(p.status);
    if (opts.quiet) return;
    if (p.status === 'SUCCEEDED') toasts.success(`已完成：${opts.label}`, detail);
    else toasts.error(`${opts.label}没有成功`, undefined, detail);
  });
  return { kind: 'running', op };
}
