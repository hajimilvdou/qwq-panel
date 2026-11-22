// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * AI 悬浮窗状态（SPEC §4 状态机的数据面；外观由 features/dock 实现）
 * --------------------------------------------------------------------------
 *   rest     默认
 *   working  有进行中的 AI 操作或会话（由 agent 功能设置 busy）
 *   reach    有未看过的待审批：球向左伸出胶囊
 *   open     展开（点击球、⌘K "问 AI"、"问问 AI"按钮、202 AWAITING_APPROVAL）
 *
 *   dock.open({ approvalId?, prompt? })   展开，可定位审批卡或带入问题
 *   dock.close()
 * ========================================================================== */
import { approvals } from './approvals.svelte';

export type DockMode = 'rest' | 'working' | 'reach' | 'open';

class DockState {
  expanded = $state(false);
  /** 由 agent 会话流 / 操作跟踪设置 */
  busy = $state(false);
  /** 需要聚焦的审批卡 */
  focusApprovalId = $state<string | null>(null);
  /** 带入输入框的文本（⌘K "问 AI：…"） */
  prompt = $state('');
  /** 在 /agent 页时只保留球形提醒，不提供对话 */
  chatSuppressed = $state(false);

  readonly mode = $derived<DockMode>(
    this.expanded ? 'open' : approvals.unseen.length ? 'reach' : this.busy ? 'working' : 'rest',
  );

  open(opts: { approvalId?: string; prompt?: string } = {}): void {
    if (opts.approvalId) this.focusApprovalId = opts.approvalId;
    if (opts.prompt !== undefined) this.prompt = opts.prompt;
    this.expanded = true;
  }

  close(): void {
    this.expanded = false;
    this.focusApprovalId = null;
  }
}

export const dock = new DockState();
