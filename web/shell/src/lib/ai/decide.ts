// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 审批决定与审批卡展示规则（纯逻辑，ApprovalCard 与测试共用）
 * --------------------------------------------------------------------------
 *   decideApproval(a, input, key)   提交决定，把错误归为卡片能直接展示的结果
 *   requesterOf(facts, me)          发起者行
 *   whyAsk(facts)                   为什么要问你
 *   nextFocus(ids, decided)         批完一张后聚焦哪一张
 * SPEC §4 审批卡；契约 §2.9：409 STATE_CONFLICT = 已被处理；403 MFA_REQUIRED = 字段错误。
 * ========================================================================== */
import { ApiError } from '$api/client';
import { approvals as api } from '$api/endpoints';
import type { Approval, ApprovalFacts } from '$api/types';

export type DecideResult =
  | { kind: 'ok'; approval: Approval }
  | { kind: 'handled' }
  | { kind: 'mfa'; message: string }
  | { kind: 'error'; error: unknown };

export interface DecideInput {
  decision: 'approve' | 'reject';
  mfaCode?: string;
  comment?: string;
}

export async function decideApproval(
  a: Approval,
  input: DecideInput,
  key: string,
  call: typeof api.decide = api.decide,
): Promise<DecideResult> {
  try {
    const approval = await call(
      a.approval_id,
      {
        decision: input.decision,
        expected_revision: a.revision,
        ...(input.comment?.trim() ? { comment: input.comment.trim().slice(0, 500) } : {}),
        ...(input.mfaCode ? { mfa_code: input.mfaCode } : {}),
      },
      key,
    );
    return { kind: 'ok', approval };
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.code === 'STATE_CONFLICT' || error.code === 'NOT_FOUND') return { kind: 'handled' };
      if (error.code === 'MFA_REQUIRED')
        return { kind: 'mfa', message: input.mfaCode ? '验证码不对或已过期' : '请输入 6 位验证码' };
    }
    return { kind: 'error', error };
  }
}

/* ------------------------------------------------------------------ 展示 */

export interface Requester {
  kind: 'ai' | 'external' | 'human' | 'system';
  text: string;
}

export function requesterOf(f: ApprovalFacts, myUserId: string | undefined): Requester {
  const a = f.requested_by;
  if (a.id.startsWith('dlg_')) return { kind: 'external', text: `外部 AI「${a.display_name ?? a.id}」代你发起` };
  if (a.kind === 'ai_agent') return { kind: 'ai', text: 'AI 助手代你发起' };
  if (a.kind === 'human') return { kind: 'human', text: a.id === myUserId ? '你发起' : `${a.display_name ?? a.id} 发起` };
  return { kind: 'system', text: `${a.display_name ?? '系统'}发起` };
}

const HOST_ACTION_LABELS: Record<string, string> = {
  'host.plugins.enable': '启用插件',
  'host.plugins.disable': '停用插件',
  'host.plugins.uninstall': '卸载插件',
  'host.plugins.restart': '重启插件',
  'host.users.create': '创建用户',
  'host.users.update': '更新用户',
  'host.users.delete': '删除用户',
  'host.account.update': '更新账户资料',
  'host.ai_providers.create': '添加 AI 服务',
  'host.ai_providers.update': '修改 AI 服务',
  'host.ai_providers.delete': '删除 AI 服务',
  'host.service_accounts.create': '创建服务账号',
  'host.service_accounts.delete': '删除服务账号',
  'host.nodes.revoke': '吊销节点',
};

/** 审批卡片标题：把宿主机原始英文摘要转为易读中文并附带目标标识，插件与自定义摘要保持原样 */
export function approvalTitle(f: ApprovalFacts): string {
  if (f.approval_summary) return f.approval_summary;
  const raw = f.action.summary || f.action.id;
  if (f.action.source === 'host') {
    const zh = HOST_ACTION_LABELS[f.action.id];
    if (zh && /^[A-Za-z0-9\s._:-]+$/.test(raw)) {
      const args = (f.args ?? {}) as Record<string, unknown>;
      const target =
        (typeof args.plugin_id === 'string' && args.plugin_id) ||
        (typeof args.username === 'string' && args.username) ||
        (typeof args.name === 'string' && args.name) ||
        (typeof f.target?.plugin_id === 'string' && f.target.plugin_id) ||
        (typeof f.target?.subject === 'string' && f.target.subject.split('/').at(-1)) ||
        '';
      return target ? `${zh} ${target}` : zh;
    }
  }
  return raw;
}

export function whyAsk(f: ApprovalFacts): string {
  const level = f.action.approval;
  if (f.requested_by.kind === 'human') {
    if (f.effect === 'destructive') return '破坏性操作，需要再次确认';
    if (f.effective_risk === 'high') return '高风险操作，需要再次确认';
    return '这项操作需要你确认后才会执行';
  }
  if (f.permission_mode === 'safe') return '你设置了"重要操作先问我"';
  if (level === 'confirm') return '这项操作每次都要人来确认';
  if (level === 'ai_confirm' && f.requested_by.kind === 'ai_agent') return 'AI 发起的这类操作需要你确认';
  if (f.effective_risk === 'high') return '风险较高，需要你确认';
  return '需要你确认后才会执行';
}

export const RISK_META = {
  low: { label: '低风险', tone: 'ok' },
  medium: { label: '中风险', tone: 'warn' },
  high: { label: '高风险', tone: 'bad' },
} as const;

/** 审批有效期的静态文字（不倒计时，SPEC §4） */
export function validityText(a: Approval): string {
  const mins = Math.max(1, Math.round((Date.parse(a.expires_at) - Date.parse(a.created_at)) / 60_000));
  return `${mins} 分钟内有效`;
}

export const isExpired = (a: Approval, now = Date.now()) => Date.parse(a.expires_at) <= now;

/** 批完 decided 之后该聚焦哪一张：优先它后面那张，否则前一张；没有了返回 null */
export function nextFocus(ids: readonly string[], decided: string): string | null {
  const i = ids.indexOf(decided);
  if (i < 0) return ids[0] ?? null;
  return ids[i + 1] ?? ids[i - 1] ?? null;
}

/** 悬浮窗胶囊文案："AI 想开启防火墙" / "有一项操作等你确认：…" */
export function reachText(a: Approval): string {
  const what = approvalTitle(a.facts);
  const r = a.facts.requested_by;
  if (r.id.startsWith('dlg_')) return `${r.display_name ?? '外部 AI'}想${what}`;
  if (r.kind === 'ai_agent') return `AI 想${what}`;
  return `等你确认：${what}`;
}
