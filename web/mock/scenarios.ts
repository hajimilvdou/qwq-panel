// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 场景开关（ENG §7）
 * --------------------------------------------------------------------------
 *   POST /__mock/scenario {name}   或首次加载时 ?mock=<name>
 *   POST /__mock/reset             恢复种子（场景回到 healthy）
 *   GET  /__mock/state             当前场景与可选列表
 * 每个场景都在全新种子上施加修改；已登录会话保留（fresh 除外）。
 * ========================================================================== */
import { SECURITY } from './catalog.ts';
import type { Db } from './store.ts';

export interface Scenario {
  description: string;
  apply(db: Db): void;
}

export const SCENARIOS: Record<string, Scenario> = {
  healthy: { description: '默认：一切正常，2 条待审批', apply() {} },
  fresh: {
    description: '未初始化：进入 /setup（令牌见启动日志）',
    apply(db) {
      db.setup.initialized = false;
      db.users.clear();
      db.passwords.clear();
      db.sessions.clear();
    },
  },
  mfa: {
    description: 'alice 已开启两步验证（验证码固定 123456，恢复码 qwq-rec-0001）',
    apply(db) {
      const a = db.users.get('usr_alice');
      if (a) a.mfa_enabled = true;
    },
  },
  attention: {
    description: '多条待审批（含需要验证码的破坏性操作），会话需要关注',
    apply(db) {
      const base = db.approvals.get('apr_firewall');
      if (!base) return;
      const extra = [
        { id: 'apr_kill', op: 'op_kill', action: 'com.qwq.monitor/process.kill', args: { pid: 4211, name: 'node' }, mfa: true },
        { id: 'apr_ban', op: 'op_ban', action: `${SECURITY}/ssh.ban_ip`, args: { ip: '203.0.113.9' }, mfa: false },
      ];
      for (const e of extra) {
        const meta = db.actions.find((a) => a.id === e.action)!;
        const opRow = { ...db.operations.get('op_firewall')!, operation_id: e.op, action: e.action, approval_id: e.id, args: e.args };
        db.operations.set(e.op, opRow);
        db.approvals.set(e.id, {
          ...base,
          approval_id: e.id,
          operation_id: e.op,
          requires_mfa: e.mfa,
          facts: { ...base.facts, action: meta, args: e.args, effect: meta.effect, effective_risk: meta.risk, declared_risk: meta.risk, approval_summary: meta.approval_summary, approval_description: meta.approval_description },
        });
      }
      const s = db.agentSessions.get('ses_slow');
      if (s) s.status = 'attention';
    },
  },
  degraded: {
    description: '磁盘告急、安全体检有问题：主页标题"出故障了"',
    apply(db) {
      db.flags.degraded = true;
    },
  },
  'no-plugins': {
    description: '只有内置 AI 助手：主页显示"装上系统监控"引导',
    apply(db) {
      for (const id of [...db.plugins.keys()]) if (!db.plugins.get(id)?.builtin) db.plugins.delete(id);
      db.approvals.delete('apr_firewall');
      db.operations.delete('op_firewall');
    },
  },
  empty: {
    description: '空数据：无应用、无动态、无会话、无审计',
    apply(db) {
      SCENARIOS['no-plugins']!.apply(db);
      db.operations.clear();
      db.approvals.clear();
      db.pending.clear();
      db.agentSessions.clear();
      db.agentMessages.clear();
      db.audit.length = 0;
      db.delegations.clear();
    },
  },
  viewer: {
    description: 'alice 降为只读（viewer）：写入口隐藏、直接访问显示权限态',
    apply(db) {
      const a = db.users.get('usr_alice');
      if (a) a.role = 'viewer';
    },
  },
  slow: { description: '每个请求 +800ms', apply: (db) => void (db.flags.delayMs = 800) },
  flaky: { description: '10% 的请求返回 503', apply: (db) => void (db.flags.flakyRate = 0.1) },
  offline: { description: '宿主不可用：所有 API 返回 503、事件流断开', apply: (db) => void (db.flags.offline = true) },
  'sse-drop': { description: '事件流每 30 秒被服务端断开', apply: (db) => void (db.flags.sseDropMs = 30_000) },
  resync: { description: '每次连上事件流都先收到 resync', apply: (db) => void (db.flags.resyncOnConnect = true) },
  'session-expire': { description: '会话 60 秒后过期（测试 401 跳登录与草稿暂存）', apply: (db) => void (db.flags.sessionTtlMs = 60_000) },
  'agent-running': {
    description: 'AI 会话"排查磁盘"正在处理（悬浮窗 working 态、Agent 页"停止"按钮）；无待审批',
    apply(db) {
      db.approvals.clear();
      const s = db.agentSessions.get('ses_team');
      if (!s) return;
      const list = db.agentMessages.get('ses_team') ?? [];
      const at = new Date().toISOString();
      list.length = 0;
      list.push(
        { seq: 1, message_id: 'msg_run_1', role: 'user', content: '磁盘是不是快满了？', created_at: at },
        { seq: 2, message_id: 'msg_run_2', role: 'assistant', content: '我先看看各分区的占用。', created_at: at },
        { seq: 3, message_id: 'msg_run_3', role: 'tool', content: '读取磁盘占用', content_json: { action: 'com.qwq.monitor/overview.disk', status: 'running' }, created_at: at },
      );
      Object.assign(s, { title: '排查磁盘', status: 'running', pending_approvals: 0, last_seq: 3, last_message_preview: '我先看看各分区的占用。' });
      const slow = db.agentSessions.get('ses_slow');
      if (slow) Object.assign(slow, { status: 'idle', pending_approvals: 0 });
    },
  },
};
