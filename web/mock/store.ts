// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 内存状态、事件流、operation 引擎
 * --------------------------------------------------------------------------
 * 所有写入都走 runOperation()：统一产生 Operation、发 operation.updated 与
 * resource.changed、写审计——与真实宿主同构，前端无法分辨。
 *
 *   publish(db, type, subject, payload)   追加到事件环（1000 条）并推给订阅者
 *   changed(db, subject, kind, actor)     resource.changed 便捷封装
 *   runOperation(ctx, spec, apply)        invoke 同步完成 → 200 Outcome
 *                                         job 异步 → 202 RUNNING，进度事件
 *                                         需审批 → 202 AWAITING_APPROVAL
 * ========================================================================== */
import type { ServerResponse } from 'node:http';
import { accepted, ok, type Ctx, type Result, type S } from './http.ts';
import type { AiProvider, AuditEntry, Plugin } from '../shell/src/api/additions.ts';

/* ------------------------------------------------------------------ 类型 */

export interface MockSession {
  sid: string;
  userId: string;
  csrf: string;
  createdAt: number;
  expiresAt: number;
  mfaVerifiedAt?: number;
}

export interface Flags {
  /** 每个 API 请求额外延迟 */
  delayMs: number;
  /** 随机 503 的比例 */
  flakyRate: number;
  /** SSE 连接保持多久后被服务端断开（0 = 不断） */
  sseDropMs: number;
  /** 每次连上都先发 resync */
  resyncOnConnect: boolean;
  /** 会话寿命（0 = 默认 12h） */
  sessionTtlMs: number;
  /** 所有 API 返回 503 */
  offline: boolean;
  /** 小组件报告磁盘告急等问题 */
  degraded: boolean;
}

export const DEFAULT_FLAGS: Flags = {
  delayMs: 0,
  flakyRate: 0,
  sseDropMs: 0,
  resyncOnConnect: false,
  sessionTtlMs: 0,
  offline: false,
  degraded: false,
};

export interface StoredEvent {
  seq: number;
  event: S['Event'];
  /** 仅投递给该用户（agent_sessions/* 的 owner 隔离） */
  ownerId?: string;
}

export interface SseClient {
  res: ServerResponse;
  userId: string;
  topics: string[];
}

export interface IdemRecord {
  fingerprint: string;
  status: number;
  body: unknown;
  done: boolean;
}

export type Op = S['Operation'] & { args?: Record<string, unknown> };
export type AgentSessionRow = S['AgentSession'] & { owner_id: string; last_message_preview?: string; turn?: number };

export interface Db {
  scenario: string;
  flags: Flags;
  password: string;
  setup: { initialized: boolean; token: string; tls_fingerprint: string };
  users: Map<string, S['User']>;
  passwords: Map<string, string>;
  sessions: Map<string, MockSession>;
  challenges: Map<string, { userId: string; expiresAt: number }>;
  enrollTokens: Map<string, { userId: string; expiresAt: number }>;
  totpPending: Map<string, string>;
  delegations: Map<string, S['Delegation']>;
  nodes: Map<string, S['Node']>;
  plugins: Map<string, Plugin>;
  pluginConfigs: Map<string, S['PluginConfig']>;
  pluginSchemas: Map<string, Record<string, unknown>>;
  uploads: Map<string, { upload: S['PluginPackageUpload']; ownerId: string; manifestOf: string }>;
  actions: S['ActionMeta'][];
  operations: Map<string, Op>;
  approvals: Map<string, S['Approval']>;
  plans: Map<string, S['Plan']>;
  agentSessions: Map<string, AgentSessionRow>;
  agentMessages: Map<string, S['AgentSessionMessage'][]>;
  agentEvents: Map<string, S['AgentSessionEvent'][]>;
  agentClients: Map<string, Set<ServerResponse>>;
  providers: Map<string, AiProvider & { api_key?: string }>;
  audit: AuditEntry[];
  idem: Map<string, IdemRecord>;
  seq: number;
  ring: StoredEvent[];
  clients: Set<SseClient>;
  /** 等待审批的 operation 的执行体 */
  pending: Map<string, () => unknown>;
  timers: Set<ReturnType<typeof setTimeout>>;
  revCounter: number;
  startedAt: number;
}

/* ------------------------------------------------------------------ 小工具 */

const RING = 1000;

export const nowIso = (t = Date.now()) => new Date(t).toISOString();
export const rev = (db: Db) => `r${++db.revCounter}`;

let idCounter = 0;
export const newId = (prefix: string) => `${prefix}_${(Date.now() % 1e8).toString(36)}${(++idCounter).toString(36).padStart(3, '0')}`;

/** 受控定时器：reset / 换场景时统一清理 */
export function later(db: Db, ms: number, fn: () => void): void {
  const t = setTimeout(() => {
    db.timers.delete(t);
    fn();
  }, ms);
  db.timers.add(t);
}

export function actorOf(user: S['User'] | null, kind: S['ActorKind'] = 'human'): S['Actor'] {
  if (!user) return { kind: 'system', id: 'system', display_name: '系统' };
  return { kind, id: user.user_id, display_name: user.display_name || user.username };
}

/* ------------------------------------------------------------------ 事件 */

export function topicMatch(topics: readonly string[], type: string): boolean {
  return topics.some((t) => t === type || (t.endsWith('.*') && type.startsWith(t.slice(0, -1))));
}

export function sseWrite(res: ServerResponse, frame: { event?: string; id?: string | number; data: unknown }): void {
  let s = '';
  if (frame.event) s += `event: ${frame.event}\n`;
  if (frame.id !== undefined) s += `id: ${frame.id}\n`;
  s += `data: ${JSON.stringify(frame.data)}\n\n`;
  res.write(s);
}

export function publish(
  db: Db,
  type: string,
  subject: string,
  payload: Record<string, unknown>,
  opts: { actor?: S['Actor']; operationId?: string; ownerId?: string } = {},
): void {
  const seq = ++db.seq;
  const event: S['Event'] = {
    event_id: `evt_${seq.toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    sequence: String(seq),
    type,
    schema_version: '1',
    subject,
    occurred_at: nowIso(),
    actor: opts.actor,
    operation_id: opts.operationId,
    delivery_class: 'reliable',
    payload,
  };
  db.ring.push({ seq, event, ownerId: opts.ownerId });
  if (db.ring.length > RING) db.ring.shift();
  for (const c of db.clients) {
    if (opts.ownerId && c.userId !== opts.ownerId) continue;
    if (topicMatch(c.topics, type)) sseWrite(c.res, { id: seq, data: event });
  }
}

export function changed(
  db: Db,
  subject: string,
  kind: 'create' | 'update' | 'delete',
  actor: S['Actor'],
  opts: { revision?: string; operationId?: string; pointers?: string[]; ownerId?: string } = {},
): void {
  publish(
    db,
    'resource.changed',
    subject,
    {
      subject,
      revision: opts.revision ?? `r${db.revCounter}`,
      kind,
      actor,
      operation_id: opts.operationId,
      changed_pointers: opts.pointers ?? [],
    },
    { actor, operationId: opts.operationId, ownerId: opts.ownerId },
  );
}

export function writeAudit(db: Db, e: Omit<AuditEntry, 'audit_id' | 'at'> & { at?: string }): void {
  db.audit.unshift({ audit_id: newId('aud'), at: e.at ?? nowIso(), ...e });
  if (db.audit.length > 2000) db.audit.pop();
}

/* ------------------------------------------------------------------ operation 引擎 */

export interface OpSpec {
  action: string;
  target?: S['Target'];
  args?: Record<string, unknown>;
  risk?: S['RiskLevel'];
  /** job：异步执行，返回 202 RUNNING，按 steps 推进度 */
  job?: { steps: string[]; stepMs?: number };
  /** 强制要求审批（否则按动作目录的 approval 与发起者类型判定） */
  approval?: boolean;
  actorKind?: S['ActorKind'];
  /** 显式指定发起者（AI 代用户操作时） */
  actor?: S['Actor'];
  /** 执行完成（成功或失败）后回调，供 agent 脚本续写会话 */
  onSettled?: (op: Op) => void;
}

function emitOp(db: Db, op: Op, previous?: S['OperationStatus']) {
  publish(
    db,
    'operation.updated',
    `operations/${op.operation_id}`,
    {
      operation_id: op.operation_id,
      action: op.action,
      status: op.status,
      previous_status: previous,
      attempt: op.attempt,
      actor: op.actor,
      target: op.target,
      effective_risk: op.effective_risk,
      approval_id: op.approval_id,
      progress: op.progress,
      error: op.error,
      revision: op.revision,
    },
    { actor: op.actor, operationId: op.operation_id },
  );
}

export function setOpStatus(db: Db, op: Op, status: S['OperationStatus'], patch: Partial<Op> = {}): void {
  const prev = op.status;
  Object.assign(op, patch, { status, updated_at: nowIso(), revision: rev(db) });
  if (['SUCCEEDED', 'FAILED', 'CANCELED', 'REJECTED', 'EXPIRED'].includes(status)) op.finished_at = op.updated_at;
  emitOp(db, op, prev);
}

function needsApproval(db: Db, spec: OpSpec, kind: S['ActorKind']): boolean {
  if (spec.approval !== undefined) return spec.approval;
  const meta = db.actions.find((a) => a.id === spec.action);
  if (!meta?.approval || meta.approval === 'auto') return false;
  return meta.approval === 'confirm' || kind !== 'human';
}

/** 执行 apply；抛出的 MockProblem 记为 FAILED */
function execute(db: Db, op: Op, apply: () => unknown): void {
  try {
    const result = apply();
    setOpStatus(db, op, 'SUCCEEDED', { result, progress: { percent: 100 } });
    writeAudit(db, { actor: op.actor, action: op.action, subject: op.target.subject ?? op.action, outcome: 'success', operation_id: op.operation_id });
  } catch (err) {
    const p = err as { status?: number; code?: string; detail?: string };
    setOpStatus(db, op, 'FAILED', {
      error: {
        type: 'about:blank',
        title: 'failed',
        status: p.status ?? 500,
        code: (p.code ?? 'INTERNAL') as S['ProblemCode'],
        detail: p.detail,
        retryable: false,
        request_id: newId('req'),
      },
    });
    writeAudit(db, { actor: op.actor, action: op.action, subject: op.target.subject ?? op.action, outcome: 'failure', operation_id: op.operation_id });
  }
}

function runJob(db: Db, op: Op, spec: NonNullable<OpSpec['job']>, finish: () => void) {
  const stepMs = spec.stepMs ?? 700;
  spec.steps.forEach((step, i) => {
    later(db, stepMs * (i + 1), () => {
      if (op.status !== 'RUNNING') return;
      setOpStatus(db, op, 'RUNNING', { progress: { step, message: step, percent: Math.round(((i + 1) / (spec.steps.length + 1)) * 100) } });
    });
  });
  later(db, stepMs * (spec.steps.length + 1), () => op.status === 'RUNNING' && finish());
}

export function runOperation(ctx: Ctx, spec: OpSpec, apply: () => unknown): Result {
  const { db } = ctx;
  const kind = spec.actor?.kind ?? spec.actorKind ?? 'human';
  const actor = spec.actor ?? actorOf(ctx.user, kind);
  const meta = db.actions.find((a) => a.id === spec.action);
  const op: Op = {
    operation_id: newId('op'),
    action: spec.action,
    status: 'PENDING',
    target: spec.target ?? {},
    actor,
    effective_risk: spec.risk ?? meta?.risk ?? 'low',
    attempt: 1,
    created_at: nowIso(),
    updated_at: nowIso(),
    revision: rev(db),
    args: spec.args,
    ui_route: meta?.ui_route,
  };
  db.operations.set(op.operation_id, op);
  const finish = () => {
    execute(db, op, apply);
    spec.onSettled?.(op);
  };

  if (needsApproval(db, spec, kind)) {
    const approval = createApproval(db, op, meta);
    db.pending.set(op.operation_id, () => (spec.job ? runJob(db, op, spec.job, finish) : finish()));
    setOpStatus(db, op, 'AWAITING_APPROVAL', { approval_id: approval.approval_id });
    return accepted(op);
  }
  if (spec.job) {
    setOpStatus(db, op, 'RUNNING', { progress: { percent: 0 } });
    runJob(db, op, spec.job, finish);
    return accepted(op);
  }
  setOpStatus(db, op, 'RUNNING');
  finish();
  const out: S['OperationOutcome'] = {
    operation_id: op.operation_id,
    action: op.action,
    status: op.status,
    effective_risk: op.effective_risk,
    result: op.result,
    error: op.error,
    revision: op.revision,
  };
  return ok(out);
}

/** 为一个已处于 AWAITING_APPROVAL 的操作登记"批准后做什么"（种子数据用） */
export function deferExecute(db: Db, op: Op, apply: () => unknown): void {
  db.pending.set(op.operation_id, () => execute(db, op, apply));
}

export function createApproval(db: Db, op: Op, meta: S['ActionMeta'] | undefined): S['Approval'] {
  const a: S['Approval'] = {
    approval_id: newId('apr'),
    operation_id: op.operation_id,
    status: 'PENDING',
    facts: {
      action: meta ?? { id: op.action, summary: op.action, effect: 'write', risk: op.effective_risk, mode: 'invoke', idempotent: false, plannable: false, source: 'host' },
      args: op.args ?? {},
      target: op.target,
      node_name: '东京-01',
      required_capabilities: [],
      effect: meta?.effect ?? 'write',
      declared_risk: meta?.risk ?? op.effective_risk,
      effective_risk: op.effective_risk,
      reversible: Boolean(meta?.undo),
      undo: meta?.undo,
      requested_by: op.actor,
      approval_summary: meta?.approval_summary,
      approval_description: meta?.approval_description,
      permission_mode: op.actor.kind === 'ai_agent' ? 'safe' : undefined,
    },
    requires_mfa: meta?.effect === 'destructive',
    created_at: nowIso(),
    expires_at: nowIso(Date.now() + 15 * 60_000),
    revision: rev(db),
  };
  db.approvals.set(a.approval_id, a);
  changed(db, `approvals/${a.approval_id}`, 'create', op.actor, { revision: a.revision, operationId: op.operation_id });
  return a;
}

/** 审批决定：批准则执行挂起的执行体，拒绝则 operation → REJECTED */
export function decideApproval(db: Db, a: S['Approval'], decision: 'approve' | 'reject', by: S['Actor'], comment?: string): void {
  a.status = decision === 'approve' ? 'APPROVED' : 'REJECTED';
  a.decided_by = by;
  a.decided_at = nowIso();
  a.comment = comment;
  a.revision = rev(db);
  changed(db, `approvals/${a.approval_id}`, 'update', by, { revision: a.revision, operationId: a.operation_id, pointers: ['/status'] });
  const op = db.operations.get(a.operation_id);
  const run = db.pending.get(a.operation_id);
  db.pending.delete(a.operation_id);
  if (!op) return;
  if (decision === 'reject') {
    setOpStatus(db, op, 'REJECTED');
    return;
  }
  setOpStatus(db, op, 'APPROVED');
  setOpStatus(db, op, 'RUNNING');
  if (run) run();
  else execute(db, op, () => ({}));
}
