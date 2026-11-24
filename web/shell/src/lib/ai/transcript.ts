// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 会话记录模型（纯函数：历史消息 + 会话流事件 → 时间线条目）
 * --------------------------------------------------------------------------
 * 后端契约 §3.2 / §4.4。界面只认 TranscriptItem，不直接看原始帧：
 *
 *   fromMessages(messages)   GET /agent-sessions/{id} 的快照 → 条目
 *   reduce(state, event)     会话流单帧 → 新状态（不可变，方便测试与回放）
 *
 * 要点：
 *   - seq 单调；≤ 已见 seq 的帧是回放重复，直接丢弃（seq 有空洞属正常）
 *   - native 核心每步只发一次整段 delta；也兼容真正的增量 delta
 *   - 工具调用按 call_id 聚合：tool_call → approval_required → approval_decided → tool_result
 *   - turn.completed 决定会话状态；未知取值（如旧 mock 的 "completed"）按 idle 处理
 * ========================================================================== */
import type { AgentSessionEvent, AgentSessionMessage, AgentSessionStatus, AgentToolStatus, RiskLevel } from '$api/types';

export interface ToolItem {
  kind: 'tool';
  id: string;
  action: string;
  status: AgentToolStatus;
  /** 人话说明（历史消息里的 content，或审批摘要） */
  text?: string;
  risk?: RiskLevel;
  operationId?: string;
  approvalId?: string;
  error?: string;
  startedAt?: number;
  endedAt?: number;
}

export interface PlanStep {
  id: string;
  content: string;
  status: 'pending' | 'in_progress' | 'completed';
}

export interface PlanState {
  explanation?: string;
  steps: PlanStep[];
}

export interface TelemetryState {
  turns: number;
  steps: number;
  ttftMs: number;
  modelMs: number;
  toolMs: number;
  tps: number;
  promptTokens: number;
  completionTokens: number;
  cachedTokens: number;
  cacheHitPct: number;
  contextPct: number;
  maxContextTokens: number;
  systemTokens: number;
  toolDefTokens: number;
  messageTokens: number;
  model?: string;
}

export type TranscriptItem =
  | { kind: 'user'; id: string; text: string; at: string; state?: 'sending' | 'failed' }
  | { kind: 'assistant'; id: string; text: string; at: string; streaming: boolean }
  | { kind: 'reasoning'; id: string; text: string; at: string; streaming: boolean }
  | { kind: 'command'; id: string; command: string; text: string; ok: boolean; at: string }
  | ToolItem
  | { kind: 'error'; id: string; code: string; detail: string };

export interface TranscriptState {
  items: TranscriptItem[];
  /** 已见最大 seq：续传的 Last-Event-ID */
  seq: number;
  status: AgentSessionStatus;
  /** 实时任务执行清单（由 plan.updated 驱动） */
  plan?: PlanState;
  /** 实时 DSH 级遥测指标（由 telemetry.updated 驱动） */
  telemetry?: TelemetryState;
}

const TURN_STATUS: Record<string, AgentSessionStatus> = {
  idle: 'idle',
  waiting_approval: 'waiting_approval',
  cancelled: 'cancelled',
  failed: 'failed',
};

const TOOL_STATUS = new Set<AgentToolStatus>(['proposed', 'running', 'awaiting_approval', 'succeeded', 'failed', 'rejected', 'cancelled']);

export const TOOL_DONE = new Set<AgentToolStatus>(['succeeded', 'failed', 'rejected', 'cancelled']);

/* ------------------------------------------------------------------ 快照 */

export interface InFlightSnapshot {
  message_id: string;
  reasoning?: string;
  content: string;
  head_seq: number;
}

export function fromMessages(messages: readonly AgentSessionMessage[], status: AgentSessionStatus, seq: number): TranscriptState {
  const items: TranscriptItem[] = [];
  for (const m of [...messages].sort((a, b) => a.seq - b.seq)) {
    if (m.role === 'user') items.push({ kind: 'user', id: m.message_id, text: m.content, at: m.created_at });
    else if (m.role === 'assistant') {
      if (m.content) items.push({ kind: 'assistant', id: m.message_id, text: m.content, at: m.created_at, streaming: false });
    } else if (m.role === 'tool') {
      const j = (m.content_json ?? {}) as {
        call_id?: string;
        action?: string;
        status?: string;
        error?: { code?: string; detail?: string };
      };
      const st = TOOL_STATUS.has(j.status as AgentToolStatus) ? (j.status as AgentToolStatus) : 'succeeded';
      const rawText = (m.content ?? '').trim();
      const hideRawText =
        rawText === '' ||
        rawText.startsWith('{') ||
        rawText.startsWith('[') ||
        rawText.startsWith('(result omitted:');
      items.push({
        kind: 'tool',
        id: j.call_id || m.message_id,
        action: j.action ?? '',
        status: st,
        text: hideRawText ? undefined : m.content,
        error: j.error?.detail ?? j.error?.code,
        operationId: m.operation_id,
        approvalId: m.approval_id,
      });
    } else if (m.role === 'system') {
      /* 仅展示持久化报错卡片（content_json.kind === 'error'），其余系统提示不展示 */
      const j = (m.content_json ?? {}) as { kind?: string; code?: string; detail?: string };
      if (j.kind === 'error') {
        items.push({
          kind: 'error',
          id: m.message_id,
          code: j.code || 'INTERNAL',
          detail: j.detail || m.content || '',
        });
      }
    }
  }
  return { items, seq: Math.max(seq, messages.at(-1)?.seq ?? 0), status };
}

/** 合并快照与实时流状态，防止 reload / resync 用滞后的 SQLite 快照清零正在流式输出或刚完成的气泡 */
export function mergeSnapshotPreservingLiveStream(
  prev: TranscriptState,
  fresh: TranscriptState,
  inFlight?: InFlightSnapshot | null,
): TranscriptState {
  const localPendingUsers = prev.items.filter(
    (x) =>
      x.kind === 'user' &&
      Boolean(x.state) &&
      !(x.state === 'sending' && fresh.items.some((f) => f.kind === 'user' && f.text === x.text)),
  );
  const nowIso = new Date().toISOString();

  if (inFlight && inFlight.message_id) {
    // If live SSE already advanced beyond this HTTP snapshot's head_seq, keep
    // prev intact so newer streamed deltas are never overwritten or skipped.
    if (prev.seq > inFlight.head_seq && prev.items.length > 0) {
      return {
        ...prev,
        plan: prev.plan,
        telemetry: prev.telemetry,
      };
    }
    const extras: TranscriptItem[] = [];
    if (inFlight.reasoning) {
      extras.push({
        kind: 'reasoning',
        id: `think-${inFlight.message_id}`,
        text: inFlight.reasoning,
        at: nowIso,
        streaming: true,
      });
    }
    if (inFlight.content) {
      extras.push({
        kind: 'assistant',
        id: inFlight.message_id,
        text: inFlight.content,
        at: nowIso,
        streaming: true,
      });
    }
    return {
      ...fresh,
      plan: prev.plan,
      telemetry: prev.telemetry,
      seq: Math.max(fresh.seq, inFlight.head_seq),
      items: [...fresh.items, ...extras, ...localPendingUsers],
    };
  }

  // If live SSE is strictly ahead of this HTTP snapshot (whether still streaming
  // OR just finished message.completed + turn.completed), never roll back to a
  // stale snapshot.
  if (prev.seq > fresh.seq && prev.items.length > 0) {
    return {
      ...prev,
      plan: prev.plan,
      telemetry: prev.telemetry,
    };
  }

  return {
    ...fresh,
    plan: prev.plan,
    telemetry: prev.telemetry,
    items: [...fresh.items, ...localPendingUsers],
  };
}

/* ------------------------------------------------------------------ 增量 */

export function reduce(s: TranscriptState, e: AgentSessionEvent, now = Date.now()): TranscriptState {
  if (e.seq <= s.seq) return s;
  const next: TranscriptState = { ...s, seq: e.seq, items: s.items };
  const at = e.at ?? new Date(now).toISOString();

  const patchTool = (match: (t: ToolItem) => boolean, patch: Partial<ToolItem>, create?: ToolItem) => {
    const i = findLast(next.items, (x): x is ToolItem => x.kind === 'tool' && match(x));
    if (i >= 0) next.items = replaceAt(next.items, i, { ...(next.items[i] as ToolItem), ...patch });
    else if (create) next.items = [...next.items, { ...create, ...patch }];
  };

  const closeReasoning = () => {
    if (next.items.some((x) => x.kind === 'reasoning' && x.streaming)) {
      next.items = next.items.map((x) => (x.kind === 'reasoning' && x.streaming ? { ...x, streaming: false } : x));
    }
  };

  switch (e.type) {
    case 'message.delta':
    case 'message.completed': {
      closeReasoning();
      const streaming = e.type === 'message.delta';
      const hasId = typeof e.message_id === 'string' && e.message_id.length > 0;
      const id = hasId ? e.message_id! : `m${e.seq}`;
      let i = hasId ? findLast(next.items, (x) => x.kind === 'assistant' && x.id === id) : -1;
      /* 防御：若后端/适配器未带 message_id，合并到当前正在流式输出的助手气泡，绝不按单字拆屏 */
      if (i < 0 && !hasId) {
        i = findLast(next.items, (x) => x.kind === 'assistant' && x.streaming);
      }
      if (i >= 0) {
        const cur = next.items[i] as Extract<TranscriptItem, { kind: 'assistant' }>;
        const delta = e.delta ?? '';
        /* 防御：completed 携带整段重复全文时不二次拼接 */
        const nextText = !streaming && delta !== '' && delta === cur.text ? cur.text : cur.text + delta;
        next.items = replaceAt(next.items, i, { ...cur, text: nextText, streaming });
      } else if (e.delta) {
        next.items = [...next.items, { kind: 'assistant', id, text: e.delta, at, streaming }];
      }
      next.status = 'running';
      break;
    }
    case 'tool_call':
      closeReasoning();
      /* 工具调用开始时闭合前一段仍在流式输出的助手气泡，避免工具后正文倒灌到工具前气泡 */
      if (next.items.some((x) => x.kind === 'assistant' && x.streaming)) {
        next.items = next.items.map((x) => (x.kind === 'assistant' && x.streaming ? { ...x, streaming: false } : x));
      }
      patchTool(
        (t) => t.id === e.call_id,
        { status: 'running', risk: e.risk },
        { kind: 'tool', id: e.call_id ?? `c${e.seq}`, action: e.action ?? '', status: 'running', startedAt: now },
      );
      next.status = 'running';
      break;
    case 'approval_required':
      patchTool(
        (t) => t.id === e.call_id,
        { status: 'awaiting_approval', approvalId: e.approval_id, operationId: e.operation_id, risk: e.risk, text: e.summary },
        { kind: 'tool', id: e.call_id ?? `c${e.seq}`, action: e.action ?? '', status: 'awaiting_approval', startedAt: now },
      );
      next.status = 'waiting_approval';
      break;
    case 'approval_decided':
      patchTool((t) => t.approvalId === e.approval_id, { status: e.decision === 'approve' ? 'running' : 'rejected' });
      next.status = e.decision === 'approve' ? 'running' : next.status;
      break;
    case 'tool_result': {
      const st = TOOL_STATUS.has(e.status as AgentToolStatus) ? (e.status as AgentToolStatus) : 'failed';
      patchTool(
        (t) => t.id === e.call_id || (!!e.approval_id && t.approvalId === e.approval_id),
        {
          status: st,
          operationId: e.operation_id,
          error: e.error?.detail ?? e.error?.code,
          endedAt: now,
        },
        { kind: 'tool', id: e.call_id ?? `c${e.seq}`, action: e.action ?? '', status: st },
      );
      break;
    }
    case 'turn.completed':
      next.status = TURN_STATUS[e.status ?? ''] ?? 'idle';
      next.items = next.items.map((x) =>
        (x.kind === 'assistant' || x.kind === 'reasoning') && x.streaming ? { ...x, streaming: false } : x,
      );
      /* 取消/失败时，仍在跑的工具调用不会再有结果 */
      if (next.status === 'cancelled' || next.status === 'failed')
        next.items = next.items.map((x) =>
          x.kind === 'tool' && x.status === 'running' ? { ...x, status: 'cancelled', endedAt: now } : x,
        );
      break;
    case 'error':
      next.items = [...next.items, { kind: 'error', id: `e${e.seq}`, code: e.code ?? 'INTERNAL', detail: e.detail ?? '' }];
      break;
    default: {
      /* 扩展多 Agent 事件（后端 Result / Delta 承载，兼容 events_ext.go 嵌套与扁平格式） */
      const raw = e as unknown as {
        type: string;
        delta?: string;
        result?: unknown;
      };
      const res = raw.result && typeof raw.result === 'object' && !Array.isArray(raw.result) ? (raw.result as Record<string, unknown>) : null;
      if (raw.type === 'reasoning.delta') {
        const d = raw.delta ?? (typeof res?.delta === 'string' ? res.delta : '');
        if (d) {
          const i = findLast(next.items, (x) => x.kind === 'reasoning' && x.streaming);
          if (i >= 0) {
            const cur = next.items[i] as Extract<TranscriptItem, { kind: 'reasoning' }>;
            next.items = replaceAt(next.items, i, { ...cur, text: cur.text + d });
          } else {
            next.items = [...next.items, { kind: 'reasoning', id: `r${e.seq}`, text: d, at, streaming: true }];
          }
          next.status = 'running';
        }
      } else if (raw.type === 'plan.updated') {
        const stepsRaw = Array.isArray(raw.result)
          ? raw.result
          : Array.isArray(res?.steps)
            ? res.steps
            : Array.isArray(res?.items)
              ? res.items
              : [];
        const steps: PlanStep[] = stepsRaw
          .filter((x): x is Record<string, unknown> => !!x && typeof x === 'object')
          .map((x, idx) => ({
            id: typeof x.id === 'string' && x.id ? x.id : `s${idx + 1}`,
            content:
              typeof x.title === 'string' && x.title
                ? x.title
                : typeof x.content === 'string'
                  ? x.content
                  : String(x.step ?? ''),
            status: (x.status === 'completed' || x.status === 'in_progress' || x.status === 'pending'
              ? x.status
              : 'pending') as PlanStep['status'],
          }))
          .filter((x) => x.content.length > 0);
        next.plan = {
          explanation: typeof res?.explanation === 'string' ? res.explanation : undefined,
          steps,
        };
      } else if (raw.type === 'telemetry.updated' && res) {
        const num = (obj: Record<string, unknown> | null, k: string, fb = 0) =>
          obj && typeof obj[k] === 'number' && Number.isFinite(obj[k] as number) ? (obj[k] as number) : fb;
        const tok = res.tokens && typeof res.tokens === 'object' ? (res.tokens as Record<string, unknown>) : null;
        const ctx = res.context && typeof res.context === 'object' ? (res.context as Record<string, unknown>) : null;
        next.telemetry = {
          turns: num(res, 'turns', next.telemetry?.turns ?? 1),
          steps: num(res, 'steps', next.telemetry?.steps ?? 1),
          ttftMs: num(res, 'ttft_ms', next.telemetry?.ttftMs ?? 0),
          modelMs: num(res, 'model_ms', next.telemetry?.modelMs ?? 0),
          toolMs: num(res, 'tool_ms', next.telemetry?.toolMs ?? 0),
          tps: num(res, 'tps', next.telemetry?.tps ?? 0),
          promptTokens: num(tok, 'input', num(res, 'prompt_tokens', next.telemetry?.promptTokens ?? 0)),
          completionTokens: num(tok, 'output', num(res, 'completion_tokens', next.telemetry?.completionTokens ?? 0)),
          cachedTokens: num(tok, 'cached_read', num(res, 'cached_tokens', next.telemetry?.cachedTokens ?? 0)),
          cacheHitPct: num(tok, 'cache_hit_pct', num(res, 'cache_hit_pct', next.telemetry?.cacheHitPct ?? 0)),
          contextPct: num(ctx, 'pct', num(res, 'context_pct', next.telemetry?.contextPct ?? 0)),
          maxContextTokens: num(ctx, 'max_tokens', num(res, 'max_context_tokens', next.telemetry?.maxContextTokens ?? 128000)),
          systemTokens: num(ctx, 'system_tokens', num(res, 'system_tokens', next.telemetry?.systemTokens ?? 0)),
          toolDefTokens: num(ctx, 'tool_tokens', num(res, 'tool_def_tokens', next.telemetry?.toolDefTokens ?? 0)),
          messageTokens: num(ctx, 'message_tokens', num(res, 'message_tokens', next.telemetry?.messageTokens ?? 0)),
          model: typeof res.model === 'string' ? res.model : next.telemetry?.model,
        };
      } else if (raw.type === 'command.result' && res) {
        const msg = typeof res.summary === 'string' ? res.summary : typeof res.message === 'string' ? res.message : '';
        next.items = [
          ...next.items,
          {
            kind: 'command',
            id: `cmd${e.seq}`,
            command: typeof res.command === 'string' ? res.command : '/cmd',
            text: msg,
            ok: res.ok !== false,
            at,
          },
        ];
      } else if (raw.type === 'session.compacted' && res) {
        const before = typeof res.before_tokens === 'number' ? res.before_tokens : 0;
        const after = typeof res.after_tokens === 'number' ? res.after_tokens : 0;
        next.items = [
          ...next.items,
          {
            kind: 'command',
            id: `cmp${e.seq}`,
            command: '/compact',
            text: `上下文已压缩（约 ${before.toLocaleString()} → ${after.toLocaleString()} tokens，历史审计记录未受影响）`,
            ok: true,
            at,
          },
        ];
      }
      break;
    }
  }
  return next;
}

/* ------------------------------------------------------------------ 本地乐观条目 */

/** 发送中的用户消息先上屏；成功后用服务端 message_id 替换，失败标红可重试 */
export function addLocalUser(s: TranscriptState, id: string, text: string): TranscriptState {
  return { ...s, items: [...s.items, { kind: 'user', id, text, at: new Date().toISOString(), state: 'sending' }] };
}

export function settleLocalUser(s: TranscriptState, localId: string, result: { id: string } | 'failed'): TranscriptState {
  return {
    ...s,
    items: s.items.map((x) =>
      x.kind === 'user' && x.id === localId
        ? result === 'failed'
          ? { ...x, state: 'failed' as const }
          : { ...x, id: result.id, state: undefined }
        : x,
    ),
  };
}

/** 一轮里"第 n/m 步"：本轮（最后一条用户消息之后）的工具调用计数 */
export function turnProgress(s: TranscriptState): { done: number; total: number } {
  let start = 0;
  for (let i = s.items.length - 1; i >= 0; i--)
    if (s.items[i]!.kind === 'user') {
      start = i + 1;
      break;
    }
  const tools = s.items.slice(start).filter((x): x is ToolItem => x.kind === 'tool');
  return { done: tools.filter((t) => TOOL_DONE.has(t.status)).length, total: tools.length };
}

/* ------------------------------------------------------------------ 工具 */

function findLast<T>(arr: readonly T[], pred: (x: T) => boolean): number {
  for (let i = arr.length - 1; i >= 0; i--) if (pred(arr[i]!)) return i;
  return -1;
}

function replaceAt<T>(arr: readonly T[], i: number, v: T): T[] {
  const copy = arr.slice();
  copy[i] = v;
  return copy;
}
