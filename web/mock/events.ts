// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 事件流（GET /api/v1/events 与会话流）
 * --------------------------------------------------------------------------
 * 全局流：retry: 3000 → ready{head_sequence} → 续传（Last-Event-ID / last_event_id）
 *   比事件环更旧 → resync{retention_exceeded}；心跳 15s；按 topics 过滤；
 *   agent_sessions/* 只投给 owner（缺口 6 的可见性）。
 * 会话流：data 为 AgentSessionEvent，id 为 seq；从 last seq 之后续传。
 * ========================================================================== */
import type { Ctx } from './http.ts';
import { sseWrite, topicMatch, type Db, type SseClient } from './store.ts';

const DEFAULT_TOPICS = ['resource.changed', 'operation.updated'];
const HEARTBEAT = 15_000;

function openSse(ctx: Ctx): void {
  ctx.res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store',
    Connection: 'keep-alive',
    'X-Request-Id': ctx.requestId,
    'X-Accel-Buffering': 'no',
  });
  ctx.res.write('retry: 3000\n\n');
}

function lastId(ctx: Ctx): number | null {
  const raw = (ctx.req.headers['last-event-id'] as string | undefined) ?? ctx.query.get('last_event_id');
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

export function streamEvents(ctx: Ctx): 'stream' {
  const { db, res } = ctx;
  const topics = (ctx.query.get('topics') ?? '').split(',').filter(Boolean);
  const client: SseClient = { res, userId: ctx.user!.user_id, topics: topics.length ? topics : DEFAULT_TOPICS };
  openSse(ctx);
  sseWrite(res, { event: 'ready', data: { head_sequence: String(db.seq), heartbeat_seconds: 15 } });

  const since = lastId(ctx);
  const oldest = db.ring[0]?.seq ?? db.seq + 1;
  if (db.flags.resyncOnConnect || (since !== null && since < oldest - 1)) {
    sseWrite(res, { event: 'resync', data: { reason: db.flags.resyncOnConnect ? 'server_restart' : 'retention_exceeded', head_sequence: String(db.seq) } });
  } else if (since !== null) {
    for (const e of db.ring) {
      if (e.seq <= since || (e.ownerId && e.ownerId !== client.userId)) continue;
      if (topicMatch(client.topics, e.event.type)) sseWrite(res, { id: e.seq, data: e.event });
    }
  }

  db.clients.add(client);
  const beat = setInterval(() => sseWrite(res, { event: 'heartbeat', data: { head_sequence: String(db.seq), server_time: new Date().toISOString() } }), HEARTBEAT);
  const drop = db.flags.sseDropMs ? setTimeout(() => res.end(), db.flags.sseDropMs) : null;
  const done = () => {
    clearInterval(beat);
    if (drop) clearTimeout(drop);
    db.clients.delete(client);
  };
  res.on('close', done);
  return 'stream';
}

/* ------------------------------------------------------------------ 会话流 */

export function streamSession(ctx: Ctx, sessionId: string): 'stream' {
  const { db, res } = ctx;
  openSse(ctx);
  const since = lastId(ctx) ?? -1;
  for (const e of db.agentEvents.get(sessionId) ?? []) if (e.seq > since) sseWrite(res, { id: e.seq, data: e });
  let set = db.agentClients.get(sessionId);
  if (!set) db.agentClients.set(sessionId, (set = new Set()));
  set.add(res);
  const beat = setInterval(() => res.write(': ping\n\n'), HEARTBEAT);
  res.on('close', () => {
    clearInterval(beat);
    set.delete(res);
  });
  return 'stream';
}

/** 追加一条会话事件并推给正在看的客户端 */
export function pushSessionEvent(db: Db, sessionId: string, e: Omit<import('./http').S['AgentSessionEvent'], 'seq' | 'session_id'>): void {
  const list = db.agentEvents.get(sessionId) ?? [];
  db.agentEvents.set(sessionId, list);
  const s = db.agentSessions.get(sessionId);
  const seq = (s?.last_seq ?? list.length) + 1;
  if (s) s.last_seq = seq;
  const ev = { ...e, seq, session_id: sessionId, at: new Date().toISOString() };
  list.push(ev);
  if (list.length > 500) list.shift();
  for (const res of db.agentClients.get(sessionId) ?? []) sseWrite(res, { id: seq, data: ev });
}

/** 换场景 / reset 时断开所有长连接（客户端会自行重连） */
export function closeAllStreams(db: Db): void {
  for (const c of db.clients) c.res.end();
  db.clients.clear();
  for (const set of db.agentClients.values()) for (const r of set) r.end();
  db.agentClients.clear();
}
