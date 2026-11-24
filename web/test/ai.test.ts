// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * AI 部分的纯逻辑：会话记录 reduce、会话流帧、Markdown 子集、审批决定、悬浮窗尺寸
 * ========================================================================== */
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../shell/src/api/client';
import type { AgentSessionEvent, Approval } from '../shell/src/api/types';
import { addLocalUser, fromMessages, reduce, settleLocalUser, turnProgress, type TranscriptState } from '../shell/src/lib/ai/transcript';
import { parseSessionFrame, byteLength } from '../shell/src/lib/ai/session-stream.svelte';
import { decideApproval, nextFocus, requesterOf, reachText } from '../shell/src/lib/ai/decide';
import { clampSize, loadSize, saveSize, sizeFromPointer } from '../shell/src/lib/ai/dock-layout';
import { createMarkdownCache, parseInline, parseInlineLinear, parseMarkdown, safeHref } from '../shell/src/ui/markdown';

const ev = (seq: number, e: Partial<AgentSessionEvent>): AgentSessionEvent => ({ seq, type: 'message.delta', ...e }) as AgentSessionEvent;
const empty = (): TranscriptState => ({ items: [], seq: 0, status: 'idle' });
const run = (s: TranscriptState, list: AgentSessionEvent[]) => list.reduce((acc, e) => reduce(acc, e, 1000 + e.seq * 100), s);

/* ------------------------------------------------------------------ transcript */

describe('transcript', () => {
  it('快照：工具消息读取 content_json，system 不展示', () => {
    const s = fromMessages(
      [
        { seq: 2, message_id: 'm2', role: 'tool', content: '读取 CPU', content_json: { action: 'mon/cpu', status: 'succeeded' }, created_at: 't' },
        { seq: 1, message_id: 'm1', role: 'user', content: 'hi', created_at: 't' },
        { seq: 3, message_id: 'm3', role: 'system', content: 'x', created_at: 't' },
      ],
      'idle',
      3,
    );
    expect(s.items.map((x) => x.kind)).toEqual(['user', 'tool']);
    expect(s.items[1]).toMatchObject({ action: 'mon/cpu', status: 'succeeded', text: '读取 CPU' });
    expect(s.seq).toBe(3);
  });

  it('delta 累加、completed 收尾；重复 seq 丢弃', () => {
    const s = run(empty(), [
      ev(1, { type: 'message.delta', message_id: 'a', delta: '你' }),
      ev(2, { type: 'message.delta', message_id: 'a', delta: '好' }),
      ev(2, { type: 'message.delta', message_id: 'a', delta: '好' }),
      ev(3, { type: 'message.completed', message_id: 'a' }),
    ]);
    expect(s.items).toEqual([expect.objectContaining({ kind: 'assistant', text: '你好', streaming: false })]);
    expect(s.seq).toBe(3);
  });

  it('无 message_id 增量自动合并至同气泡；completed 重复全文不翻倍；正文开始时收起思考态', () => {
    const s = run(empty(), [
      ev(1, { type: 'reasoning.delta' as AgentSessionEvent['type'], delta: '思考中' }),
      ev(2, { type: 'message.delta', delta: '签名' }),
      ev(3, { type: 'message.delta', delta: '校验' }),
      ev(4, { type: 'message.completed', delta: '签名校验' }),
    ]);
    expect(s.items).toHaveLength(2);
    expect(s.items[0]).toMatchObject({ kind: 'reasoning', text: '思考中', streaming: false });
    expect(s.items[1]).toMatchObject({ kind: 'assistant', text: '签名校验', streaming: false });
  });

  it('审批时序：tool_call → approval_required → approval_decided → tool_result → turn.completed', () => {
    let s = run(empty(), [
      ev(1, { type: 'tool_call', call_id: 'c1', action: 'sec/fw', risk: 'high' }),
      ev(2, { type: 'approval_required', call_id: 'c1', approval_id: 'apv1', operation_id: 'op1', summary: '开启防火墙' }),
      ev(3, { type: 'turn.completed', status: 'waiting_approval' }),
    ]);
    expect(s.status).toBe('waiting_approval');
    expect(s.items[0]).toMatchObject({ kind: 'tool', status: 'awaiting_approval', approvalId: 'apv1', text: '开启防火墙' });
    s = run(s, [
      ev(4, { type: 'approval_decided', approval_id: 'apv1', decision: 'approve' }),
      ev(5, { type: 'tool_result', call_id: 'c1', status: 'succeeded', operation_id: 'op1' }),
      ev(7, { type: 'turn.completed', status: 'idle' }),
    ]);
    expect(s.items).toHaveLength(1);
    expect(s.items[0]).toMatchObject({ status: 'succeeded', operationId: 'op1', startedAt: 1100, endedAt: 1500 });
    expect(s.status).toBe('idle');
  });

  it('拒绝 → rejected；取消时进行中的工具标为 cancelled；未知 turn 状态按 idle', () => {
    let s = run(empty(), [
      ev(1, { type: 'tool_call', call_id: 'c1', action: 'x' }),
      ev(2, { type: 'approval_required', call_id: 'c1', approval_id: 'p' }),
      ev(3, { type: 'approval_decided', approval_id: 'p', decision: 'reject' }),
    ]);
    expect(s.items[0]).toMatchObject({ status: 'rejected' });
    s = run(s, [ev(4, { type: 'tool_call', call_id: 'c2', action: 'y' }), ev(5, { type: 'turn.completed', status: 'cancelled' })]);
    expect(s.items[1]).toMatchObject({ status: 'cancelled' });
    expect(run(s, [ev(6, { type: 'turn.completed', status: 'completed' })]).status).toBe('idle');
  });

  it('error 帧（顶层 code/detail）成为错误条目', () => {
    const s = run(empty(), [ev(1, { type: 'error', code: 'UNAVAILABLE', detail: 'down' })]);
    expect(s.items[0]).toEqual({ kind: 'error', id: 'e1', code: 'UNAVAILABLE', detail: 'down' });
  });

  it('乐观用户气泡：发送中 → 换成服务端 id / 失败', () => {
    let s = addLocalUser(empty(), 'l1', 'hi');
    expect(s.items[0]).toMatchObject({ state: 'sending' });
    expect(settleLocalUser(s, 'l1', 'failed').items[0]).toMatchObject({ state: 'failed' });
    s = settleLocalUser(s, 'l1', { id: 'm9' });
    expect(s.items[0]).toMatchObject({ id: 'm9', state: undefined });
  });

  it('turnProgress 只数最后一条用户消息之后的工具调用', () => {
    let s = addLocalUser(empty(), 'u0', 'a');
    s = run(s, [ev(1, { type: 'tool_call', call_id: 'old', action: 'x' }), ev(2, { type: 'tool_result', call_id: 'old', status: 'succeeded' })]);
    s = addLocalUser(s, 'u1', 'b');
    s = run(s, [
      ev(3, { type: 'tool_call', call_id: 'a', action: 'x' }),
      ev(4, { type: 'tool_result', call_id: 'a', status: 'succeeded' }),
      ev(5, { type: 'tool_call', call_id: 'b', action: 'x' }),
    ]);
    expect(turnProgress(s)).toEqual({ done: 1, total: 2 });
  });

  it('扩展事件：reasoning.delta、plan.updated、telemetry.updated、command.result、session.compacted', () => {
    const ext = (seq: number, type: string, extra: Record<string, unknown>) =>
      ({ seq, type, ...extra }) as unknown as AgentSessionEvent;
    const s = run(empty(), [
      ext(1, 'reasoning.delta', { delta: '先检查 ' }),
      ext(2, 'reasoning.delta', { result: { delta: 'sshd 配置' } }),
      ext(3, 'plan.updated', {
        result: [
          { id: '1', title: '读取 sshd -T', status: 'completed' },
          { id: '2', title: '检查 cloud-init', status: 'in_progress' },
        ],
      }),
      ext(4, 'telemetry.updated', {
        result: {
          turns: 1,
          steps: 2,
          ttft_ms: 180,
          tps: 68.5,
          tokens: { input: 2000, cached_read: 1840, output: 300, cache_hit_pct: 92 },
          context: { max_tokens: 128000, pct: 18, system_tokens: 800, tool_tokens: 600, message_tokens: 900 },
        },
      }),
      ext(5, 'command.result', { result: { command: '/status', summary: '运行正常', ok: true } }),
      ext(6, 'session.compacted', { result: { before_tokens: 12000, after_tokens: 3400 } }),
      ev(7, { type: 'turn.completed', status: 'idle' }),
    ]);
    expect(s.items.find((x) => x.kind === 'reasoning')).toMatchObject({ text: '先检查 sshd 配置', streaming: false });
    expect(s.plan?.steps).toHaveLength(2);
    expect(s.telemetry).toMatchObject({ turns: 1, steps: 2, ttftMs: 180, cacheHitPct: 92, contextPct: 18 });
    expect(s.items.filter((x) => x.kind === 'command')).toHaveLength(2);
  });
});

/* ------------------------------------------------------------------ 会话流帧 */

describe('parseSessionFrame', () => {
  it('区分 ready / resync / 事件 / 坏帧', () => {
    expect(parseSessionFrame({ event: 'ready', data: '{}' })).toEqual({ kind: 'ready' });
    expect(parseSessionFrame({ event: 'resync', data: '{}' })).toEqual({ kind: 'resync' });
    expect(parseSessionFrame({ event: 'heartbeat', data: '{}' })).toBeNull();
    expect(parseSessionFrame({ data: 'not json' })).toBeNull();
    expect(parseSessionFrame({ data: '{"type":"x"}' })).toBeNull();
    expect(parseSessionFrame({ id: '3', data: '{"type":"error","seq":3}' })).toMatchObject({ kind: 'event', event: { seq: 3 } });
  });
  it('字节计数按 UTF-8', () => {
    expect(byteLength('a中')).toBe(4);
  });
});

/* ------------------------------------------------------------------ Markdown */

describe('markdown 子集', () => {
  it('块级：标题、列表、代码块、引用、段落', () => {
    const b = parseMarkdown('# 标题\n\n- a\n- b\n\n1. x\n2. y\n\n```sh\nls <b>\n```\n> 引用\n\n正文');
    expect(b.map((x) => x.t)).toEqual(['h', 'list', 'list', 'pre', 'quote', 'p']);
    expect(b[3]).toEqual({ t: 'pre', lang: 'sh', v: 'ls <b>' });
  });
  it('HTML 原样当文本', () => {
    expect(parseInline('<img src=x onerror=alert(1)>')).toEqual([{ t: 'text', v: '<img src=x onerror=alert(1)>' }]);
  });
  it('行内：粗体、斜体、代码、换行', () => {
    expect(parseInline('**粗** *斜* `c`\n下')).toEqual([
      { t: 'strong', c: [{ t: 'text', v: '粗' }] },
      { t: 'text', v: ' ' },
      { t: 'em', c: [{ t: 'text', v: '斜' }] },
      { t: 'text', v: ' ' },
      { t: 'code', v: 'c' },
      { t: 'br' },
      { t: 'text', v: '下' },
    ]);
  });
  it('链接只放行 https 与站内路径', () => {
    expect(safeHref('javascript:alert(1)')).toBeNull();
    expect(safeHref('//evil.com')).toBeNull();
    expect(safeHref('http://a.com')).toBeNull();
    expect(safeHref('/activity')).toBe('/activity');
    expect(parseInline('[x](javascript:alert(1))')[0]).toMatchObject({ t: 'text' });
    expect(parseInline('[文档](https://a.com/x)')[0]).toEqual({ t: 'link', href: 'https://a.com/x', c: [{ t: 'text', v: '文档' }] });
  });
  it('下划线在单词中间不算斜体', () => {
    expect(parseInline('snake_case_name')).toEqual([{ t: 'text', v: 'snake_case_name' }]);
  });
  it('O(N) 线性行内解析：64 KiB 未闭合定界符不卡顿', () => {
    const evil = '*a '.repeat(8000) + '_b '.repeat(8000) + '[c'.repeat(8000) + '`d'.repeat(4000);
    const t0 = performance.now();
    const out = parseInlineLinear(evil);
    const dt = performance.now() - t0;
    expect(out.length).toBeGreaterThan(0);
    expect(dt).toBeLessThan(150);
  });
  it('增量缓存：流式追加时已闭合段落直接复用 AST', () => {
    const cache = createMarkdownCache();
    const b1 = cache.parse('# 标题\n\n第一段内容\n\n第二段');
    const b2 = cache.parse('# 标题\n\n第一段内容\n\n第二段继续流式吐字');
    expect(b2[0]).toBe(b1[0]);
    expect(b2[1]).toBe(b1[1]);
    expect(b2[2]).toEqual({ t: 'p', c: [{ t: 'text', v: '第二段继续流式吐字' }] });
  });
});

/* ------------------------------------------------------------------ 审批 */

const approval = (over: Partial<Approval> = {}): Approval =>
  ({
    approval_id: 'apv1',
    operation_id: 'op1',
    status: 'PENDING',
    requires_mfa: false,
    created_at: '2026-01-01T00:00:00Z',
    expires_at: '2026-01-01T00:15:00Z',
    revision: '7',
    facts: {
      action: { id: 'host.users.create', summary: '创建用户', source: 'host' },
      args: {},
      target: {},
      required_capabilities: [],
      effect: 'write',
      declared_risk: 'medium',
      effective_risk: 'medium',
      reversible: true,
      requested_by: { kind: 'ai_agent', id: 'session:sess_1' },
    },
    ...over,
  }) as Approval;

describe('审批决定', () => {
  it('提交带 expected_revision、裁剪备注', async () => {
    const call = vi.fn().mockResolvedValue(approval({ status: 'APPROVED' }));
    const r = await decideApproval(approval(), { decision: 'approve', comment: '  ok  ', mfaCode: '123456' }, 'k1', call);
    expect(r.kind).toBe('ok');
    expect(call).toHaveBeenCalledWith('apv1', { decision: 'approve', expected_revision: '7', comment: 'ok', mfa_code: '123456' }, 'k1');
  });
  it('409 → 已被处理；MFA_REQUIRED → 字段错误；其它原样', async () => {
    const fail = (code: string, status: number) => vi.fn().mockRejectedValue(new ApiError(status, { code, title: code, status } as never, code));
    expect(await decideApproval(approval(), { decision: 'reject' }, 'k', fail('STATE_CONFLICT', 409))).toEqual({ kind: 'handled' });
    expect(await decideApproval(approval(), { decision: 'approve', mfaCode: '000000' }, 'k', fail('MFA_REQUIRED', 403))).toMatchObject({
      kind: 'mfa',
      message: '验证码不对或已过期',
    });
    expect((await decideApproval(approval(), { decision: 'approve' }, 'k', fail('INTERNAL', 500))).kind).toBe('error');
  });
  it('发起者与胶囊文案', () => {
    const f = approval().facts;
    expect(requesterOf(f, 'usr_a').text).toBe('AI 助手代你发起');
    expect(requesterOf({ ...f, requested_by: { kind: 'ai_agent', id: 'dlg_1', display_name: 'Claude' } }, 'u').text).toContain('外部 AI「Claude」');
    expect(requesterOf({ ...f, requested_by: { kind: 'human', id: 'usr_a' } }, 'usr_a').text).toBe('你发起');
    expect(reachText(approval())).toBe('AI 想创建用户');
  });
  it('批完一张后聚焦：后一张 → 前一张 → 无', () => {
    expect(nextFocus(['a', 'b', 'c'], 'b')).toBe('c');
    expect(nextFocus(['a', 'b'], 'b')).toBe('a');
    expect(nextFocus(['a'], 'a')).toBeNull();
    expect(nextFocus(['x', 'y'], 'gone')).toBe('x');
  });
});

/* ------------------------------------------------------------------ 悬浮窗尺寸 */

describe('悬浮窗尺寸', () => {
  it('钳制到 360×360 ~ 720×80vh，并给视口留边', () => {
    expect(clampSize({ w: 100, h: 100 }, 1400, 1000)).toEqual({ w: 360, h: 360 });
    expect(clampSize({ w: 2000, h: 2000 }, 1400, 1000)).toEqual({ w: 720, h: 800 });
    expect(clampSize({ w: 700, h: 400 }, 500, 1000).w).toBe(468);
  });
  it('拖右上角：宽为到中线距离的 2 倍，高为到底边距离', () => {
    expect(sizeFromPointer({ x: 1000, y: 300 }, { centerX: 700, bottom: 900, top: 24 }, 1400, 1000)).toEqual({ w: 600, h: 600 });
  });
  it('存取 localStorage，坏值忽略', () => {
    const store = new Map<string, string>();
    const s = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v), removeItem: (k: string) => void store.delete(k) };
    saveSize({ w: 500, h: 400 }, s);
    expect(loadSize(s)).toEqual({ w: 500, h: 400 });
    store.set('qwq.dock.size', '{bad');
    expect(loadSize(s)).toBeNull();
  });
});

/* ------------------------------------------------------------------ ⌘K 条目 */

import { buildGroups, gradeOf, moveCursor, pushRecent } from '../shell/src/features/palette/items';

describe('⌘K 条目', () => {
  const pages = [
    { kind: 'page' as const, id: 'page:/', label: '主页', href: '/', icon: 'home' as const },
    { kind: 'page' as const, id: 'page:/apps', label: '应用中心', href: '/apps', icon: 'apps' as const, keywords: 'plugin' },
  ];
  const act = { id: 'host.users.create', summary: '创建用户', effect: 'write', risk: 'high', source: 'host' } as never;

  it('分组顺序：页面 → 操作 → 最近 → 问 AI；最近去重', () => {
    const g = buildGroups({ q: '', pages, actions: [act], recent: [pages[0]!, { kind: 'page', id: 'page:/x', label: 'X', href: '/x', icon: 'home' }] });
    expect(g.map((x) => x.title)).toEqual(['页面', '操作', '最近', 'AI']);
    expect(g[2]!.items.map((x) => x.id)).toEqual(['page:/x']);
    expect(g.at(-1)!.items[0]).toMatchObject({ kind: 'ask', label: '问 AI' });
  });
  it('关键词命中、无结果时只剩问 AI', () => {
    expect(buildGroups({ q: 'PLUGIN', pages, actions: [], recent: [] })[0]!.items[0]!.id).toBe('page:/apps');
    const g = buildGroups({ q: '重启 nginx', pages, actions: [], recent: [] });
    expect(g).toHaveLength(1);
    expect(g[0]!.items[0]).toMatchObject({ prompt: '重启 nginx', label: '问 AI：重启 nginx' });
  });
  it('游标循环、最近置顶去重', () => {
    expect(moveCursor(0, -1, 3)).toBe(2);
    expect(moveCursor(2, 1, 3)).toBe(0);
    expect(pushRecent([pages[0]!, pages[1]!], pages[1]!).map((x) => x.id)).toEqual(['page:/apps', 'page:/']);
  });
  it('定级：人发起时哪些会进审批', () => {
    expect(gradeOf({ effect: 'read', risk: 'low' }).needsApproval).toBe(false);
    expect(gradeOf({ effect: 'write', risk: 'low', approval: 'auto' }).needsApproval).toBe(false);
    expect(gradeOf({ effect: 'write', risk: 'low', approval: 'confirm' }).needsApproval).toBe(true);
    expect(gradeOf({ effect: 'write', risk: 'medium' }).needsApproval).toBe(true);
    expect(gradeOf({ effect: 'destructive', risk: 'low' }).label).toContain('验证码');
  });
});

/* ------------------------------------------------------------------ 悬浮窗状态机 */

import { ApprovalQueue } from '../shell/src/lib/ai/approvals.svelte';

describe('悬浮窗状态机（审批队列驱动 reach）', () => {
  it('未看过的待审批 → unseen；markSeen 后清空；决定后移出队列', async () => {
    const a1 = approval({ approval_id: 'a1', created_at: '2026-01-01T00:01:00Z' });
    const a2 = approval({ approval_id: 'a2', created_at: '2026-01-01T00:00:00Z' });
    const q = new ApprovalQueue(async () => ({ items: [a1, a2], revision: '1', delta: false }) as never, async () => a1);
    await q.load();
    expect(q.pending.map((x) => x.approval_id)).toEqual(['a2', 'a1']);
    expect(q.unseen).toHaveLength(2);
    q.markSeen('a2');
    expect(q.unseen.map((x) => x.approval_id)).toEqual(['a1']);
    q.upsert({ ...a1, status: 'APPROVED' });
    expect(q.pending.map((x) => x.approval_id)).toEqual(['a2']);
    expect(q.unseen).toHaveLength(0);
  });
});

import { approvals } from '../shell/src/lib/ai/approvals.svelte';
import { dock } from '../shell/src/lib/ai/dock.svelte';

describe('悬浮窗模式优先级：open > reach > working > rest', () => {
  it('busy / 未看审批 / 展开 依次覆盖；收起清掉聚焦', () => {
    expect(dock.mode).toBe('rest');
    dock.busy = true;
    expect(dock.mode).toBe('working');
    approvals.upsert(approval({ approval_id: 'z1' }));
    expect(dock.mode).toBe('reach');
    dock.open({ approvalId: 'z1', prompt: '查一下磁盘' });
    expect([dock.mode, dock.focusApprovalId, dock.prompt]).toEqual(['open', 'z1', '查一下磁盘']);
    dock.close();
    expect([dock.mode, dock.focusApprovalId]).toEqual(['reach', null]);
    approvals.markSeen('z1');
    expect(dock.mode).toBe('working');
    dock.busy = false;
    expect(dock.mode).toBe('rest');
  });
});
