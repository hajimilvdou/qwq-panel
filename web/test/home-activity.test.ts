// SPDX-License-Identifier: AGPL-3.0-only
/* 主页与动态：小组件结果校验、健康度聚合、折线几何、人话句子、按天分组、增量时间线 */
import { describe, expect, it } from 'vitest';
import type { Op } from '$api/endpoints';
import type { Page } from '$api/types';
import { actorView, groupByDay, opObject, opSentence } from '$lib/activity';
import { collectWidgets, levelOf, parseWidget, refreshMs, worstLevel, WidgetShapeError } from '$lib/widgets';
import { chartGeometry, niceCeil } from '$ui/chart';
import { OpsFeed } from '../shell/src/features/activity/feed.svelte';

describe('parseWidget', () => {
  it('stat：合法值通过，percent 夹在 0..100', () => {
    const w = parseWidget('stat', { value: 42, unit: '%', percent: 140, level: 'warn', extra: 'x' });
    expect(w).toEqual({ kind: 'stat', data: { value: 42, unit: '%', sub: undefined, percent: 100, spark: undefined, level: 'warn' } });
  });

  it('非法形状抛 WidgetShapeError 并指出路径', () => {
    expect(() => parseWidget('stat', { value: NaN })).toThrow(WidgetShapeError);
    expect(() => parseWidget('checks', { items: [{ label: 'a', value: 'b', level: 'great' }] })).toThrow(/items\[0\]\.level/);
    expect(() => parseWidget('series', { series: [{ name: 'x', points: [[1, 'a']] }] })).toThrow(/points\[0\]\[1\]/);
    expect(() => parseWidget('list', null)).toThrow(WidgetShapeError);
  });

  it('series：点按时间排序，未知颜色丢弃', () => {
    const w = parseWidget('series', { series: [{ name: '下行', color: 'neon', points: [[3, 1], [1, 2]] }] });
    expect(w.kind === 'series' && w.data.series[0]).toEqual({ name: '下行', color: undefined, points: [[1, 2], [3, 1]] });
  });

  it('长字符串截断', () => {
    const w = parseWidget('list', { items: [{ title: 'x'.repeat(500) }] });
    expect(w.kind === 'list' && w.data.items[0]!.title.length).toBe(120);
  });
});

describe('健康度', () => {
  it('worstLevel：全 ok→ok，任一 warn→warn，任一 bad→bad，未知不计', () => {
    expect(worstLevel([])).toBe('ok');
    expect(worstLevel(['ok', undefined, 'warn'])).toBe('warn');
    expect(worstLevel(['warn', 'bad', 'ok'])).toBe('bad');
  });

  it('levelOf：checks 取最差项；series 与 list 不参与', () => {
    expect(levelOf(parseWidget('checks', { items: [{ label: 'a', value: '1', level: 'ok' }, { label: 'b', value: '2', level: 'bad' }] }))).toBe('bad');
    expect(levelOf(parseWidget('list', { items: [{ title: 'x', level: 'warn' }] }))).toBeUndefined();
    expect(levelOf(parseWidget('series', { series: [] }))).toBeUndefined();
  });

  it('refreshMs 下限 2 秒', () => {
    expect(refreshMs({ refresh_seconds: 0 })).toBe(2000);
    expect(refreshMs({ refresh_seconds: 30 })).toBe(30_000);
  });

  it('collectWidgets 跳过未运行的插件', () => {
    const w = { id: 'cpu', title: 'CPU', kind: 'stat', operation: 'o', refresh_seconds: 2, size: 's' } as const;
    const mk = (id: string, state: 'running' | 'stopped') =>
      ({ plugin_id: id, runtime: { state }, ui: { entry_url: '', routes: [], widgets: [w], connect_sources: [] } }) as never;
    expect(collectWidgets([mk('a', 'running'), mk('b', 'stopped')]).map((s) => s.key)).toEqual(['a/cpu']);
  });
});

describe('chartGeometry', () => {
  it('niceCeil 取 1/2/2.5/5 档', () => {
    expect([0, 0.7, 3, 7.2, 23, 240].map(niceCeil)).toEqual([1, 1, 5, 10, 25, 250]);
  });

  it('纵轴从 0 起，首尾点落在左右边缘', () => {
    const g = chartGeometry([{ name: 'a', points: [[10, 0], [20, 4]] }], { width: 100, height: 50 });
    expect(g.hi).toBe(5);
    expect(g.project([10, 0])[0]).toBe(0);
    expect(g.project([20, 4])[0]).toBe(100);
    expect(g.lines[0]!.line.startsWith('M0.0 ')).toBe(true);
    expect(g.lines[0]!.area.endsWith('Z')).toBe(true);
  });

  it('nearest 找到最近的点；空系列安全', () => {
    const g = chartGeometry([{ name: 'a', points: [[0, 1], [10, 2], [20, 3]] }], { width: 200, height: 50 });
    expect(g.nearest(95)).toBe(1);
    expect(g.nearest(9999)).toBe(2);
    expect(chartGeometry([], { width: 10, height: 10 }).nearest(5)).toBe(-1);
  });
});

describe('动态人话', () => {
  it('actorView：自己写"你"，AI 与系统各有兜底名', () => {
    expect(actorView({ kind: 'human', id: 'u1', display_name: 'Alice' }, 'u1').name).toBe('你');
    expect(actorView({ kind: 'human', id: 'u2', display_name: 'Bob' }, 'u1')).toEqual({ name: 'Bob', face: 'human', ai: false });
    expect(actorView({ kind: 'ai_agent', id: 'a' })).toEqual({ name: 'AI 助手', face: 'ai', ai: true });
    expect(actorView({ kind: 'service', id: 's' }).face).toBe('system');
  });

  it('opSentence 用目录摘要，缺失时回退 id 末段', () => {
    const cat = new Map([['host.users.update', '修改用户']]);
    expect(opSentence({ action: 'host.users.update' }, cat)).toBe('修改用户');
    expect(opSentence({ action: 'com.qwq.security/ssh.ban_ip' })).toBe('ssh ban ip');
  });

  it('opObject：参数优先，其次 subject，再次插件名', () => {
    expect(opObject({ args: { ip: '1.2.3.4' }, target: {} })).toBe('1.2.3.4');
    expect(opObject({ target: { subject: 'users/usr_bob' } })).toBe('bob');
    expect(opObject({ target: { plugin_id: 'p' } }, () => '系统监控')).toBe('系统监控');
    expect(opObject({ target: {} })).toBeUndefined();
  });

  it('groupByDay：今天/昨天/日期，组内保持顺序', () => {
    const now = new Date(2026, 10, 9, 15, 0).getTime();
    const at = (d: number, h: number) => new Date(2026, 10, d, h).toISOString();
    const g = groupByDay([at(9, 14), at(9, 1), at(8, 23), at(3, 9)], (x) => x, now);
    expect(g.map((x) => x.label)).toEqual(['今天', '昨天', '11月3日 周二']);
    expect(g[0]!.items).toHaveLength(2);
  });
});

describe('OpsFeed', () => {
  const op = (id: string, at: string, rev = 'r1'): Op =>
    ({ operation_id: id, created_at: at, revision: rev, status: 'SUCCEEDED' }) as Op;
  const page = (items: Op[], extra: Partial<Page<Op>> = {}): Page<Op> => ({ items, revision: 'r5', delta: false, ...extra });

  it('reload → more → sync 增量合并并删除 deleted_ids', async () => {
    const calls: unknown[] = [];
    const replies = [
      page([op('b', '2026-11-09T02:00:00Z'), op('a', '2026-11-09T01:00:00Z')], { next_cursor: 'c1' }),
      page([op('z', '2026-11-08T01:00:00Z'), op('a', '2026-11-09T01:00:00Z')]),
      page([op('c', '2026-11-09T03:00:00Z')], { delta: true, deleted_ids: ['z'], revision: 'r6' }),
    ];
    const feed = new OpsFeed(async (q) => {
      calls.push(q);
      return replies.shift()!;
    });
    await feed.reload();
    expect(feed.next).toBe('c1');
    await feed.more();
    expect(feed.items.map((o) => o.operation_id)).toEqual(['b', 'a', 'z']);
    await feed.sync();
    expect(feed.items.map((o) => o.operation_id)).toEqual(['c', 'b', 'a']);
    expect(calls).toEqual([{ limit: 30 }, { cursor: 'c1', limit: 30 }, { since_revision: 'r5', limit: 100 }]);
  });

  it('过期的 reload 响应被丢弃；首屏失败进入 error', async () => {
    let n = 0;
    const feed = new OpsFeed(async () => {
      const k = ++n;
      if (k === 1) {
        await new Promise((r) => setTimeout(r, 20));
        return page([op('old', '2026-11-09T01:00:00Z')]);
      }
      return page([op('new', '2026-11-09T02:00:00Z')]);
    });
    const slow = feed.reload();
    await feed.reload();
    await slow;
    expect(feed.items.map((o) => o.operation_id)).toEqual(['new']);

    const bad = new OpsFeed(async () => {
      throw new Error('x');
    });
    await bad.reload();
    expect(bad.status).toBe('error');
  });
});
