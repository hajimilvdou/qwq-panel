// SPDX-License-Identifier: AGPL-3.0-only
/* 路由匹配、回跳地址校验、错误映射、草稿脱敏 */
import { describe, expect, it } from 'vitest';
import { createMatcher, safeNext } from '$lib/router.svelte';
import { describeError } from '$lib/errors';
import { stripSecrets } from '$lib/drafts';
import { ApiError, NetworkError } from '$api/client';
import type { RouteDef } from '$lib/router.svelte';

const stub = (pattern: string): RouteDef => ({ pattern, title: pattern, load: async () => ({ default: (() => {}) as never }) });

describe('router', () => {
  const match = createMatcher(['/', '/activity/:operationId', '/plugins/:pluginId/*', '/apps/install', '/apps/:pluginId', '/*'].map(stub));

  it('参数解码与首个匹配优先', () => {
    expect(match('/')?.route.pattern).toBe('/');
    expect(match('/activity/op%2F1')?.params).toEqual({ operationId: 'op/1' });
    expect(match('/apps/install')?.route.pattern).toBe('/apps/install');
    expect(match('/apps/com.qwq.dns')?.params).toEqual({ pluginId: 'com.qwq.dns' });
  });

  it('通配子路径', () => {
    expect(match('/plugins/com.qwq.monitor')?.params).toEqual({ pluginId: 'com.qwq.monitor' });
    expect(match('/plugins/com.qwq.monitor/a/b')?.params).toEqual({ pluginId: 'com.qwq.monitor', rest: 'a/b' });
    expect(match('/nope/x')?.route.pattern).toBe('/*');
  });

  it('safeNext 只接受站内相对路径', () => {
    expect(safeNext('/apps?x=1')).toBe('/apps?x=1');
    for (const bad of ['//evil.com', '/\\evil.com', 'https://evil.com', 'apps', '', null, '/a\nb']) {
      expect(safeNext(bad)).toBe('/');
    }
  });
});

describe('describeError', () => {
  const api = (status: number, code: string, extra: object = {}) =>
    new ApiError(status, { type: 'x', title: 'Internal Title', status, code: code as never, retryable: false, request_id: 'req_9', ...extra }, '');

  it('按 code 给人话，不展示 title', () => {
    const v = describeError(api(409, 'REVISION_CONFLICT'));
    expect(v.message).toContain('别人改过');
    expect(v.message).not.toContain('Internal');
    expect(v.action).toBe('reload');
  });

  it('5xx 带 request_id；PLUGIN_ERROR 标出插件原文', () => {
    expect(describeError(api(500, 'INTERNAL')).requestId).toBe('req_9');
    expect(describeError(api(502, 'PLUGIN_ERROR', { detail: 'nft failed' })).fromPlugin).toBe('nft failed');
  });

  it('未知 code 按状态类兜底；字段错误按指针', () => {
    expect(describeError(api(404, 'SOMETHING_NEW')).message).toContain('找不到');
    const v = describeError(api(400, 'VALIDATION_FAILED', { violations: [{ in: 'body', pointer: '/name', code: 'X', message: '必填' }] }));
    expect(v.fields).toEqual({ '/name': '必填' });
  });

  it('网络错误与限流', () => {
    expect(describeError(new NetworkError(new Error())).action).toBe('retry');
    expect(describeError(api(429, 'RATE_LIMITED', { retry_after: 12 })).message).toContain('12 秒');
  });
});

describe('drafts', () => {
  it('剔除口令、令牌、验证码类字段（含嵌套）', () => {
    expect(stripSecrets({ name: 'a', password: 'x', nested: { api_key: 'k', note: 'n' }, mfa_code: '1' })).toEqual({ name: 'a', nested: { note: 'n' } });
  });
});
