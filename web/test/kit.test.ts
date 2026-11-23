// SPDX-License-Identifier: AGPL-3.0-only
/* Track 07 缺陷修复回归 + @qwq/kit v1 ↔ PluginBridge 端到端协议互通测试 */
import { describe, expect, it, vi } from 'vitest';
import {
  createPluginBridge,
  generateOpenSSHEd25519KeyPair,
  invokeWithApprovalFollowup,
  parseInitialFragment,
  PluginHostError,
  PluginInvokeError,
  QwqPluginBridge,
  unwrapInvokeOutcome,
} from '../kit/src/index';
import { MAX_MESSAGE_BYTES, PluginBridge, subjectAllowed } from '../shell/src/lib/plugin-host/index';
import { roleCan } from '../shell/src/lib/session.svelte';
import { stripSecrets } from '../shell/src/lib/drafts';
import { createFormIntent } from '../shell/src/lib/ops';
import { safeHref } from '../shell/src/ui/markdown';
import { safeExternalHref, safeInternalPath } from '../shell/src/ui/safe-url';
import { fieldsOf } from '../shell/src/ui/schema-form';
import { activeHref, isActive } from '../shell/src/app/nav';

describe('Track 07 P0/P1 修复回归', () => {
  it('P0-FE-02: roleCan 与后端 internal/authz/roles.go 一致', () => {
    expect(roleCan('admin', 'host.users:delete')).toBe(true);
    expect(roleCan('operator', 'host.plugins:config')).toBe(true);
    expect(roleCan('operator', 'host.plugins:rollback')).toBe(true);
    expect(roleCan('operator', 'host.agent_sessions:write')).toBe(true);
    expect(roleCan('operator', 'host.ai_providers:read')).toBe(true);
    expect(roleCan('operator', 'host.ai_providers:create')).toBe(false);
    expect(roleCan('operator', 'host.users:read')).toBe(false);
    expect(roleCan('operator', 'host.audit:read')).toBe(false);
    expect(roleCan('viewer', 'host.plugins:read')).toBe(true);
    expect(roleCan('viewer', 'host.plugins:watch')).toBe(true);
    expect(roleCan('viewer', 'host.plugins:logs')).toBe(false);
    expect(roleCan('viewer', 'host.account:update')).toBe(true);
    expect(roleCan('viewer', 'host.plugins:config')).toBe(false);
    expect(roleCan('viewer', 'host.users:read')).toBe(false);
  });

  it('P0-FE-03 / P1-FE-08: x-secret 识别与数组嵌套对象机密剔除', () => {
    const fields = fieldsOf({
      type: 'object',
      properties: {
        a: { type: 'string', 'x-secret': true },
        b: { type: 'string', 'x-qwq-secret': true },
      },
    });
    expect(fields.map((f) => f.kind)).toEqual(['secret', 'secret']);
    const cleaned = stripSecrets({
      name: 'ok',
      inbounds: [{ tag: 'vless', private_key: 'SECRET', nested: { token: 't', port: 443 } }],
    });
    expect(cleaned).toEqual({
      name: 'ok',
      inbounds: [{ tag: 'vless', nested: { port: 443 } }],
    });
  });

  it('P0-FE-04: FormIntent 相同载荷复用 Key，载荷变更或 422/409 后自动轮换', () => {
    const fi = createFormIntent();
    const k1 = fi.keyFor({ name: 'a' });
    expect(fi.keyFor({ name: 'a' })).toBe(k1);
    fi.onError(503);
    expect(fi.keyFor({ name: 'a' })).toBe(k1);
    fi.onError(422);
    const k2 = fi.keyFor({ name: 'a' });
    expect(k2).not.toBe(k1);
    const k3 = fi.keyFor({ name: 'b' });
    expect(k3).not.toBe(k2);
  });

  it('P1-FE-01: safeHref 拒绝 /\\\\evil.com、制表符跨源归一与换行注入', () => {
    expect(safeHref('/\\evil.com')).toBeNull();
    expect(safeHref('/\t\\example.invalid/path')).toBeNull();
    expect(safeHref('/ok\nfoo')).toBeNull();
    expect(safeHref('//evil.example/x')).toBeNull();
    expect(safeHref('/apps/security')).toBe('/apps/security');
  });

  it('P1-FE-02: subjectAllowed 放行插件与节点级插件 subject，拒绝越权', () => {
    expect(subjectAllowed('com.qwq.xray', 'plugins/com.qwq.xray')).toBe(true);
    expect(subjectAllowed('com.qwq.xray', 'plugins/com.qwq.xray/nodes')).toBe(true);
    expect(subjectAllowed('com.qwq.xray', 'nodes/local/plugins/com.qwq.xray/status')).toBe(true);
    expect(subjectAllowed('com.qwq.xray', 'nodes/local/plugins/com.qwq.other/status')).toBe(false);
    expect(subjectAllowed('com.qwq.xray', 'users/admin')).toBe(false);
  });
});

describe('@qwq/kit v1 ↔ PluginBridge 端到端握手与调用', () => {
  it('完成 plugin.hello → plugin.port → ui.ready、pendingRoute 回放、带 CAS 的 invoke 与事件订阅', async () => {
    let pluginMsgListener: ((e: MessageEvent) => void) | null = null;
    const parentWin = {
      postMessage: (data: unknown) => {
        hostBridge.onWindowMessage({ source: iframeWin, data } as unknown as MessageEvent);
      },
    } as unknown as Window;
    const iframeWin = {
      postMessage: (data: unknown, _origin: string, transfer?: Transferable[]) => {
        pluginMsgListener?.({ source: parentWin, data, ports: (transfer ?? []) as unknown as MessagePort[] } as unknown as MessageEvent);
      },
    } as unknown as Window;

    const invoked: Array<{ id: string; key: string | undefined; subject?: string; expectedRevision?: string }> = [];
    const hostEvents: { emit: ((e: { subject: string; type: string }) => void) | null } = { emit: null };
    const onReady = vi.fn();

    const hostBridge = new PluginBridge({
      pluginId: 'com.qwq.demo',
      operations: [
        { id: 'com.qwq.demo/read_job', effect: 'read', mode: 'job' },
        { id: 'com.qwq.demo/save', effect: 'write', mode: 'invoke' },
      ],
      routes: [{ path: '/' }, { path: '/bans' }],
      invoke: async (op, _payload, key, meta) => {
        invoked.push({ id: op.id, key, subject: meta?.subject, expectedRevision: meta?.expectedRevision });
        return { ok: true, op: op.id };
      },
      toProblem: () => ({ code: 'INTERNAL', status: 500 }),
      subscribe: (fn) => {
        hostEvents.emit = (e) => fn(e);
        return () => {
          hostEvents.emit = null;
        };
      },
      newKey: () => 'idem_123',
      onReady,
      onResize: vi.fn(),
      onToast: vi.fn(),
      onNavigate: vi.fn(),
      onTimeout: vi.fn(),
    });

    hostBridge.attach(iframeWin);
    /* 握手前先下发路由，应缓存并在连接后回放 */
    hostBridge.route('/bans');

    const routes: string[] = [];
    const client = await createPluginBridge({
      hash: '#theme=dark&motion=reduced&density=compact&path=/',
      win: {
        addEventListener: (_t: string, fn: EventListenerOrEventListenerObject) => {
          pluginMsgListener = fn as (e: MessageEvent) => void;
        },
        removeEventListener: () => {
          pluginMsgListener = null;
        },
      },
      parent: parentWin,
    });

    expect(parseInitialFragment('#theme=dark&density=compact&path=/bans').route).toBe('/bans');
    client.onRoute((r) => routes.push(r));

    /* 已中止的 signal 立即 reject，绝不永久挂起 */
    const preAborted = new AbortController();
    preAborted.abort();
    await expect(client.invoke('save', {}, { signal: preAborted.signal })).rejects.toMatchObject({ code: 'ABORTED' });

    const res = await client.invoke<{ ok: boolean }>('save', { a: 1 }, { subject: 'plugins/com.qwq.demo/cfg', expectedRevision: 'rev_7' });
    expect(res).toEqual({ ok: true, op: 'com.qwq.demo/save' });
    expect(invoked[0]).toEqual({
      id: 'com.qwq.demo/save',
      key: 'idem_123',
      subject: 'plugins/com.qwq.demo/cfg',
      expectedRevision: 'rev_7',
    });

    /* read + mode=job 必须附带幂等键 */
    await client.invoke('read_job', {});
    expect(invoked[1]?.key).toBe('idem_123');

    /* 未声明操作返回 PluginHostError(PERMISSION_DENIED) */
    await expect(client.invoke('forbidden_op', {})).rejects.toBeInstanceOf(PluginHostError);

    /* 事件订阅只放行本插件 subject */
    const gotEvents: string[] = [];
    client.subscribe(['nodes/local/plugins/com.qwq.demo'], (e) => gotEvents.push(e.subject));
    await new Promise((r) => setTimeout(r, 20));
    hostEvents.emit?.({ subject: 'nodes/local/plugins/com.qwq.demo/live', type: 'resource.changed' });
    hostEvents.emit?.({ subject: 'users/admin', type: 'resource.changed' });
    await new Promise((r) => setTimeout(r, 20));
    expect(gotEvents).toEqual(['nodes/local/plugins/com.qwq.demo/live']);
    expect(onReady).toHaveBeenCalledOnce();

    client.dispose();
    hostBridge.dispose();
  });

  it('P1 加固回归：拒绝非 parent 来源伪造 port，且重连复用 kit_1 时旧连接结果不串扰', async () => {
    let pluginMsgListener: ((e: MessageEvent) => void) | null = null;
    const resolvers: Array<{ resolve: (v: unknown) => void; signal?: AbortSignal }> = [];
    const makePair = () => {
      const parentWin = {
        postMessage: (data: unknown) => {
          hostBridge.onWindowMessage({ source: iframeWin, data } as unknown as MessageEvent);
        },
      } as unknown as Window;
      const iframeWin = {
        postMessage: (data: unknown, _origin: string, transfer?: Transferable[]) => {
          pluginMsgListener?.({ source: parentWin, data, ports: (transfer ?? []) as unknown as MessagePort[] } as unknown as MessageEvent);
        },
      } as unknown as Window;
      return { parentWin, iframeWin };
    };

    const hostBridge = new PluginBridge({
      pluginId: 'com.qwq.demo',
      operations: [{ id: 'com.qwq.demo/slow', effect: 'read', mode: 'invoke' }],
      routes: [{ path: '/' }],
      invoke: (_op, _payload, _key, meta) =>
        new Promise((resolve) => {
          resolvers.push({ resolve, signal: meta?.signal });
        }),
      toProblem: () => ({ code: 'INTERNAL', status: 500 }),
      subscribe: () => () => {},
      newKey: () => 'k',
      onReady: vi.fn(),
      onResize: vi.fn(),
      onToast: vi.fn(),
      onNavigate: vi.fn(),
      onTimeout: vi.fn(),
    });

    /* 1. 伪造非 parent 来源的 plugin.port 必须被忽略 */
    const p1 = makePair();
    hostBridge.attach(p1.iframeWin);
    const fakeCh = new MessageChannel();
    const client1Promise = createPluginBridge({
      win: {
        addEventListener: (_t: string, fn: EventListenerOrEventListenerObject) => {
          pluginMsgListener = fn as (e: MessageEvent) => void;
          /* 立即注入一条来自其它窗口的伪造 port，不能被采信 */
          pluginMsgListener({ source: {} as Window, data: { t: 'plugin.port' }, ports: [fakeCh.port2] } as unknown as MessageEvent);
        },
        removeEventListener: () => {
          pluginMsgListener = null;
        },
      },
      parent: p1.parentWin,
    });
    const client1 = await client1Promise;
    fakeCh.port1.close();
    fakeCh.port2.close();

    /* 2. 连接 1 发起 kit_1（挂起中），随后重连创建连接 2 也发起 kit_1 */
    const oldReq = client1.invoke<{ gen: number }>('slow', {});
    await new Promise((r) => setTimeout(r, 15));
    expect(resolvers.length).toBe(1);

    const p2 = makePair();
    hostBridge.attach(p2.iframeWin);
    expect(resolvers[0]?.signal?.aborted).toBe(true);
    const client2 = await createPluginBridge({
      win: {
        addEventListener: (_t: string, fn: EventListenerOrEventListenerObject) => {
          pluginMsgListener = fn as (e: MessageEvent) => void;
        },
        removeEventListener: () => {
          pluginMsgListener = null;
        },
      },
      parent: p2.parentWin,
    });

    const newReq = client2.invoke<{ gen: number }>('slow', {});
    await new Promise((r) => setTimeout(r, 15));
    expect(resolvers.length).toBe(2);

    /* 先完成旧连接 1 的 Promise，不能误落到连接 2 的 kit_1 上 */
    resolvers[0]!.resolve({ gen: 1 });
    await new Promise((r) => setTimeout(r, 15));
    resolvers[1]!.resolve({ gen: 2 });
    await expect(newReq).resolves.toEqual({ gen: 2 });

    client1.dispose();
    await expect(oldReq).rejects.toMatchObject({ code: 'DISPOSED' });
    client2.dispose();
    hostBridge.dispose();
  });

  it('STEP-16: @qwq/kit v2 public_origin / ui.confirm / ui.copy / events.unsubscribe / 三态解包与 QwqPluginBridge', async () => {
    let pluginMsgListener: ((e: MessageEvent) => void) | null = null;
    const parentWin = {
      postMessage: (data: unknown) => {
        hostBridge.onWindowMessage({ source: iframeWin, data } as unknown as MessageEvent);
      },
    } as unknown as Window;
    const iframeWin = {
      postMessage: (data: unknown, _origin: string, transfer?: Transferable[]) => {
        pluginMsgListener?.({ source: parentWin, data, ports: (transfer ?? []) as unknown as MessagePort[] } as unknown as MessageEvent);
      },
    } as unknown as Window;

    const hostEvents: { emit: ((e: { subject: string; type: string }) => void) | null; unsubCalled: number } = {
      emit: null,
      unsubCalled: 0,
    };
    const copied: Array<{ text: string; label?: string }> = [];
    const hostBridge = new PluginBridge({
      pluginId: 'proxy.advanced',
      operations: [
        { id: 'proxy.advanced/list', effect: 'read', mode: 'invoke' },
        { id: 'proxy.advanced/delete', effect: 'destructive', mode: 'invoke' },
      ],
      routes: [{ path: '/' }],
      invoke: async (op) => {
        if (op.id === 'proxy.advanced/delete') {
          return { status: 'AWAITING_APPROVAL', operation_id: 'op_1', approval_id: 'apv_9' };
        }
        return { status: 'SUCCEEDED', operation_id: 'op_0', result: { items: [1, 2] } };
      },
      toProblem: () => ({ code: 'INTERNAL', status: 500 }),
      subscribe: (fn) => {
        hostEvents.emit = (e) => fn(e);
        return () => {
          hostEvents.emit = null;
          hostEvents.unsubCalled++;
        };
      },
      newKey: () => 'idem_v2',
      onReady: vi.fn(),
      onResize: vi.fn(),
      onToast: vi.fn(),
      onNavigate: vi.fn(),
      onTimeout: vi.fn(),
      onConfirm: async (req) => req.danger === true,
      onCopy: async (req) => {
        copied.push(req);
      },
    });

    hostBridge.settings({
      theme: 'dark',
      motion: 'full',
      density: 'comfortable',
      tokens: { '--accent': '#6366f1' },
      visible: true,
      public_origin: 'https://panel.example.com:8443',
    });
    hostBridge.attach(iframeWin);

    const bridge = new QwqPluginBridge({
      hash: '#theme=dark&path=/',
      win: {
        addEventListener: (_t: string, fn: EventListenerOrEventListenerObject) => {
          pluginMsgListener = fn as (e: MessageEvent) => void;
        },
        removeEventListener: () => {
          pluginMsgListener = null;
        },
      },
      parent: parentWin,
    });
    await bridge.connect();
    await new Promise((r) => setTimeout(r, 20));

    expect(bridge.publicOrigin).toBe('https://panel.example.com:8443');
    expect(bridge.buildPublicURL('/p/proxy.advanced/sub/abc')).toBe('https://panel.example.com:8443/p/proxy.advanced/sub/abc');

    const okRes = await bridge.invoke<{ items: number[] }>('list');
    expect(okRes).toEqual({ kind: 'done', operationId: 'op_0', result: { items: [1, 2] } });

    const waitRes = await bridge.invoke('delete');
    expect(waitRes).toEqual({ kind: 'awaiting_approval', operationId: 'op_1', approvalId: 'apv_9' });

    expect(unwrapInvokeOutcome({ status: 'RUNNING', operation_id: 'op_2' })).toEqual({ kind: 'running', operationId: 'op_2' });

    for (const badStatus of ['FAILED', 'REJECTED', 'CANCELED', 'EXPIRED']) {
      expect(() => unwrapInvokeOutcome({ status: badStatus, operation_id: 'op_fail' })).toThrow(PluginInvokeError);
    }
    expect(() => unwrapInvokeOutcome({ status: 'SUCCEEDED', error: 'PLUGIN_ERROR' })).toThrow(PluginInvokeError);
    expect(() => unwrapInvokeOutcome({ status: 'FAILED', error: { code: 'CONFLICT', detail: '版本冲突' } })).toThrow(/版本冲突/);

    /* 超过 4 MiB 的 api.invoke 应返回显式 PAYLOAD_TOO_LARGE 错误而不是静默丢弃 */
    expect(MAX_MESSAGE_BYTES).toBe(4 * 1024 * 1024);
    await expect(
      bridge.invoke('list', { blob: 'x'.repeat(MAX_MESSAGE_BYTES + 128) }, 2000),
    ).rejects.toMatchObject({ code: 'PAYLOAD_TOO_LARGE', status: 413 });

    expect(await bridge.confirm({ title: '删除节点', body: '不可恢复', danger: true })).toBe(true);
    expect(await bridge.confirm({ title: '普通确认', body: '继续？', danger: false })).toBe(false);

    await bridge.copyText('vless://abc', '已复制节点链接');
    expect(copied).toEqual([{ text: 'vless://abc', label: '已复制节点链接' }]);

    const received: string[] = [];
    const off = bridge.subscribe('plugins/proxy.advanced', (e) => received.push(e.subject));
    await new Promise((r) => setTimeout(r, 20));
    hostEvents.emit?.({ subject: 'plugins/proxy.advanced/users', type: 'resource.changed' });
    await new Promise((r) => setTimeout(r, 20));
    expect(received).toEqual(['plugins/proxy.advanced/users']);

    off();
    await new Promise((r) => setTimeout(r, 20));
    expect(hostEvents.unsubCalled).toBe(1);

    bridge.dispose();
    hostBridge.dispose();
  });

  it('STEP-15: safeInternalPath / safeExternalHref 与 nav 最长前缀唯一激活', () => {
    expect(safeInternalPath('/plugins/security.basic/firewall')).toBe('/plugins/security.basic/firewall');
    expect(safeInternalPath('javascript:alert(1)', '')).toBe('');
    expect(safeInternalPath('//evil.com/x', '/')).toBe('/');
    expect(safeInternalPath('/\\evil.com', '/')).toBe('/');

    expect(safeExternalHref('https://github.com/org/repo')).toBe('https://github.com/org/repo');
    expect(safeExternalHref('http://127.0.0.1:8080/auth')).toBe('http://127.0.0.1:8080/auth');
    expect(safeExternalHref('javascript:alert(1)')).toBeNull();
    expect(safeExternalHref('data:text/html,<script>1</script>')).toBeNull();

    const items = [
      { href: '/' },
      { href: '/plugins/security.basic' },
      { href: '/plugins/security.basic/firewall' },
    ];
    expect(activeHref(items, '/plugins/security.basic/firewall')).toBe('/plugins/security.basic/firewall');
    expect(isActive('/plugins/security.basic', '/plugins/security.basic/firewall', items)).toBe(false);
    expect(isActive('/plugins/security.basic/firewall', '/plugins/security.basic/firewall', items)).toBe(true);
  });

  it('STEP-11: invokeWithApprovalFollowup 自动跟单审批与 generateOpenSSHEd25519KeyPair 生成标准 OpenSSH 私钥', async () => {
    const toasts: string[] = [];
    let subCb: ((ev: { subject: string; operation_id?: string }) => void) | null = null;
    let unsubbed = 0;
    const fakeBridge = {
      invokeOutcome: async () => ({ kind: 'awaiting_approval' as const, operationId: 'op_wait_1', approvalId: 'apr_1' }),
      toast: (msg: string) => toasts.push(msg),
      subscribe: (_patterns: string[], cb: (ev: { subject: string; operation_id?: string }) => void) => {
        subCb = cb;
        return () => {
          unsubbed++;
        };
      },
    };
    let settledCount = 0;
    const outcome = await invokeWithApprovalFollowup(
      fakeBridge as unknown as Parameters<typeof invokeWithApprovalFollowup>[0],
      'nodes.upsert',
      {},
      {
        pluginId: 'server.probe',
        onBackgroundSettled: () => {
          settledCount++;
        },
      },
    );
    expect(outcome.kind).toBe('awaiting_approval');
    expect(toasts.length).toBe(1);
    expect(subCb).not.toBeNull();
    subCb!({ subject: 'plugins/server.probe/nodes', operation_id: 'op_wait_1' });
    await Promise.resolve();
    expect(settledCount).toBe(1);
    expect(unsubbed).toBe(1);

    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const kp = await generateOpenSSHEd25519KeyPair('test@qwq');
      expect(kp.publicKeyAuthorized.startsWith('ssh-ed25519 ')).toBe(true);
      expect(kp.publicKeyAuthorized.endsWith(' test@qwq')).toBe(true);
      expect(kp.privateKeyOpenSSHPEM).toContain('OPENSSH PRIVATE KEY-----');
    }
  });
});
