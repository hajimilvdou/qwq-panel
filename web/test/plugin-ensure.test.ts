// SPDX-License-Identifier: AGPL-3.0-only
/* STEP-04 零信任 ui.ensure_plugins 桥接协议与处理器单元测试 */
import { describe, expect, it, vi } from 'vitest';
import type { OpResult } from '../shell/src/api/client';
import type { Plugin } from '../shell/src/api/types';
import {
  ENSURE_PLUGIN_ALLOWLIST,
  PluginBridge,
  isEnsurePluginAllowed,
  parsePluginMessage,
  type EnsurePluginsResult,
  type ShellToPlugin,
} from '../shell/src/lib/plugin-host/index';
import { EnsurePluginsError, createEnsurePluginsHandler, toProblem } from '../shell/src/lib/plugin-host/wiring';

function makePlugin(id: string, runtimeState: 'running' | 'stopped' | 'crashed' | 'unknown', activeStatus: 'ACTIVE' | 'STOPPED' = 'ACTIVE'): Plugin {
  return {
    plugin_id: id,
    name: id,
    summary: id,
    placement: 'node',
    active_status: activeStatus,
    config_revision: 'rev_1',
    versions: [],
    created_at: '2026-01-01T00:00:00Z',
    revision: 'rev_1',
    runtime: { state: runtimeState },
  } as unknown as Plugin;
}

function makeBridgePair(onEnsurePlugins?: (req: { plugins: string[]; reason?: string }) => Promise<EnsurePluginsResult>) {
  let pluginPort: MessagePort | null = null;
  const received: ShellToPlugin[] = [];

  const hostBridge = new PluginBridge({
    pluginId: 'containers.docker',
    operations: [],
    routes: [{ path: '/' }],
    invoke: async () => ({}),
    toProblem,
    subscribe: () => () => {},
    newKey: () => 'idem_1',
    onReady: vi.fn(),
    onResize: vi.fn(),
    onToast: vi.fn(),
    onNavigate: vi.fn(),
    onTimeout: vi.fn(),
    onEnsurePlugins,
  });

  const iframeWin = {
    postMessage: (data: unknown, _origin: string, transfer?: Transferable[]) => {
      if ((data as { t?: string })?.t === 'plugin.port' && transfer?.[0]) {
        pluginPort = transfer[0] as unknown as MessagePort;
        pluginPort.onmessage = (m) => {
          received.push(m.data as ShellToPlugin);
        };
        pluginPort.start?.();
      }
    },
  } as unknown as Window;

  hostBridge.attach(iframeWin);
  hostBridge.onWindowMessage({ source: iframeWin, data: { t: 'plugin.hello', kit_major: 1 } } as unknown as MessageEvent);

  const sendAndWait = async (msg: Record<string, unknown>): Promise<ShellToPlugin> => {
    const startIdx = received.length;
    pluginPort!.postMessage(msg);
    for (let i = 0; i < 40; i++) {
      if (received.length > startIdx) return received[startIdx]!;
      await new Promise((r) => setTimeout(r, 10));
    }
    throw new Error('timed out waiting for bridge response');
  };

  const cleanup = () => {
    pluginPort?.close();
    hostBridge.dispose();
  };

  return { hostBridge, sendAndWait, cleanup };
}

describe('STEP-04: 零信任 ui.ensure_plugins 桥接协议与处理器', () => {
  it('白名单仅放行 web.ingress / tls.certificates / domain.dns', () => {
    expect([...ENSURE_PLUGIN_ALLOWLIST]).toEqual(['web.ingress', 'tls.certificates', 'domain.dns']);
    expect(isEnsurePluginAllowed('web.ingress')).toBe(true);
    expect(isEnsurePluginAllowed('tls.certificates')).toBe(true);
    expect(isEnsurePluginAllowed('domain.dns')).toBe(true);
    expect(isEnsurePluginAllowed('evil.plugin')).toBe(false);
    expect(isEnsurePluginAllowed('core.xray')).toBe(false);
    expect(isEnsurePluginAllowed('containers.docker')).toBe(false);

    expect(parsePluginMessage({ t: 'ui.ensure_plugins', id: 'e1', plugins: ['web.ingress'], reason: '反代需要' })).toEqual({
      t: 'ui.ensure_plugins',
      id: 'e1',
      plugins: ['web.ingress'],
      reason: '反代需要',
    });
    expect(parsePluginMessage({ t: 'ui.ensure_plugins', id: 'e2', plugins: [] })).toBeNull();
    expect(parsePluginMessage({ t: 'ui.ensure_plugins', id: 'e3', plugins: ['web.ingress'], reason: 'x'.repeat(600) })).toBeNull();
  });

  it('PluginBridge 拦截非白名单插件 ID（如 evil.plugin / core.xray）并返回 PERMISSION_DENIED，绝不触发回调', async () => {
    const onEnsure = vi.fn();
    const { sendAndWait, cleanup } = makeBridgePair(onEnsure);
    try {
      const res1 = await sendAndWait({ t: 'ui.ensure_plugins', id: 'req_1', plugins: ['evil.plugin'] });
      expect(res1).toMatchObject({
        t: 'ui.ensure_plugins.result',
        id: 'req_1',
        ok: false,
        problem: { code: 'PERMISSION_DENIED', status: 403 },
      });

      const res2 = await sendAndWait({ t: 'ui.ensure_plugins', id: 'req_2', plugins: ['web.ingress', 'core.xray'] });
      expect(res2).toMatchObject({
        t: 'ui.ensure_plugins.result',
        id: 'req_2',
        ok: false,
        problem: { code: 'PERMISSION_DENIED', status: 403 },
      });

      expect(onEnsure).not.toHaveBeenCalled();
    } finally {
      cleanup();
    }
  });

  it('用户拒绝确认时返回 { ready: false, cancelled: true } 且不发起安装或启用', async () => {
    const installPlugin = vi.fn();
    const enablePlugin = vi.fn();
    const confirmAction = vi.fn(async () => false);

    const handler = createEnsurePluginsHandler({
      listPlugins: async () => ({
        items: [
          makePlugin('domain.dns', 'running', 'ACTIVE'),
          makePlugin('tls.certificates', 'stopped', 'STOPPED'),
        ],
      }),
      installPlugin,
      enablePlugin,
      waitForOp: async (op) => op,
      newKey: () => 'idem_cancel',
      confirmAction,
    });

    const { sendAndWait, cleanup } = makeBridgePair(handler);
    try {
      const reply = await sendAndWait({
        t: 'ui.ensure_plugins',
        id: 'req_cancel',
        plugins: ['web.ingress', 'tls.certificates', 'domain.dns', 'web.ingress'],
        reason: '为容器开启域名反代与自动 HTTPS',
      });
      expect(reply).toEqual({
        t: 'ui.ensure_plugins.result',
        id: 'req_cancel',
        ok: true,
        data: {
          ready: false,
          cancelled: true,
          installed: [],
          enabled: [],
          already_ready: ['domain.dns'],
        },
      });
      expect(confirmAction).toHaveBeenCalledOnce();
      expect(installPlugin).not.toHaveBeenCalled();
      expect(enablePlugin).not.toHaveBeenCalled();
    } finally {
      cleanup();
    }
  });

  it('用户确认后自动安装缺失组件、启用停用组件并等待 Operation 终态', async () => {
    let keySeq = 0;
    const installCalls: Array<{ id: string; key: string; autoEnable?: boolean }> = [];
    const enableCalls: Array<{ id: string; key: string }> = [];
    const waitedOps: string[] = [];
    const onChanged = vi.fn();
    const confirmAction = vi.fn(async () => true);

    const handler = createEnsurePluginsHandler({
      listPlugins: async () => ({
        items: [
          makePlugin('domain.dns', 'running', 'ACTIVE'),
          makePlugin('tls.certificates', 'stopped', 'STOPPED'),
        ],
      }),
      installPlugin: async (id, key, autoEnable): Promise<OpResult> => {
        installCalls.push({ id, key, autoEnable });
        return { operationId: `op_install_${id}`, status: 'PENDING' };
      },
      enablePlugin: async (id, key): Promise<OpResult> => {
        enableCalls.push({ id, key });
        return { operationId: `op_enable_${id}`, status: 'RUNNING' };
      },
      waitForOp: async (op): Promise<OpResult> => {
        if (op.operationId) waitedOps.push(op.operationId);
        return { ...op, status: 'SUCCEEDED' };
      },
      newKey: () => `idem_${++keySeq}`,
      confirmAction,
      onChanged,
    });

    const { sendAndWait, cleanup } = makeBridgePair(handler);
    try {
      const reply = await sendAndWait({
        t: 'ui.ensure_plugins',
        id: 'req_ok',
        plugins: ['web.ingress', 'tls.certificates', 'domain.dns'],
      });
      expect(reply).toEqual({
        t: 'ui.ensure_plugins.result',
        id: 'req_ok',
        ok: true,
        data: {
          ready: true,
          installed: ['web.ingress'],
          enabled: ['tls.certificates'],
          already_ready: ['domain.dns'],
        },
      });
      expect(confirmAction).toHaveBeenCalledOnce();
      expect(installCalls).toEqual([{ id: 'web.ingress', key: 'idem_1', autoEnable: true }]);
      expect(enableCalls).toEqual([{ id: 'tls.certificates', key: 'idem_2' }]);
      expect(waitedOps).toEqual(['op_install_web.ingress', 'op_enable_tls.certificates']);
      expect(onChanged).toHaveBeenCalledOnce();
    } finally {
      cleanup();
    }
  });

  it('目标组件全部已就绪时直接返回 already_ready，不重复弹窗确认', async () => {
    const confirmAction = vi.fn(async () => true);
    const handler = createEnsurePluginsHandler({
      listPlugins: async () => ({
        items: [
          makePlugin('web.ingress', 'running', 'ACTIVE'),
          makePlugin('tls.certificates', 'running', 'ACTIVE'),
        ],
      }),
      enablePlugin: vi.fn(),
      waitForOp: async (op) => op,
      newKey: () => 'k',
      confirmAction,
    });

    const res = await handler({ plugins: ['web.ingress', 'tls.certificates'] });
    expect(res).toEqual({
      ready: true,
      installed: [],
      enabled: [],
      already_ready: ['web.ingress', 'tls.certificates'],
    });
    expect(confirmAction).not.toHaveBeenCalled();

    await expect(handler({ plugins: ['core.xray'] })).rejects.toBeInstanceOf(EnsurePluginsError);
    await expect(handler({ plugins: ['core.xray'] })).rejects.toMatchObject({ code: 'PERMISSION_DENIED', status: 403 });
  });
});
