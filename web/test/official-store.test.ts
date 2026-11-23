// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import type { PluginCatalogItem } from '../shell/src/api/additions';
import { resolveInstallOrder } from '../shell/src/features/apps/official-install';

describe('resolveInstallOrder (official plugin store)', () => {
  const sampleCatalog: PluginCatalogItem[] = [
    {
      plugin_id: 'core.xray',
      name: '全协议代理核心驱动',
      summary: 'Xray + AnyTLS',
      version: '0.1.11',
      category: 'proxy',
      memory_max_mb: 64,
      dependencies: [],
      download_url: 'https://example.com/core.xray.qwqpkg',
      size: 1024,
      installed: false,
      update_available: false,
    },
    {
      plugin_id: 'proxy.advanced',
      name: '高级代理工作台',
      summary: '多用户配额与订阅',
      version: '0.1.11',
      category: 'proxy',
      memory_max_mb: 32,
      dependencies: ['core.xray'],
      download_url: 'https://example.com/proxy.advanced.qwqpkg',
      size: 1024,
      installed: false,
      update_available: false,
    },
  ];

  it('installs uninstalled dependencies before target plugin', () => {
    const plan = resolveInstallOrder('proxy.advanced', sampleCatalog);
    expect(plan.map((p) => p.plugin_id)).toEqual(['core.xray', 'proxy.advanced']);
  });

  it('skips already-installed dependencies', () => {
    const withCoreInstalled = sampleCatalog.map((item) =>
      item.plugin_id === 'core.xray' ? { ...item, installed: true } : item,
    );
    const plan = resolveInstallOrder('proxy.advanced', withCoreInstalled);
    expect(plan.map((p) => p.plugin_id)).toEqual(['proxy.advanced']);
  });
});
