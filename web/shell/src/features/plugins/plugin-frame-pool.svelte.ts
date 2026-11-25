// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * PluginFramePool · 插件 iframe 驻留池（切页/切 Tab 后 0ms 瞬开）
 * --------------------------------------------------------------------------
 * 最多保留最近访问的 4 个活跃插件 iframe 实例；离开插件页或切到设置/日志
 * Tab 时仅隐藏容器并通知插件 visible=false，返回工作台时直接显现，无需重载。
 * 插件停用、卸载或版本切换（entry_url 变化）时自动淘汰对应实例。
 * ========================================================================== */
import { isPluginActiveReady } from '$api/endpoints-plugins';
import type { Plugin } from '$api/types';

export interface PooledPluginFrame {
  key: string;
  plugin: Plugin;
  path: string;
  reloadTick: number;
}

const MAX_POOLED = 4;

class PluginFramePool {
  entries = $state<PooledPluginFrame[]>([]);
  activeKey = $state<string | null>(null);
  modalOpen = $state(false);

  setModalOpen(open: boolean): void {
    this.modalOpen = open;
  }

  keyOf(plugin: Plugin): string {
    return `${plugin.plugin_id}::${plugin.ui?.entry_url ?? ''}`;
  }

  activate(plugin: Plugin, path: string): string {
    const key = this.keyOf(plugin);
    const idx = this.entries.findIndex((e) => e.key === key);
    if (idx >= 0) {
      const existing = this.entries[idx]!;
      const sameEntry = existing.plugin === plugin && existing.path === path;
      if (sameEntry && idx === this.entries.length - 1) {
        if (this.activeKey !== key) this.activeKey = key;
        return key;
      }
      const updated: PooledPluginFrame = sameEntry ? existing : { ...existing, plugin, path };
      if (idx === this.entries.length - 1) {
        this.entries = [...this.entries.slice(0, idx), updated];
      } else {
        this.entries = [...this.entries.slice(0, idx), ...this.entries.slice(idx + 1), updated];
      }
    } else {
      const next = [...this.entries, { key, plugin, path, reloadTick: 0 }];
      this.entries = next.length > MAX_POOLED ? next.slice(next.length - MAX_POOLED) : next;
    }
    if (this.activeKey !== key) this.activeKey = key;
    return key;
  }

  deactivate(key?: string): void {
    if (!this.activeKey) return;
    if (!key || this.activeKey === key) {
      this.activeKey = null;
      this.modalOpen = false;
    }
  }

  reload(pluginId: string): void {
    let changed = false;
    const next = this.entries.map((e) => {
      if (e.plugin.plugin_id !== pluginId) return e;
      changed = true;
      return { ...e, reloadTick: e.reloadTick + 1 };
    });
    if (changed) this.entries = next;
  }

  evict(pluginId: string): void {
    const filtered = this.entries.filter((e) => e.plugin.plugin_id !== pluginId);
    if (filtered.length !== this.entries.length) {
      if (this.activeKey?.startsWith(`${pluginId}::`)) this.activeKey = null;
      this.entries = filtered;
    }
  }

  syncWithPlugins(list: readonly Plugin[]): void {
    if (!this.entries.length) return;
    const byId = new Map(list.map((p) => [p.plugin_id, p]));
    const next: PooledPluginFrame[] = [];
    let changed = false;
    for (const entry of this.entries) {
      const cur = byId.get(entry.plugin.plugin_id);
      if (!cur || !isPluginActiveReady(cur) || !cur.ui?.entry_url || this.keyOf(cur) !== entry.key) {
        changed = true;
        if (this.activeKey === entry.key) this.activeKey = null;
        continue;
      }
      next.push(cur === entry.plugin ? entry : { ...entry, plugin: cur });
    }
    if (changed) this.entries = next;
  }

  clear(): void {
    this.entries = [];
    this.activeKey = null;
    this.modalOpen = false;
  }
}

export const pluginFramePool = new PluginFramePool();
