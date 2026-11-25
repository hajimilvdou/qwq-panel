// SPDX-License-Identifier: AGPL-3.0-only
/* 轻量小组件槽位收集（供首页在不拉取校验器/图表的前提下判定是否有小组件） */
import type { Plugin, PluginWidget } from '$api/additions';

export interface WidgetSlot {
  /** `${plugin_id}/${widget.id}`，栅格 key 与健康度表的键 */
  key: string;
  plugin: Plugin;
  widget: PluginWidget;
}

/**
 * 运行中或休眠中的活跃按需插件声明的小组件（宿主已限 ≤16/插件）。
 * 主页 C 位由底层框架内置的宿主资源监控承接，不再把基础安全封禁球或重复的旧监控卡抢占主页 C 位。
 */
export function collectWidgets(list: readonly Plugin[] | undefined): WidgetSlot[] {
  const out: WidgetSlot[] = [];
  for (const p of list ?? []) {
    if (p.enabled === false) continue;
    const st = p.runtime?.state;
    const ready = !st || st === 'running' || st === 'standby';
    if (!ready) continue;
    /* 基础安全封禁球不再放到主页 C 位（可在「基础安全」页内随时查看） */
    if (p.plugin_id === 'security.basic') continue;
    for (const w of (p.ui?.widgets ?? []).slice(0, 16)) {
      /* 避免与主页内置实时资源监控重复堆叠 CPU/内存/磁盘基础单值卡 */
      if (p.plugin_id === 'monitor.basic' && w.kind === 'stat') continue;
      out.push({ key: `${p.plugin_id}/${w.id}`, plugin: p, widget: w });
    }
  }
  return out;
}
