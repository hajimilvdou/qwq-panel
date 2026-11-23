// SPDX-License-Identifier: AGPL-3.0-only
/* 轻量小组件槽位收集（供首页在不拉取校验器/图表的前提下判定是否有小组件） */
import type { Plugin, PluginWidget } from '$api/additions';

export interface WidgetSlot {
  /** `${plugin_id}/${widget.id}`，栅格 key 与健康度表的键 */
  key: string;
  plugin: Plugin;
  widget: PluginWidget;
}

/** 运行中或休眠中的活跃按需插件声明的全部小组件（宿主已限 ≤16/插件，这里再保守截断） */
export function collectWidgets(list: readonly Plugin[] | undefined): WidgetSlot[] {
  const out: WidgetSlot[] = [];
  for (const p of list ?? []) {
    const sleepingOnDemand =
      p.runtime?.state === 'stopped' &&
      (p.active_status === 'ACTIVE' ||
        (p as { manifest?: { lifecycle?: { startup?: string } } }).manifest?.lifecycle?.startup === 'on_demand');
    if (p.runtime && p.runtime.state !== 'running' && !sleepingOnDemand) continue;
    for (const w of (p.ui?.widgets ?? []).slice(0, 16)) out.push({ key: `${p.plugin_id}/${w.id}`, plugin: p, widget: w });
  }
  return out;
}
