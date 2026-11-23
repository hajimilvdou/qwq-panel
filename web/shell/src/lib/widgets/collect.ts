// SPDX-License-Identifier: AGPL-3.0-only
/* 轻量小组件槽位收集（供首页在不拉取校验器/图表的前提下判定是否有小组件） */
import type { Plugin, PluginWidget } from '$api/additions';

export interface WidgetSlot {
  /** `${plugin_id}/${widget.id}`，栅格 key 与健康度表的键 */
  key: string;
  plugin: Plugin;
  widget: PluginWidget;
}

/** 运行中插件声明的全部小组件（宿主已限 ≤16/插件，这里再保守截断） */
export function collectWidgets(list: readonly Plugin[] | undefined): WidgetSlot[] {
  const out: WidgetSlot[] = [];
  for (const p of list ?? []) {
    if (p.runtime && p.runtime.state !== 'running') continue;
    for (const w of (p.ui?.widgets ?? []).slice(0, 16)) out.push({ key: `${p.plugin_id}/${w.id}`, plugin: p, widget: w });
  }
  return out;
}
