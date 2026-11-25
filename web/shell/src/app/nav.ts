// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 导航模型（侧栏与手机 Tab 栏共用）
 * --------------------------------------------------------------------------
 * 固定项 + 插件声明的 ui.routes[nav=true]。插件底块色：widget 声明的色优先，
 * 否则按 plugin_id 哈希取分类色（稳定、不随顺序变化）。
 * ========================================================================== */
import { plugins as pluginsApi } from '$api/endpoints';
import { isPluginActiveReady } from '$api/endpoints-plugins';
import type { Plugin } from '$api/types';
import { hashIndex } from '$lib/format';
import type { ResourceOptions } from '$lib/resource.svelte';
import { CATEGORY_COLORS, type CategoryColor, type IconName } from '$ui';

export interface NavItem {
  href: string;
  label: string;
  icon: IconName;
  color: CategoryColor | 'ai';
  perm?: string;
  pluginId?: string;
}

export const PRIMARY: readonly NavItem[] = [
  { href: '/', label: '主页', icon: 'home', color: 'blue' },
  { href: '/activity', label: '动态', icon: 'activity', color: 'teal', perm: 'host.operations:read' },
  { href: '/agent', label: 'AI 助手', icon: 'ai', color: 'ai', perm: 'host.agent_sessions:write' },
];
export const APP_CENTER: NavItem = { href: '/apps', label: '应用中心', icon: 'apps', color: 'violet', perm: 'host.plugins:read' };
export const SETTINGS: NavItem = { href: '/settings', label: '设置', icon: 'settings', color: 'slate' };

/** 手机底部 Tab：主页 / 动态 / AI / 应用 / 设置 */
export const TABS: readonly NavItem[] = [...PRIMARY, { ...APP_CENTER, label: '应用' }, SETTINGS];

/** 插件列表快照（侧栏、主页"我的应用"共用同一缓存键） */
export const pluginsResource: ResourceOptions<Plugin[]> = {
  key: 'plugins',
  load: () => pluginsApi.list().then((p) => p.items),
  subjects: ['plugins/'],
};

const ICON_GUESS: [RegExp, IconName][] = [
  [/monitor|metric|stat|probe/, 'cpu'],
  [/secur|firewall|guard|ssh|xray/, 'shield'],
  [/backup|snapshot/, 'backup'],
  [/net|dns|proxy|ingress/, 'net'],
  [/cert|tls/, 'lock'],
  [/ai\.relay/, 'ai'],
  [/notify/, 'send'],
  [/disk|storage|file/, 'disk'],
];

/** 插件声明的 color 是 untrusted 字符串，只接受合法分类色 */
const isCategoryColor = (c: string | undefined): c is CategoryColor =>
  !!c && (CATEGORY_COLORS as readonly string[]).includes(c);

/** 插件的底块色与图标（侧栏、主页"我的应用"、应用中心共用） */
export function pluginLook(p: Plugin): { color: CategoryColor; icon: IconName } {
  const declared = p.ui?.widgets.map((w) => w.color).find(isCategoryColor);
  return {
    color: declared ?? CATEGORY_COLORS[hashIndex(p.plugin_id, CATEGORY_COLORS.length)]!,
    icon: ICON_GUESS.find(([re]) => re.test(p.plugin_id))?.[1] ?? 'apps',
  };
}

/** 每个活跃插件在左侧栏只呈现唯一 1 个入口，内部子功能全部收口到插件页面自身分页中 */
export function pluginNav(list: readonly Plugin[]): NavItem[] {
  const out: NavItem[] = [];
  const hasProxy = list.some((x) => x.plugin_id === 'proxy.advanced' && isPluginActiveReady(x));
  for (const p of list) {
    if (!isPluginActiveReady(p)) continue;
    /* monitor.basic 已深度并入主页底座；若已安装合并后的 proxy.advanced 则不再重复列出旧 core.xray */
    if (p.plugin_id === 'monitor.basic') continue;
    if (p.plugin_id === 'core.xray' && hasProxy) continue;
    const { color, icon } = pluginLook(p);
    const routes = p.ui?.routes ?? [];
    const primary = routes.find((r) => r.nav) ?? routes[0];
    const sub = primary ? primary.path.replace(/^\/+/, '') : '';
    out.push({
      href: `/plugins/${encodeURIComponent(p.plugin_id)}${sub ? '/' + sub : ''}`,
      label: p.name || primary?.title || p.plugin_id,
      icon,
      color,
      perm: primary?.permission || 'host.plugins:read',
      pluginId: p.plugin_id,
    });
  }
  return out;
}

/** 计算当前路径在给定导航集合中的唯一最长前缀匹配项 */
export function activeHref(items: readonly { href: string }[], path: string): string | null {
  let best: string | null = null;
  for (const it of items) {
    const href = it.href;
    const hit = href === '/' ? path === '/' : path === href || path.startsWith(href + '/');
    if (hit && (!best || href.length > best.length)) best = href;
  }
  return best;
}

/** 当前路径是否属于该导航项（传入 items 时启用最长路径唯一激活匹配） */
export function isActive(href: string, path: string, items?: readonly { href: string }[]): boolean {
  if (items) return activeHref(items, path) === href;
  return href === '/' ? path === '/' : path === href || path.startsWith(href + '/');
}
