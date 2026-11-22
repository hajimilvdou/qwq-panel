// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 路由表（SPEC §2）
 * --------------------------------------------------------------------------
 * 自上而下首个匹配生效。新增页面：在 features/<域>/ 下建组件，加一行到这里。
 * perm 只用于隐藏入口与渲染权限态；后端仍是唯一裁决。
 * ========================================================================== */
import type { RouteDef } from '$lib/router.svelte';

export const routes: readonly RouteDef[] = [
  /* ---------------------------------------------------------------- 匿名（不套 Shell） */
  { pattern: '/setup', title: '初始化', public: true, bare: true, load: () => import('../features/auth/SetupPage.svelte') },
  { pattern: '/login', title: '登录', public: true, bare: true, load: () => import('../features/auth/LoginPage.svelte') },
  { pattern: '/enroll', title: '设置密码', public: true, bare: true, load: () => import('../features/auth/EnrollPage.svelte') },

  /* ---------------------------------------------------------------- 主体 */
  { pattern: '/', title: '主页', load: () => import('../features/home/Page.svelte') },
  { pattern: '/activity', title: '动态', perm: 'host.operations:read', load: () => import('../features/activity/Page.svelte') },
  {
    pattern: '/activity/:operationId',
    title: '操作详情',
    perm: 'host.operations:read',
    load: () => import('../features/activity/DetailPage.svelte'),
  },
  { pattern: '/agent', title: 'AI 助手', load: () => import('../features/agent/Page.svelte') },
  { pattern: '/agent/:sessionId', title: 'AI 助手', load: () => import('../features/agent/Page.svelte') },
  { pattern: '/apps', title: '应用中心', perm: 'host.plugins:read', load: () => import('../features/apps/Page.svelte') },
  {
    pattern: '/apps/install',
    title: '安装应用',
    perm: 'host.plugins:install',
    load: () => import('../features/apps/InstallPage.svelte'),
  },
  {
    pattern: '/apps/:pluginId',
    title: '应用详情',
    perm: 'host.plugins:read',
    load: () => import('../features/apps/DetailPage.svelte'),
  },
  /* 插件页的细粒度权限来自 manifest ui.routes[].permission，由页面自行判定 */
  { pattern: '/plugins/:pluginId/*', title: '应用', load: () => import('../features/plugins/Page.svelte') },

  /* ---------------------------------------------------------------- 设置 */
  { pattern: '/settings', title: '设置', redirect: '/settings/account', load: () => import('../features/settings/Page.svelte') },
  { pattern: '/settings/:section', title: '设置', load: () => import('../features/settings/Page.svelte') },

  /* ---------------------------------------------------------------- 兜底 */
  { pattern: '/*', title: '找不到页面', load: () => import('../features/NotFound.svelte') },
];
