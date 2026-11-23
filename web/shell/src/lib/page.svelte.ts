// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 页面级共享状态：顶栏标题、服务器健康度
 * --------------------------------------------------------------------------
 *   page.title          顶栏 <h1 id="page-title">；缺省用路由表 title
 *   page.setTitle(t)    页面内动态标题（如插件名、操作详情）；导航时自动复位
 *   health.level        ok | warn | bad：主页按小组件 level 聚合后写入，
 *                       侧栏服务器卡的表情随之变化（无小组件时保持 ok）
 * ========================================================================== */

export type HealthLevel = 'ok' | 'warn' | 'bad';

class PageMeta {
  /** 路由表给的默认标题 */
  routeTitle = $state('');
  /** 页面覆盖的标题 */
  override = $state<string | null>(null);

  readonly title = $derived(this.override ?? this.routeTitle);

  setTitle(t: string | null): void {
    this.override = t;
  }
}

class Health {
  level = $state<HealthLevel>('ok');
  /** 与事件总线 offline 状态同步，避免首页直接引入 SSE 栈 */
  offline = $state(false);
}

export const page = new PageMeta();
export const health = new Health();
