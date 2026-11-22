// SPDX-License-Identifier: AGPL-3.0-only
/** 设置分项与其权限（SPEC §7）；无权分项隐藏，直接访问显示权限态 */
export const SETTINGS_SECTIONS = [
  { id: 'account', title: '账户' },
  { id: 'appearance', title: '外观' },
  { id: 'users', title: '用户', perm: 'host.users:read' },
  { id: 'delegations', title: 'AI 令牌', perm: 'host.delegations:read' },
  { id: 'ai', title: 'AI 服务', perm: 'host.ai_providers:read' },
  { id: 'system', title: '系统', perm: 'host.system:read' },
] as const satisfies readonly { id: string; title: string; perm?: string }[];
