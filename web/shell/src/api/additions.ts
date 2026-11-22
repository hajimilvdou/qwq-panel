// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 契约补齐 · 前端专属类型
 * --------------------------------------------------------------------------
 * 阶段 2（p2-a/p2-b）已合入 main，缺口 1–7 的路由与 DTO 都进了
 * api/public/v1/openapi.yaml 并重生成为 schema.d.ts。本文件不再重复定义
 * 这些形状，而是直接复用生成类型（单一事实源），只保留两类前端专属内容：
 *   1. 生成类型的别名（沿用界面既有的导入名）；
 *   2. openapi 不约束的前端形状：分类色枚举、小组件结果（Stat/Series/Checks/List，
 *      由插件负责、宿主不校验）、Operation 的 args 补充。
 * 改 openapi 后跑 `npm run gen:api`，不要手改 schema.d.ts。
 * ========================================================================== */
import type { components } from './schema';

type S = components['schemas'];

/* ------------------------------------------------------------------ 1 · 账户（缺口 1，机密例外路由） */

/** POST /api/v1/enrollments（匿名）：成功即登录，响应是 Session */
export type EnrollmentRedeemResult = S['Session'];
/** POST /api/v1/users/{user_id}/enrollment-token → 200；令牌只在本次响应，幂等重放省略 */
export type EnrollmentTokenCreated = S['EnrollmentToken'];
/** PATCH /api/v1/sessions/current/profile：走 host.account.update，outcome.result 是 User */
export type AccountUpdateRequest = S['ProfileUpdateRequest'];
export type TotpEnrollment = S['TotpEnrollment'];
/** confirm 不轮换会话、不标新鲜 MFA、CSRF 不变；session 是当前会话 */
export type TotpConfirmResult = S['TotpConfirmResult'];

/* ------------------------------------------------------------------ 2 · AI 服务（缺口 2） */

export type AiProvider = S['AiProvider'];
export type AiProviderCreateRequest = S['AiProviderCreateRequest'];
export type AiProviderUpdateRequest = S['AiProviderUpdateRequest'];
export type AiProviderTestResult = S['AiProviderTestResult'];
/** GET /api/v1/agent-cores 的条目：available/reason */
export type AgentCoreInfo = S['AgentCoreInfo'];

/* ------------------------------------------------------------------ 3 · 插件界面元数据（缺口 3） */

export type PluginCapability = S['PluginCapability'];
export type PluginResources = S['PluginResources'];
export type PluginRoute = S['PluginRoute'];
export type PluginUi = S['PluginUi'];
export type PluginRuntime = S['PluginRuntime'];
/** Plugin DTO 已含 description/icon_url/ui/runtime/builtin/has_config 等可选成员 */
export type Plugin = S['Plugin'];
/** widget.color 是插件声明的字符串（untrusted）；渲染前用 CATEGORY_COLORS 校验为 CategoryColor */
export type PluginWidget = S['PluginWidget'];

/** 分类色：彩色底块只表示"类别"，与 $ui 的 CATEGORY_COLORS 一致 */
export type CategoryColor =
  | 'blue'
  | 'indigo'
  | 'violet'
  | 'teal'
  | 'cyan'
  | 'green'
  | 'amber'
  | 'orange'
  | 'red'
  | 'pink'
  | 'slate';

/* ------------------------------------------------------------------ 4 · 安装前检查（缺口 4） */

export type PluginPackageInspection = S['PluginPackageInspection'];

/* ------------------------------------------------------------------ 5 · 动作目录（缺口 5） */

/** ActionMeta 已含 reachability?；宿主钳制 risk≥high、approval≥ai_confirm，派生 confirm 保留 */
export type ActionMeta = S['ActionMeta'];
/** GET /api/v1/actions/{action_id}：ActionMeta + 必填 request_schema */
export type ActionDetail = S['ActionDetail'];
/** GET /api/v1/actions：{items, truncated}，无 ListMeta（搜索页不是资源集合） */
export type ActionSearchResult = S['ActionList'];

/* ------------------------------------------------------------------ 6 · agent 会话进入全局事件流（缺口 6） */

export type AgentSessionUpdatedPayload = S['AgentSessionUpdatedPayload'];
export type AgentSessionAttentionPayload = S['AgentSessionAttentionPayload'];
/** AgentSession 已含 last_message_preview?（≤120，untrusted） */
export type AgentSession = S['AgentSession'];

/* ------------------------------------------------------------------ 7 · 审计、插件运维、系统（缺口 7） */

/** Operation 的补充成员：参数（secret 已替换为引用），把动态写成人能读懂的句子 */
export type OperationExtra = {
  args?: Record<string, unknown>;
};

export type AuditEntry = S['AuditEntry'];
/** {items, meta:{next_cursor}}：无 revision/delta，不支持 since_revision */
export type AuditPage = S['AuditPage'];
export type PluginLogLine = S['PluginLogLine'];
/** 页内时间正序、next_cursor 向后跟随；limit≤100 */
export type PluginLogPage = S['PluginLogPage'];
/** GET /api/v1/system；listen/data_dir 仅 admin，plugins_enabled 是布尔，无 built_at */
export type SystemInfo = S['SystemInfo'];

/* ------------------------------------------------------------------ 小组件结果形状（manifest 1.3，插件负责，宿主不校验） */

export type Level = 'ok' | 'warn' | 'bad';

export interface StatWidgetData {
  value: number | string;
  unit?: string;
  sub?: string;
  percent?: number;
  spark?: number[];
  level?: Level;
}
export interface SeriesWidgetData {
  unit?: string;
  max?: number;
  series: { name: string; color?: CategoryColor; points: [number, number][] }[];
}
export interface ChecksWidgetData {
  headline?: { value: number | string; label: string };
  bars?: number[];
  items: { label: string; value: string; level: Level }[];
}
export interface ListWidgetData {
  items: { title: string; sub?: string; level?: Level; at?: string }[];
}