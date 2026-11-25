// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 端点统一出口（纯 re-export 桶文件，按域拆分便于 tree-shaking）
 * ========================================================================== */
export { events, nodes, sessions, system } from './endpoints-core';
export { plugins } from './endpoints-plugins';
export { agent, agentExchange, ai } from './endpoints-agent';
export { account, actions, approvals, audit, delegations, operations, plans, users } from './endpoints-ops';
export type { ActionMeta, Op, TargetInput } from './endpoints-ops';
