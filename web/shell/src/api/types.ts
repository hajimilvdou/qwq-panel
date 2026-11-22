// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 公共 API 类型别名
 * --------------------------------------------------------------------------
 * 全部来自 schema.d.ts（由 openapi.yaml 生成）。界面代码只从这里取类型，
 * 不直接引用 components['schemas'][...] 的长路径。
 * ========================================================================== */
import type { components } from './schema';

type S = components['schemas'];

export type Problem = S['Problem'];
export type ProblemCode = S['ProblemCode'];
export type FieldViolation = S['FieldViolation'];
export type FailedPrecondition = S['FailedPrecondition'];
export type Revision = S['Revision'];
export type RiskLevel = S['RiskLevel'];
export type Effect = S['Effect'];
export type Mode = S['Mode'];
export type ApprovalLevel = S['ApprovalLevel'];
export type PermissionMode = S['PermissionMode'];
export type ActorKind = S['ActorKind'];
export type Actor = S['Actor'];
export type Target = S['Target'];
export type TargetInput = S['TargetInput'];
export type ActionSummary = S['ActionSummary'];
export type ActionDescription = S['ActionDescription'];
export type OperationStatus = S['OperationStatus'];
export type OperationProgress = S['OperationProgress'];
export type Operation = S['Operation'];
export type OperationOutcome = S['OperationOutcome'];
export type ListMeta = S['ListMeta'];
export type PlanRequest = S['PlanRequest'];
export type PlannedChange = S['PlannedChange'];
export type Plan = S['Plan'];
export type ApprovalStatus = S['ApprovalStatus'];
export type ApprovalFacts = S['ApprovalFacts'];
export type Approval = S['Approval'];
export type AgentSessionStatus = S['AgentSessionStatus'];
export type AgentCore = S['AgentCore'];
export type AgentToolStatus = S['AgentToolStatus'];
export type AgentSessionMessage = S['AgentSessionMessage'];
export type AgentSessionApproval = S['AgentSessionApproval'];
export type AgentSessionDetail = S['AgentSessionDetail'];
export type AgentSessionEvent = S['AgentSessionEvent'];
export type AgentSessionError = S['AgentSessionError'];
export type AgentSessionMessageToolCall = S['AgentSessionMessageToolCall'];
export type Node = S['Node'];
export type PluginVersion = S['PluginVersion'];
export type PluginPackageUpload = S['PluginPackageUpload'];
export type PluginUpdateResult = S['PluginUpdateResult'];
export type PluginConfig = S['PluginConfig'];
export type Role = S['Role'];
export type User = S['User'];
export type Session = S['Session'];
export type MfaChallenge = S['MfaChallenge'];
export type SetupStatus = S['SetupStatus'];
export type DelegationPolicy = S['DelegationPolicy'];
export type Delegation = S['Delegation'];
export type DelegationCreated = S['DelegationCreated'];
export type Event = S['Event'];
export type ResourceChangedPayload = S['ResourceChangedPayload'];
export type OperationUpdatedPayload = S['OperationUpdatedPayload'];
export type StreamReady = S['StreamReady'];
export type StreamResync = S['StreamResync'];
export type StreamHeartbeat = S['StreamHeartbeat'];

/** 列表响应：ListMeta + items */
export type Page<T> = ListMeta & { items: T[] };

export type {
  ActionMeta,
  AgentSession,
  Plugin,
  PluginUi,
  PluginWidget,
  PluginRoute,
  PluginCapability,
  PluginRuntime,
  CategoryColor,
  Level,
} from './additions';
