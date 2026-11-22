// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 端点：所有路径集中在这里，界面不拼 URL
 * ========================================================================== */
import { buildUrl, http, upload, toOpResult, type OpResult, type RequestOptions } from './client';
import type {
  ActionMeta,
  AgentCore,
  AgentSession,
  AgentSessionApproval,
  AgentSessionDetail,
  AgentSessionMessage,
  Approval,
  ApprovalStatus,
  Delegation,
  DelegationCreated,
  DelegationPolicy,
  MfaChallenge,
  Node,
  Operation,
  OperationOutcome,
  OperationStatus,
  Page,
  PermissionMode,
  Plan,
  PlanRequest,
  Plugin,
  PluginConfig,
  PluginPackageUpload,
  PluginUpdateResult,
  PluginVersion,
  Role,
  Session,
  SetupStatus,
  TargetInput,
  User,
} from './types';
import type {
  AccountUpdateRequest,
  ActionDetail,
  ActionSearchResult,
  AgentCoreAuthStatus,
  AgentCoreInfo,
  AgentCoreLoginRequest,
  AgentRegistryInstallResult,
  AgentRegistrySearchResult,
  AgentWorkspaceFileContent,
  AgentWorkspaceFileEntry,
  AgentWorkspaceListResult,
  AgentWorkspaceWriteRequest,
  AiProvider,
  AiProviderCreateRequest,
  AiProviderFetchModelsRequest,
  AiProviderFetchModelsResult,
  AiProviderTestResult,
  AiProviderUpdateRequest,
  ExternalCliCore,
  WorkspaceArea,
  AuditEntry,
  AuditPage,
  EnrollmentRedeemResult,
  EnrollmentTokenCreated,
  OperationExtra,
  PanelAccessSettings,
  PanelAccessUpdateRequest,
  PluginLogPage,
  PluginPackageInspection,
  SystemInfo,
  TotpConfirmResult,
  TotpEnrollment,
} from './additions';

const enc = encodeURIComponent;
export type Op = Operation & OperationExtra;
type Mutating = Operation | OperationOutcome;

/* ------------------------------------------------------------------ 系统与初始化 */
export const system = {
  health: () => http.get<{ status: string }>('/healthz'),
  ready: () => http.get<{ status: string }>('/readyz'),
  info: () => http.get<SystemInfo>('/api/v1/system').then((r) => r.data),
  access: () => http.get<PanelAccessSettings>('/api/v1/system/access').then((r) => r.data),
  updateAccess: (body: PanelAccessUpdateRequest) =>
    http.put<PanelAccessSettings>('/api/v1/system/access', body).then((r) => r.data),
  setupStatus: (opts?: RequestOptions) => http.get<SetupStatus>('/api/v1/setup', opts).then((r) => r.data),
  completeSetup: (body: { setup_token: string; username: string; password: string; display_name?: string }) =>
    http.post<Session>('/api/v1/setup', body).then((r) => r.data),
};

/* ------------------------------------------------------------------ 会话与账户 */
export const sessions = {
  login: (username: string, password: string) =>
    http.post<Session | MfaChallenge>('/api/v1/sessions', { username, password }).then((r) => r.data),
  verifyMfa: (challenge_id: string, method: 'totp' | 'recovery_code', code: string) =>
    http.post<Session>('/api/v1/sessions/mfa', { challenge_id, method, code }).then((r) => r.data),
  current: (opts?: RequestOptions) => http.get<Session>('/api/v1/sessions/current', opts).then((r) => r.data),
  logout: () => http.del<void>('/api/v1/sessions/current'),
};

/** GAPS 缺口 1：全部为机密例外路由（不进 operation），幂等记录剔除机密 */
export const account = {
  /** 匿名；成功即登录，响应是 Session（含新 csrf） */
  redeemEnrollment: (token: string, password: string, key: string) =>
    http.post<EnrollmentRedeemResult>('/api/v1/enrollments', { token, password }, { idempotency: key }).then((r) => r.data),
  /** 走 host.account.update（人类自服务，AI 不可调）；outcome.result 是更新后的 User */
  updateProfile: (body: AccountUpdateRequest, key: string): Promise<OpResult> =>
    http.patch<Mutating>('/api/v1/sessions/current/profile', body, { idempotency: key }).then(toOpResult),
  /** 旧口令错为 403 PERMISSION_DENIED（不是 401，避免触发登出）；会撤销其他会话 */
  changePassword: (current_password: string, new_password: string, key: string) =>
    http.put<void>('/api/v1/sessions/current/password', { current_password, new_password }, { idempotency: key }),
  beginTotp: (key: string) =>
    http.post<TotpEnrollment>('/api/v1/sessions/current/mfa/totp', undefined, { idempotency: key }).then((r) => r.data),
  confirmTotp: (code: string, key: string) =>
    http
      .post<TotpConfirmResult>('/api/v1/sessions/current/mfa/totp/confirm', { code }, { idempotency: key })
      .then((r) => r.data),
  /** 关闭改 POST …/totp/disable（code 走 body）；验证码错为 403 MFA_REQUIRED */
  disableTotp: (code: string, key: string) =>
    http.post<User>('/api/v1/sessions/current/mfa/totp/disable', { code }, { idempotency: key }).then((r) => r.data),
};

/* ------------------------------------------------------------------ 用户（host.users.*，写入走 operation） */
export const users = {
  list: (q: { cursor?: string; limit?: number } = {}) => http.get<Page<User>>('/api/v1/users', { query: q }).then((r) => r.data),
  get: (id: string) => http.get<User>(`/api/v1/users/${enc(id)}`).then((r) => r.data),
  create: (body: { username: string; role: Role; display_name?: string }, key: string): Promise<OpResult> =>
    http.post<Mutating>('/api/v1/users', body, { idempotency: key }).then(toOpResult),
  update: (
    id: string,
    body: { expected_revision: string; display_name?: string; role?: Role; disabled?: boolean },
    key: string,
  ): Promise<OpResult> => http.patch<Mutating>(`/api/v1/users/${enc(id)}`, body, { idempotency: key }).then(toOpResult),
  remove: (id: string, expected_revision: string, key: string): Promise<OpResult> =>
    http.del<Mutating>(`/api/v1/users/${enc(id)}`, { query: { expected_revision }, idempotency: key }).then(toOpResult),
  /** 200；要求 MFA 新鲜（或带 mfa_code）；令牌只在本次响应出现，幂等重放不含令牌 */
  createEnrollmentToken: (id: string, key: string, mfa_code?: string) =>
    http
      .post<EnrollmentTokenCreated>(`/api/v1/users/${enc(id)}/enrollment-token`, mfa_code ? { mfa_code } : {}, { idempotency: key })
      .then((r) => r.data),
};

/* ------------------------------------------------------------------ 委托（外部 AI 接入） */
export const delegations = {
  list: (owner: 'me' | 'all' = 'me') =>
    http.get<Page<Delegation>>('/api/v1/delegations', { query: { owner } }).then((r) => r.data),
  create: (body: { label: string; policy?: DelegationPolicy; ttl_seconds?: number }, key: string) =>
    http.post<DelegationCreated>('/api/v1/delegations', body, { idempotency: key }).then((r) => r.data),
  update: (id: string, body: { expected_revision: string; status?: 'active' | 'suspended'; policy?: DelegationPolicy }, key: string) =>
    http.patch<Delegation>(`/api/v1/delegations/${enc(id)}`, body, { idempotency: key }).then((r) => r.data),
  revoke: (id: string, expected_revision: string, key: string) =>
    http.del<void>(`/api/v1/delegations/${enc(id)}`, { query: { expected_revision }, idempotency: key }),
};

/* ------------------------------------------------------------------ 节点 */
export const nodes = {
  list: () => http.get<Page<Node>>('/api/v1/nodes').then((r) => r.data),
  get: (id: string) => http.get<Node>(`/api/v1/nodes/${enc(id)}`).then((r) => r.data),
};

/* ------------------------------------------------------------------ 插件 */
export const plugins = {
  list: () => http.get<Page<Plugin>>('/api/v1/plugins', { query: { limit: 200 } }).then((r) => r.data),
  get: (id: string) => http.get<Plugin>(`/api/v1/plugins/${enc(id)}`).then((r) => r.data),
  upload: (file: File, onProgress?: (loaded: number, total: number) => void, signal?: AbortSignal) => {
    const form = new FormData();
    form.append('package', file, file.name);
    return upload<PluginPackageUpload>('/api/v1/plugin-packages', form, onProgress, signal).then((r) => r.data);
  },
  inspect: (uploadId: string) =>
    http.get<PluginPackageInspection>(`/api/v1/plugin-packages/${enc(uploadId)}`).then((r) => r.data),
  install: (body: { upload_id: string; accepted_capabilities: { name: string; scope: string }[] }, key: string) =>
    http.post<PluginVersion>('/api/v1/plugins', body, { idempotency: key }).then((r) => r.data),
  update: (
    id: string,
    body: { upload_id: string; accepted_capabilities: { name: string; scope: string }[]; expected_revision?: string },
    key: string,
  ) => http.post<PluginUpdateResult>(`/api/v1/plugins/${enc(id)}/update`, body, { idempotency: key }).then((r) => r.data),
  rollback: (id: string, key: string, expected_revision?: string) =>
    http
      .post<PluginUpdateResult>(`/api/v1/plugins/${enc(id)}/rollback`, expected_revision ? { expected_revision } : {}, {
        idempotency: key,
      })
      .then((r) => r.data),
  /** job，202；purge_data=true 为 destructive（需 MFA）；被依赖时 409 STATE_CONFLICT */
  uninstall: (id: string, expected_revision: string, key: string, purge_data = false): Promise<OpResult> =>
    http
      .del<Mutating>(`/api/v1/plugins/${enc(id)}`, { query: { expected_revision, purge_data }, idempotency: key })
      .then(toOpResult),
  getConfig: (id: string) => http.get<PluginConfig>(`/api/v1/plugins/${enc(id)}/config`).then((r) => r.data),
  putConfig: (id: string, config: Record<string, unknown>, expected_revision: string, key: string) =>
    http.put<PluginConfig>(`/api/v1/plugins/${enc(id)}/config`, { config, expected_revision }, { idempotency: key }).then((r) => r.data),
  configSchema: (id: string) =>
    http.get<Record<string, unknown>>(`/api/v1/plugins/${enc(id)}/config-schema`).then((r) => r.data),
  /** 不产生 operation（运行时自身生命周期，catalog-exempt）；200 返回刷新后的 Plugin */
  restart: (id: string, key: string, reason?: string): Promise<Plugin> =>
    http.post<Plugin>(`/api/v1/plugins/${enc(id)}/restart`, reason ? { reason } : {}, { idempotency: key }).then((r) => r.data),
  enable: (id: string, key: string): Promise<OpResult> =>
    http.post<Mutating>(`/api/v1/plugins/${enc(id)}/enable`, {}, { idempotency: key }).then(toOpResult),
  disable: (id: string, key: string): Promise<OpResult> =>
    http.post<Mutating>(`/api/v1/plugins/${enc(id)}/disable`, {}, { idempotency: key }).then(toOpResult),
  logs: (id: string, q: { cursor?: string; limit?: number; stream?: 'stdout' | 'stderr' } = {}) =>
    http.get<PluginLogPage>(`/api/v1/plugins/${enc(id)}/logs`, { query: q }).then((r) => r.data),
  /** 调用插件 operation：读操作不需要幂等键 */
  invoke: (
    p: { pluginId: string; operation: string; placement: 'node' | 'controller'; nodeId?: string; instanceId?: string },
    payload: Record<string, unknown>,
    opts: { key?: string; planId?: string; subject?: string; expectedRevision?: string; signal?: AbortSignal } = {},
  ): Promise<OpResult> => {
    const path =
      p.placement === 'controller'
        ? `/api/v1/plugins/${enc(p.pluginId)}/operations/${enc(p.operation)}`
        : `/api/v1/nodes/${enc(p.nodeId ?? 'local')}/plugins/${enc(p.pluginId)}/instances/${enc(p.instanceId ?? 'default')}/operations/${enc(p.operation)}`;
    const body: Record<string, unknown> = { payload };
    if (opts.planId) body.plan_id = opts.planId;
    if (opts.subject) body.subject = opts.subject;
    if (opts.expectedRevision) body.expected_revision = opts.expectedRevision;
    return http.post<Mutating>(path, body, { idempotency: opts.key, signal: opts.signal }).then(toOpResult);
  },
};

/* ------------------------------------------------------------------ Operation / Plan / Approval */
export const operations = {
  list: (q: {
    status?: OperationStatus[];
    actor_kind?: string;
    plugin_id?: string;
    node_id?: string;
    cursor?: string;
    limit?: number;
    since_revision?: string;
  } = {}) => http.get<Page<Op>>('/api/v1/operations', { query: q }).then((r) => r.data),
  get: (id: string, signal?: AbortSignal) => http.get<Op>(`/api/v1/operations/${enc(id)}`, { signal }).then((r) => r.data),
  cancel: (id: string, key: string, reason?: string) =>
    http.post<Op>(`/api/v1/operations/${enc(id)}/cancel`, reason ? { reason } : {}, { idempotency: key }).then((r) => r.data),
};

export const plans = {
  create: (body: PlanRequest) => http.post<Plan>('/api/v1/plans', body).then((r) => r.data),
  get: (id: string) => http.get<Plan>(`/api/v1/plans/${enc(id)}`).then((r) => r.data),
  execute: (id: string, key: string): Promise<OpResult> =>
    http.post<Mutating>(`/api/v1/plans/${enc(id)}/execute`, undefined, { idempotency: key }).then(toOpResult),
};

export const approvals = {
  list: (status: ApprovalStatus = 'PENDING', q: { operation_id?: string; since_revision?: string } = {}) =>
    http.get<Page<Approval>>('/api/v1/approvals', { query: { status, limit: 100, ...q } }).then((r) => r.data),
  get: (id: string) => http.get<Approval>(`/api/v1/approvals/${enc(id)}`).then((r) => r.data),
  decide: (
    id: string,
    body: { decision: 'approve' | 'reject'; expected_revision: string; comment?: string; mfa_code?: string },
    key: string,
  ) => http.post<Approval>(`/api/v1/approvals/${enc(id)}/decision`, body, { idempotency: key }).then((r) => r.data),
};

/* ------------------------------------------------------------------ 动作目录（面向人，Ctrl K） */
export const actions = {
  search: (q: string, opts: { plugin_id?: string; effect?: string; limit?: number; signal?: AbortSignal } = {}) =>
    http
      .get<ActionSearchResult>('/api/v1/actions', {
        query: { q, plugin_id: opts.plugin_id, effect: opts.effect, limit: opts.limit ?? 12 },
        signal: opts.signal,
      })
      .then((r) => r.data),
  describe: (id: string) => http.get<ActionDetail>(`/api/v1/actions/${enc(id)}`).then((r) => r.data),
};
export type { ActionMeta, TargetInput };

/* ------------------------------------------------------------------ Agent 会话 */
export const agent = {
  list: (status?: string) =>
    http.get<Page<AgentSession>>('/api/v1/agent-sessions', { query: { status, limit: 100 } }).then((r) => r.data),
  cores: () => http.get<{ items: AgentCoreInfo[] }>('/api/v1/agent-cores').then((r) => r.data),
  coreAuth: () => http.get<{ items: AgentCoreAuthStatus[] }>('/api/v1/agent-cores/auth').then((r) => r.data),
  startCoreLogin: (core: ExternalCliCore, body: AgentCoreLoginRequest) =>
    http.post<AgentCoreAuthStatus>(`/api/v1/agent-cores/${enc(core)}/login`, body).then((r) => r.data),
  logoutCore: (core: ExternalCliCore) =>
    http.del<AgentCoreAuthStatus>(`/api/v1/agent-cores/${enc(core)}/login`).then((r) => r.data),
  workspaceList: (area: WorkspaceArea) =>
    http.get<AgentWorkspaceListResult>('/api/v1/agent-workspace/files', { query: { area } }).then((r) => r.data),
  workspaceRead: (area: WorkspaceArea, path: string) =>
    http.get<AgentWorkspaceFileContent>('/api/v1/agent-workspace/file', { query: { area, path } }).then((r) => r.data),
  workspaceWrite: (body: AgentWorkspaceWriteRequest) =>
    http.put<AgentWorkspaceFileEntry>('/api/v1/agent-workspace/file', body).then((r) => r.data),
  workspaceDelete: (area: WorkspaceArea, path: string) =>
    http.del<void>('/api/v1/agent-workspace/file', { query: { area, path } }),
  registrySearch: (q: { kind?: 'all' | 'skill' | 'mcp'; source?: string; q?: string; refresh?: boolean } = {}) =>
    http
      .get<AgentRegistrySearchResult>('/api/v1/agent-registry', {
        query: { kind: q.kind, source: q.source, q: q.q, refresh: q.refresh ? '1' : undefined },
      })
      .then((r) => r.data),
  registryInstall: (id: string) =>
    http.post<AgentRegistryInstallResult>('/api/v1/agent-registry/install', { id }).then((r) => r.data),
  /** config.provider_id 缺省用默认提供方；用 provider_id 时 config.base_url 必须为空 */
  create: (body: { title?: string; core?: AgentCore; permission_mode?: PermissionMode; config?: Record<string, unknown> }) =>
    http.post<AgentSession>('/api/v1/agent-sessions', body).then((r) => r.data),
  get: (id: string) => http.get<AgentSessionDetail>(`/api/v1/agent-sessions/${enc(id)}`).then((r) => r.data),
  /** 缺口 6：向前翻页，owner，最多 200 */
  messages: (id: string, q: { before_seq?: number; limit?: number } = {}) =>
    http
      .get<{ items: AgentSessionMessage[] }>(`/api/v1/agent-sessions/${enc(id)}/messages`, { query: q })
      .then((r) => r.data),
  update: (
    id: string,
    body: { expected_revision: string; title?: string; permission_mode?: PermissionMode; config?: Record<string, unknown> },
  ) => http.patch<AgentSession>(`/api/v1/agent-sessions/${enc(id)}`, body).then((r) => r.data),
  remove: (id: string) => http.del<void>(`/api/v1/agent-sessions/${enc(id)}`),
  send: (id: string, content: string, client_message_id: string) =>
    http
      .post<{ session: AgentSession; message: AgentSessionMessage }>(`/api/v1/agent-sessions/${enc(id)}/messages`, {
        content,
        client_message_id,
      })
      .then((r) => r.data),
  cancel: (id: string, reason?: string) =>
    http.post<AgentSession>(`/api/v1/agent-sessions/${enc(id)}/cancel`, reason ? { reason } : {}).then((r) => r.data),
  approvals: (id: string) =>
    http.get<{ items: AgentSessionApproval[] }>(`/api/v1/agent-sessions/${enc(id)}/approvals`).then((r) => r.data),
  eventsUrl: (id: string) => `/api/v1/agent-sessions/${enc(id)}/events`,
};

/* ------------------------------------------------------------------ 全局事件流 */
export const events = {
  /** agent.session.* 需显式订阅（缺口 6）；续传优先用 Last-Event-ID 头 */
  url: (topics: readonly string[], lastEventId?: string) =>
    buildUrl('/api/v1/events', { topics, last_event_id: lastEventId }),
};

/* ------------------------------------------------------------------ AI 服务 */
/** 缺口 2：create/update/delete 走 operation；Key 只写，走机密例外路由 */
export const ai = {
  providers: () => http.get<{ items: AiProvider[] }>('/api/v1/ai/providers').then((r) => r.data),
  createProvider: (body: AiProviderCreateRequest, key: string): Promise<OpResult> =>
    http.post<Mutating>('/api/v1/ai/providers', body, { idempotency: key }).then(toOpResult),
  updateProvider: (id: string, body: AiProviderUpdateRequest, key: string): Promise<OpResult> =>
    http.patch<Mutating>(`/api/v1/ai/providers/${enc(id)}`, body, { idempotency: key }).then(toOpResult),
  removeProvider: (id: string, expected_revision: string, key: string): Promise<OpResult> =>
    http
      .del<Mutating>(`/api/v1/ai/providers/${enc(id)}`, { query: { expected_revision }, idempotency: key })
      .then(toOpResult),
  setKey: (id: string, api_key: string, key: string) =>
    http.put<void>(`/api/v1/ai/providers/${enc(id)}/api-key`, { api_key }, { idempotency: key }),
  clearKey: (id: string, key: string) => http.del<void>(`/api/v1/ai/providers/${enc(id)}/api-key`, { idempotency: key }),
  testProvider: (id: string, key: string) =>
    http
      .post<AiProviderTestResult>(`/api/v1/ai/providers/${enc(id)}/test`, undefined, { idempotency: key })
      .then((r) => r.data),
  fetchModels: (body: AiProviderFetchModelsRequest) =>
    http.post<AiProviderFetchModelsResult>('/api/v1/ai/providers/fetch-models', body).then((r) => r.data),
};

/* ------------------------------------------------------------------ 审计 */
export const audit = {
  list: (
    q: {
      actor?: string;
      action?: string;
      subject?: string;
      outcome?: AuditEntry['outcome'];
      operation_id?: string;
      from?: string;
      to?: string;
      cursor?: string;
      limit?: number;
    } = {},
  ) => http.get<AuditPage>('/api/v1/audit', { query: q }).then((r) => r.data),
};
