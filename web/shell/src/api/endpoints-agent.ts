// SPDX-License-Identifier: AGPL-3.0-only
/* Agent 会话与 AI 服务提供方端点 */
import { http, toOpResult, type OpResult } from './client';
import type {
  AgentCore,
  AgentSession,
  AgentSessionApproval,
  AgentSessionDetail,
  AgentSessionMessage,
  Operation,
  OperationOutcome,
  Page,
  PermissionMode,
} from './types';
import type {
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
} from './additions';

const enc = encodeURIComponent;
type Mutating = Operation | OperationOutcome;

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
  create: (body: { title?: string; core?: AgentCore; permission_mode?: PermissionMode; config?: Record<string, unknown> }) =>
    http.post<AgentSession>('/api/v1/agent-sessions', body).then((r) => r.data),
  get: (id: string) => http.get<AgentSessionDetail>(`/api/v1/agent-sessions/${enc(id)}`).then((r) => r.data),
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
