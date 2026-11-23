// SPDX-License-Identifier: AGPL-3.0-only
/* 账户、用户、委托、操作、计划、审批、动作目录与审计端点 */
import { http, toOpResult, type OpResult } from './client';
import type {
  ActionMeta,
  Approval,
  ApprovalStatus,
  Delegation,
  DelegationCreated,
  DelegationPolicy,
  Operation,
  OperationOutcome,
  OperationStatus,
  Page,
  Plan,
  PlanRequest,
  Role,
  TargetInput,
  User,
} from './types';
import type {
  AccountUpdateRequest,
  ActionDetail,
  ActionSearchResult,
  AuditEntry,
  AuditPage,
  EnrollmentRedeemResult,
  EnrollmentTokenCreated,
  OperationExtra,
  TotpConfirmResult,
  TotpEnrollment,
} from './additions';

const enc = encodeURIComponent;
export type Op = Operation & OperationExtra;
type Mutating = Operation | OperationOutcome;

export const account = {
  redeemEnrollment: (token: string, password: string, key: string) =>
    http.post<EnrollmentRedeemResult>('/api/v1/enrollments', { token, password }, { idempotency: key }).then((r) => r.data),
  updateProfile: (body: AccountUpdateRequest, key: string): Promise<OpResult> =>
    http.patch<Mutating>('/api/v1/sessions/current/profile', body, { idempotency: key }).then(toOpResult),
  changePassword: (current_password: string, new_password: string, key: string) =>
    http.put<void>('/api/v1/sessions/current/password', { current_password, new_password }, { idempotency: key }),
  beginTotp: (key: string) =>
    http.post<TotpEnrollment>('/api/v1/sessions/current/mfa/totp', undefined, { idempotency: key }).then((r) => r.data),
  confirmTotp: (code: string, key: string) =>
    http
      .post<TotpConfirmResult>('/api/v1/sessions/current/mfa/totp/confirm', { code }, { idempotency: key })
      .then((r) => r.data),
  disableTotp: (code: string, key: string) =>
    http.post<User>('/api/v1/sessions/current/mfa/totp/disable', { code }, { idempotency: key }).then((r) => r.data),
};

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
  createEnrollmentToken: (id: string, key: string, mfa_code?: string) =>
    http
      .post<EnrollmentTokenCreated>(`/api/v1/users/${enc(id)}/enrollment-token`, mfa_code ? { mfa_code } : {}, { idempotency: key })
      .then((r) => r.data),
};

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
