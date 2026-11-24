// SPDX-License-Identifier: AGPL-3.0-only
/* 核心引导端点：会话、系统、节点、全局事件流 */
import { buildUrl, http, type RequestOptions } from './client';
import type { MfaChallenge, Node, Page, Plugin, Session, SetupStatus } from './types';
import type { PanelAccessSettings, PanelAccessUpdateRequest, SystemInfo } from './additions';

const enc = encodeURIComponent;

export const system = {
  health: () => http.get<{ status: string }>('/healthz'),
  ready: () => http.get<{ status: string }>('/readyz'),
  info: () => http.get<SystemInfo>('/api/v1/system').then((r) => r.data),
  access: () => http.get<PanelAccessSettings>('/api/v1/system/access').then((r) => r.data),
  updateAccess: (body: PanelAccessUpdateRequest, mfaCode?: string) =>
    http
      .put<PanelAccessSettings>(
        '/api/v1/system/access',
        body,
        mfaCode ? { headers: { 'X-QWQ-MFA-Code': mfaCode } } : undefined,
      )
      .then((r) => r.data),
  setupStatus: (opts?: RequestOptions) => http.get<SetupStatus>('/api/v1/setup', opts).then((r) => r.data),
  completeSetup: (body: { setup_token: string; username: string; password: string; display_name?: string }) =>
    http.post<Session>('/api/v1/setup', body).then((r) => r.data),
};

export const sessions = {
  login: (username: string, password: string) =>
    http.post<Session | MfaChallenge>('/api/v1/sessions', { username, password }).then((r) => r.data),
  verifyMfa: (challenge_id: string, method: 'totp' | 'recovery_code', code: string) =>
    http.post<Session>('/api/v1/sessions/mfa', { challenge_id, method, code }).then((r) => r.data),
  current: (opts?: RequestOptions) => http.get<Session>('/api/v1/sessions/current', opts).then((r) => r.data),
  logout: () => http.del<void>('/api/v1/sessions/current'),
};

export const nodes = {
  list: () => http.get<Page<Node>>('/api/v1/nodes').then((r) => r.data),
  get: (id: string) => http.get<Node>(`/api/v1/nodes/${enc(id)}`).then((r) => r.data),
};

export const listPlugins = () => http.get<Page<Plugin>>('/api/v1/plugins', { query: { limit: 200 } }).then((r) => r.data);

export const events = {
  /** agent.session.* 需显式订阅（缺口 6）；续传优先用 Last-Event-ID 头 */
  url: (topics: readonly string[], lastEventId?: string) =>
    buildUrl('/api/v1/events', { topics, last_event_id: lastEventId }),
};
