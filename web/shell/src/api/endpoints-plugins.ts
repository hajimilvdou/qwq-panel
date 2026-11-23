// SPDX-License-Identifier: AGPL-3.0-only
/* 插件端点 */
import { http, toOpResult, type OpResult } from './client';
import { upload } from './upload';
import { listPlugins } from './endpoints-core';
import type {
  Operation,
  OperationOutcome,
  Plugin,
  PluginConfig,
  PluginPackageUpload,
  PluginUpdateResult,
  PluginVersion,
} from './types';
import type {
  PluginCatalogResponse,
  PluginLogPage,
  PluginPackageFetchRequest,
  PluginPackageInspection,
  PluginTrustKey,
  PluginTrustKeyCreateRequest,
  PluginTrustKeyList,
} from './additions';

const enc = encodeURIComponent;
type Mutating = Operation | OperationOutcome;

/** 判断插件是否已处于可用运行态（running 或无 runtime 报告时的 ACTIVE） */
export function isPluginActiveReady(plugin: Plugin | undefined): boolean {
  if (!plugin) return false;
  const runtimeState = plugin.runtime?.state;
  if (runtimeState === 'running') return true;
  if (runtimeState && runtimeState !== 'unknown') return false;
  return plugin.active_status === 'ACTIVE';
}

export const plugins = {
  list: listPlugins,
  catalog: (refresh = false) =>
    http
      .get<PluginCatalogResponse>('/api/v1/plugin-catalog', refresh ? { query: { refresh: '1' } } : undefined)
      .then((r) => r.data),
  get: (id: string) => http.get<Plugin>(`/api/v1/plugins/${enc(id)}`).then((r) => r.data),
  upload: (file: File, onProgress?: (loaded: number, total: number) => void, signal?: AbortSignal) => {
    const form = new FormData();
    form.append('package', file, file.name);
    return upload<PluginPackageUpload>('/api/v1/plugin-packages', form, onProgress, signal).then((r) => r.data);
  },
  fetchFromUrl: (body: PluginPackageFetchRequest, signal?: AbortSignal) =>
    http.post<PluginPackageUpload>('/api/v1/plugin-packages/fetch', body, { signal }).then((r) => r.data),
  inspect: (uploadId: string) =>
    http.get<PluginPackageInspection>(`/api/v1/plugin-packages/${enc(uploadId)}`).then((r) => r.data),
  trustKeys: () => http.get<PluginTrustKeyList>('/api/v1/plugin-trust-keys').then((r) => r.data),
  addTrustKey: (body: PluginTrustKeyCreateRequest, mfa?: string) =>
    http
      .post<PluginTrustKey>(
        '/api/v1/plugin-trust-keys',
        body,
        mfa ? { headers: { 'X-QWQ-MFA-Code': mfa } } : undefined,
      )
      .then((r) => r.data),
  removeTrustKey: (keyId: string, mfa?: string) =>
    http
      .del<void>(
        `/api/v1/plugin-trust-keys/${enc(keyId)}`,
        mfa ? { headers: { 'X-QWQ-MFA-Code': mfa } } : undefined,
      )
      .then(() => undefined),
  install: (body: { upload_id: string; accepted_capabilities: { name: string; scope: string }[] }, key: string) =>
    http.post<PluginVersion>('/api/v1/plugins', body, { idempotency: key }).then((r) => r.data),
  /** 尝试通过宿主官方内置目录接口安装并启用指定内置插件（需宿主支持该端点） */
  installBuiltin: (id: string, key: string, autoEnable = true): Promise<OpResult> =>
    http
      .post<Mutating>(`/api/v1/plugins/${enc(id)}/install-builtin`, { auto_enable: autoEnable }, { idempotency: key })
      .then(toOpResult),
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
