// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 官方插件商店一键安装管线
 * --------------------------------------------------------------------------
 *   resolveInstallOrder(targetId, items)  解析未装依赖的拓扑安装顺序
 *   installOfficialPlugin(targetId, opts) 自动下载 → 验签 → 安装/更新 → 启用
 *
 * 所有安装包均经过宿主 SSRF 防护下载器、SHA-256 校验与官方 Ed25519 签名验证，
 * 仅对 signature.valid && signature.trusted 且无兼容性/资源阻断的官方包自动放行。
 * ========================================================================== */
import { newIdempotencyKey } from '$api/client';
import { plugins as pluginsApi } from '$api/endpoints-plugins';
import type { PluginCatalogItem } from '$api/additions';
import { blockers } from './install';

export type OfficialInstallStage = 'downloading' | 'verifying' | 'installing' | 'updating' | 'enabling';

export interface OfficialInstallProgress {
  pluginId: string;
  pluginName: string;
  stage: OfficialInstallStage;
  stepIndex: number;
  totalSteps: number;
}

export interface OfficialInstallResult {
  installed: string[];
  updated: string[];
}

export function resolveInstallOrder(targetId: string, items: readonly PluginCatalogItem[]): PluginCatalogItem[] {
  const byId = new Map<string, PluginCatalogItem>();
  for (const it of items) byId.set(it.plugin_id, it);
  const target = byId.get(targetId);
  if (!target) {
    throw new Error(`官方插件目录中未找到 ${targetId}`);
  }

  const ordered: PluginCatalogItem[] = [];
  const visiting = new Set<string>();
  const visited = new Set<string>();

  const visit = (item: PluginCatalogItem, isRoot: boolean) => {
    if (visited.has(item.plugin_id)) return;
    if (visiting.has(item.plugin_id)) return;
    visiting.add(item.plugin_id);
    for (const depId of item.dependencies ?? []) {
      const dep = byId.get(depId);
      if (dep && !dep.installed) {
        visit(dep, false);
      }
    }
    visiting.delete(item.plugin_id);
    visited.add(item.plugin_id);
    if (isRoot || !item.installed) {
      ordered.push(item);
    }
  };

  visit(target, true);
  return ordered;
}

export async function installOfficialPlugin(
  targetId: string,
  opts: {
    items?: readonly PluginCatalogItem[];
    signal?: AbortSignal;
    onProgress?: (p: OfficialInstallProgress) => void;
  } = {},
): Promise<OfficialInstallResult> {
  const catalogItems = opts.items ?? (await pluginsApi.catalog()).items;
  const plan = resolveInstallOrder(targetId, catalogItems);
  const installed: string[] = [];
  const updated: string[] = [];

  for (let i = 0; i < plan.length; i++) {
    const item = plan[i]!;
    if (!item.download_url) {
      throw new Error(`未获取到 ${item.name} (${item.plugin_id}) 的官方下载地址，请点击「刷新目录」重试`);
    }
    const emit = (stage: OfficialInstallStage) =>
      opts.onProgress?.({
        pluginId: item.plugin_id,
        pluginName: item.name,
        stage,
        stepIndex: i + 1,
        totalSteps: plan.length,
      });

    emit('downloading');
    const staged = await pluginsApi.fetchFromUrl(
      {
        url: item.download_url,
        ...(item.sha256 ? { expected_sha256: item.sha256 } : {}),
      },
      opts.signal,
    );

    emit('verifying');
    const ins = await pluginsApi.inspect(staged.upload_id);
    const problems = blockers(ins);
    if (problems.length > 0) {
      throw new Error(`${item.name} 安装检查未通过：${problems.join('；')}`);
    }
    const accepted_capabilities = (ins.manifest?.capabilities ?? []).map((c) => ({
      name: c.name,
      scope: c.scope,
    }));

    if (item.installed) {
      emit('updating');
      await pluginsApi.update(
        item.plugin_id,
        {
          upload_id: staged.upload_id,
          accepted_capabilities,
          ...(item.installed_revision ? { expected_revision: item.installed_revision } : {}),
        },
        newIdempotencyKey(),
      );
      updated.push(item.plugin_id);
    } else {
      emit('installing');
      await pluginsApi.install(
        {
          upload_id: staged.upload_id,
          accepted_capabilities,
        },
        newIdempotencyKey(),
      );
      emit('enabling');
      try {
        await pluginsApi.enable(item.plugin_id, newIdempotencyKey());
      } catch {
        // 部分插件安装后已处于 ACTIVE，重复 enable 返回冲突时忽略即可
      }
      installed.push(item.plugin_id);
    }
  }

  return { installed, updated };
}
