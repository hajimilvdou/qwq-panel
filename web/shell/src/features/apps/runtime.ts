// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 插件运行态 → 人话 + 状态色（应用中心列表、详情共用）
 * ========================================================================== */
import type { Plugin, PluginRuntime } from '$api/types';
import type { Tone } from '$ui';

export const RUNTIME: Record<PluginRuntime['state'], { label: string; tone: Tone }> = {
  running: { label: '运行中', tone: 'ok' },
  standby: { label: '按需待命', tone: 'info' },
  starting: { label: '启动中', tone: 'info' },
  stopped: { label: '已停止', tone: 'neutral' },
  crashed: { label: '出错了', tone: 'bad' },
  quarantined: { label: '已隔离', tone: 'bad' },
  unknown: { label: '状态未知', tone: 'neutral' },
};

export const runtimeOf = (p: Plugin) => RUNTIME[p.runtime?.state ?? 'unknown'] ?? RUNTIME.unknown;

export const RISK_LABEL: Record<string, string> = { low: '低风险', medium: '中风险', high: '高风险' };
export const EFFECT_LABEL: Record<string, string> = { read: '只读', write: '修改', destructive: '破坏性' };
