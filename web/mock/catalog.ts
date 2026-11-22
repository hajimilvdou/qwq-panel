// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 动作目录与插件清单（种子的"静态"部分）
 * --------------------------------------------------------------------------
 * 宿主动作 + 三个示例插件（系统监控 / 安全防护 / 备份）+ 内置 agent 插件。
 * 插件 operation 的 action id 形如 `com.qwq.security/firewall.enable`。
 * ========================================================================== */
import type { S } from './http.ts';
import type { Plugin, PluginWidget } from '../shell/src/api/additions.ts';

type Meta = S['ActionMeta'] & { reachability?: boolean };

const host = (id: string, summary: string, effect: S['Effect'], risk: S['RiskLevel'], extra: Partial<Meta> = {}): Meta => ({
  id,
  summary,
  effect,
  risk,
  mode: 'invoke',
  idempotent: false,
  plannable: false,
  source: 'host',
  permission: id.replace(/^host\.([a-z_]+)\.(\w+)$/, 'host.$1:$2'),
  approval: 'auto',
  ...extra,
});

const op = (plugin: string, name: string, summary: string, effect: S['Effect'], risk: S['RiskLevel'], extra: Partial<Meta> = {}): Meta => ({
  id: `${plugin}/${name}`,
  summary,
  effect,
  risk,
  mode: 'invoke',
  idempotent: effect === 'read',
  plannable: false,
  source: 'plugin',
  plugin_id: plugin,
  placement: plugin === 'com.qwq.backup' ? 'controller' : 'node',
  approval: effect === 'read' ? 'auto' : 'ai_confirm',
  ...extra,
});

export const MONITOR = 'com.qwq.monitor';
export const SECURITY = 'com.qwq.security';
export const BACKUP = 'com.qwq.backup';
export const AGENT = 'com.qwq.agent';

export const ACTIONS: Meta[] = [
  host('host.users.create', '创建用户', 'write', 'medium', { approval: 'ai_confirm', ui_route: '/settings/users' }),
  host('host.users.update', '修改用户', 'write', 'medium', { approval: 'ai_confirm' }),
  host('host.users.delete', '删除用户', 'destructive', 'high', { approval: 'confirm' }),
  host('host.account.update', '修改自己的显示名', 'write', 'low', { ui_route: '/settings/account', idempotent: true, plannable: true }),
  host('host.plugins.install', '安装应用', 'write', 'high', { approval: 'ai_confirm', mode: 'job', ui_route: '/apps/install' }),
  host('host.plugins.update', '更新应用', 'write', 'high', { mode: 'job' }),
  host('host.plugins.restart', '重启应用', 'write', 'low'),
  host('host.plugins.enable', '启用应用', 'write', 'high', { approval: 'ai_confirm', mode: 'job' }),
  host('host.plugins.disable', '停用应用', 'write', 'high', { approval: 'ai_confirm', mode: 'job' }),
  host('host.plugins.uninstall', '卸载应用', 'destructive', 'high', { approval: 'confirm', mode: 'job' }),
  host('host.plugins.configure', '修改应用设置', 'write', 'medium'),
  host('host.ai_providers.create', '添加 AI 服务', 'write', 'low'),
  host('host.ai_providers.update', '修改 AI 服务', 'write', 'low'),
  host('host.ai_providers.delete', '删除 AI 服务', 'destructive', 'high'),
  host('host.delegations.create', '签发 AI 令牌', 'write', 'medium'),
  host('host.operations.cancel', '取消操作', 'write', 'low'),
  op(MONITOR, 'overview.cpu', '读取 CPU 使用率', 'read', 'low'),
  op(MONITOR, 'overview.memory', '读取内存使用', 'read', 'low'),
  op(MONITOR, 'overview.disk', '读取磁盘使用', 'read', 'low'),
  op(MONITOR, 'overview.network', '读取网络流量', 'read', 'low'),
  op(MONITOR, 'process.kill', '结束进程', 'destructive', 'high', {
    approval_summary: '结束进程',
    approval_description: '强制结束指定进程。未保存的数据会丢失。',
  }),
  op(SECURITY, 'overview.checks', '安全体检', 'read', 'low'),
  op(SECURITY, 'overview.events', '最近的安全事件', 'read', 'low'),
  op(SECURITY, 'firewall.enable', '开启防火墙', 'write', 'high', {
    reachability: true,
    approval_summary: '开启防火墙，只放行 SSH 与 HTTPS',
    approval_description:
      '将默认策略改为拒绝入站，只保留 22（SSH）和 443（HTTPS）端口。\n\n如果你通过其他端口管理服务器，开启后可能无法连接。',
    undo: `${SECURITY}/firewall.disable`,
  }),
  op(SECURITY, 'firewall.disable', '关闭防火墙', 'write', 'high', { reachability: true }),
  op(SECURITY, 'ssh.ban_ip', '封禁 IP', 'write', 'medium', { approval_summary: '封禁可疑 IP', undo: `${SECURITY}/ssh.unban_ip` }),
  op(SECURITY, 'ssh.unban_ip', '解封 IP', 'write', 'low'),
  op(BACKUP, 'overview.recent', '最近的备份', 'read', 'low'),
  op(BACKUP, 'backup.run', '立即备份', 'write', 'low', { mode: 'job', approval: 'auto' }),
  op(BACKUP, 'backup.restore', '从备份恢复', 'destructive', 'high', {
    approval: 'confirm',
    approval_summary: '用备份覆盖当前数据',
    approval_description: '恢复会覆盖当前数据目录，恢复前的改动将丢失。',
  }),
];

/* ------------------------------------------------------------------ 插件 */

const widget = (w: Omit<PluginWidget, 'refresh_seconds'> & { refresh_seconds?: number }): PluginWidget => ({
  refresh_seconds: 5,
  ...w,
});

interface PluginSeed {
  id: string;
  name: string;
  summary: string;
  description: string;
  version: string;
  placement: 'node' | 'controller';
  widgets: PluginWidget[];
  nav: boolean;
  capabilities: Plugin['capabilities'];
  builtin?: boolean;
  dependencies?: string[];
}

export const PLUGIN_SEEDS: PluginSeed[] = [
  {
    id: MONITOR,
    name: '系统监控',
    summary: '看 CPU、内存、磁盘和网络',
    description: '每 5 秒采集一次系统指标，保留 7 天。主页小组件来自这里。',
    version: '1.4.0',
    placement: 'node',
    nav: true,
    widgets: [
      widget({ id: 'cpu', title: 'CPU', kind: 'stat', operation: 'overview.cpu', size: 's', icon: 'cpu', color: 'blue', refresh_seconds: 2 }),
      widget({ id: 'memory', title: '内存', kind: 'stat', operation: 'overview.memory', size: 's', icon: 'memory', color: 'violet' }),
      widget({ id: 'disk', title: '磁盘', kind: 'stat', operation: 'overview.disk', size: 's', icon: 'disk', color: 'amber', refresh_seconds: 30 }),
      widget({ id: 'net', title: '网络', kind: 'series', operation: 'overview.network', size: 'm', icon: 'net', color: 'teal' }),
    ],
    capabilities: [
      { name: 'system.metrics', scope: 'read', reason: '读取 CPU、内存、磁盘与网络指标', sensitive: false },
      { name: 'process.signal', scope: 'kill', reason: '按你的要求结束失控进程', sensitive: true },
    ],
  },
  {
    id: SECURITY,
    name: '安全防护',
    summary: '防火墙、SSH 防爆破与安全体检',
    description: '检测弱口令与暴露端口，自动封禁反复登录失败的 IP。',
    version: '0.9.2',
    placement: 'node',
    nav: true,
    widgets: [
      widget({ id: 'checks', title: '安全体检', kind: 'checks', operation: 'overview.checks', size: 'm', icon: 'shield', color: 'green', refresh_seconds: 60 }),
      widget({ id: 'events', title: '安全事件', kind: 'list', operation: 'overview.events', size: 's', icon: 'alert', color: 'red', refresh_seconds: 30 }),
    ],
    capabilities: [
      { name: 'firewall.manage', scope: 'nftables', reason: '开启和调整防火墙规则', sensitive: true },
      { name: 'auth.log', scope: 'read', reason: '读取 SSH 登录日志发现爆破', sensitive: false },
    ],
    dependencies: [MONITOR],
  },
  {
    id: BACKUP,
    name: '备份',
    summary: '定时把面板数据备份到对象存储',
    description: '支持 S3 兼容存储，每天凌晨自动备份，保留 14 份。',
    version: '2.1.0',
    placement: 'controller',
    nav: false,
    widgets: [widget({ id: 'recent', title: '最近备份', kind: 'list', operation: 'overview.recent', size: 's', icon: 'backup', color: 'slate', refresh_seconds: 60 })],
    capabilities: [
      { name: 'storage.read', scope: 'data_dir', reason: '读取面板数据目录用于备份', sensitive: true },
      { name: 'net.egress', scope: 's3', reason: '上传到你配置的对象存储', sensitive: false },
    ],
  },
  {
    id: AGENT,
    name: 'AI 助手',
    summary: '内置的原生 Agent 核心',
    description: '在面板内运行的 AI 助手，按你设置的权限模式操作服务器。',
    version: '1.0.0',
    placement: 'controller',
    nav: false,
    widgets: [],
    capabilities: [],
    builtin: true,
  },
];

/** 插件配置 schema（JSON Schema 子集，x-qwq-secret 标记密文字段） */
export const CONFIG_SCHEMAS: Record<string, Record<string, unknown>> = {
  [MONITOR]: {
    type: 'object',
    properties: {
      interval_seconds: { type: 'integer', title: '采集间隔（秒）', minimum: 2, maximum: 60, default: 5 },
      retain_days: { type: 'integer', title: '保留天数', minimum: 1, maximum: 30, default: 7 },
    },
    required: ['interval_seconds'],
    'x-qwq-hot-apply': true,
  },
  [SECURITY]: {
    type: 'object',
    properties: {
      ssh_port: { type: 'integer', title: 'SSH 端口', minimum: 1, maximum: 65535, default: 22 },
      ban_threshold: { type: 'integer', title: '失败几次后封禁', minimum: 3, maximum: 20, default: 5 },
      notify_token: { type: 'string', title: '通知机器人令牌', 'x-qwq-secret': true },
    },
    'x-qwq-hot-apply': false,
  },
  [BACKUP]: {
    type: 'object',
    properties: {
      endpoint: { type: 'string', title: '存储地址', format: 'uri' },
      bucket: { type: 'string', title: '存储桶' },
      access_key: { type: 'string', title: 'Access Key', 'x-qwq-secret': true },
      keep: { type: 'integer', title: '保留份数', minimum: 1, maximum: 60, default: 14 },
    },
    'x-qwq-hot-apply': true,
  },
};
