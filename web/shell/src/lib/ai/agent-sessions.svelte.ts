// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * Agent 会话：列表缓存、已读水位、展示文案（Agent 页与悬浮窗共用）
 * --------------------------------------------------------------------------
 *   sessionsResource        useResource 选项；agent_sessions/* 变化与 agent.session.* 失效
 *   readMarks.mark(id, seq) / readMarks.unread(session)
 *   MODE_META / CORE_LABEL / STATUS_META
 *   lastSession             悬浮窗记住的最后会话（localStorage）
 * 没有已读回执 API（契约 §4.4）：本地记录每个会话已读到的 seq。
 * ========================================================================== */
import { SvelteMap } from 'svelte/reactivity';
import { agent } from '$api/endpoints';
import type { AgentCore, AgentSession, AgentSessionStatus, PermissionMode } from '$api/types';
import type { ResourceOptions } from '../resource.svelte';
import type { Tone } from '$ui';
import { formatContextTokens, resolveModelContext } from './model-context-catalog';

export const sessionsResource: ResourceOptions<AgentSession[]> = {
  key: 'agent-sessions',
  load: () => agent.list().then((p) => p.items),
  subjects: ['agent_sessions/'],
  events: ['agent.session.updated'],
};

export const BUSY = new Set<AgentSessionStatus>(['running', 'waiting_approval']);

/* ------------------------------------------------------------------ 文案 */

export const MODE_META: Record<PermissionMode, { label: string; short: string; note?: string; danger?: boolean }> = {
  read_only: { label: '只看不动', short: '只读' },
  safe: { label: '重要操作先问我', short: '先问我' },
  full: { label: '按授权直接做', short: '直接做', note: '包括可能影响连接的操作', danger: true },
  custom: { label: '按动作配置', short: '自定义', note: '规则表尚未开放' },
};
export const MODES = ['read_only', 'safe', 'full', 'custom'] as const satisfies readonly PermissionMode[];

export const CORE_LABEL: Record<AgentCore, string> = {
  native: '内置原生',
  'claude-code': 'Claude Code',
  codex: 'Codex',
  opencode: 'OpenCode',
  dsh: 'DSH (DeepSeek)',
  acp: 'ACP 通用代理',
};

export const coreLabel = (core: string): string =>
  (CORE_LABEL as Record<string, string>)[core] ?? core;

export const SLASH_COMMANDS = [
  { cmd: '/status', label: '会话状态', desc: '查看当前核心、模型、思考深度与历史消息统计', instant: true },
  { cmd: '/compact', label: '压缩上下文', desc: '将较早轮次总结压缩，保留审计记录', instant: true },
  { cmd: '/plan', label: '计划模式', desc: '切换只读计划模式，先输出步骤清单再执行', instant: true },
  { cmd: '/mode', label: '权限模式', desc: '切换 read_only / safe / full 授权级别', instant: false },
  { cmd: '/model', label: '切换模型', desc: '如 /model gpt-5 high，即时切换模型与思考深度', instant: false },
  { cmd: '/effort', label: '思考挡位', desc: '设置自定义思考挡位（如 minimal / high / xhigh / max / 16384 或 auto）', instant: false },
  { cmd: '/context', label: '上下文大小', desc: '设置上下文窗口上限，如 /context auto、/context 200k 或 /context 1m', instant: false },
  { cmd: '/skills', label: '运维技能列表', desc: '列出当前内置 VPS 运维技能包', instant: true },
  { cmd: '/mcp', label: '宿主 MCP 工具', desc: '查看当前授权挂载的宿主与插件动作', instant: true },
  { cmd: '/help', label: '指令帮助', desc: '查看所有可用斜杠指令', instant: true },
] as const;

export const EFFORT_OPTIONS = [
  { value: '', label: '跟随模型默认' },
  { value: 'none', label: '关闭思考 (none)' },
  { value: 'low', label: '低 (low)' },
  { value: 'medium', label: '中 (medium)' },
  { value: 'high', label: '高 (high)' },
  { value: 'xhigh', label: '极高 (xhigh)' },
] as const;

export const CONTEXT_OPTIONS = [
  { value: '0', label: '自动默认 (128K)' },
  { value: '32768', label: '32K (32,768)' },
  { value: '65536', label: '64K (65,536)' },
  { value: '128000', label: '128K (128,000)' },
  { value: '200000', label: '200K (200,000)' },
  { value: '512000', label: '512K (512,000)' },
  { value: '1000000', label: '1M (1,000,000)' },
] as const;

export const effortLabel = (v?: string): string => {
  const s = (v ?? '').trim();
  if (!s) return '自动';
  switch (s.toLowerCase()) {
    case 'none':
    case 'off':
    case 'disabled':
      return '关闭';
    case 'minimal':
      return '极简';
    case 'low':
      return '低';
    case 'medium':
      return '中';
    case 'high':
      return '高';
    case 'xhigh':
      return '极高';
    case 'max':
      return '最大';
    default:
      return s;
  }
};

export const formatContextSize = (n?: number, model?: string): string => {
  if (!n || n <= 0) {
    if (model?.trim()) {
      const r = resolveModelContext(model, 0);
      return `自动 (${r.label})`;
    }
    return '自动';
  }
  return formatContextTokens(n);
};

export const BUILTIN_SKILLS = [
  { id: 'ssh-hardening', label: 'SSH 安全体检', desc: '检查 sshd -T 生效项、cloud-init 覆盖与公钥状态', prompt: '请使用只读检查排查当前主机的 SSH 生效配置、是否存在 cloud-init 覆盖开启密码登录的风险，以及公钥配置情况。' },
  { id: 'proxy-audit', label: '代理节点审计', desc: '核查入站端口、配置版本与限速策略', prompt: '请排查当前代理节点状态、监听端口与配置版本，给出风险与优化建议。' },
  { id: 'memory-triage', label: '1C1G 内存体检', desc: '排查高占用进程、宿主机常驻内存与 OOM 风险', prompt: '请对当前服务器做一次轻量内存体检，识别异常占用并给出不中断业务的优化建议。' },
  { id: 'port-diagnosis', label: '端口与防火墙排查', desc: '检查监听端口、防火墙放行规则与冲突项', prompt: '请检查当前监听端口和防火墙规则，识别未授权暴露或端口冲突。' },
] as const;

export const STATUS_META: Record<AgentSessionStatus, { label: string; tone: Tone }> = {
  idle: { label: '空闲', tone: 'neutral' },
  running: { label: '处理中', tone: 'ai' },
  waiting_approval: { label: '等你确认', tone: 'warn' },
  attention: { label: '需要关注', tone: 'warn' },
  cancelled: { label: '已停止', tone: 'neutral' },
  failed: { label: '出错了', tone: 'bad' },
};

export const statusMeta = (s: string) => STATUS_META[s as AgentSessionStatus] ?? STATUS_META.idle;

/* ------------------------------------------------------------------ 已读水位 */

const READ_KEY = 'qwq.agent.read';
const LAST_KEY = 'qwq.agent.last';

class ReadMarks {
  #map = new SvelteMap<string, number>();

  constructor() {
    try {
      const raw = JSON.parse(localStorage.getItem(READ_KEY) ?? '{}') as Record<string, number>;
      for (const [k, v] of Object.entries(raw)) if (typeof v === 'number') this.#map.set(k, v);
    } catch {
      /* 无存储或损坏：全部视为未读也无妨 */
    }
  }

  mark(id: string, seq: number): void {
    if ((this.#map.get(id) ?? -1) >= seq) return;
    this.#map.set(id, seq);
    this.#save();
  }

  unread(s: AgentSession): boolean {
    const seen = this.#map.get(s.session_id);
    return seen !== undefined ? s.last_seq > seen : false;
  }

  forget(id: string): void {
    this.#map.delete(id);
    this.#save();
  }

  #save() {
    try {
      localStorage.setItem(READ_KEY, JSON.stringify(Object.fromEntries(this.#map)));
    } catch {
      /* 配额或隐私模式：忽略 */
    }
  }
}

export const readMarks = typeof localStorage === 'undefined' ? null : new ReadMarks();

export const lastSession = {
  get: (): string | null => {
    try {
      return localStorage.getItem(LAST_KEY);
    } catch {
      return null;
    }
  },
  set: (id: string | null): void => {
    try {
      if (id) localStorage.setItem(LAST_KEY, id);
      else localStorage.removeItem(LAST_KEY);
    } catch {
      /* 忽略 */
    }
  },
};
