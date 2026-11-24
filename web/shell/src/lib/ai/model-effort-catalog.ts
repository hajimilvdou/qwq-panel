// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 主流 AI 模型思考挡位清单与自动匹配规则
 * --------------------------------------------------------------------------
 * 与后端 internal/agentsession/model_catalog.go 保持完全一致：
 *   1. 用户手动填写了自定义挡位 → 原样透传；
 *   2. 用户未手动填写（留空）→ 自动按模型名匹配下方主流清单；
 *   3. 未命中清单且未自定义 → 自动兜底为 high。
 * ========================================================================== */

export const FALLBACK_EFFORT = 'high';

export const GENERIC_EFFORT_LEVELS = [
  'none',
  'minimal',
  'low',
  'medium',
  'high',
  'xhigh',
  'max',
] as const;

export interface ModelEffortProfile {
  family: string;
  patterns: readonly string[];
  levels: readonly string[];
  defaultEffort: string;
  notes: string;
}

export const MODEL_EFFORT_CATALOG: readonly ModelEffortProfile[] = [
  {
    family: 'OpenAI GPT-5.2+ / Codex',
    patterns: ['gpt-5.4', 'gpt-5.3', 'gpt-5.2', 'gpt-5-codex', 'gpt-5-pro', 'codex-max', 'codex-mini', 'codex'],
    levels: ['none', 'minimal', 'low', 'medium', 'high', 'xhigh'],
    defaultEffort: 'high',
    notes: '官方支持 none / minimal / low / medium / high / xhigh',
  },
  {
    family: 'OpenAI GPT-5 mini / nano',
    patterns: ['gpt-5-mini', 'gpt-5-nano', 'gpt-5.1-mini', 'gpt-5.1-nano'],
    levels: ['minimal', 'low', 'medium', 'high'],
    defaultEffort: 'medium',
    notes: '轻量版推荐默认 medium，支持 minimal–high',
  },
  {
    family: 'OpenAI GPT-5 / 5.1',
    patterns: ['gpt-5.1', 'gpt-5'],
    levels: ['none', 'minimal', 'low', 'medium', 'high'],
    defaultEffort: 'high',
    notes: '支持 none / minimal / low / medium / high',
  },
  {
    family: 'OpenAI o1 / o3 / o4-mini',
    patterns: ['o4-mini', 'o3-pro', 'o3-mini', 'o3', 'o1-pro', 'o1-mini', 'o1'],
    levels: ['low', 'medium', 'high'],
    defaultEffort: 'high',
    notes: 'o 系列官方挡位 low / medium / high',
  },
  {
    family: 'Anthropic Claude Opus 4.6+',
    patterns: ['claude-opus-4-7', 'claude-opus-4.7', 'claude-opus-4-6', 'claude-opus-4.6', 'claude-4-6-opus', 'claude-opus-5', 'claude-5-opus'],
    levels: ['low', 'medium', 'high', 'xhigh', 'max'],
    defaultEffort: 'high',
    notes: '支持 low / medium / high / xhigh / max 或直接填数字 budget',
  },
  {
    family: 'Anthropic Claude Haiku 4.5+',
    patterns: ['claude-haiku-4', 'claude-4-5-haiku', 'claude-4-6-haiku'],
    levels: ['low', 'medium', 'high'],
    defaultEffort: 'medium',
    notes: '推荐默认 medium，支持 low / medium / high',
  },
  {
    family: 'Anthropic Claude 3.7 / 4.x Sonnet & Opus',
    patterns: [
      'claude-sonnet-4',
      'claude-4-6-sonnet',
      'claude-4-5-sonnet',
      'claude-4-sonnet',
      'claude-opus-4',
      'claude-4-opus',
      'claude-3-7-sonnet',
      'claude-3.7-sonnet',
    ],
    levels: ['low', 'medium', 'high', 'max'],
    defaultEffort: 'high',
    notes: '支持 low / medium / high / max 或直接填 token 预算数字',
  },
  {
    family: 'Google Gemini 3 / 4',
    patterns: ['gemini-4', 'gemini-3.1', 'gemini-3-pro', 'gemini-3-flash', 'gemini-3'],
    levels: ['minimal', 'low', 'medium', 'high', 'xhigh'],
    defaultEffort: 'high',
    notes: '支持 minimal / low / medium / high / xhigh',
  },
  {
    family: 'Google Gemini 2.5 Flash',
    patterns: ['gemini-2.5-flash', 'gemini-2-5-flash'],
    levels: ['none', 'low', 'medium', 'high'],
    defaultEffort: 'medium',
    notes: '推荐默认 medium，支持 none / low / medium / high',
  },
  {
    family: 'Google Gemini 2.5 Pro',
    patterns: ['gemini-2.5-pro', 'gemini-2-5-pro', 'gemini-2.5'],
    levels: ['low', 'medium', 'high'],
    defaultEffort: 'high',
    notes: '支持 low / medium / high',
  },
  {
    family: 'DeepSeek Reasoner / R1 / V3.2+',
    patterns: ['deepseek-reasoner', 'deepseek-r1', 'deepseek-v4', 'deepseek-v3.2'],
    levels: ['none', 'low', 'medium', 'high', 'max'],
    defaultEffort: 'high',
    notes: '支持 none / low / medium / high / max',
  },
  {
    family: 'xAI Grok 3 / 4',
    patterns: ['grok-4', 'grok-3-mini', 'grok-3'],
    levels: ['low', 'medium', 'high'],
    defaultEffort: 'high',
    notes: '支持 low / medium / high',
  },
  {
    family: 'Alibaba Qwen3 / QwQ',
    patterns: ['qwen3', 'qwen-3', 'qwq'],
    levels: ['none', 'low', 'medium', 'high', 'max'],
    defaultEffort: 'high',
    notes: '支持 none / low / medium / high / max 或数字预算',
  },
  {
    family: 'Zhipu GLM-4.5 / 5',
    patterns: ['glm-5', 'glm-4.7', 'glm-4.6', 'glm-4.5', 'glm-z1'],
    levels: ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'],
    defaultEffort: 'high',
    notes: '支持 none / minimal / low / medium / high / xhigh / max',
  },
  {
    family: 'Moonshot Kimi K2 / K3',
    patterns: ['kimi-k3', 'kimi-k2'],
    levels: ['low', 'medium', 'high', 'max'],
    defaultEffort: 'high',
    notes: '支持 low / medium / high / max',
  },
  {
    family: 'MiniMax M1 / M2',
    patterns: ['minimax-m2', 'minimax-m1'],
    levels: ['low', 'medium', 'high'],
    defaultEffort: 'high',
    notes: '支持 low / medium / high',
  },
  {
    family: 'Doubao Seed / Thinking',
    patterns: ['doubao-seed', 'doubao-1.6', 'doubao-1.5-thinking'],
    levels: ['minimal', 'low', 'medium', 'high'],
    defaultEffort: 'high',
    notes: '支持 minimal / low / medium / high',
  },
  {
    family: 'Mistral Magistral',
    patterns: ['magistral'],
    levels: ['low', 'medium', 'high'],
    defaultEffort: 'high',
    notes: '支持 low / medium / high',
  },
];

function normalizeModelId(model: string): string {
  const m = model.trim().toLowerCase();
  const slash = m.lastIndexOf('/');
  return slash >= 0 && slash < m.length - 1 ? m.slice(slash + 1) : m;
}

export function matchModelEffort(model: string): ModelEffortProfile | null {
  const norm = normalizeModelId(model);
  if (!norm) return null;
  for (const p of MODEL_EFFORT_CATALOG) {
    if (p.patterns.some((pat) => norm.startsWith(pat) || norm.includes(pat))) {
      return p;
    }
  }
  return null;
}

export function resolveModelEffort(
  model: string,
  configured: string,
): { effort: string; source: 'custom' | 'catalog' | 'fallback'; profile: ModelEffortProfile | null } {
  const profile = matchModelEffort(model);
  const custom = configured.trim();
  if (custom) {
    return { effort: custom, source: 'custom', profile };
  }
  if (profile) {
    return { effort: profile.defaultEffort, source: 'catalog', profile };
  }
  return { effort: FALLBACK_EFFORT, source: 'fallback', profile: null };
}
