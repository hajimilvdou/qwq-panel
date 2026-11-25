// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 主流 AI 模型上下文窗口自动匹配清单（与后端 internal/agentsession/context_catalog.go 1:1 对齐）
 * --------------------------------------------------------------------------
 *   - 当 max_context_tokens === 0 时，根据模型名自动选择该模型的官方上下文窗口大小；
 *   - 支持显式后缀识别（如 claude-sonnet-4-5[1m]、local-64k）；
 *   - 未命中清单时默认兜底 128K；用户随时可手动点选或填写自定义数字覆盖。
 * ========================================================================== */

export const DEFAULT_FALLBACK_CONTEXT_TOKENS = 128_000;

export interface ModelContextProfile {
  readonly family: string;
  readonly patterns: readonly string[];
  readonly contextTokens: number;
  readonly label: string;
  readonly notes: string;
}

export const MODEL_CONTEXT_CATALOG: readonly ModelContextProfile[] = [
  {
    family: 'OpenAI GPT-5.3 / 5.4',
    patterns: ['gpt-5.4', 'gpt-5.3'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: 'GPT-5.3 / GPT-5.4 原生 1M 上下文',
  },
  {
    family: 'OpenAI GPT-5 / 5.1 / 5.2 / Codex',
    patterns: ['gpt-5.2', 'gpt-5.1', 'gpt-5-codex', 'gpt-5-pro', 'gpt-5-mini', 'gpt-5-nano', 'gpt-5', 'codex-max', 'codex-mini', 'codex'],
    contextTokens: 400_000,
    label: '400K',
    notes: 'GPT-5 / 5.1 / 5.2 / Codex 官方 400K 上下文',
  },
  {
    family: 'OpenAI GPT-4.1',
    patterns: ['gpt-4.1-mini', 'gpt-4.1-nano', 'gpt-4.1'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: 'GPT-4.1 全系（含 mini / nano）官方 1M 上下文',
  },
  {
    family: 'OpenAI o1 / o3 / o4-mini',
    patterns: ['o4-mini', 'o3-pro', 'o3-mini', 'o3', 'o1-pro', 'o1'],
    contextTokens: 200_000,
    label: '200K',
    notes: 'OpenAI o1 / o3 / o4-mini 官方 200K 上下文',
  },
  {
    family: 'OpenAI GPT-4o / o1-mini / GPT-4 Turbo',
    patterns: ['o1-mini', 'gpt-4o', 'chatgpt-4o', 'gpt-4-turbo'],
    contextTokens: 128_000,
    label: '128K',
    notes: 'GPT-4o / o1-mini / GPT-4 Turbo 官方 128K 上下文',
  },
  {
    family: 'Anthropic Claude 4.6+ / 5',
    patterns: [
      'claude-opus-4-7', 'claude-opus-4.7',
      'claude-opus-4-6', 'claude-opus-4.6', 'claude-4-6-opus',
      'claude-sonnet-4-6', 'claude-sonnet-4.6', 'claude-4-6-sonnet',
      'claude-opus-5', 'claude-sonnet-5', 'claude-5',
    ],
    contextTokens: 1_000_000,
    label: '1M',
    notes: 'Claude 4.6+ / 5 支持 1M 上下文（标准通道可手动改 200K）',
  },
  {
    family: 'Anthropic Claude 3.5 / 3.7 / 4 / 4.5 / Haiku 4',
    patterns: [
      'claude-sonnet-4-5', 'claude-sonnet-4.5', 'claude-4-5-sonnet',
      'claude-opus-4-5', 'claude-opus-4.5', 'claude-4-5-opus',
      'claude-opus-4-1', 'claude-opus-4.1',
      'claude-sonnet-4', 'claude-opus-4', 'claude-haiku-4',
      'claude-4-sonnet', 'claude-4-opus', 'claude-4-haiku',
      'claude-3-7', 'claude-3.7', 'claude-3-5', 'claude-3.5', 'claude-3',
    ],
    contextTokens: 200_000,
    label: '200K',
    notes: 'Claude 3.5 / 3.7 / 4 / 4.5 / Haiku 4 标准 200K 上下文',
  },
  {
    family: 'Google Gemini 1.5 Pro',
    patterns: ['gemini-1.5-pro', 'gemini-1-5-pro'],
    contextTokens: 2_000_000,
    label: '2M',
    notes: 'Gemini 1.5 Pro 支持 2M 上下文',
  },
  {
    family: 'Google Gemini 2.0 / 2.5 / 3 / 3.1 / 4',
    patterns: ['gemini-4', 'gemini-3.1', 'gemini-3', 'gemini-2.5', 'gemini-2-5', 'gemini-2.0', 'gemini-2-0', 'gemini-1.5-flash', 'gemini-exp'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: 'Gemini 2.0 / 2.5 / 3 / 3.1 / 4 全系 1M 上下文',
  },
  {
    family: 'DeepSeek V4',
    patterns: ['deepseek-v4'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: 'DeepSeek V4 长上下文 1M',
  },
  {
    family: 'DeepSeek V3 / V3.2 / R1',
    patterns: ['deepseek-v3.2', 'deepseek-v3.1', 'deepseek-v3', 'deepseek-r1', 'deepseek-reasoner', 'deepseek-chat', 'deepseek'],
    contextTokens: 128_000,
    label: '128K',
    notes: 'DeepSeek V3 / V3.2 / R1 官方 API 128K 上下文',
  },
  {
    family: 'Alibaba Qwen Long / Qwen2.5-1M',
    patterns: ['qwen-long', 'qwen2.5-1m', 'qwen-2.5-1m'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: '通义千问 Qwen-Long / Qwen2.5-1M 1M 上下文',
  },
  {
    family: 'Alibaba Qwen3 Coder / Max / Plus / 3.5',
    patterns: ['qwen3-coder', 'qwen3-max', 'qwen3-plus', 'qwen3.5', 'qwen-3.5'],
    contextTokens: 262_144,
    label: '256K',
    notes: '通义千问 Qwen3-Coder / Max / Plus / 3.5 原生 256K',
  },
  {
    family: 'Alibaba Qwen3 / QwQ / Qwen2.5',
    patterns: ['qwen3', 'qwen-3', 'qwq', 'qwen2.5', 'qwen-plus', 'qwen-turbo', 'qwen-max'],
    contextTokens: 131_072,
    label: '128K',
    notes: '通义千问 Qwen3 / QwQ / Qwen2.5 标准 128K',
  },
  {
    family: 'xAI Grok 4.1 / 4.20 / 4 Fast',
    patterns: ['grok-4.20', 'grok-4.2', 'grok-4.1', 'grok-4-fast', 'grok-code-fast'],
    contextTokens: 2_000_000,
    label: '2M',
    notes: 'xAI Grok 4.1 / 4.20 / 4 Fast 官方 2M 上下文',
  },
  {
    family: 'xAI Grok 4',
    patterns: ['grok-4'],
    contextTokens: 256_000,
    label: '256K',
    notes: 'xAI Grok 4 标准 256K 上下文',
  },
  {
    family: 'xAI Grok 3 / Grok 2',
    patterns: ['grok-3', 'grok-2'],
    contextTokens: 131_072,
    label: '128K',
    notes: 'xAI Grok 3 / Grok 2 标准 128K 上下文',
  },
  {
    family: 'Zhipu GLM-4-Long',
    patterns: ['glm-4-long'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: '智谱 GLM-4-Long 1M 上下文',
  },
  {
    family: 'Zhipu GLM-5 / GLM-4.7 / GLM-4.6',
    patterns: ['glm-5', 'glm-4.7', 'glm-4.6'],
    contextTokens: 200_000,
    label: '200K',
    notes: '智谱 GLM-5 / GLM-4.7 / GLM-4.6 官方 200K 上下文',
  },
  {
    family: 'Zhipu GLM-4.5 / GLM-4 / GLM-Z1',
    patterns: ['glm-4.5', 'glm-4', 'glm-z1'],
    contextTokens: 128_000,
    label: '128K',
    notes: '智谱 GLM-4.5 / GLM-4 / GLM-Z1 标准 128K 上下文',
  },
  {
    family: 'Moonshot Kimi K3',
    patterns: ['kimi-k3'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: '月之暗面 Kimi K3 长上下文 1M',
  },
  {
    family: 'Moonshot Kimi K2 / K2.5 / K2.6',
    patterns: ['kimi-k2.6', 'kimi-k2.5', 'kimi-k2'],
    contextTokens: 262_144,
    label: '256K',
    notes: '月之暗面 Kimi K2 / K2.5 / K2.6 官方 256K 上下文',
  },
  {
    family: 'Moonshot v1-128k',
    patterns: ['moonshot-v1-128k'],
    contextTokens: 128_000,
    label: '128K',
    notes: 'Moonshot v1 128K',
  },
  {
    family: 'Moonshot v1-32k',
    patterns: ['moonshot-v1-32k'],
    contextTokens: 32_768,
    label: '32K',
    notes: 'Moonshot v1 32K',
  },
  {
    family: 'Moonshot v1-8k',
    patterns: ['moonshot-v1-8k'],
    contextTokens: 8_192,
    label: '8K',
    notes: 'Moonshot v1 8K',
  },
  {
    family: 'MiniMax M1 / M3',
    patterns: ['minimax-m3', 'minimax-m1'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: 'MiniMax M1 / M3 原生 1M 上下文',
  },
  {
    family: 'MiniMax M2 / M2.5',
    patterns: ['minimax-m2.5', 'minimax-m2'],
    contextTokens: 204_800,
    label: '200K',
    notes: 'MiniMax M2 / M2.5 官方 200K 上下文',
  },
  {
    family: 'Doubao Seed / 1.5 / 1.6',
    patterns: ['doubao-seed', 'doubao-1.6', 'doubao-1.5', 'doubao-pro'],
    contextTokens: 256_000,
    label: '256K',
    notes: '字节豆包 Seed / 1.5 / 1.6 官方 256K 上下文',
  },
  {
    family: 'Meta Llama 4 Scout',
    patterns: ['llama-4-scout', 'llama4-scout'],
    contextTokens: 10_000_000,
    label: '10M',
    notes: 'Meta Llama 4 Scout 最高 10M 上下文',
  },
  {
    family: 'Meta Llama 4 Maverick',
    patterns: ['llama-4-maverick', 'llama4-maverick', 'llama-4', 'llama4'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: 'Meta Llama 4 Maverick 1M 上下文',
  },
  {
    family: 'Meta Llama 3.1 / 3.2 / 3.3',
    patterns: ['llama-3.3', 'llama-3.2', 'llama-3.1', 'llama3.3', 'llama3.2', 'llama3.1'],
    contextTokens: 128_000,
    label: '128K',
    notes: 'Meta Llama 3.1 / 3.2 / 3.3 标准 128K 上下文',
  },
  {
    family: 'Mistral Large 4',
    patterns: ['mistral-large-4'],
    contextTokens: 1_000_000,
    label: '1M',
    notes: 'Mistral Large 4 1M 上下文',
  },
  {
    family: 'Mistral Codestral / Devstral',
    patterns: ['codestral', 'devstral'],
    contextTokens: 256_000,
    label: '256K',
    notes: 'Mistral Codestral / Devstral 256K 上下文',
  },
  {
    family: 'Mistral Large / Medium / Magistral',
    patterns: ['mistral-large', 'mistral-medium', 'mistral-small', 'magistral', 'mistral-nemo', 'pixtral'],
    contextTokens: 128_000,
    label: '128K',
    notes: 'Mistral 系列标准 128K 上下文',
  },
];

export const CONTEXT_PRESETS = [
  { tokens: 32_768, label: '32K' },
  { tokens: 65_536, label: '64K' },
  { tokens: 128_000, label: '128K' },
  { tokens: 200_000, label: '200K' },
  { tokens: 256_000, label: '256K' },
  { tokens: 400_000, label: '400K' },
  { tokens: 512_000, label: '512K' },
  { tokens: 1_000_000, label: '1M' },
  { tokens: 2_000_000, label: '2M' },
] as const;

function normalizeModelId(model: string): string {
  const m = model.trim().toLowerCase();
  const idx = m.lastIndexOf('/');
  return idx >= 0 && idx < m.length - 1 ? m.slice(idx + 1) : m;
}

const BOUNDARY = new Set(['-', '_', '.', ':', '/']);
function matchesPattern(norm: string, pat: string): boolean {
  if (!pat) return false;
  if (pat.length <= 2) {
    let start = 0;
    while (start < norm.length) {
      const idx = norm.indexOf(pat, start);
      if (idx < 0) return false;
      const end = idx + pat.length;
      const leftOk = idx === 0 || BOUNDARY.has(norm[idx - 1]!);
      const rightOk = end === norm.length || BOUNDARY.has(norm[end]!);
      if (leftOk && rightOk) return true;
      start = idx + 1;
    }
    return false;
  }
  return norm.startsWith(pat) || norm.includes(pat);
}

const EXPLICIT_SUFFIX_RE = /(?:\[(\d+)([km])\]|(?:^|[-_:.])(\d+)([km])(?:$|[-_:.]))/gi;

function parseExplicitModelContext(norm: string): number | null {
  EXPLICIT_SUFFIX_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = EXPLICIT_SUFFIX_RE.exec(norm)) !== null) {
    const numStr = match[1] || match[3] || '';
    const unit = (match[2] || match[4] || '').toLowerCase();
    const n = Number.parseInt(numStr, 10);
    if (!Number.isFinite(n) || n <= 0) continue;
    let tokens = 0;
    if (unit === 'k' && n >= 4 && n <= 4096) tokens = n * 1000;
    else if (unit === 'm' && n >= 1 && n <= 10) tokens = n * 1_000_000;
    if (tokens >= 1024 && tokens <= 10_000_000) return tokens;
  }
  return null;
}

export function formatContextTokens(tokens: number): string {
  if (!Number.isFinite(tokens) || tokens <= 0) return '自动';
  if (tokens >= 1_000_000) {
    return tokens % 1_000_000 === 0 ? `${tokens / 1_000_000}M` : `${(tokens / 1_000_000).toFixed(1)}M`;
  }
  const exactMap: Record<number, string> = {
    8192: '8K',
    16384: '16K',
    32768: '32K',
    65536: '64K',
    131072: '128K',
    204800: '200K',
    262144: '256K',
    524288: '512K',
  };
  if (exactMap[tokens]) return exactMap[tokens]!;
  if (tokens >= 1000) return `${Math.round(tokens / 1000)}K`;
  return String(tokens);
}

export function matchModelContextProfile(model: string): ModelContextProfile | null {
  const norm = normalizeModelId(model);
  if (!norm) return null;
  if (norm.includes('[')) {
    const explicit = parseExplicitModelContext(norm);
    if (explicit) {
      return {
        family: '模型标注上下文',
        patterns: [],
        contextTokens: explicit,
        label: formatContextTokens(explicit),
        notes: '根据模型名中的显式上下文标记自动识别',
      };
    }
  }
  for (const profile of MODEL_CONTEXT_CATALOG) {
    if (profile.patterns.some((pat) => matchesPattern(norm, pat))) {
      return profile;
    }
  }
  const explicit = parseExplicitModelContext(norm);
  if (explicit) {
    return {
      family: '模型后缀识别',
      patterns: [],
      contextTokens: explicit,
      label: formatContextTokens(explicit),
      notes: '根据模型名称后缀自动识别上下文窗口',
    };
  }
  return null;
}

export interface ResolvedModelContext {
  readonly tokens: number;
  readonly label: string;
  readonly source: 'custom' | 'catalog' | 'fallback';
  readonly profile: ModelContextProfile | null;
}

export function resolveModelContext(model: string, configured: string | number): ResolvedModelContext {
  const profile = matchModelContextProfile(model);
  const num = typeof configured === 'number' ? configured : Number.parseInt(String(configured || '').trim(), 10) || 0;
  if (num > 0) {
    return { tokens: num, label: formatContextTokens(num), source: 'custom', profile };
  }
  if (profile) {
    return { tokens: profile.contextTokens, label: profile.label, source: 'catalog', profile };
  }
  return {
    tokens: DEFAULT_FALLBACK_CONTEXT_TOKENS,
    label: formatContextTokens(DEFAULT_FALLBACK_CONTEXT_TOKENS),
    source: 'fallback',
    profile: null,
  };
}
