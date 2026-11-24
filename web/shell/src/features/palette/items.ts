// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * ⌘K 面板的条目模型（纯逻辑：页面目录、匹配、最近使用、键盘游标）
 * --------------------------------------------------------------------------
 * 分组顺序（SPEC §5）：页面 → 操作 → 最近 → 末项"问 AI：{输入}"。
 * 匹配：忽略大小写与空白的子串匹配，标签命中优先于关键词命中。
 * ========================================================================== */
import type { ActionMeta } from '$api/additions';
import type { IconName } from '$ui';

export type PaletteItem =
  | { kind: 'page'; id: string; label: string; href: string; icon: IconName; keywords?: string }
  | { kind: 'action'; id: string; label: string; action: ActionMeta }
  | { kind: 'ask'; id: 'ask'; label: string; prompt: string };

export interface PaletteGroup {
  title: string;
  items: PaletteItem[];
}

/** 官方插件中英文检索关键词索引，确保在 ⌘K 输入英文缩写/协议名能直接命中中文插件页 */
export const OFFICIAL_PLUGIN_SEARCH_KEYWORDS: Readonly<Record<string, string>> = {
  'security.basic': 'security firewall ssh nftables ban 防火墙 安全 防爆破',
  'monitor.basic': 'monitor cpu memory disk load 监控 负载 性能',
  'server.probe': 'probe status ping sla uptime 探针 延迟 在线率 监控墙',
  'domain.dns': 'dns cloudflare aliyun dnspod domain 域名 解析 记录',
  'tls.certificates': 'tls ssl https cert acme letsencrypt 证书 续期 泛域名',
  'core.xray': 'xray vless vmess trojan shadowsocks hysteria2 anytls warp 核心 协议',
  'proxy.advanced': 'proxy node sub clash singbox v2ray reality warp 代理 节点 订阅 分流',
  'web.ingress': 'ingress nginx caddy reverse proxy site static 反代 建站 网关 网站',
  'containers.docker': 'docker container compose image volume 容器 镜像 编排',
  'ai.relay': 'ai relay oneapi newapi openai claude gemini token 中转 渠道 额度',
  'notify.hub': 'notify alert telegram webhook smtp feishu dingtalk 告警 通知 机器人',
};

const norm = (s: string) => s.toLowerCase().replace(/\s+/g, '');

/** 0 = 不匹配；2 = 标签命中；1 = 关键词命中 */
export function score(item: { label: string; keywords?: string }, q: string): number {
  const n = norm(q);
  if (!n) return 1;
  if (norm(item.label).includes(n)) return 2;
  return item.keywords && norm(item.keywords).includes(n) ? 1 : 0;
}

export function filterPages<T extends { label: string; keywords?: string }>(pages: readonly T[], q: string, max?: number): T[] {
  const ranked = pages
    .map((p, i) => ({ p, s: score(p, q), i }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || a.i - b.i)
    .map((x) => x.p);
  const limit = max ?? (norm(q) ? 12 : ranked.length);
  return ranked.slice(0, limit);
}

/** 组装分组；最近项去掉已出现在上面的；有权限时问 AI 永远在末尾 */
export function buildGroups(input: {
  q: string;
  pages: readonly Extract<PaletteItem, { kind: 'page' }>[];
  actions: readonly ActionMeta[];
  recent: readonly PaletteItem[];
  canAsk?: boolean;
}): PaletteGroup[] {
  const { q, canAsk = true } = input;
  const pages = filterPages(input.pages, q);
  const actions: PaletteItem[] = input.actions.map((a) => ({ kind: 'action', id: 'action:' + a.id, label: a.summary || a.id, action: a }));
  const shown = new Set([...pages, ...actions].map((x) => x.id));
  const recent = input.recent.filter((r) => r.kind !== 'ask' && !shown.has(r.id) && score(r, q) > 0).slice(0, 4);
  const trimmed = q.trim();
  const groups: PaletteGroup[] = [
    { title: '页面', items: pages },
    { title: '操作', items: actions },
    { title: '最近', items: recent },
    ...(canAsk ? [{ title: 'AI', items: [{ kind: 'ask' as const, id: 'ask' as const, label: trimmed ? `问 AI：${trimmed}` : '问 AI', prompt: trimmed }] }] : []),
  ];
  return groups.filter((g) => g.items.length);
}

/** ↑↓ 循环移动游标 */
export function moveCursor(cur: number, delta: number, count: number): number {
  if (!count) return 0;
  return (((cur + delta) % count) + count) % count;
}

/* ------------------------------------------------------------------ 最近使用 */

const RECENT_KEY = 'qwq.palette.recent';
const RECENT_MAX = 8;

function recentStorageKey(userId?: string | null): string {
  const clean = typeof userId === 'string' ? userId.trim() : '';
  return clean ? `${RECENT_KEY}.${clean}` : RECENT_KEY;
}

/** 只存可序列化的最小信息；操作项只存 id/summary（详情选中时再取） */
export function pushRecent(list: readonly PaletteItem[], item: PaletteItem): PaletteItem[] {
  if (item.kind === 'ask') return [...list];
  return [item, ...list.filter((x) => x.id !== item.id)].slice(0, RECENT_MAX);
}

export function loadRecent(userId?: string | null): PaletteItem[] {
  try {
    const v = JSON.parse(localStorage.getItem(recentStorageKey(userId)) ?? '[]') as PaletteItem[];
    return Array.isArray(v) ? v.filter((x) => x && (x.kind === 'page' || x.kind === 'action')) : [];
  } catch {
    return [];
  }
}

export function saveRecent(list: readonly PaletteItem[], userId?: string | null): void {
  try {
    localStorage.setItem(recentStorageKey(userId), JSON.stringify(list));
  } catch {
    /* 忽略 */
  }
}

/* ------------------------------------------------------------------ 定级展示 */

/**
 * 人发起时会不会进审批（契约 §5.3，非 AI 调用者固定 safe + auto_approve_max_risk=low）：
 * destructive、风险 ≥ medium、或插件声明 confirm → 执行后进悬浮窗确认（需要 MFA 时另提示）。
 */
export function gradeOf(a: Pick<ActionMeta, 'effect' | 'risk' | 'approval'>): { label: string; needsApproval: boolean } {
  if (a.effect === 'read' && a.risk !== 'high') return { label: '只读，直接执行', needsApproval: false };
  if (a.effect === 'destructive') return { label: '破坏性操作，需确认并输入验证码', needsApproval: true };
  if (a.approval === 'confirm' || a.risk !== 'low') return { label: '提交后需要确认', needsApproval: true };
  return { label: '直接执行', needsApproval: false };
}
