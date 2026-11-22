// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 种子数据（ENG §7）
 * --------------------------------------------------------------------------
 * 确定性：固定随机种子 + 以启动时刻为基准的固定偏移，重复 reset 得到同样的形状。
 *   用户   alice（admin，密码见启动日志）、bob（operator）、carol（viewer）、dave（待注册）
 *   插件   系统监控 / 安全防护 / 备份（含小组件、配置 schema、iframe 示例页）+ 内置 AI 助手
 *   动态   60 条历史操作；1 条 AI 待审批（创建用户）、1 条可达性审批（开启防火墙）
 *   Agent  2 个会话；AI 提供方 1 个；委托 1 个；审计 100 条
 * ========================================================================== */
import { randomBytes } from 'node:crypto';
import type { S } from './http.ts';
import { ACTIONS, AGENT, BACKUP, CONFIG_SCHEMAS, MONITOR, PLUGIN_SEEDS, SECURITY } from './catalog.ts';
import { changed, DEFAULT_FLAGS, deferExecute, nowIso, rev, type AgentSessionRow, type Db, type Op } from './store.ts';
import type { Plugin } from '../shell/src/api/additions.ts';

const MIN = 60_000;
const HOUR = 60 * MIN;

/** mulberry32：小而确定的 PRNG */
function prng(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function mockPassword(): string {
  return process.env.QWQ_MOCK_PASSWORD || randomBytes(9).toString('base64url');
}

export function seed(password: string): Db {
  const T = Math.floor(Date.now() / MIN) * MIN;
  const at = (ago: number) => nowIso(T - ago);
  const rnd = prng(20261109);
  let r = 0;
  const rv = () => `r${++r}`;

  const db: Db = {
    scenario: 'healthy',
    flags: { ...DEFAULT_FLAGS },
    password,
    setup: { initialized: true, token: 'qwq-setup-' + randomBytes(6).toString('hex'), tls_fingerprint: 'SHA256:4F:9A:21:7C:E0:5B:3D:88:12:AF:60:C4:9E:77:D2:0B' },
    users: new Map(),
    passwords: new Map(),
    sessions: new Map(),
    challenges: new Map(),
    enrollTokens: new Map(),
    totpPending: new Map(),
    delegations: new Map(),
    nodes: new Map(),
    plugins: new Map(),
    pluginConfigs: new Map(),
    pluginSchemas: new Map(Object.entries(CONFIG_SCHEMAS)),
    uploads: new Map(),
    actions: ACTIONS,
    operations: new Map(),
    approvals: new Map(),
    plans: new Map(),
    agentSessions: new Map(),
    agentMessages: new Map(),
    agentEvents: new Map(),
    agentClients: new Map(),
    providers: new Map(),
    audit: [],
    idem: new Map(),
    seq: 4200,
    ring: [],
    clients: new Set(),
    pending: new Map(),
    timers: new Set(),
    revCounter: 0,
    startedAt: T - 3 * 24 * HOUR - 5 * HOUR,
  };

  /* ---------------------------------------------------------------- 用户 */
  const user = (id: string, username: string, display_name: string, role: S['Role'], ago: number): S['User'] => ({
    user_id: id,
    username,
    display_name,
    role,
    mfa_enabled: false,
    disabled: false,
    created_at: at(ago),
    updated_at: at(ago),
    revision: rv(),
  });
  for (const u of [
    user('usr_alice', 'alice', 'Alice', 'admin', 40 * 24 * HOUR),
    user('usr_bob', 'bob', '小鲍', 'operator', 20 * 24 * HOUR),
    user('usr_carol', 'carol', 'Carol', 'viewer', 9 * 24 * HOUR),
    user('usr_dave', 'dave', 'Dave', 'operator', 2 * HOUR),
  ]) {
    db.users.set(u.user_id, u);
  }
  db.passwords.set('usr_alice', password);
  db.passwords.set('usr_bob', password);
  db.passwords.set('usr_carol', password);

  const alice = { kind: 'human', id: 'usr_alice', display_name: 'Alice' } as const satisfies S['Actor'];
  const ai = { kind: 'ai_agent', id: 'agt_native', on_behalf_of: 'usr_alice', display_name: 'AI 助手' } as const satisfies S['Actor'];
  const system = { kind: 'system', id: 'system', display_name: '系统' } as const satisfies S['Actor'];

  /* ---------------------------------------------------------------- 节点 */
  db.nodes.set('local', {
    node_id: 'local',
    name: '东京-01',
    status: 'online',
    last_seen_at: at(0),
    protocol_version: '1',
    reported: { hostname: 'tokyo-01', agent_version: '0.6.0', os: 'Debian GNU/Linux 12', arch: 'amd64' },
    created_at: at(40 * 24 * HOUR),
    revision: rv(),
  });

  /* ---------------------------------------------------------------- 插件 */
  for (const p of PLUGIN_SEEDS) {
    const installed = at(30 * 24 * HOUR);
    const version: S['PluginVersion'] = {
      plugin_id: p.id,
      version: p.version,
      digest: 'sha256:' + randomBytes(16).toString('hex'),
      status: 'ACTIVE',
      install_status: 'INSTALLED',
      active: true,
      installed_at: installed,
      activated_at: installed,
      revision: rv(),
    };
    const prev: S['PluginVersion'] = { ...version, version: p.version.replace(/\d+$/, (n) => String(Math.max(0, Number(n) - 1))), status: 'STOPPED', active: false, revision: rv() };
    const plugin: Plugin = {
      plugin_id: p.id,
      name: p.name,
      summary: p.summary,
      description: p.description,
      publisher_id: p.builtin ? 'qwq-builtin' : 'qwq',
      placement: p.placement,
      active_version: p.version,
      active_status: 'ACTIVE',
      install_status: 'INSTALLED',
      config_revision: rv(),
      versions: p.builtin ? [version] : [version, prev],
      created_at: installed,
      revision: rv(),
      icon_url: p.builtin ? undefined : `/plugin-ui/${p.id}/${p.version}/icon.svg`,
      homepage: 'https://qwq.dev/apps/' + p.id.split('.').pop(),
      license: 'Apache-2.0',
      builtin: p.builtin,
      has_config: p.id in CONFIG_SCHEMAS,
      capabilities: p.capabilities,
      operations: ACTIONS.filter((a) => a.plugin_id === p.id),
      dependencies: p.dependencies ?? [],
      resources: { memory_max_mb: 128, cpu_quota_percent: 50, pids_max: 64, fds_max: 256, disk_max_mb: 512 },
      runtime: { state: 'running', since: at(3 * 24 * HOUR), restarts: 0, memory_bytes: 18_000_000 + Math.floor(rnd() * 30_000_000), memory_max_bytes: 128 * 1024 * 1024 },
      ui: p.builtin
        ? undefined
        : {
            entry_url: `/plugin-ui/${p.id}/${p.version}/index.html`,
            routes: [{ path: '/', title: p.name, nav: p.nav, permission: 'host.plugins:read' }],
            widgets: p.widgets,
            connect_sources: [],
          },
    };
    db.plugins.set(p.id, plugin);
    if (p.id in CONFIG_SCHEMAS) {
      const config: Record<string, unknown> =
        p.id === MONITOR ? { interval_seconds: 5, retain_days: 7 } : p.id === SECURITY ? { ssh_port: 22, ban_threshold: 5, notify_token: { $secret: 'sec_notify' } } : { endpoint: 'https://s3.example.com', bucket: 'qwq-backup', access_key: { $secret: 'sec_s3' }, keep: 14 };
      db.pluginConfigs.set(p.id, { plugin_id: p.id, revision: plugin.config_revision, config, active: true, created_at: installed, applied_at: installed });
    }
  }

  /* ---------------------------------------------------------------- 历史操作 60 条 */
  const templates: [string, S['Actor'], Record<string, unknown>, S['Target']][] = [
    ['host.plugins.restart', alice, {}, { plugin_id: MONITOR }],
    [`${SECURITY}/ssh.ban_ip`, ai, { ip: '203.0.113.42', reason: '30 分钟内 12 次登录失败' }, { plugin_id: SECURITY, node_id: 'local' }],
    [`${BACKUP}/backup.run`, system, { trigger: 'schedule' }, { plugin_id: BACKUP }],
    ['host.users.update', alice, { username: 'bob', role: 'operator' }, { subject: 'users/usr_bob' }],
    ['host.plugins.configure', alice, { interval_seconds: 5 }, { plugin_id: MONITOR }],
    [`${SECURITY}/ssh.ban_ip`, system, { ip: '198.51.100.7', reason: '自动封禁' }, { plugin_id: SECURITY, node_id: 'local' }],
    ['host.delegations.create', alice, { label: 'Claude 桌面版' }, { subject: 'delegations/dlg_claude' }],
  ];
  for (let i = 0; i < 60; i++) {
    const [action, actor, args, target] = templates[Math.floor(rnd() * templates.length)]!;
    const ago = Math.floor((i + 1) * (7 * 24 * HOUR) / 60 + rnd() * 40 * MIN);
    const failed = rnd() < 0.08;
    const op: Op = {
      operation_id: `op_h${String(i).padStart(3, '0')}`,
      action,
      status: failed ? 'FAILED' : 'SUCCEEDED',
      target,
      actor,
      effective_risk: ACTIONS.find((a) => a.id === action)?.risk ?? 'low',
      attempt: 1,
      created_at: at(ago),
      updated_at: at(ago - 4000),
      finished_at: at(ago - 4000),
      revision: rv(),
      args,
      error: failed
        ? { type: 'about:blank', title: 'plugin error', status: 502, code: 'PLUGIN_ERROR', detail: 'nft: Could not process rule: No such file or directory', retryable: true, request_id: `req_h${i}` }
        : undefined,
    };
    db.operations.set(op.operation_id, op);
  }

  /* ---------------------------------------------------------------- 待审批 2 条 */
  const awaiting = (id: string, action: string, actor: S['Actor'], args: Record<string, unknown>, target: S['Target'], ago: number) => {
    const meta = ACTIONS.find((a) => a.id === action)!;
    const op: Op = {
      operation_id: id,
      action,
      status: 'AWAITING_APPROVAL',
      target,
      actor,
      effective_risk: meta.risk,
      approval_id: id.replace('op_', 'apr_'),
      attempt: 1,
      created_at: at(ago),
      updated_at: at(ago),
      revision: rv(),
      args,
    };
    db.operations.set(op.operation_id, op);
    db.approvals.set(op.approval_id!, {
      approval_id: op.approval_id!,
      operation_id: op.operation_id,
      status: 'PENDING',
      facts: {
        action: meta,
        args,
        target,
        node_name: '东京-01',
        required_capabilities: meta.plugin_id === SECURITY ? [{ name: 'firewall.manage', scope: 'nftables' }] : [],
        effect: meta.effect,
        declared_risk: meta.risk,
        effective_risk: meta.risk,
        reversible: Boolean(meta.undo),
        undo: meta.undo,
        requested_by: actor,
        approval_summary: meta.approval_summary,
        approval_description: meta.approval_description,
        permission_mode: 'safe',
      },
      requires_mfa: false,
      created_at: at(ago),
      expires_at: nowIso(T + 15 * MIN - ago),
      revision: rv(),
    });
  };
  awaiting('op_create_erin', 'host.users.create', ai, { username: 'erin', display_name: 'Erin', role: 'operator' }, { subject: 'users' }, 3 * MIN);
  awaiting('op_firewall', `${SECURITY}/firewall.enable`, ai, { default_policy: 'deny', allow: [22, 443] }, { plugin_id: SECURITY, node_id: 'local' }, 1 * MIN);

  /* ---------------------------------------------------------------- Agent 会话 2 个 */
  const session = (id: string, title: string, status: S['AgentSessionStatus'], pending: number, ago: number, preview: string): AgentSessionRow => ({
    session_id: id,
    plugin_id: AGENT,
    title,
    core: 'native',
    permission_mode: 'safe',
    status,
    config: { provider_id: 'aip_default' },
    has_api_key: false,
    last_seq: 0,
    pending_approvals: pending,
    last_message_at: at(ago),
    created_at: at(ago + 20 * MIN),
    updated_at: at(ago),
    revision: rv(),
    owner_id: 'usr_alice',
    last_message_preview: preview,
  });
  const s1 = session('ses_slow', '服务器为什么变慢了', 'waiting_approval', 1, 1 * MIN, '我准备开启防火墙，只放行 22 和 443，需要你确认。');
  const s2 = session('ses_team', '给小鲍的同事开账号', 'waiting_approval', 1, 3 * MIN, '我会创建用户 erin（运维），需要你确认。');
  for (const s of [s1, s2]) db.agentSessions.set(s.session_id, s);
  const msg = (sid: string, seq: number, role: S['AgentSessionMessage']['role'], content: string, ago: number, extra: Partial<S['AgentSessionMessage']> = {}): S['AgentSessionMessage'] => ({
    seq,
    message_id: `msg_${sid}_${seq}`,
    role,
    content,
    created_at: at(ago),
    ...extra,
  });
  db.agentMessages.set('ses_slow', [
    msg('ses_slow', 1, 'user', '服务器这两天好像变慢了，帮我看看？', 8 * MIN),
    msg('ses_slow', 2, 'assistant', '我先看一下系统指标。', 7 * MIN),
    msg('ses_slow', 3, 'tool', '读取 CPU 使用率：均值 23%，峰值 61%', 7 * MIN, { content_json: { action: `${MONITOR}/overview.cpu`, status: 'succeeded' } }),
    msg('ses_slow', 4, 'assistant', '资源占用正常。不过 SSH 日志里过去一小时有 **312 次**登录失败，来自 14 个 IP——这会拖慢 sshd。\n\n建议开启防火墙，只放行 SSH（22）与 HTTPS（443）。', 2 * MIN),
    msg('ses_slow', 5, 'tool', '开启防火墙：等待你批准', 1 * MIN, { approval_id: 'apr_firewall', operation_id: 'op_firewall', content_json: { action: `${SECURITY}/firewall.enable`, status: 'awaiting_approval' } }),
  ]);
  db.agentMessages.set('ses_team', [
    msg('ses_team', 1, 'user', '帮我给 erin 开个运维账号', 5 * MIN),
    msg('ses_team', 2, 'assistant', '好的，我会创建用户 erin，角色为运维（operator）。创建后会生成一次性注册链接。', 4 * MIN),
    msg('ses_team', 3, 'tool', '创建用户：等待你批准', 3 * MIN, { approval_id: 'apr_create_erin', operation_id: 'op_create_erin', content_json: { action: 'host.users.create', status: 'awaiting_approval' } }),
  ]);
  for (const [sid, list] of db.agentMessages) {
    db.agentSessions.get(sid)!.last_seq = list.length;
    db.agentEvents.set(sid, []);
  }

  /* ---------------------------------------------------------------- AI 提供方、委托 */
  db.providers.set('aip_default', {
    provider_id: 'aip_default',
    name: 'OpenAI 兼容服务',
    kind: 'openai_compatible',
    base_url: 'https://api.example.com/v1',
    model: 'gpt-4o-mini',
    has_api_key: true,
    is_default: true,
    created_at: at(20 * 24 * HOUR),
    updated_at: at(20 * 24 * HOUR),
    revision: rv(),
    api_key: 'sk-mock',
  });
  db.delegations.set('dlg_claude', {
    delegation_id: 'dlg_claude',
    label: 'Claude 桌面版',
    owner_id: 'usr_alice',
    policy: { auto_approve_max_risk: 'low', on_approval_required: 'queue', requests_per_minute: 60 },
    status: 'active',
    token_prefix: 'qwq_dlg_7Hk2',
    last_used_at: at(26 * HOUR),
    created_at: at(12 * 24 * HOUR),
    expires_at: nowIso(T + 18 * 24 * HOUR),
    revision: rv(),
  });

  /* ---------------------------------------------------------------- 审计 100 条 */
  const auditActions = ['session.login', 'host.plugins.restart', 'host.users.update', `${SECURITY}/ssh.ban_ip`, 'session.login', 'host.delegations.create', 'approval.decide'];
  for (let i = 0; i < 100; i++) {
    const action = auditActions[Math.floor(rnd() * auditActions.length)]!;
    const who = action === `${SECURITY}/ssh.ban_ip` ? (rnd() < 0.5 ? ai : system) : alice;
    const fail = action === 'session.login' && rnd() < 0.25;
    db.audit.push({
      audit_id: `aud_${String(i).padStart(3, '0')}`,
      at: at(Math.floor((i + 1) * 70 * MIN + rnd() * 20 * MIN)),
      actor: fail ? { kind: 'human', id: 'unknown', display_name: '未知用户' } : who,
      action,
      subject: action === 'session.login' ? 'sessions' : action.startsWith('host.users') ? 'users/usr_bob' : `plugins/${SECURITY}`,
      outcome: fail ? (rnd() < 0.5 ? 'failure' : 'denied') : 'success',
      request_id: `req_a${i.toString(36)}`,
      node_id: 'local',
      detail: fail ? { reason: 'bad_password', remote: '203.0.113.' + Math.floor(rnd() * 250) } : undefined,
    });
  }

  db.revCounter = r;

  /* 种子审批批准后的效果 */
  deferExecute(db, db.operations.get('op_create_erin')!, () => {
    const u = user('usr_erin', 'erin', 'Erin', 'operator', 0);
    u.revision = rev(db);
    db.users.set(u.user_id, u);
    changed(db, 'users/usr_erin', 'create', ai, { revision: u.revision, operationId: 'op_create_erin' });
    return { user: u, enrollment_pending: true, enrollment_expires_at: nowIso(Date.now() + 24 * HOUR) };
  });
  deferExecute(db, db.operations.get('op_firewall')!, () => ({ enabled: true, default_policy: 'deny', allow: [22, 443] }));
  return db;
}
