<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置 · 系统（SPEC §7 / GAPS 缺口 7，host.system:read）
  版本、运行角色、TLS 状态与指纹、面板入口安全设置（端口、密道、伪装页、反代域名自动免密道）。
-->
<script lang="ts">
  import { Alert, Button, Card, Chip, CopyButton, Dialog, ErrorState, Input, OtpInput, Select, Skeleton, Switch } from '$ui';
  import type { DisguiseMode, PanelAccessSettings, PanelAccessUpdateRequest } from '$api/additions';
  import { system } from '$api/endpoints';
  import { describeError } from '$lib/errors';
  import { dateTime, relativeTime } from '$lib/format';
  import { useResource } from '$lib/resource.svelte';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';

  const info = useResource({ key: 'system.info', load: () => system.info() });
  const isAdmin = $derived(session.user?.role === 'admin');
  const access = useResource<PanelAccessSettings | null>({
    key: 'system.access',
    load: () => (isAdmin ? system.access() : Promise.resolve(null)),
  });

  const ROLE: Record<string, string> = { standalone: '单机', controller: '控制节点', agent: '被控节点' };
  const TLS: Record<string, string> = { self_signed: '自签名证书', acme: '自动签发（ACME）', proxy: '由反向代理终止' };
  const BYPASS_REASON: Record<string, string> = {
    panel_domain: '已配置面板反代域名',
    tls_proxy: '当前处于反向代理 TLS 模式',
    public_origin: '已配置公开域名来源',
  };
  const DISGUISE_OPTIONS: readonly { value: DisguiseMode; label: string }[] = [
    { value: 'drop', label: '无服务断连伪装（推荐 · 模拟未开放端口，F12 无状态码与响应头）' },
    { value: 'nginx_404', label: '伪装标准 Nginx 404（无面板指纹头）' },
    { value: 'nginx_403', label: '伪装标准 Nginx 403（无面板指纹头）' },
    { value: 'blank_404', label: '空白 404（零响应体、无面板指纹头）' },
    { value: 'custom_html', label: '自定义静态伪装页 HTML' },
  ];
  const BASE_LISTEN_OPTIONS: readonly { value: string; label: string }[] = [
    { value: '127.0.0.1', label: '127.0.0.1（仅本机 SSH 隧道 / 本机反向代理）' },
    { value: '0.0.0.0', label: '0.0.0.0（开放 IPv4 公网直连与订阅访问）' },
    { value: '::', label: '::（开放 IPv4 + IPv6 双栈公网直连）' },
  ];

  let listenHost = $state('127.0.0.1');
  let portText = $state('');
  let entryPath = $state('');
  let disguise = $state<DisguiseMode>('drop');
  let disguiseHtml = $state('');
  let panelDomain = $state('');
  let autoDisableOnDomain = $state(true);
  let syncedRevision = $state<number | null>(null);
  let saving = $state(false);
  let saveError = $state('');
  let reboundUrl = $state('');

  /* 两步验证弹窗状态（修改面板监听入口触发 MFA_REQUIRED 时弹出） */
  let mfaOpen = $state(false);
  let mfaUseRecovery = $state(false);
  let mfaCode = $state('');
  let mfaErr = $state('');
  let pendingBody = $state<PanelAccessUpdateRequest | null>(null);

  const listenOptions = $derived.by(() => {
    if (BASE_LISTEN_OPTIONS.some((o) => o.value === listenHost) || !listenHost) return BASE_LISTEN_OPTIONS;
    return [...BASE_LISTEN_OPTIONS, { value: listenHost, label: `${listenHost}（自定义网卡地址）` }];
  });

  /** 检测服务器时钟与本地浏览器偏差（>30s 时提示同步 NTP，防 TOTP 与 Reality 失灵） */
  const clockDriftSec = $derived.by(() => {
    const st = info.data?.server_time;
    if (!st) return 0;
    const ms = Date.parse(st);
    if (!Number.isFinite(ms)) return 0;
    return Math.round(Math.abs(ms - Date.now()) / 1000);
  });

  $effect(() => {
    const a = access.data;
    if (!a || syncedRevision === a.revision) return;
    syncedRevision = a.revision;
    listenHost = a.listen_host || '127.0.0.1';
    portText = String(a.port);
    entryPath = a.entry_path;
    disguise = a.disguise;
    disguiseHtml = a.disguise_html;
    panelDomain = a.panel_domain;
    autoDisableOnDomain = a.auto_disable_on_domain;
  });

  const willAutoBypass = $derived(
    autoDisableOnDomain &&
      (panelDomain.trim() !== '' ||
        access.data?.tls_mode === 'proxy' ||
        access.data?.bypass_reason === 'public_origin'),
  );

  function buildReboundPanelUrl(opts: {
    panelDomain: string;
    autoDisableOnDomain: boolean;
    listenHost: string;
    port: number;
    effectiveEntryPath: string;
  }): string {
    const dom = opts.panelDomain.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    const curProto = typeof location !== 'undefined' ? location.protocol : 'https:';
    const curHost = typeof location !== 'undefined' ? location.hostname : '';
    const curPort = typeof location !== 'undefined' ? location.port : '';
    if (dom && curHost === dom && curPort === '') {
      return opts.effectiveEntryPath && !opts.autoDisableOnDomain
        ? `https://${dom}/${opts.effectiveEntryPath}`
        : `https://${dom}/`;
    }
    let rawHost = dom || curHost || opts.listenHost || '127.0.0.1';
    if (rawHost === '0.0.0.0' || rawHost === '::') {
      rawHost = curHost || '127.0.0.1';
    }
    const bracketedHost = rawHost.includes(':') && !rawHost.startsWith('[') ? `[${rawHost}]` : rawHost;
    const base = `${curProto}//${bracketedHost}:${opts.port}`;
    return opts.effectiveEntryPath ? `${base}/${opts.effectiveEntryPath}` : `${base}/`;
  }

  const previewUrl = $derived.by(() => {
    const dom = panelDomain.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    const cleanPath = entryPath.trim().replace(/^\/+|\/+$/g, '');
    if (dom && autoDisableOnDomain) {
      return `https://${dom}/`;
    }
    const proto = access.data?.tls_mode === 'proxy' ? 'http:' : (typeof location !== 'undefined' ? location.protocol : 'https:');
    const rawHost = dom || (typeof location !== 'undefined' ? location.hostname : listenHost || '127.0.0.1');
    const host = rawHost.includes(':') && !rawHost.startsWith('[') ? `[${rawHost}]` : rawHost;
    const port = portText.trim() || String(access.data?.port ?? 8443);
    const origin = `${proto}//${host}:${port}`;
    return cleanPath && !willAutoBypass ? `${origin}/${cleanPath}` : `${origin}/`;
  });

  const rescueUrl = $derived.by(() => {
    const cleanPath = entryPath.trim().replace(/^\/+|\/+$/g, '');
    const proto = access.data?.tls_mode === 'proxy' ? 'http:' : 'https:';
    const port = portText.trim() || String(access.data?.port ?? 8443);
    return cleanPath ? `${proto}//<服务器IP>:${port}/${cleanPath}` : `${proto}//<服务器IP>:${port}/`;
  });

  function randomHighPort() {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    portText = String(20000 + ((buf[0] ?? 0) % 40000));
  }

  function randomEntryPath() {
    const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
    const buf = new Uint8Array(10);
    crypto.getRandomValues(buf);
    entryPath = Array.from(buf, (b) => chars[b % chars.length]).join('');
  }

  async function submitAccess(body: PanelAccessUpdateRequest, code?: string) {
    saving = true;
    saveError = '';
    mfaErr = '';
    try {
      const updated = await system.updateAccess(body, code);
      mfaOpen = false;
      mfaCode = '';
      pendingBody = null;
      syncedRevision = null;
      await Promise.all([access.refresh(), info.refresh()]);
      toasts.success(updated.port_changed ? `面板监听地址已热切换至 ${updated.listen}` : '面板入口与伪装设置已生效');
      if (updated.port_changed) {
        reboundUrl = buildReboundPanelUrl({
          panelDomain: updated.panel_domain,
          autoDisableOnDomain: updated.auto_disable_on_domain,
          listenHost: updated.listen_host,
          port: updated.port,
          effectiveEntryPath: updated.effective_entry_path,
        });
      }
    } catch (err) {
      const v = describeError(err);
      if (v.code === 'MFA_REQUIRED') {
        pendingBody = body;
        if (!mfaOpen) {
          mfaOpen = true;
          mfaUseRecovery = false;
          mfaCode = '';
          mfaErr = '';
        } else {
          mfaErr = v.message || '两步验证码不正确或已过期，请重试';
        }
      } else {
        mfaOpen = false;
        saveError = v.message;
      }
    } finally {
      saving = false;
    }
  }

  async function saveAccess(e: SubmitEvent) {
    e.preventDefault();
    if (!access.data || saving) return;
    saveError = '';
    reboundUrl = '';
    const parsedPort = Number.parseInt(portText.trim(), 10);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      saveError = '监听端口必须是 1 ~ 65535 之间的整数';
      return;
    }
    const body: PanelAccessUpdateRequest = {
      listen_host: listenHost,
      port: parsedPort,
      entry_path: entryPath.trim().replace(/^\/+|\/+$/g, ''),
      disguise,
      disguise_html: disguiseHtml,
      panel_domain: panelDomain.trim(),
      auto_disable_on_domain: autoDisableOnDomain,
      expected_revision: access.data.revision,
    };
    await submitAccess(body);
  }

  function submitMfa(code?: string) {
    const val = (code ?? mfaCode).trim();
    if (!pendingBody || !val || saving) return;
    void submitAccess(pendingBody, val);
  }
</script>

{#if info.status === 'loading'}
  <Card title="系统" icon="cpu" color="slate"><Skeleton lines={5} height={16} /></Card>
{:else if info.status === 'error' && !info.data}
  <Card title="系统" icon="cpu" color="slate">
    <ErrorState compact message={describeError(info.error).message} requestId={describeError(info.error).requestId} onretry={info.refresh} />
  </Card>
{:else if info.data}
  {@const s = info.data}
  <Card title="面板" icon="cpu" color="slate">
    <dl class="kv">
      <dt>版本</dt>
      <dd><span class="mono">{s.version}</span>{#if s.commit}<span class="faint mono"> · {s.commit.slice(0, 12)}</span>{/if}</dd>
      <dt>运行角色</dt>
      <dd>{ROLE[s.role] ?? s.role}</dd>
      <dt>启动于</dt>
      <dd title={dateTime(s.started_at)}>{relativeTime(s.started_at)}</dd>
      {#if s.server_time}
        <dt>服务器时间</dt>
        <dd class="mono">
          {dateTime(s.server_time)}
          {#if clockDriftSec > 30}
            <Chip size="sm" tone="warn">偏差约 {clockDriftSec} 秒</Chip>
          {/if}
        </dd>
      {/if}
      <dt>应用</dt>
      <dd><Chip size="sm" tone={s.plugins_enabled ? 'ok' : 'neutral'}>{s.plugins_enabled ? '已启用' : '未启用'}</Chip></dd>
      {#if s.listen}<dt>监听地址</dt><dd class="mono">{s.listen}</dd>{/if}
      {#if s.data_dir}<dt>数据目录</dt><dd class="mono">{s.data_dir}</dd>{/if}
    </dl>
    {#if clockDriftSec > 30}
      <div class="drift-warn">
        <Alert tone="warn" title="检测到服务器时钟与当前设备偏差约 {clockDriftSec} 秒">
          系统时钟偏差超过 30 秒会导致两步验证（TOTP）、VLESS-Reality 与 ACME 证书签发异常。建议执行
          <code class="mono">sudo timedatectl set-ntp true</code> 同步时间。
        </Alert>
      </div>
    {/if}
  </Card>

  {#if isAdmin}
    <Card title="面板入口与安全伪装" icon="shield" color="blue">
      {#if access.status === 'loading' && !access.data}
        <Skeleton lines={5} height={18} />
      {:else if access.status === 'error' && !access.data}
        <ErrorState compact message={describeError(access.error).message} requestId={describeError(access.error).requestId} onretry={access.refresh} />
      {:else if access.data}
        {@const a = access.data}
        <form class="access-form" onsubmit={saveAccess}>
          <div class="status-row">
            {#if a.bypass_reason}
              <Chip size="sm" tone="ok">{BYPASS_REASON[a.bypass_reason] ?? '已启用反代域名'} · 密道与伪装页已自动关闭</Chip>
            {:else if a.entry_gate_active}
              <Chip size="sm" tone="info">安全密道已生效（/{a.effective_entry_path}）</Chip>
            {:else}
              <Chip size="sm" tone="warn">未设置安全密道</Chip>
            {/if}
          </div>

          {#if willAutoBypass}
            <Alert tone="ok" title="反代域名模式：密道与伪装页已自动关闭">
              配置反代域名后，直接输入域名即可访问面板，无需再拼接随机密道路径；清空反代域名后会自动恢复密道保护。
            </Alert>
          {/if}

          {#if reboundUrl}
            <Alert tone="warn" title="监听端口已热切换，请使用新地址访问（旧端口将在 5 秒后关闭）">
              <div class="url-row">
                <code class="mono">{reboundUrl}</code>
                <CopyButton text={reboundUrl} label="复制新地址" />
                <a class="jump" href={reboundUrl}>前往新地址 →</a>
              </div>
            </Alert>
          {/if}

          {#if saveError}
            <Alert tone="bad">{saveError}</Alert>
          {/if}

          <Select
            label="监听范围"
            bind:value={listenHost}
            options={listenOptions}
            hint={listenHost === '127.0.0.1' || listenHost === '::1'
              ? '仅允许本机 SSH 隧道或本机反向代理接入；如需外部直接访问面板、拉取代理订阅或接收探针上报，请切为 0.0.0.0 或 ::'
              : '已开放公网监听：强烈建议保留安全密道或绑定 HTTPS 反代域名，防火墙将自动同步放行面板端口'}
          />

          <div class="inline-field">
            <Input
              label="监听端口"
              type="number"
              min="1"
              max="65535"
              mono
              bind:value={portText}
              hint="建议使用 20000–59999 高位随机端口；保存后将实时热切换，如已配置防火墙请同步放行新端口"
            />
            <div class="inline-act">
              <Button type="button" variant="ghost" onclick={randomHighPort}>随机高位端口</Button>
            </div>
          </div>

          <div class="inline-field">
            <Input
              label="安全密道（Entry Path）"
              mono
              placeholder="例如 jsnsjx8k（留空则关闭密道）"
              bind:value={entryPath}
              hint="4–48 位字母/数字/短横线；端口正确但密道不对时将直接触发下方伪装策略"
            />
            <div class="inline-act">
              <Button type="button" variant="ghost" onclick={randomEntryPath}>随机生成</Button>
            </div>
          </div>

          <Select
            label="密道错误时的伪装响应"
            bind:value={disguise}
            options={DISGUISE_OPTIONS}
            hint="「无服务断连伪装」会在发送任何 HTTP 状态码或响应头前直接中断连接，浏览器与 F12 控制台均呈现与未开服务端口一致的断连状态"
          />

          {#if disguise === 'custom_html'}
            <Input
              label="自定义伪装页 HTML"
              multiline
              rows={5}
              mono
              placeholder="<!doctype html><html><head><title>Welcome</title></head><body><h1>Under Maintenance</h1></body></html>"
              bind:value={disguiseHtml}
              hint="最大 64 KiB，返回时不附带任何面板响应头与 Cookie"
            />
          {/if}

          <Input
            label="面板反代域名（可选）"
            mono
            placeholder="例如 panel.example.com（直连 IP:端口 时留空）"
            bind:value={panelDomain}
            hint="若通过 Nginx / Caddy 反代并绑定了域名，填入域名后可自动关闭密道，直接输入域名即达面板"
          />

          <Switch
            label="配置反代域名后自动关闭密道与伪装页"
            hint="默认开启：检测到反代域名或反代 TLS 模式时自动放行根路径"
            bind:checked={autoDisableOnDomain}
          />

          <div class="preview">
            <span class="preview-label">当前入口预览</span>
            <div class="url-row">
              <code class="mono">{previewUrl}</code>
              <CopyButton text={previewUrl} label="复制入口地址" />
            </div>
            {#if panelDomain.trim()}
              <span class="preview-label">裸 IP 应急救援地址（域名解析异常时仍可通过密道直连）</span>
              <div class="url-row">
                <code class="mono">{rescueUrl}</code>
                <CopyButton text={rescueUrl} label="复制救援地址" />
              </div>
            {/if}
          </div>

          <div class="foot">
            <Button type="submit" loading={saving}>保存入口与伪装设置</Button>
          </div>
        </form>
      {/if}
    </Card>
  {/if}

  <Card title="TLS" icon="lock" color="green">
    <dl class="kv">
      <dt>模式</dt>
      <dd>{TLS[s.tls.mode] ?? s.tls.mode}</dd>
      {#if s.tls.domains?.length}<dt>域名</dt><dd class="mono">{s.tls.domains.join('、')}</dd>{/if}
      {#if s.tls.not_after}<dt>到期</dt><dd>{dateTime(s.tls.not_after)}</dd>{/if}
      {#if s.tls.fingerprint}
        <dt>证书指纹</dt>
        <dd class="fp"><code class="mono">{s.tls.fingerprint}</code><CopyButton text={s.tls.fingerprint} label="复制指纹" /></dd>
      {/if}
    </dl>
  </Card>
  <Dialog
    bind:open={mfaOpen}
    title="两步验证确认"
    description="修改面板监听地址、端口、安全密道或反代域名属于敏感操作，请输入当前 6 位动态验证码或恢复码。"
    size="sm"
  >
    {#if mfaUseRecovery}
      <Input
        label="恢复码"
        mono
        placeholder="xxxx-xxxx"
        bind:value={mfaCode}
        autofocus
        disabled={saving}
      />
    {:else}
      <div class="otp">
        <OtpInput bind:value={mfaCode} autofocus disabled={saving} oncomplete={(c) => submitMfa(c)} />
      </div>
    {/if}
    <div class="mfa-toggle">
      <Button
        type="button"
        variant="plain"
        size="sm"
        onclick={() => {
          mfaUseRecovery = !mfaUseRecovery;
          mfaCode = '';
          mfaErr = '';
        }}
      >
        {mfaUseRecovery ? '改用 6 位动态验证码' : '改用恢复码验证'}
      </Button>
    </div>
    {#if mfaErr}<Alert tone="bad">{mfaErr}</Alert>{/if}
    {#snippet footer()}
      <Button variant="plain" onclick={() => (mfaOpen = false)}>取消</Button>
      <Button
        variant="primary"
        loading={saving}
        disabled={mfaUseRecovery ? mfaCode.trim().length < 6 : mfaCode.length !== 6}
        onclick={() => submitMfa()}
      >
        验证并保存
      </Button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .drift-warn {
    margin-top: var(--s-4);
  }
  .otp {
    display: flex;
    justify-content: center;
    margin-bottom: var(--s-3);
  }
  .mfa-toggle {
    display: flex;
    justify-content: center;
    margin-bottom: var(--s-2);
  }
  .kv {
    display: grid;
    grid-template-columns: 112px minmax(0, 1fr);
    gap: var(--s-3) var(--s-4);
    margin: 0;
  }
  dt {
    color: var(--text-3);
  }
  dd {
    margin: 0;
    min-width: 0;
    word-break: break-all;
  }
  .fp,
  .url-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }
  .fp code,
  .url-row code {
    font-size: var(--fs-xs);
    word-break: break-all;
  }
  .access-form {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
  }
  .status-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .inline-field {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: var(--s-3);
    align-items: start;
  }
  .inline-act {
    padding-top: 26px;
  }
  .preview {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 10px 12px;
    border-radius: var(--r-sm);
    background: var(--surface-2);
  }
  .preview-label {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .jump {
    color: var(--accent-text);
    font-weight: var(--fw-medium);
    text-decoration: none;
  }
  .jump:hover {
    text-decoration: underline;
  }
  .foot {
    display: flex;
    justify-content: flex-end;
  }
  @media (max-width: 640px) {
    .inline-field {
      grid-template-columns: 1fr;
    }
    .inline-act {
      padding-top: 0;
    }
  }
</style>
