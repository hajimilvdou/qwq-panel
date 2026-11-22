// SPDX-License-Identifier: AGPL-3.0-only
// 分发用户独立自服务门户前端逻辑（使用专属 X-Relay-Session 头与门户隔离存储键，绝不触碰 VPS 面板 Cookie）。

const SESSION_KEY = 'qwq_ai_relay_portal_token';
const basePath = window.location.pathname.replace(/\/index\.html$/, '').replace(/\/$/, '');
const apiRootOrigin = window.location.origin + basePath.replace(/\/portal$/, '');

let currentMode = 'login';
let sessionToken = sessionStorage.getItem(SESSION_KEY) || '';

async function portalFetch(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (sessionToken) headers['X-Relay-Session'] = sessionToken;
  const res = await fetch(`${basePath}${path}`, { ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) {
      sessionToken = '';
      sessionStorage.removeItem(SESSION_KEY);
      toggleViews(false);
    }
    throw new Error(data.message || `请求失败 (${res.status})`);
  }
  return data;
}

function fmtUSD(micros) {
  return `$${((Number(micros) || 0) / 1_000_000).toFixed(4)}`;
}

function showNotice(text) {
  const el = document.getElementById('app-banner');
  el.hidden = false;
  el.textContent = text;
}

function toggleViews(loggedIn) {
  document.getElementById('auth-view').hidden = loggedIn;
  document.getElementById('app-view').hidden = !loggedIn;
}

for (const btn of document.querySelectorAll('#auth-tabs button')) {
  btn.onclick = () => {
    currentMode = btn.dataset.mode;
    for (const b of document.querySelectorAll('#auth-tabs button')) b.classList.toggle('active', b === btn);
    document.getElementById('wrap-invite').hidden = currentMode !== 'invite';
    document.getElementById('wrap-email').hidden = currentMode !== 'email';
    document.getElementById('wrap-otp').hidden = currentMode !== 'email';
    document.getElementById('btn-auth-submit').textContent =
      currentMode === 'login' ? '立即登录' : '注册并领取初始额度';
  };
}

document.getElementById('btn-send-otp').onclick = async () => {
  const email = document.getElementById('f-email').value.trim();
  const msgEl = document.getElementById('auth-msg');
  try {
    await portalFetch('/api/auth/send-email-code', { method: 'POST', body: JSON.stringify({ email }) });
    msgEl.textContent = '验证码已发送，请查收邮箱（10 分钟内有效）';
  } catch (e) {
    msgEl.textContent = e.message;
  }
};

document.getElementById('auth-form').onsubmit = async (ev) => {
  ev.preventDefault();
  const msgEl = document.getElementById('auth-msg');
  const payload = {
    mode: currentMode,
    username: document.getElementById('f-username').value.trim(),
    password: document.getElementById('f-password').value,
    invite_code: document.getElementById('f-invite').value.trim(),
    email: document.getElementById('f-email').value.trim(),
    email_code: document.getElementById('f-otp').value.trim(),
  };
  try {
    const res = await portalFetch('/api/auth/submit', { method: 'POST', body: JSON.stringify(payload) });
    sessionToken = res.session_token;
    sessionStorage.setItem(SESSION_KEY, sessionToken);
    toggleViews(true);
    await loadDashboard();
  } catch (e) {
    msgEl.textContent = e.message;
  }
};

document.getElementById('btn-linuxdo-oauth').onclick = () => {
  window.location.href = `${basePath}/api/oauth/linuxdo/start`;
};

document.getElementById('btn-logout').onclick = () => {
  sessionToken = '';
  sessionStorage.removeItem(SESSION_KEY);
  toggleViews(false);
};

document.getElementById('btn-checkin').onclick = async () => {
  try {
    const res = await portalFetch('/api/quota/checkin', { method: 'POST', body: '{}' });
    showNotice(`签到成功！本次获赠统计额度 ${fmtUSD(res.granted_micros)}`);
    await loadDashboard();
  } catch (e) {
    showNotice(e.message);
  }
};

document.getElementById('btn-redeem').onclick = async () => {
  const code = document.getElementById('cdk-input').value.trim();
  if (!code) return;
  try {
    const res = await portalFetch('/api/quota/redeem', { method: 'POST', body: JSON.stringify({ code }) });
    document.getElementById('cdk-input').value = '';
    showNotice(`兑换成功！到账统计额度 ${fmtUSD(res.granted_micros)}`);
    await loadDashboard();
  } catch (e) {
    showNotice(e.message);
  }
};

function renderClientSnippet(plainOrMaskedKey) {
  const box = document.getElementById('snippet-box');
  const pre = document.getElementById('snippet-code');
  box.hidden = false;
  pre.textContent = [
    '# 1. OpenAI / Cherry Studio / NextChat / Cursor 通用接入',
    `OPENAI_BASE_URL="${apiRootOrigin}/v1"`,
    `OPENAI_API_KEY="${plainOrMaskedKey}"`,
    '',
    '# 2. Claude Code 原生直连 (~/.claude/settings.json -> env)',
    '{',
    '  "env": {',
    `    "ANTHROPIC_BASE_URL": "${apiRootOrigin}",`,
    `    "ANTHROPIC_AUTH_TOKEN": "${plainOrMaskedKey}"`,
    '  }',
    '}',
    '',
    '# 3. OpenAI Codex CLI (~/.codex/config.toml) Responses 接入',
    `base_url = "${apiRootOrigin}/v1"`,
  ].join('\n');
}

document.getElementById('btn-create-tok').onclick = async () => {
  const limitUsd = Number(document.getElementById('tok-limit').value || 0);
  const payload = {
    name: document.getElementById('tok-name').value.trim() || 'default-key',
    quota_limit_micros: limitUsd > 0 ? Math.round(limitUsd * 1_000_000) : 0,
    allowed_models: document.getElementById('tok-models').value.split(',').map((s) => s.trim()).filter(Boolean),
    allowed_ips: document.getElementById('tok-ips').value.split(',').map((s) => s.trim()).filter(Boolean),
  };
  try {
    const res = await portalFetch('/api/tokens', { method: 'POST', body: JSON.stringify(payload) });
    showNotice(`新令牌已创建（请立即复制保存完整密钥）：${res.plain_key}`);
    renderClientSnippet(res.plain_key);
    await loadDashboard();
  } catch (e) {
    showNotice(e.message);
  }
};

async function loadDashboard() {
  const d = await portalFetch('/api/me');
  document.getElementById('user-badge').textContent =
    `账号：${d.user.username} · 分组：${d.user.group_name} · 来源：${d.user.signup_source}`;
  document.getElementById('st-balance').textContent = fmtUSD(d.user.balance_micros);
  document.getElementById('st-used').textContent = fmtUSD(d.user.used_micros);
  document.getElementById('st-reqs').textContent = `共 ${d.user.request_count || 0} 次调用`;
  document.getElementById('st-my-invite').textContent = d.user.personal_invite_code || '-';
  if (d.user.auto_refill_cap_micros > 0) {
    document.getElementById('st-refill-hint').textContent =
      `周期自动回血上限：${fmtUSD(d.user.auto_refill_cap_micros)} (${d.user.auto_refill_cycle})`;
  }

  const tokBody = document.getElementById('tokens-tbody');
  tokBody.replaceChildren();
  for (const t of d.tokens || []) {
    const tr = document.createElement('tr');
    const limText = t.quota_limit_micros > 0 ? fmtUSD(t.quota_limit_micros) : '共享总额';
    const scopeText = `${(t.allowed_models || []).length ? t.allowed_models.join(',') : '全模型'} · ${t.rpm_limit} RPM`;
    for (const val of [t.name, t.key_masked, `${fmtUSD(t.used_micros)} / ${limText}`, scopeText]) {
      const td = document.createElement('td');
      td.textContent = val;
      tr.appendChild(td);
    }
    const btnTd = document.createElement('td');
    const cfgBtn = document.createElement('button');
    cfgBtn.className = 'btn outline';
    cfgBtn.textContent = '生成接入脚本';
    cfgBtn.onclick = () => renderClientSnippet(t.plain_key || t.key_masked);
    btnTd.appendChild(cfgBtn);
    tr.appendChild(btnTd);
    tokBody.appendChild(tr);
  }

  const modBody = document.getElementById('models-tbody');
  modBody.replaceChildren();
  for (const m of d.models || []) {
    const tr = document.createElement('tr');
    for (const val of [
      m.model_name,
      `$${((m.input_micros_per_1k || 0) / 1000).toFixed(2)}`,
      `$${((m.output_micros_per_1k || 0) / 1000).toFixed(2)}`,
      `${Math.round((m.cache_read_ratio || 0.1) * 100)}%`,
    ]) {
      const td = document.createElement('td');
      td.textContent = val;
      tr.appendChild(td);
    }
    modBody.appendChild(tr);
  }

  const logBody = document.getElementById('logs-tbody');
  logBody.replaceChildren();
  for (const l of d.recent_logs || []) {
    const tr = document.createElement('tr');
    const ts = new Date(l.created_at).toLocaleTimeString();
    for (const val of [
      ts,
      `${l.model_name} (${l.protocol_in})`,
      `${l.input_tokens}(${l.cached_read_tokens}) / ${l.output_tokens}`,
      fmtUSD(l.cost_micros),
      `${l.ttft_ms}ms`,
    ]) {
      const td = document.createElement('td');
      td.textContent = val;
      tr.appendChild(td);
    }
    logBody.appendChild(tr);
  }
}

const hashParams = new URLSearchParams(window.location.hash.slice(1));
if (hashParams.get('relay_session')) {
  sessionToken = hashParams.get('relay_session');
  sessionStorage.setItem(SESSION_KEY, sessionToken);
  history.replaceState(null, '', window.location.pathname);
}

if (sessionToken) {
  toggleViews(true);
  loadDashboard().catch(() => toggleViews(false));
} else {
  toggleViews(false);
}
