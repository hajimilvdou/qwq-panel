// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  let view = 'orb-cards';
  let inAdmin = false;
  let adminToken = '';
  let visitorToken = '';
  let snapshot = { nodes: [], service_monitors: [] };

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function fmtBytes(n) {
    const v = Number(n || 0);
    if (v >= 1099511627776) return (v / 1099511627776).toFixed(2) + ' TiB';
    if (v >= 1073741824) return (v / 1073741824).toFixed(1) + ' GiB';
    return (v / 1048576).toFixed(0) + ' MiB';
  }

  async function loadPublic() {
    try {
      const headers = {};
      if (visitorToken) headers['X-Probe-Visitor-Token'] = visitorToken;
      if (adminToken) headers['X-Probe-Admin-Token'] = adminToken;
      const resp = await fetch('./api/public/snapshot', { headers });
      if (!resp.ok) return;
      snapshot = await resp.json();
      if (snapshot.site_title) $('site-title').textContent = snapshot.site_title;
      if (snapshot.site_subtitle) $('site-sub').textContent = snapshot.site_subtitle;
      if (snapshot.banner_text) $('banner-text').textContent = snapshot.banner_text;
      renderShowcase();
    } catch {
      // 离线打开时保持静默优雅状态
    }
  }

  function renderShowcase() {
    const nodes = Array.isArray(snapshot.nodes) ? snapshot.nodes : [];
    const online = nodes.filter((n) => n.online).length;
    $('fleet-summary').textContent = `在线 ${online} / ${nodes.length} 台`;

    $('tty-container').hidden = view !== 'tty-terminal';
    $('nodes-container').hidden = view === 'tty-terminal';

    if (view === 'tty-terminal') {
      if (!$('tty-output').textContent) {
        $('tty-output').textContent = 'qwq-probe Monitor TTY v0.1 (pure read-only sandbox)\nType "help", "ls", "top", or "login" to switch to admin console.\n';
      }
      return;
    }

    $('nodes-container').innerHTML = nodes.map((n) => {
      const cpu = Number(n.live?.cpu_pct || 0).toFixed(1);
      const memPct = n.mem_total_bytes ? ((Number(n.live?.mem_used_bytes || 0) / n.mem_total_bytes) * 100).toFixed(1) : '0.0';
      const rx = (Number(n.live?.net_rx_bps || 0) / 1e6).toFixed(2);
      const tx = (Number(n.live?.net_tx_bps || 0) / 1e6).toFixed(2);
      const bars = Array.from({ length: 45 }, () => '<i></i>').join('');
      return `<article class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <strong>[${esc(n.region_code)}] ${esc(n.name)}</strong>
          <span style="font-size:12px;color:var(--jade)">${n.online ? '● 在线' : '○ 离线'} · ${Number(n.uptime_90d_pct || 100).toFixed(2)}%</span>
        </div>
        <div style="font-size:12.5px;color:var(--text-2);margin-top:8px">
          CPU ${cpu}% · 内存 ${memPct}% · ↓ ${rx} Mbps / ↑ ${tx} Mbps
        </div>
        <div style="font-size:12px;color:var(--text-2);margin-top:6px">
          月流量 ${fmtBytes(n.quota_used_bytes)} / ${n.quota_bytes ? fmtBytes(n.quota_bytes) : '不限'} ${n.billing_badge ? '· ' + esc(n.billing_badge) : ''}
        </div>
        <div class="sla-bar" aria-label="近期在线率状态条">${bars}</div>
      </article>`;
    }).join('');
  }

  async function syncAdminPane() {
    if (!adminToken) return;
    const resp = await fetch('./api/admin/state', { headers: { 'X-Probe-Admin-Token': adminToken } });
    if (!resp.ok) return;
    const data = await resp.json();
    $('standalone-dnc-msg').textContent = data.dnc_capabilities?.fallback_reason || '已连接面板证书服务';
    if (data.settings?.custom_domain) $('adm-domain').value = data.settings.custom_domain;
  }

  document.querySelectorAll('[data-view]').forEach((btn) => {
    btn.addEventListener('click', () => {
      view = btn.dataset.view;
      document.querySelectorAll('[data-view]').forEach((b) => b.classList.toggle('active', b === btn));
      renderShowcase();
    });
  });

  $('theme-toggle').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
  });

  $('admin-switch-btn').addEventListener('click', () => {
    if (inAdmin) {
      inAdmin = false;
      $('standalone-admin').hidden = true;
      $('public-showcase').hidden = false;
      $('admin-switch-btn').textContent = '切换后台管理';
      return;
    }
    if (adminToken) {
      inAdmin = true;
      $('standalone-admin').hidden = false;
      $('public-showcase').hidden = true;
      $('admin-switch-btn').textContent = '返回展示前台';
      void syncAdminPane();
      return;
    }
    $('login-modal').hidden = false;
  });

  $('login-cancel').addEventListener('click', () => { $('login-modal').hidden = true; });

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = $('login-password').value;
    const resp = await fetch('./api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    if (!resp.ok) return;
    const data = await resp.json();
    adminToken = data.admin_token || '';
    $('login-password').value = '';
    $('login-modal').hidden = true;
    inAdmin = true;
    $('standalone-admin').hidden = false;
    $('public-showcase').hidden = true;
    $('admin-switch-btn').textContent = '返回展示前台';
    void syncAdminPane();
  });

  $('adm-save-domain').addEventListener('click', async () => {
    const resp = await fetch('./api/admin/domain/bind', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Probe-Admin-Token': adminToken },
      body: JSON.stringify({
        custom_domain: $('adm-domain').value.trim(),
        binding_track: $('adm-track').value,
        acme_email: $('adm-email').value.trim()
      })
    });
    const data = await resp.json();
    if (data.proxy_snippets?.nginx_baota_conf) {
      $('adm-snippet').hidden = false;
      $('adm-snippet').textContent = data.proxy_snippets.nginx_baota_conf;
    }
  });

  $('adm-add-node').addEventListener('click', async () => {
    const resp = await fetch('./api/admin/nodes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Probe-Admin-Token': adminToken },
      body: JSON.stringify({
        name: $('adm-node-name').value.trim(),
        region_code: $('adm-node-region').value.trim() || 'HK'
      })
    });
    const data = await resp.json();
    if (data.linux_install) {
      $('adm-install-cmd').hidden = false;
      $('adm-install-cmd').textContent = data.linux_install;
    }
  });

  $('tty-input').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const cmd = $('tty-input').value.trim();
    $('tty-input').value = '';
    let out = `\n$ ${cmd}\n`;
    if (cmd === 'help') out += 'Commands: ls, top, ping, login, clear\n';
    else if (cmd === 'clear') { $('tty-output').textContent = ''; return; }
    else if (cmd === 'login') { $('login-modal').hidden = false; out += 'Opening standalone admin unlock dialog...\n'; }
    else if (cmd === 'ls' || cmd === 'top') {
      out += (snapshot.nodes || []).map((n) => `${n.id.padEnd(12)} [${n.region_code}] CPU:${Number(n.live?.cpu_pct || 0).toFixed(1)}% UP:${n.online}`).join('\n') + '\n';
    } else {
      out += `Unknown command: ${cmd} (type help)\n`;
    }
    $('tty-output').textContent += out;
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('login-modal').hidden) {
      $('login-modal').hidden = true;
      return;
    }
    if (e.altKey && (e.key === 'm' || e.key === 'M')) {
      e.preventDefault();
      $('admin-switch-btn').click();
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) void loadPublic();
  });

  void loadPublic();
  setInterval(() => {
    if (!document.hidden) void loadPublic();
  }, 3000);
})();
