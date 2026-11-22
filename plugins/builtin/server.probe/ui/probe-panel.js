// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const root = document.documentElement;
  const $ = (id) => document.getElementById(id);
  let port = null;
  let seq = 0;
  let mode = 'admin';
  let latest = null;
  const pending = new Map();

  function send(msg) {
    if (port) port.postMessage(msg);
  }

  function invoke(operation, payload = {}) {
    if (!port) return Promise.reject(new Error('尚未建立宿主通道'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        pending.delete(id);
        reject(new Error('宿主响应超时'));
      }, 6000);
      pending.set(id, { resolve, reject, deadline });
      send({ t: 'api.invoke', id, operation, payload });
    });
  }

  function esc(str) {
    return String(str ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function render(data) {
    latest = data;
    const caps = data.dnc_capabilities || {};
    $('dnc-track-hint').textContent = caps.tls_certificates_ready
      ? '已探测到面板证书套件就绪：可直接借用 domain.dns 解析与 certbind_* 自动续期证书'
      : (caps.fallback_reason || '未安装面板域名插件：已启用探针自身独立域名与 HTTPS 绑定闭环');
    $('track-badge').textContent = caps.tls_certificates_ready ? '轨道 A 可借用' : '轨道 B 自闭环';

    const nodes = Array.isArray(data.public_nodes) ? data.public_nodes : [];
    const cardsHTML = nodes.map((n) => {
      const cpu = Number(n.live?.cpu_pct || 0).toFixed(1);
      const rxMbps = (Number(n.live?.net_rx_bps || 0) / 1e6).toFixed(2);
      const txMbps = (Number(n.live?.net_tx_bps || 0) / 1e6).toFixed(2);
      return `<div class="node-card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <strong>[${esc(n.region_code)}] ${esc(n.name)}</strong>
          <span class="badge ${n.online ? '' : 'warn'}">${n.online ? '在线' : '离线'}</span>
        </div>
        <div style="font-size:12.5px;color:var(--text-2)">
          CPU ${cpu}% · ↓ ${rxMbps} Mbps / ↑ ${txMbps} Mbps · 90天在线 ${Number(n.uptime_90d_pct || 100).toFixed(2)}%
        </div>
      </div>`;
    }).join('');
    $('admin-nodes-grid').innerHTML = cardsHTML;
    $('visitor-nodes-grid').innerHTML = cardsHTML;
    if (data.settings?.site_title) {
      $('preview-title').textContent = data.settings.site_title;
    }
    if (data.proxy_snippets?.nginx_baota_conf) {
      $('proxy-snippet-box').hidden = false;
      $('proxy-snippet-box').textContent = data.proxy_snippets.nginx_baota_conf;
    }
  }

  async function refresh() {
    try {
      const res = await invoke('probe.overview', {});
      $('conn-status').textContent = '已连接 qwq 插件沙箱运行时 · 实时遥测同步中';
      render(res);
    } catch (err) {
      $('conn-status').textContent = err.message || '等待宿主连接';
    }
  }

  document.querySelectorAll('[data-mode]').forEach((btn) => {
    btn.addEventListener('click', () => {
      mode = btn.dataset.mode;
      document.querySelectorAll('[data-mode]').forEach((b) => b.setAttribute('aria-pressed', String(b === btn)));
      $('admin-pane').hidden = mode !== 'admin';
      $('visitor-pane').hidden = mode !== 'visitor-preview';
    });
  });

  $('add-node-btn').addEventListener('click', async () => {
    const name = $('node-name').value.trim();
    const region = $('node-region').value.trim() || 'HK';
    const quotaMode = $('node-quota-mode').value;
    if (!name) return;
    try {
      const res = await invoke('probe.nodes.upsert', { name, region_code: region, quota_mode: quotaMode });
      $('install-cmd-box').hidden = false;
      $('install-cmd-box').textContent = res.linux_install || '已创建节点';
      $('node-name').value = '';
      void refresh();
    } catch (err) {
      $('conn-status').textContent = '操作已提交宿主审批或暂不可用：' + err.message;
    }
  });

  $('bind-domain-btn').addEventListener('click', async () => {
    const customDomain = $('domain-input').value.trim();
    const bindingTrack = $('track-select').value;
    if (!customDomain) return;
    try {
      const res = await invoke('probe.domain.bind', { custom_domain: customDomain, binding_track: bindingTrack });
      if (res.proxy_snippets?.nginx_baota_conf) {
        $('proxy-snippet-box').hidden = false;
        $('proxy-snippet-box').textContent = res.proxy_snippets.nginx_baota_conf;
      }
      void refresh();
    } catch (err) {
      $('conn-status').textContent = '域名绑定校验提示：' + err.message;
    }
  });

  const ro = new ResizeObserver(() => {
    send({ t: 'ui.resize', height: Math.ceil($('probe-app').getBoundingClientRect().height) + 24 });
  });
  ro.observe($('probe-app'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent) return;
    if (event.data?.t === 'plugin.port' && event.ports[0] && !port) {
      port = event.ports[0];
      port.onmessage = (msg) => {
        const d = msg.data;
        if (!d || typeof d !== 'object') return;
        if (d.t === 'api.result' && pending.has(d.id)) {
          const req = pending.get(d.id);
          clearTimeout(req.deadline);
          pending.delete(d.id);
          if (d.ok) req.resolve(d.data?.result ?? d.data);
          else req.reject(new Error(d.data?.error?.message || '调用失败'));
        }
        if (d.t === 'ui.settings' && (d.theme === 'light' || d.theme === 'dark')) {
          root.dataset.theme = d.theme;
        }
      };
      send({ t: 'ui.ready' });
      void refresh();
    }
  });

  window.addEventListener('pagehide', () => {
    ro.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.deadline);
    }
    pending.clear();
    if (port) {
      port.onmessage = null;
      if (typeof port.close === 'function') port.close();
      port = null;
    }
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
  if (latest === null) {
    render({ public_nodes: [], dnc_capabilities: {} });
  }
})();
