// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const hash = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(hash.get('theme'), ['light', 'dark'], 'light');

  const statusEl = document.getElementById('bridge-status');
  let port = null;
  let seq = 0;
  const pending = new Map();
  const pendingConfirm = new Map();
  const pendingCopy = new Map();

  const setStatus = (t) => { statusEl.textContent = t; };
  const send = (msg) => { if (port) port.postMessage(msg); };

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  const runAction = async (fn, okMsg) => {
    try {
      await fn();
      if (okMsg) setStatus(okMsg);
    } catch (err) {
      if (err && err.awaitingApproval) {
        setStatus('等待审批确认：请在宿主审批浮窗确认后刷新');
        send({ t: 'ui.toast', text: '操作已提交，等待审批确认' });
        return;
      }
      setStatus('操作失败：' + (err?.message || '未知错误'));
    }
  };

  const invoke = (operation, payload = {}) => new Promise((resolve, reject) => {
    if (!port) return reject(new Error('宿主桥尚未就绪'));
    const id = `ing_${++seq}`;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error('宿主响应超时'));
    }, 15000);
    pending.set(id, { resolve, reject, timer });
    send({ t: 'api.invoke', id, operation, payload });
  });

  const hostConfirm = (title, body, { danger = false, confirmLabel } = {}) => new Promise((resolve) => {
    if (!port) return resolve(false);
    const id = `cf_${++seq}`;
    pendingConfirm.set(id, { resolve });
    const msg = { t: 'ui.confirm', id, title, body, danger: Boolean(danger) };
    if (confirmLabel) msg.confirm_label = confirmLabel;
    send(msg);
  });

  const hostCopy = (text, label) => new Promise((resolve, reject) => {
    if (!port) return reject(new Error('宿主桥尚未就绪'));
    if (!text) return reject(new Error('没有可复制的内容'));
    const id = `cp_${++seq}`;
    const timer = setTimeout(() => {
      pendingCopy.delete(id);
      reject(new Error('复制响应超时'));
    }, 8000);
    pendingCopy.set(id, { resolve, reject, timer });
    const msg = { t: 'ui.copy', id, text: String(text) };
    if (label) msg.label = label;
    send(msg);
  });

  document.getElementById('nav-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    for (const b of document.querySelectorAll('#nav-tabs button')) b.classList.toggle('active', b === btn);
    for (const p of document.querySelectorAll('[data-pane]')) p.hidden = p.dataset.pane !== btn.dataset.tab;
    if (btn.dataset.tab === 'preview') void runAction(loadPreview);
  });

  async function loadPreview() {
    const res = await invoke('ingress.config.preview', {});
    document.getElementById('pre-caddy').textContent = res.caddyfile || '';
    document.getElementById('pre-nginx').textContent = res.nginx || '';
  }

  async function refresh() {
    try {
      const data = await invoke('ingress.overview', {});
      const sites = data.sites || [];
      const snaps = data.snapshots || [];
      document.getElementById('st-engine').textContent = data.backend?.active_engine || 'builtin-go';
      document.getElementById('st-sites').textContent = String(sites.length);
      document.getElementById('st-active').textContent = String(data.active_routes || 0);
      document.getElementById('st-snaps').textContent = String(snaps.length);

      const st = document.getElementById('sites-tbody');
      st.replaceChildren();
      for (const s of sites) {
        const tr = document.createElement('tr');
        const flags = [s.tls_mode, s.websocket ? 'WS' : '', s.has_basic_auth ? 'BasicAuth' : ''].filter(Boolean).join(' · ');
        for (const txt of [s.domain + (s.path_prefix !== '/' ? s.path_prefix : ''), s.upstream_url, flags, s.rate_limit_rps > 0 ? `${s.rate_limit_rps} rps` : '不限']) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const act = document.createElement('td');
        const pBtn = document.createElement('button');
        pBtn.className = 'btn ghost';
        pBtn.type = 'button';
        pBtn.textContent = '探测上游';
        pBtn.addEventListener('click', () => void runAction(async () => {
          const r = await invoke('ingress.upstream.probe', { id: s.id });
          setStatus(r.reachable ? `${s.domain} 上游可达 (HTTP ${r.status_code}, ${r.latency_ms}ms)` : `${s.domain} 上游不可达: ${r.error}`);
        }));
        const dBtn = document.createElement('button');
        dBtn.className = 'btn danger btn-gap';
        dBtn.type = 'button';
        dBtn.textContent = '删除';
        dBtn.addEventListener('click', () => {
          void runAction(async () => {
            const ok = await hostConfirm('删除反代站点', `确认删除反代站点「${s.domain}」？（变更前将自动保留回滚快照）`, { danger: true, confirmLabel: '确认删除' });
            if (!ok) return;
            await invoke('ingress.site.delete', { id: s.id });
            await refresh();
            setStatus(`已删除站点 ${s.domain}`);
          });
        });
        act.append(pBtn, dBtn);
        tr.appendChild(act);
        st.appendChild(tr);
      }

      const snt = document.getElementById('snaps-tbody');
      snt.replaceChildren();
      for (const sn of snaps) {
        const tr = document.createElement('tr');
        for (const txt of [`v${sn.revision}`, sn.reason, String(sn.site_count)]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const act = document.createElement('td');
        const rBtn = document.createElement('button');
        rBtn.className = 'btn ghost';
        rBtn.type = 'button';
        rBtn.textContent = '回滚至此版本';
        rBtn.addEventListener('click', () => {
          void runAction(async () => {
            const ok = await hostConfirm('回滚反代配置', `确认将反代配置回滚至快照 v${sn.revision} 并立即热重载？`, { danger: true, confirmLabel: '确认回滚' });
            if (!ok) return;
            await invoke('ingress.rollback', { snapshot_id: sn.id });
            await refresh();
            setStatus(`已回滚至快照 v${sn.revision}`);
          });
        });
        act.appendChild(rBtn);
        tr.appendChild(act);
        snt.appendChild(tr);
      }
      setStatus('已连接');
    } catch (err) {
      setStatus('加载失败：' + (err.message || '未知错误'));
    }
  }

  document.getElementById('btn-save-site').addEventListener('click', () => void runAction(async () => {
    await invoke('ingress.site.upsert', {
      domain: document.getElementById('s-domain').value.trim(),
      upstream_url: document.getElementById('s-upstream').value.trim(),
      path_prefix: document.getElementById('s-prefix').value.trim() || '/',
      tls_mode: document.getElementById('s-tls').value,
      cert_id: document.getElementById('s-cert').value.trim(),
      rate_limit_rps: Number(document.getElementById('s-rps').value || 0),
      basic_auth_user: document.getElementById('s-user').value.trim(),
      basic_auth_pass: document.getElementById('s-pass').value,
      websocket: true,
      enabled: true,
    });
    document.getElementById('s-pass').value = '';
    await refresh();
  }, '站点已保存并生成新快照'));

  const doApply = () => void runAction(async () => {
    const res = await invoke('ingress.apply', {});
    await refresh();
    setStatus(`已热重载：生效路由 ${res.active_routes ?? 0} 条 (${res.engine || 'builtin-go'})`);
  });
  document.getElementById('btn-apply').addEventListener('click', doApply);
  document.getElementById('btn-apply-2').addEventListener('click', doApply);
  document.getElementById('btn-load-preview').addEventListener('click', () => void runAction(loadPreview, '配置预览已刷新'));
  document.getElementById('btn-copy-caddy').addEventListener('click', () => void runAction(async () => {
    await hostCopy(document.getElementById('pre-caddy').textContent || '', '已复制 Caddyfile');
  }, '已复制 Caddyfile'));
  document.getElementById('btn-copy-nginx').addEventListener('click', () => void runAction(async () => {
    await hostCopy(document.getElementById('pre-nginx').textContent || '', '已复制 Nginx 配置');
  }, '已复制 Nginx 配置'));

  function accept(data) {
    if (!data || typeof data !== 'object') return;
    if (data.t === 'api.result' && pending.has(data.id)) {
      const p = pending.get(data.id);
      clearTimeout(p.timer);
      pending.delete(data.id);
      if (data.ok === true) {
        const env = data.data;
        if (env && typeof env === 'object' && (env.status === 'AWAITING_APPROVAL' || env.approval_id)) {
          const err = new Error('等待审批确认');
          err.awaitingApproval = true;
          err.approvalId = env.approval_id;
          p.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'EXPIRED')) {
          p.reject(new Error(extractErrorMessage(env.error, `操作未完成 (${env.status || 'ERROR'})`)));
          return;
        }
        const result = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        p.resolve(result ?? {});
      } else {
        p.reject(new Error(extractErrorMessage(data.problem || data.error, '请求失败')));
      }
      return;
    }
    if (data.t === 'ui.confirm.result' && pendingConfirm.has(data.id)) {
      const req = pendingConfirm.get(data.id);
      pendingConfirm.delete(data.id);
      req.resolve(Boolean(data.ok && data.data?.confirmed));
      return;
    }
    if (data.t === 'ui.copy.result' && pendingCopy.has(data.id)) {
      const req = pendingCopy.get(data.id);
      clearTimeout(req.timer);
      pendingCopy.delete(data.id);
      if (data.ok) req.resolve(true);
      else req.reject(new Error(extractErrorMessage(data.problem || data.error, '复制失败')));
      return;
    }
    if (data.t === 'ui.settings' && (data.theme === 'light' || data.theme === 'dark')) {
      root.dataset.theme = data.theme;
    }
  }

  const ro = new ResizeObserver(() => {
    send({ t: 'ui.resize', height: Math.ceil(document.getElementById('ingress-root').getBoundingClientRect().height) + 24 });
  });
  ro.observe(document.getElementById('ingress-root'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (m) => accept(m.data);
    send({ t: 'ui.ready' });
    void refresh();
  });

  window.addEventListener('pagehide', () => {
    ro.disconnect();
    for (const p of pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error('页面已关闭'));
    }
    pending.clear();
    for (const req of pendingConfirm.values()) req.resolve(false);
    pendingConfirm.clear();
    for (const req of pendingCopy.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
    }
    pendingCopy.clear();
    if (port) {
      port.onmessage = null;
      if (typeof port.close === 'function') port.close();
      port = null;
    }
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
