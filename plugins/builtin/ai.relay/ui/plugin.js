// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const hash = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(hash.get('theme'), ['light', 'dark'], 'light');

  for (const btn of document.querySelectorAll('#nav-tabs button')) {
    btn.addEventListener('click', () => {
      for (const b of document.querySelectorAll('#nav-tabs button')) b.classList.toggle('active', b === btn);
      for (const p of document.querySelectorAll('[data-pane]')) p.hidden = p.dataset.pane !== btn.dataset.tab;
    });
  }

  let port = null;
  let seq = 0;
  let publicOrigin = '';
  const pending = new Map();
  const pendingConfirm = new Map();
  const pendingCopy = new Map();

  const send = (msg) => { if (port) port.postMessage(msg); };
  const setStatus = (t) => { document.getElementById('bridge-status').textContent = t; };

  function normalizeOrigin(raw) {
    if (typeof raw !== 'string') return '';
    const trimmed = raw.trim().replace(/\/+$/, '');
    return /^https?:\/\/[^/\s]+$/i.test(trimmed) ? trimmed : '';
  }

  function publicUrl(path) {
    return publicOrigin ? `${publicOrigin}${path}` : path;
  }

  function updatePublicUrls() {
    const portalEl = document.getElementById('portal-url');
    const gwEl = document.getElementById('gateway-url');
    if (portalEl) portalEl.textContent = publicUrl('/p/ai.relay/portal/');
    if (gwEl) gwEl.textContent = publicUrl('/p/ai.relay/v1');
  }

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function invoke(operation, payload = {}) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error('宿主响应超时'));
      }, 15000);
      pending.set(id, { resolve, reject, timer });
      send({ t: 'api.invoke', id, operation, payload });
    });
  }

  function hostConfirm(title, body, { danger = false, confirmLabel } = {}) {
    if (!port) return Promise.resolve(false);
    const id = `cf_${++seq}`;
    return new Promise((resolve) => {
      pendingConfirm.set(id, { resolve });
      const msg = { t: 'ui.confirm', id, title, body, danger: Boolean(danger) };
      if (confirmLabel) msg.confirm_label = confirmLabel;
      send(msg);
    });
  }

  function hostCopy(text, label) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    if (!text) return Promise.reject(new Error('没有可复制的内容'));
    const id = `cp_${++seq}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingCopy.delete(id);
        reject(new Error('复制响应超时'));
      }, 8000);
      pendingCopy.set(id, { resolve, reject, timer });
      const msg = { t: 'ui.copy', id, text: String(text) };
      if (label) msg.label = label;
      send(msg);
    });
  }

  async function runAction(fn, okMsg) {
    try {
      await fn();
      if (okMsg) setStatus(okMsg);
    } catch (err) {
      if (err && err.awaitingApproval) {
        setStatus('等待审批确认：请在宿主审批浮窗确认后刷新');
        send({ t: 'ui.toast', text: '操作已提交，等待审批确认' });
        return;
      }
      setStatus(`操作失败：${err?.message || '未知错误'}`);
    }
  }

  function accept(data) {
    if (!data || typeof data !== 'object') return;
    if (data.t === 'api.result' && pending.has(data.id)) {
      const req = pending.get(data.id);
      clearTimeout(req.timer);
      pending.delete(data.id);
      if (data.ok === true) {
        const env = data.data;
        if (env && typeof env === 'object' && (env.status === 'AWAITING_APPROVAL' || env.approval_id)) {
          const err = new Error('等待审批确认');
          err.awaitingApproval = true;
          err.approvalId = env.approval_id;
          req.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'EXPIRED')) {
          req.reject(new Error(extractErrorMessage(env.error, `操作未完成 (${env.status || 'ERROR'})`)));
          return;
        }
        const result = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        req.resolve(result ?? {});
      } else {
        req.reject(new Error(extractErrorMessage(data.problem || data.error, '请求失败')));
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
    if (data.t === 'ui.settings') {
      if (data.theme) {
        root.dataset.theme = pick(data.theme, ['light', 'dark'], root.dataset.theme);
      }
      const nextOrigin = normalizeOrigin(data.public_origin);
      if (nextOrigin !== publicOrigin) {
        publicOrigin = nextOrigin;
        updatePublicUrls();
      }
    }
  }

  async function loadInitialData() {
    try {
      const [chData, uData] = await Promise.all([
        invoke('relay.channels.list', { limit: 100 }),
        invoke('relay.users.list', { limit: 100 }),
      ]);
      const tbody = document.getElementById('channels-tbody');
      tbody.replaceChildren();
      for (const c of chData.channels || []) {
        const tr = document.createElement('tr');
        for (const txt of [c.name, c.kind, (c.groups || []).join(','), c.health_state, `${c.last_ttft_ms || 0} ms`]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const actTd = document.createElement('td');
        const testBtn = document.createElement('button');
        testBtn.className = 'btn ghost';
        testBtn.type = 'button';
        testBtn.textContent = '测速验活';
        testBtn.addEventListener('click', () => {
          void runAction(async () => {
            await invoke('relay.channels.test', { id: c.id });
            await loadInitialData();
          }, `渠道 ${c.name} 测速完成`);
        });
        actTd.appendChild(testBtn);
        tr.appendChild(actTd);
        tbody.appendChild(tr);
      }

      const utbody = document.getElementById('users-tbody');
      utbody.replaceChildren();
      const fmtUsd = (m) => `$${((m || 0) / 1e6).toFixed(2)}`;
      for (const u of uData.users || []) {
        const tr = document.createElement('tr');
        for (const txt of [u.username, u.signup_source, u.group_name, fmtUsd(u.balance_micros), fmtUsd(u.used_micros), fmtUsd(u.auto_refill_cap_micros)]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        utbody.appendChild(tr);
      }
      setStatus('已连接');
    } catch (err) {
      setStatus(`加载失败：${err.message || '未知错误'}`);
    }
  }

  document.getElementById('btn-save-channel').addEventListener('click', () => {
    void runAction(async () => {
      await invoke('relay.channels.upsert', {
        name: document.getElementById('ch-name').value.trim(),
        kind: document.getElementById('ch-kind').value,
        base_url: document.getElementById('ch-url').value.trim(),
        credential: document.getElementById('ch-secret').value.trim(),
        groups: document.getElementById('ch-groups').value.split(',').map((s) => s.trim()).filter(Boolean),
        models: document.getElementById('ch-models').value.split(',').map((s) => s.trim()).filter(Boolean),
        priority: Number(document.getElementById('ch-prio').value || 0),
      });
      document.getElementById('ch-secret').value = '';
      await loadInitialData();
    }, '上游渠道已加密保存');
  });

  document.getElementById('btn-save-settings').addEventListener('click', () => {
    void runAction(async () => {
      await invoke('relay.settings.update', {
        site_title: document.getElementById('st-title').value.trim(),
        allow_invite_signup: document.getElementById('st-invite').value === '1',
        allow_email_signup: document.getElementById('st-email').value === '1',
        email_domain_allowlist: document.getElementById('st-email-domains').value.split(',').map((s) => s.trim()).filter(Boolean),
        allow_linuxdo_signup: document.getElementById('st-linuxdo').value === '1',
        linuxdo_client_id: document.getElementById('st-ld-id').value.trim(),
        linuxdo_client_secret: document.getElementById('st-ld-secret').value.trim(),
        linuxdo_min_trust_level: Number(document.getElementById('st-ld-mintl').value || 1),
        default_signup_micros: Math.round(Number(document.getElementById('st-init-usd').value || 5) * 1e6),
        checkin_drip_below_micros: Math.round(Number(document.getElementById('st-drip-usd').value || 10) * 1e6),
      });
      document.getElementById('st-ld-secret').value = '';
    }, '策略已保存');
  });

  document.getElementById('btn-gen-codes').addEventListener('click', () => {
    void runAction(async () => {
      const res = await invoke('relay.codes.generate', {
        kind: document.getElementById('cd-kind').value,
        amount_micros: Math.round(Number(document.getElementById('cd-usd').value || 10) * 1e6),
        count: Number(document.getElementById('cd-count').value || 1),
        custom_code: document.getElementById('cd-custom').value.trim(),
      });
      document.getElementById('cd-output').value = (res.codes || []).join('\n');
    }, '已签发兑换码 / 邀请码');
  });

  document.getElementById('btn-copy-codes').addEventListener('click', () => {
    const text = document.getElementById('cd-output').value.trim();
    void runAction(async () => {
      await hostCopy(text, '已复制签发结果');
    }, '已复制签发结果');
  });

  document.getElementById('btn-create-user').addEventListener('click', () => {
    void runAction(async () => {
      await invoke('relay.users.create', {
        username: document.getElementById('u-name').value.trim(),
        password: document.getElementById('u-pass').value,
        group_name: document.getElementById('u-group').value.trim() || 'default',
        init_micros: Math.round(Number(document.getElementById('u-init-usd').value || 0) * 1e6),
        daily_refill_micros: Math.round(Number(document.getElementById('u-daily-usd').value || 0) * 1e6),
      });
      document.getElementById('u-pass').value = '';
      await loadInitialData();
    }, '分发成员已创建');
  });

  const observer = new ResizeObserver(() => {
    send({ t: 'ui.resize', height: Math.ceil(document.getElementById('ai-relay-root').getBoundingClientRect().height) + 24 });
  });
  observer.observe(document.getElementById('ai-relay-root'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (msg) => accept(msg.data);
    send({ t: 'ui.ready' });
    void loadInitialData();
  });

  window.addEventListener('pagehide', () => {
    observer.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
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
