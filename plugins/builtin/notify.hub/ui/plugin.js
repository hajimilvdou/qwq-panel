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
    const id = `nh_${++seq}`;
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
  });

  function badge(status) {
    const span = document.createElement('span');
    span.className = 'badge ' + (status === 'ok' || status === 'sent' ? 'ok' : (status === 'error' || status === 'failed' ? 'err' : 'warn'));
    span.textContent = status;
    return span;
  }

  async function refresh() {
    try {
      const data = await invoke('notify.overview', {});
      const chs = data.channels || [];
      const rls = data.rules || [];
      const dels = data.deliveries || [];
      document.getElementById('st-channels').textContent = String(chs.filter((c) => c.enabled).length);
      document.getElementById('st-rules').textContent = String(rls.length);
      document.getElementById('st-sent').textContent = String(data.sent_24h || 0);
      document.getElementById('st-fail').textContent = `${data.suppressed_24h || 0} / ${data.failed_24h || 0}`;

      const ct = document.getElementById('channels-tbody');
      ct.replaceChildren();
      for (const c of chs) {
        const tr = document.createElement('tr');
        for (const txt of [c.name + ' (' + c.id + ')', c.kind, JSON.stringify(c.config_masked || {})]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const stTd = document.createElement('td');
        stTd.appendChild(badge(c.last_status || 'unknown'));
        tr.appendChild(stTd);
        const act = document.createElement('td');
        const cBtn = document.createElement('button');
        cBtn.className = 'btn ghost';
        cBtn.type = 'button';
        cBtn.textContent = '复制 ID';
        cBtn.addEventListener('click', () => void runAction(async () => {
          await hostCopy(c.id, `已复制渠道 ID ${c.id}`);
        }, `已复制渠道 ID ${c.id}`));
        const tBtn = document.createElement('button');
        tBtn.className = 'btn ghost btn-gap';
        tBtn.type = 'button';
        tBtn.textContent = '测试';
        tBtn.addEventListener('click', () => void runAction(async () => {
          const r = await invoke('notify.channel.test', { id: c.id });
          await refresh();
          setStatus(r.ok ? `渠道 ${c.name} 测试成功 (HTTP ${r.http_status})` : `测试失败：${r.error || '未知错误'}`);
        }));
        const dBtn = document.createElement('button');
        dBtn.className = 'btn danger btn-gap';
        dBtn.type = 'button';
        dBtn.textContent = '删除';
        dBtn.addEventListener('click', () => {
          void runAction(async () => {
            const ok = await hostConfirm('删除通知渠道', `确认删除通知渠道「${c.name}」及其加密凭据？`, { danger: true, confirmLabel: '确认删除' });
            if (!ok) return;
            await invoke('notify.channel.delete', { id: c.id });
            await refresh();
            setStatus(`已删除渠道 ${c.name}`);
          });
        });
        act.append(cBtn, tBtn, dBtn);
        tr.appendChild(act);
        ct.appendChild(tr);
      }

      const rt = document.getElementById('rules-tbody');
      rt.replaceChildren();
      for (const r of rls) {
        const tr = document.createElement('tr');
        const quiet = r.quiet_start ? `${r.quiet_start}-${r.quiet_end} (${r.quiet_tz})` : '关闭';
        for (const txt of [r.name, r.source_pattern, r.min_severity, `${r.cooldown_sec}s`, quiet]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const act = document.createElement('td');
        const dBtn = document.createElement('button');
        dBtn.className = 'btn danger';
        dBtn.type = 'button';
        dBtn.textContent = '删除';
        dBtn.addEventListener('click', () => {
          void runAction(async () => {
            const ok = await hostConfirm('删除路由规则', `确认删除路由规则「${r.name}」？`, { danger: true, confirmLabel: '确认删除' });
            if (!ok) return;
            await invoke('notify.rule.delete', { id: r.id });
            await refresh();
            setStatus(`已删除规则 ${r.name}`);
          });
        });
        act.appendChild(dBtn);
        tr.appendChild(act);
        rt.appendChild(tr);
      }

      const dt = document.getElementById('deliveries-tbody');
      dt.replaceChildren();
      for (const d of dels) {
        const tr = document.createElement('tr');
        for (const txt of [d.source, d.severity, d.title, d.channel_name]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const stTd = document.createElement('td');
        stTd.appendChild(badge(d.status));
        tr.appendChild(stTd);
        const atTd = document.createElement('td');
        atTd.textContent = String(d.attempts || 0);
        tr.appendChild(atTd);
        dt.appendChild(tr);
      }
      setStatus('已连接');
    } catch (err) {
      setStatus('加载失败：' + (err.message || '未知错误'));
    }
  }

  document.getElementById('btn-refresh').addEventListener('click', () => void refresh());
  document.getElementById('btn-save-ch').addEventListener('click', () => void runAction(async () => {
    const kind = document.getElementById('ch-kind').value;
    const urlVal = document.getElementById('ch-url').value.trim();
    const secretVal = document.getElementById('ch-secret').value.trim();
    const targetVal = document.getElementById('ch-target').value.trim();
    const config = {};
    if (kind === 'telegram') {
      config.bot_token = secretVal;
      config.chat_id = targetVal;
      if (urlVal) config.api_base = urlVal;
    } else if (kind === 'smtp') {
      config.smtp_host = urlVal;
      config.smtp_port = 587;
      config.smtp_pass = secretVal;
      config.smtp_from = targetVal.split(',')[0]?.trim() || '';
      config.smtp_to = targetVal.split(',').map((s) => s.trim()).filter(Boolean);
    } else {
      config.webhook_url = urlVal;
      if (secretVal) config.secret = secretVal;
    }
    await invoke('notify.channel.upsert', { name: document.getElementById('ch-name').value.trim(), kind, enabled: true, config });
    document.getElementById('ch-secret').value = '';
    await refresh();
  }, '渠道已加密保存'));

  document.getElementById('btn-save-rl').addEventListener('click', () => void runAction(async () => {
    await invoke('notify.rule.upsert', {
      name: document.getElementById('rl-name').value.trim(),
      enabled: true,
      source_pattern: document.getElementById('rl-src').value.trim() || '*',
      min_severity: document.getElementById('rl-sev').value,
      channel_ids: document.getElementById('rl-chs').value.split(',').map((s) => s.trim()).filter(Boolean),
      cooldown_sec: Number(document.getElementById('rl-cool').value || 300),
      quiet_start: document.getElementById('rl-qs').value.trim(),
      quiet_end: document.getElementById('rl-qe').value.trim(),
      quiet_tz: document.getElementById('rl-tz').value.trim() || 'UTC',
      allow_critical_bypass: true,
    });
    await refresh();
  }, '路由规则已保存'));

  document.getElementById('btn-dispatch').addEventListener('click', () => void runAction(async () => {
    const res = await invoke('notify.dispatch', {
      source: document.getElementById('dp-src').value.trim(),
      severity: document.getElementById('dp-sev').value,
      title: document.getElementById('dp-title').value.trim(),
      message: document.getElementById('dp-msg').value.trim(),
    });
    await refresh();
    setStatus(`演练分发完成：命中 ${res.matched_rules ?? 0} 条规则，成功 ${res.sent ?? 0} / 降噪 ${res.suppressed ?? 0} / 失败 ${res.failed ?? 0}`);
  }));

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
    send({ t: 'ui.resize', height: Math.ceil(document.getElementById('notify-root').getBoundingClientRect().height) + 24 });
  });
  ro.observe(document.getElementById('notify-root'));

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
