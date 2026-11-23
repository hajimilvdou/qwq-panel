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
    const id = `dk_${++seq}`;
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

  function switchTab(tab) {
    for (const b of document.querySelectorAll('#nav-tabs button')) b.classList.toggle('active', b.dataset.tab === tab);
    for (const p of document.querySelectorAll('[data-pane]')) p.hidden = p.dataset.pane !== tab;
  }

  document.getElementById('nav-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (btn) switchTab(btn.dataset.tab);
  });

  function badge(state) {
    const span = document.createElement('span');
    span.className = 'badge ' + (state === 'running' ? 'ok' : (state === 'error' ? 'err' : 'warn'));
    span.textContent = state;
    return span;
  }

  async function refresh() {
    try {
      const data = await invoke('docker.overview', {});
      const d = data.daemon || {};
      document.getElementById('st-daemon').textContent = d.available ? `v${d.server_version || 'ok'}` : '未连接';
      document.getElementById('st-ct').textContent = d.available ? `${d.containers_running || 0} / ${d.containers_total || 0}` : '-';
      document.getElementById('st-img').textContent = String((data.images || []).length);
      document.getElementById('st-st').textContent = String((data.stacks || []).length);

      const ct = document.getElementById('containers-tbody');
      ct.replaceChildren();
      for (const c of data.containers || []) {
        const tr = document.createElement('tr');
        for (const txt of [`${c.name} (${c.short_id})`, c.image]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const stTd = document.createElement('td');
        stTd.appendChild(badge(c.state));
        tr.appendChild(stTd);
        const pTd = document.createElement('td');
        pTd.textContent = (c.ports || []).join(', ') || '-';
        tr.appendChild(pTd);
        const act = document.createElement('td');
        const rBtn = document.createElement('button');
        rBtn.className = 'btn ghost';
        rBtn.type = 'button';
        rBtn.textContent = '重启';
        rBtn.addEventListener('click', () => void runAction(async () => {
          await invoke('docker.container.action', { id: c.id, action: 'restart' });
          await refresh();
        }, `已重启容器 ${c.name}`));
        const lBtn = document.createElement('button');
        lBtn.className = 'btn ghost btn-gap';
        lBtn.type = 'button';
        lBtn.textContent = '日志';
        lBtn.addEventListener('click', () => void runAction(async () => {
          document.getElementById('lim-id').value = c.short_id;
          const res = await invoke('docker.container.logs', { id: c.id, tail: 100 });
          document.getElementById('logs-pre').textContent = res.logs || '(无日志输出)';
          switchTab('images');
        }, `已加载容器 ${c.name} 最新日志`));
        act.append(rBtn, lBtn);
        tr.appendChild(act);
        ct.appendChild(tr);
      }

      const st = document.getElementById('stacks-tbody');
      st.replaceChildren();
      for (const s of data.stacks || []) {
        const tr = document.createElement('tr');
        for (const txt of [s.name, s.status, `v${s.revision}`, (s.warnings || []).join('；') || '无高危提示']) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const act = document.createElement('td');
        const dBtn = document.createElement('button');
        dBtn.className = 'btn danger';
        dBtn.type = 'button';
        dBtn.textContent = '移除';
        dBtn.addEventListener('click', () => {
          void runAction(async () => {
            const ok = await hostConfirm('移除 Compose 编排栈', `确认停止并移除 Compose 编排栈「${s.name}」？`, { danger: true, confirmLabel: '确认移除' });
            if (!ok) return;
            await invoke('docker.compose.remove', { name: s.name });
            await refresh();
            setStatus(`已移除栈 ${s.name}`);
          });
        });
        act.appendChild(dBtn);
        tr.appendChild(act);
        st.appendChild(tr);
      }

      const it = document.getElementById('images-tbody');
      it.replaceChildren();
      for (const im of data.images || []) {
        const tr = document.createElement('tr');
        for (const txt of [im.id, (im.tags || []).join(', ') || '<none>', (im.size_mb || 0).toFixed(1)]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        it.appendChild(tr);
      }
      setStatus(d.available ? '已连接 Docker' : (d.reason || '未检测到 Docker'));
    } catch (err) {
      setStatus('加载失败：' + (err.message || '未知错误'));
    }
  }

  document.getElementById('btn-refresh').addEventListener('click', () => void refresh());
  document.getElementById('btn-limits').addEventListener('click', () => void runAction(async () => {
    await invoke('docker.container.limits', {
      id: document.getElementById('lim-id').value.trim(),
      memory_mb: Number(document.getElementById('lim-mem').value || 0),
      cpus: Number(document.getElementById('lim-cpu').value || 0),
    });
    await refresh();
  }, '容器资源限额已更新'));

  const deployStack = (dryRun) => void runAction(async () => {
    await invoke('docker.compose.deploy', {
      name: document.getElementById('cp-name').value.trim(),
      compose_yaml: document.getElementById('cp-yaml').value,
      dry_run: dryRun,
    });
    await refresh();
  }, dryRun ? 'Compose 编排已通过安全扫描并暂存' : 'Compose 编排栈部署完成');

  document.getElementById('btn-deploy').addEventListener('click', () => deployStack(false));
  document.getElementById('btn-dryrun').addEventListener('click', () => deployStack(true));

  document.getElementById('btn-prune').addEventListener('click', () => {
    void runAction(async () => {
      const ok = await hostConfirm('清理悬空镜像', '确认清理所有未被容器引用的悬空 Docker 镜像？', { danger: true, confirmLabel: '确认清理' });
      if (!ok) return;
      const res = await invoke('docker.images.prune', { all: false });
      await refresh();
      setStatus(`已清理 ${res.deleted_count ?? 0} 个镜像，释放 ${(res.space_reclaimed_mb || 0).toFixed(1)} MiB`);
    });
  });

  document.getElementById('btn-copy-logs').addEventListener('click', () => {
    void runAction(async () => {
      await hostCopy(document.getElementById('logs-pre').textContent || '', '已复制容器日志');
    }, '已复制容器日志');
  });

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
    send({ t: 'ui.resize', height: Math.ceil(document.getElementById('docker-root').getBoundingClientRect().height) + 24 });
  });
  ro.observe(document.getElementById('docker-root'));

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
