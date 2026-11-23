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
  const pendingEnsure = new Map();
  let drawerOpen = false;

  const setStatus = (t) => { statusEl.textContent = t; };
  const send = (msg) => { if (port) port.postMessage(msg); };

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function timeoutForOperation(operation) {
    if (
      operation === 'docker.compose.deploy' ||
      operation === 'docker.container.ports.apply' ||
      operation === 'docker.container.proxy.upsert'
    ) {
      return 95000;
    }
    if (operation === 'docker.images.prune') return 65000;
    if (
      operation === 'docker.container.action' ||
      operation === 'docker.container.limits' ||
      operation === 'docker.container.remove' ||
      operation === 'docker.compose.remove' ||
      operation === 'docker.network.create' ||
      operation === 'docker.network.membership' ||
      operation === 'docker.container.proxy.delete'
    ) {
      return 35000;
    }
    return 15000;
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
    const timeoutMs = timeoutForOperation(operation);
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`宿主响应超时 (${Math.round(timeoutMs / 1000)}s)`));
    }, timeoutMs);
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

  const ensurePlugins = (plugins, reason) => new Promise((resolve, reject) => {
    if (!port) return reject(new Error('宿主桥尚未就绪'));
    const list = Array.isArray(plugins) ? plugins.filter(Boolean) : [];
    if (list.length === 0) return reject(new Error('未指定需要启用的组件'));
    const id = `ep_${++seq}`;
    const timer = setTimeout(() => {
      pendingEnsure.delete(id);
      reject(new Error('启用组件响应超时 (125s)'));
    }, 125000);
    pendingEnsure.set(id, { resolve, reject, timer });
    const msg = { t: 'ui.ensure_plugins', id, plugins: list };
    if (reason) msg.reason = String(reason);
    send(msg);
  });

  function reportHostHeight() {
    const rootEl = document.getElementById('docker-root');
    const contentH = rootEl ? Math.ceil(rootEl.getBoundingClientRect().height) + 24 : 560;
    send({ t: 'ui.resize', height: drawerOpen ? Math.max(contentH, 760) : contentH });
  }

  function normalizeContainerName(name) {
    return String(name || '').trim().replace(/^\/+/, '');
  }

  function buildSafeProxyHref(domain, pathPrefix, tlsMode) {
    const cleanDomain = String(domain || '').trim();
    if (!cleanDomain || /[\s/\\@<>"'`\u0000-\u001f]/.test(cleanDomain)) return null;
    const rawPath = String(pathPrefix || '/').trim() || '/';
    const safePath = rawPath.startsWith('/') ? rawPath : '/' + rawPath;
    if (/[\s<>"'`\u0000-\u001f]/.test(safePath)) return null;
    const scheme = tlsMode === 'off' ? 'http' : 'https';
    return `${scheme}://${cleanDomain}${safePath}`;
  }

  function indexIngressLinks(data) {
    const map = new Map();
    const pushLink = (name, lk) => {
      const key = normalizeContainerName(name);
      if (!key || !lk || !lk.domain) return;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(lk);
    };
    const rawList = Array.isArray(data?.ingress_links)
      ? data.ingress_links
      : Array.isArray(data?.proxy_links)
        ? data.proxy_links
        : [];
    for (const lk of rawList) {
      pushLink(lk.container_name, lk);
    }
    if (data?.proxy_links && !Array.isArray(data.proxy_links) && typeof data.proxy_links === 'object') {
      for (const [k, list] of Object.entries(data.proxy_links)) {
        if (Array.isArray(list)) {
          for (const lk of list) pushLink(k, lk);
        }
      }
    }
    return map;
  }

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
    const cls = state === 'running' ? 'ok' : (state === 'error' || state === 'degraded' ? 'err' : 'warn');
    span.className = 'badge ' + cls;
    span.textContent = state;
    return span;
  }

  function makeBtn(label, className, onClick) {
    const btn = document.createElement('button');
    btn.className = className;
    btn.type = 'button';
    btn.textContent = label;
    btn.addEventListener('click', onClick);
    return btn;
  }

  function renderInspectBox(ct) {
    const box = document.getElementById('inspect-box');
    const title = document.getElementById('inspect-title');
    const meta = document.getElementById('inspect-meta');
    if (!ct) {
      box.hidden = true;
      return;
    }
    title.textContent = `容器详情：${ct.name || ct.id}（${ct.state || '-'}）`;
    const parts = [
      `镜像：${ct.image || '-'}`,
      `内存：${Number(ct.memory_mb || 0).toFixed(1)} MiB / 上限 ${ct.memory_limit_mb > 0 ? Number(ct.memory_limit_mb).toFixed(1) + ' MiB' : '不限'}`,
      `CPU：${Number(ct.cpu_percent || 0).toFixed(1)}%`,
      `重启次数：${ct.restart_count ?? 0}`,
      `OOMKilled：${ct.oom_killed ? '是（发生过 OOM）' : '否'}`,
    ];
    meta.textContent = parts.join(' · ');
    box.hidden = false;
  }

  async function refresh() {
    try {
      const data = await invoke('docker.overview', {});
      const d = data.daemon || {};
      document.getElementById('st-daemon').textContent = d.available ? `v${d.server_version || 'ok'}` : '未连接';
      document.getElementById('st-ct').textContent = d.available ? `${d.containers_running || 0} / ${d.containers_total || 0}` : '-';
      document.getElementById('st-img').textContent = String((data.images || []).length);
      document.getElementById('st-st').textContent = String((data.stacks || []).length);

      const linksByContainer = indexIngressLinks(data);
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

        const cLinks = [
          ...(linksByContainer.get(normalizeContainerName(c.name)) || []),
          ...(Array.isArray(c.ingress_links) ? c.ingress_links : []),
          ...(Array.isArray(c.proxy_links) ? c.proxy_links : []),
        ];
        const pTd = document.createElement('td');
        const pWrap = document.createElement('div');
        pWrap.className = 'port-cell';
        const pText = document.createElement('span');
        pText.textContent = (c.ports || []).join(', ') || '-';
        pWrap.appendChild(pText);
        if (cLinks.length > 0) {
          const pillRow = document.createElement('div');
          pillRow.className = 'proxy-pills-row';
          for (const lk of cLinks) {
            const href = buildSafeProxyHref(lk.domain, lk.path_prefix, lk.tls_mode);
            const label = `${lk.tls_mode === 'off' ? 'http' : 'https'}://${lk.domain}${lk.path_prefix && lk.path_prefix !== '/' ? lk.path_prefix : ''}`;
            if (href) {
              const a = document.createElement('a');
              a.className = 'proxy-pill';
              a.href = href;
              a.target = '_blank';
              a.rel = 'noopener noreferrer';
              a.textContent = label;
              pillRow.appendChild(a);
            }
          }
          if (pillRow.childElementCount > 0) pWrap.appendChild(pillRow);
        }
        pTd.appendChild(pWrap);
        tr.appendChild(pTd);

        const act = document.createElement('td');
        act.className = 'row-actions';

        const settingsBtn = makeBtn('⚙ 设置', 'btn btn-sm', () => {
          if (window.QWQContainerDrawer) {
            void window.QWQContainerDrawer.open(c.id, 'overview');
          }
        });

        const startBtn = makeBtn('启动', 'btn ghost btn-sm', () => void runAction(async () => {
          await invoke('docker.container.action', { id: c.id, action: 'start' });
          await refresh();
        }, `已启动容器 ${c.name}`));

        const stopBtn = makeBtn('停止', 'btn ghost btn-sm', () => void runAction(async () => {
          await invoke('docker.container.action', { id: c.id, action: 'stop' });
          await refresh();
        }, `已停止容器 ${c.name}`));

        const restartBtn = makeBtn('重启', 'btn ghost btn-sm', () => void runAction(async () => {
          await invoke('docker.container.action', { id: c.id, action: 'restart' });
          await refresh();
        }, `已重启容器 ${c.name}`));

        const inspectBtn = makeBtn('详情/限额', 'btn ghost btn-sm', () => void runAction(async () => {
          document.getElementById('lim-id').value = c.short_id || c.id;
          document.getElementById('lim-mem').value = '';
          document.getElementById('lim-cpu').value = '';
          const res = await invoke('docker.container.inspect', { id: c.id });
          renderInspectBox(res.container);
        }, `已加载容器 ${c.name} 详情，可在下方留空或调整资源限额`));

        const logsBtn = makeBtn('日志', 'btn ghost btn-sm', () => void runAction(async () => {
          document.getElementById('lim-id').value = c.short_id || c.id;
          const res = await invoke('docker.container.logs', { id: c.id, tail: 100 });
          document.getElementById('logs-pre').textContent = res.logs || '(无日志输出)';
          switchTab('images');
        }, `已加载容器 ${c.name} 最新日志`));

        const removeBtn = makeBtn('删除', 'btn danger btn-sm', () => void runAction(async () => {
          const domains = cLinks.map((lk) => lk.domain).filter(Boolean);
          const body = domains.length > 0
            ? `确认强制删除容器「${c.name}」(${c.short_id})？检测到关联了 ${domains.length} 条反代域名（${domains.join('、')}），将同步清理关联反代规则以防 502 死链（如需保留反代请在「⚙ 设置」中取消勾选）。`
            : `确认强制删除容器「${c.name}」(${c.short_id})？此操作不可逆。`;
          const ok = await hostConfirm('删除容器', body, { danger: true, confirmLabel: '确认删除' });
          if (!ok) return;
          const removePayload = { id: c.id, force: true };
          if (domains.length > 0) removePayload.cleanup_linked_proxies = true;
          await invoke('docker.container.remove', removePayload);
          await refresh();
          setStatus(`已删除容器 ${c.name}`);
        }));

        act.append(settingsBtn, startBtn, stopBtn, restartBtn, inspectBtn, logsBtn, removeBtn);
        tr.appendChild(act);
        ct.appendChild(tr);
      }

      const st = document.getElementById('stacks-tbody');
      st.replaceChildren();
      for (const s of data.stacks || []) {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        const nameBtn = makeBtn(s.name, 'link-btn', () => {
          document.getElementById('cp-name').value = s.name;
          document.getElementById('cp-yaml').value = s.compose_yaml || '';
          setStatus(`已回填 Compose 栈「${s.name}」到编辑器`);
        });
        nameTd.appendChild(nameBtn);
        tr.appendChild(nameTd);

        const stTd = document.createElement('td');
        stTd.appendChild(badge(s.status || 'saved'));
        tr.appendChild(stTd);

        const revTd = document.createElement('td');
        revTd.textContent = `v${s.revision}`;
        tr.appendChild(revTd);

        const infoTd = document.createElement('td');
        const warns = Array.isArray(s.warnings) ? s.warnings : [];
        if (warns.length > 0) {
          const warnDiv = document.createElement('div');
          warnDiv.className = 'stack-warn';
          warnDiv.textContent = '预警：' + warns.join('；');
          infoTd.appendChild(warnDiv);
        }
        if (s.last_error) {
          const errDiv = document.createElement('div');
          errDiv.className = 'stack-err';
          errDiv.textContent = '最近错误：' + s.last_error;
          infoTd.appendChild(errDiv);
        }
        if (warns.length === 0 && !s.last_error) {
          infoTd.textContent = '无高危提示';
        }
        tr.appendChild(infoTd);

        const act = document.createElement('td');
        const dBtn = makeBtn('移除', 'btn danger btn-sm', () => {
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
    const id = document.getElementById('lim-id').value.trim();
    const memRaw = document.getElementById('lim-mem').value.trim();
    const cpuRaw = document.getElementById('lim-cpu').value.trim();
    if (!id) throw new Error('请先选择或输入目标容器 ID / 名称');
    if (memRaw === '' && cpuRaw === '') throw new Error('请至少填写内存上限或 CPU 核数上限之一（留空表示不修改该项）');
    const payload = { id };
    if (memRaw !== '') payload.memory_mb = Number(memRaw);
    if (cpuRaw !== '') payload.cpus = Number(cpuRaw);
    await invoke('docker.container.limits', payload);
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
    if (data.t === 'ui.ensure_plugins.result' && pendingEnsure.has(data.id)) {
      const req = pendingEnsure.get(data.id);
      clearTimeout(req.timer);
      pendingEnsure.delete(data.id);
      if (data.ok) req.resolve(data.data || { ready: true, installed: [], enabled: [], already_ready: [] });
      else req.reject(new Error(extractErrorMessage(data.problem || data.error, '启用组件失败')));
      return;
    }
    if (data.t === 'ui.settings' && (data.theme === 'light' || data.theme === 'dark')) {
      root.dataset.theme = data.theme;
    }
  }

  if (window.QWQContainerDrawer) {
    window.QWQContainerDrawer.init({
      invoke,
      hostConfirm,
      hostCopy,
      ensurePlugins,
      onListChanged: refresh,
      setGlobalStatus: setStatus,
      onDrawerToggle: (isOpen) => {
        drawerOpen = Boolean(isOpen);
        reportHostHeight();
      },
    });
  }

  const ro = new ResizeObserver(() => {
    reportHostHeight();
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
    for (const req of pendingEnsure.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
    }
    pendingEnsure.clear();
    if (port) {
      port.onmessage = null;
      if (typeof port.close === 'function') port.close();
      port = null;
    }
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
