// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const hash = new URLSearchParams(location.hash.slice(1));
  const initialTheme = pick(hash.get('theme'), ['light', 'dark'], 'light');
  root.dataset.theme = initialTheme;
  root.style.colorScheme = initialTheme;
  root.dataset.density = pick(hash.get('density'), ['comfortable', 'compact'], 'comfortable');

  function applyHostVisualSettings(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.theme === 'light' || msg.theme === 'dark') {
      root.dataset.theme = msg.theme;
      root.style.colorScheme = msg.theme;
    }
    if (msg.density === 'comfortable' || msg.density === 'compact') {
      root.dataset.density = msg.density;
    }
    if (msg.tokens && typeof msg.tokens === 'object') {
      for (const [k, v] of Object.entries(msg.tokens)) {
        if (k.startsWith('--') && typeof v === 'string' && !/[;{}<>]/.test(v)) {
          root.style.setProperty(k, v.trim());
        }
      }
      if (msg.tokens['--accent-strong']) root.style.setProperty('--cocoa', msg.tokens['--accent-strong'].trim());
      else if (msg.tokens['--accent']) root.style.setProperty('--cocoa', msg.tokens['--accent'].trim());
      if (msg.tokens['--on-accent']) root.style.setProperty('--on-cocoa', msg.tokens['--on-accent'].trim());
    }
  }

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
      operation === 'docker.images.pull'
    ) {
      return 620000;
    }
    if (
      operation === 'docker.container.ports.apply' ||
      operation === 'docker.container.proxy.upsert'
    ) {
      return 95000;
    }
    if (operation === 'docker.images.prune' || operation === 'docker.volumes.prune') return 65000;
    if (
      operation === 'docker.container.action' ||
      operation === 'docker.container.limits' ||
      operation === 'docker.container.remove' ||
      operation === 'docker.images.remove' ||
      operation === 'docker.volumes.remove' ||
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

  let lastSentHeight = 0;
  function reportHostHeight() {
    const rootEl = document.getElementById('docker-root');
    const contentH = rootEl ? Math.ceil(rootEl.getBoundingClientRect().height) + 52 : 560;
    const height = drawerOpen || quickRunOpen ? Math.max(contentH, 760) : contentH;
    if (Math.abs(height - lastSentHeight) < 2) return;
    lastSentHeight = height;
    send({ t: 'ui.resize', height });
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
      const guideEl = document.getElementById('docker-install-guide');
      if (guideEl) {
        guideEl.hidden = Boolean(d.available);
        const reasonEl = document.getElementById('docker-install-reason');
        if (reasonEl && !d.available) {
          reasonEl.textContent = (d.reason ? `当前检测结果：${d.reason}。` : '') + '可在宿主机 SSH 中运行以下官方脚本一键安装并启动 Docker：';
        }
      }
      document.getElementById('st-daemon').textContent = d.available ? `v${d.server_version || 'ok'}` : '未连接';
      document.getElementById('st-ct').textContent = d.available ? `${d.containers_running || 0} / ${d.containers_total || 0}` : '-';
      document.getElementById('st-img').textContent = `${(data.images || []).length} / ${(data.volumes || []).length}`;
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
        const actTd = document.createElement('td');
        const delImgBtn = makeBtn('删除', 'btn danger btn-sm', () => void runAction(async () => {
          const label = (im.tags && im.tags[0]) ? im.tags[0] : im.id;
          const ok = await hostConfirm('删除本地镜像', `确认删除本地 Docker 镜像「${label}」(${im.id})？`, { danger: true, confirmLabel: '确认删除' });
          if (!ok) return;
          await invoke('docker.images.remove', { id: im.id, force: false });
          await refresh();
          setStatus(`已删除镜像 ${label}`);
        }));
        actTd.appendChild(delImgBtn);
        tr.appendChild(actTd);
        it.appendChild(tr);
      }

      const vt = document.getElementById('volumes-tbody');
      if (vt) {
        vt.replaceChildren();
        const vols = Array.isArray(data.volumes) ? data.volumes : [];
        if (vols.length === 0) {
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 4;
          td.textContent = d.available ? '暂无本地存储卷' : '未连接 Docker';
          tr.appendChild(td);
          vt.appendChild(tr);
        } else {
          for (const v of vols) {
            const tr = document.createElement('tr');
            for (const txt of [v.name || '-', v.driver || 'local', v.mountpoint || '-']) {
              const td = document.createElement('td');
              td.textContent = txt;
              tr.appendChild(td);
            }
            const actTd = document.createElement('td');
            const delVolBtn = makeBtn('删除', 'btn danger btn-sm', () => void runAction(async () => {
              const ok = await hostConfirm('删除存储卷', `确认不可逆删除存储卷「${v.name}」及其数据？正在被容器使用的卷会拒绝删除。`, { danger: true, confirmLabel: '确认删除' });
              if (!ok) return;
              await invoke('docker.volumes.remove', { name: v.name, force: false });
              await refresh();
              setStatus(`已删除存储卷 ${v.name}`);
            }));
            actTd.appendChild(delVolBtn);
            tr.appendChild(actTd);
            vt.appendChild(tr);
          }
        }
      }
      setStatus(d.available ? '已连接 Docker' : (d.reason || '未检测到 Docker'));
    } catch (err) {
      setStatus('加载失败：' + (err.message || '未知错误'));
    }
  }

  document.getElementById('btn-copy-install-cmd')?.addEventListener('click', () => void runAction(async () => {
    const cmd = document.getElementById('docker-install-cmd')?.textContent || 'curl -fsSL https://get.docker.com | sh && systemctl enable --now docker';
    await hostCopy(cmd, '已复制 Docker 安装命令');
  }, '已复制 Docker 安装命令'));
  document.getElementById('btn-retry-daemon')?.addEventListener('click', () => void refresh());

  document.getElementById('btn-pull-image')?.addEventListener('click', () => void runAction(async () => {
    const imgInput = document.getElementById('pull-image-input');
    const image = (imgInput?.value || '').trim();
    if (!image) throw new Error('请输入要拉取的镜像名，例如 nginx:alpine');
    setStatus(`正在拉取镜像 ${image}（大镜像最长支持 10 分钟）…`);
    const res = await invoke('docker.images.pull', { image });
    if (imgInput) imgInput.value = '';
    await refresh();
    setStatus(`镜像 ${image} 拉取完成：${res.status || 'OK'}`);
  }));

  document.getElementById('btn-prune-volumes')?.addEventListener('click', () => void runAction(async () => {
    const ok = await hostConfirm('清理未挂载存储卷', '确认删除所有未被任何容器挂载的闲置存储卷？此操作不可逆。', { danger: true, confirmLabel: '确认清理' });
    if (!ok) return;
    const res = await invoke('docker.volumes.prune', {});
    await refresh();
    setStatus(`已清理 ${res.deleted_count ?? 0} 个存储卷，释放 ${(res.space_reclaimed_mb || 0).toFixed(1)} MiB`);
  }));

  /* ==================== 可视化「快速新建容器」向导 ==================== */
  const SAFE_CONTAINER_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
  const SAFE_ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
  const SAFE_RESTART_POLICIES = new Set(['unless-stopped', 'always', 'on-failure', 'no']);
  const yamlSingleQuote = (val) => "'" + String(val).replace(/'/g, "''") + "'";
  const escapeComposeDollars = (val) => String(val).split('$').join('$$');

  function normalizeBindIP(raw) {
    const s = String(raw || '').trim();
    if (!s) return '';
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) {
      const parts = s.split('.').map(Number);
      if (parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
        return s;
      }
      return null;
    }
    const unwrapped = s.startsWith('[') && s.endsWith(']') ? s.slice(1, -1) : s;
    if (unwrapped.includes(':') && /^[0-9a-fA-F:]+$/.test(unwrapped) && !unwrapped.includes(':::')) {
      const dbl = unwrapped.split('::');
      if (dbl.length <= 2) {
        const groups = unwrapped.split(':').filter((g) => g.length > 0);
        if (groups.every((g) => g.length <= 4) && (dbl.length === 2 ? groups.length <= 7 : groups.length === 8)) {
          return `[${unwrapped}]`;
        }
      }
    }
    return null;
  }

  function buildManagedComposeFromQuickRun(spec) {
    const name = String(spec.name || '').trim().toLowerCase();
    if (!SAFE_CONTAINER_NAME_RE.test(name)) {
      throw new Error('容器名称需为 1~48 位小写字母、数字、下划线或短横线，且以字母或数字开头');
    }
    const image = String(spec.image || '').trim();
    if (!image || /[\s'"`$;|&\\]/.test(image) || image.includes('..')) {
      throw new Error('请输入合法的 Docker 镜像名（例如 nginx:alpine 或 vaultwarden/server:latest）');
    }
    const restartPolicy = SAFE_RESTART_POLICIES.has(spec.restartPolicy) ? spec.restartPolicy : 'unless-stopped';

    const lines = [
      'services:',
      `  ${name}:`,
      `    image: ${yamlSingleQuote(image)}`,
      `    container_name: ${yamlSingleQuote(name)}`,
      `    restart: ${restartPolicy}`,
    ];

    if (spec.memoryLimitMB !== undefined && spec.memoryLimitMB !== null && spec.memoryLimitMB !== '') {
      const mem = Number(spec.memoryLimitMB);
      if (!Number.isInteger(mem) || mem < 16 || mem > 65536) {
        throw new Error('内存上限必须为 16 ~ 65536 之间的整数（MiB）');
      }
      lines.push(`    mem_limit: ${mem}m`);
    }

    const ports = Array.isArray(spec.ports) ? spec.ports : [];
    if (ports.length > 0) {
      lines.push('    ports:');
      for (const p of ports) {
        const hp = Number(p.hostPort);
        const cp = Number(p.containerPort);
        if (!Number.isInteger(hp) || hp < 1 || hp > 65535 || !Number.isInteger(cp) || cp < 1 || cp > 65535) {
          throw new Error(`端口号必须在 1 ~ 65535 之间（当前 ${p.hostPort}:${p.containerPort}）`);
        }
        const normalizedBind = normalizeBindIP(p.bindIP ?? '127.0.0.1');
        if (normalizedBind === null) {
          throw new Error(`非法的绑定 IP 地址：${p.bindIP}`);
        }
        const proto = p.protocol === 'udp' ? 'udp' : 'tcp';
        const hostBind = normalizedBind && normalizedBind !== '0.0.0.0' ? `${normalizedBind}:` : '';
        lines.push(`      - ${yamlSingleQuote(`${hostBind}${hp}:${cp}/${proto}`)}`);
      }
    }

    const namedVolumes = [];
    const volumes = Array.isArray(spec.volumes) ? spec.volumes : [];
    if (volumes.length > 0) {
      lines.push('    volumes:');
      for (const v of volumes) {
        const hp = String(v.hostPath || '').trim();
        const cp = String(v.containerPath || '').trim();
        if (!hp || !cp.startsWith('/') || /[\r\n\x00:]/.test(hp) || /[\r\n\x00:]/.test(cp)) {
          throw new Error('挂载目录需填写不含冒号与控制字符的宿主机路径/卷名，且容器内路径必须以 / 开头');
        }
        if (SAFE_CONTAINER_NAME_RE.test(hp) && !namedVolumes.includes(hp)) {
          namedVolumes.push(hp);
        }
        const suffix = v.readOnly ? ':ro' : '';
        const safeVol = escapeComposeDollars(`${hp}:${cp}${suffix}`);
        lines.push(`      - ${yamlSingleQuote(safeVol)}`);
      }
    }

    const envs = Array.isArray(spec.envs) ? spec.envs : [];
    const cleanEnvs = envs.filter((e) => String(e.key || '').trim() !== '');
    if (cleanEnvs.length > 0) {
      lines.push('    environment:');
      for (const e of cleanEnvs) {
        const k = String(e.key || '').trim();
        if (!SAFE_ENV_KEY_RE.test(k)) {
          throw new Error(`非法环境变量名 "${k}"`);
        }
        const rawVal = String(e.value ?? '');
        if (/[\r\n\x00]/.test(rawVal)) {
          throw new Error(`环境变量 "${k}" 的值不能包含换行符或空字符`);
        }
        lines.push(`      ${k}: ${yamlSingleQuote(escapeComposeDollars(rawVal))}`);
      }
    }

    const netName = String(spec.networkName || '').trim();
    if (netName && netName !== 'bridge' && netName !== 'default') {
      if (!SAFE_CONTAINER_NAME_RE.test(netName)) {
        throw new Error('网络名称仅支持小写字母、数字、下划线或短横线');
      }
      lines.push('    networks:');
      lines.push(`      - ${yamlSingleQuote(netName)}`);
    }

    if (namedVolumes.length > 0) {
      lines.push('volumes:');
      for (const nv of namedVolumes) {
        lines.push(`  ${nv}: {}`);
      }
    }

    if (netName && netName !== 'bridge' && netName !== 'default') {
      lines.push('networks:');
      lines.push(`  ${netName}:`);
      lines.push('    external: true');
    }

    return { stackName: name, composeYAML: lines.join('\n') + '\n' };
  }

  let quickRunOpen = false;
  const qrBackdrop = document.getElementById('quick-run-backdrop');
  const qrModal = document.getElementById('quick-run-modal');
  const qrError = document.getElementById('qr-error');
  const qrPreviewBox = document.getElementById('qr-preview-box');
  const qrPreviewYaml = document.getElementById('qr-preview-yaml');

  function setQrError(msg) {
    if (!qrError) return;
    if (!msg) {
      qrError.hidden = true;
      qrError.textContent = '';
    } else {
      qrError.textContent = msg;
      qrError.hidden = false;
    }
  }

  function addQrPortRow(bindIP = '127.0.0.1', hostPort = '', containerPort = '', proto = 'tcp') {
    const list = document.getElementById('qr-ports-list');
    if (!list) return;
    const row = document.createElement('div');
    row.className = 'qr-row';
    const bindSel = document.createElement('select');
    bindSel.className = 'qr-bind';
    for (const [val, label] of [['127.0.0.1', '127.0.0.1 (仅本机回环)'], ['0.0.0.0', '0.0.0.0 (公网直连)']]) {
      const opt = document.createElement('option');
      opt.value = val;
      opt.textContent = label;
      if (val === bindIP) opt.selected = true;
      bindSel.appendChild(opt);
    }
    const hp = document.createElement('input');
    hp.className = 'qr-port qr-hp';
    hp.type = 'number';
    hp.min = '1';
    hp.max = '65535';
    hp.placeholder = '宿主机端口';
    hp.value = hostPort;
    const sep = document.createElement('span');
    sep.className = 'arrow-sep';
    sep.textContent = '→';
    const cp = document.createElement('input');
    cp.className = 'qr-port qr-cp';
    cp.type = 'number';
    cp.min = '1';
    cp.max = '65535';
    cp.placeholder = '容器端口';
    cp.value = containerPort;
    const prSel = document.createElement('select');
    prSel.className = 'qr-proto';
    for (const pr of ['tcp', 'udp']) {
      const opt = document.createElement('option');
      opt.value = pr;
      opt.textContent = pr.toUpperCase();
      if (pr === proto) opt.selected = true;
      prSel.appendChild(opt);
    }
    const rmBtn = makeBtn('删除', 'btn ghost btn-sm', () => row.remove());
    row.append(bindSel, hp, sep, cp, prSel, rmBtn);
    list.appendChild(row);
  }

  function addQrVolRow(hostPath = '', containerPath = '', readOnly = false) {
    const list = document.getElementById('qr-vols-list');
    if (!list) return;
    const row = document.createElement('div');
    row.className = 'qr-row';
    const hp = document.createElement('input');
    hp.className = 'qr-grow qr-vhp';
    hp.placeholder = '卷名或相对路径 (如 ./data)';
    hp.value = hostPath;
    const sep = document.createElement('span');
    sep.className = 'arrow-sep';
    sep.textContent = ':';
    const cp = document.createElement('input');
    cp.className = 'qr-grow qr-vcp';
    cp.placeholder = '容器内路径 (如 /data)';
    cp.value = containerPath;
    const roLabel = document.createElement('label');
    roLabel.className = 'chk-inline';
    const ro = document.createElement('input');
    ro.type = 'checkbox';
    ro.className = 'qr-vro';
    ro.checked = Boolean(readOnly);
    roLabel.append(ro, document.createTextNode('只读'));
    const rmBtn = makeBtn('删除', 'btn ghost btn-sm', () => row.remove());
    row.append(hp, sep, cp, roLabel, rmBtn);
    list.appendChild(row);
  }

  function addQrEnvRow(k = '', v = '') {
    const list = document.getElementById('qr-envs-list');
    if (!list) return;
    const row = document.createElement('div');
    row.className = 'qr-row';
    const keyIn = document.createElement('input');
    keyIn.className = 'qr-grow qr-ek';
    keyIn.placeholder = '变量名 (如 TZ)';
    keyIn.value = k;
    const eq = document.createElement('span');
    eq.className = 'arrow-sep';
    eq.textContent = '=';
    const valIn = document.createElement('input');
    valIn.className = 'qr-grow qr-ev';
    valIn.placeholder = '变量值 (如 Asia/Shanghai)';
    valIn.value = v;
    const rmBtn = makeBtn('删除', 'btn ghost btn-sm', () => row.remove());
    row.append(keyIn, eq, valIn, rmBtn);
    list.appendChild(row);
  }

  function collectQuickRunSpec() {
    const ports = [];
    for (const row of document.querySelectorAll('#qr-ports-list .qr-row')) {
      const hpRaw = row.querySelector('.qr-hp')?.value?.trim() || '';
      const cpRaw = row.querySelector('.qr-cp')?.value?.trim() || '';
      if (!hpRaw && !cpRaw) continue;
      ports.push({
        bindIP: row.querySelector('.qr-bind')?.value || '127.0.0.1',
        hostPort: Number(hpRaw),
        containerPort: Number(cpRaw),
        protocol: row.querySelector('.qr-proto')?.value || 'tcp',
      });
    }
    const volumes = [];
    for (const row of document.querySelectorAll('#qr-vols-list .qr-row')) {
      const hp = row.querySelector('.qr-vhp')?.value?.trim() || '';
      const cp = row.querySelector('.qr-vcp')?.value?.trim() || '';
      if (!hp && !cp) continue;
      volumes.push({
        hostPath: hp,
        containerPath: cp,
        readOnly: Boolean(row.querySelector('.qr-vro')?.checked),
      });
    }
    const envs = [];
    for (const row of document.querySelectorAll('#qr-envs-list .qr-row')) {
      const key = row.querySelector('.qr-ek')?.value?.trim() || '';
      const value = row.querySelector('.qr-ev')?.value ?? '';
      if (!key) continue;
      envs.push({ key, value });
    }
    const memRaw = document.getElementById('qr-mem')?.value?.trim() || '';
    return {
      name: document.getElementById('qr-name')?.value || '',
      image: document.getElementById('qr-image')?.value || '',
      restartPolicy: document.getElementById('qr-restart')?.value || 'unless-stopped',
      memoryLimitMB: memRaw ? Number(memRaw) : undefined,
      networkName: document.getElementById('qr-net')?.value || '',
      ports,
      volumes,
      envs,
    };
  }

  function openQuickRunModal() {
    if (!qrBackdrop || !qrModal) return;
    setQrError('');
    if (qrPreviewBox) qrPreviewBox.hidden = true;
    const portsList = document.getElementById('qr-ports-list');
    if (portsList && portsList.childElementCount === 0) addQrPortRow('127.0.0.1', '', '', 'tcp');
    quickRunOpen = true;
    qrBackdrop.hidden = false;
    qrModal.hidden = false;
    reportHostHeight();
    document.getElementById('qr-name')?.focus();
  }

  function closeQuickRunModal() {
    if (!qrBackdrop || !qrModal) return;
    quickRunOpen = false;
    qrBackdrop.hidden = true;
    qrModal.hidden = true;
    reportHostHeight();
  }

  document.getElementById('btn-open-quick-run')?.addEventListener('click', openQuickRunModal);
  document.getElementById('btn-open-quick-run-2')?.addEventListener('click', openQuickRunModal);
  document.getElementById('qr-close')?.addEventListener('click', closeQuickRunModal);
  qrBackdrop?.addEventListener('click', closeQuickRunModal);
  document.getElementById('qr-add-port')?.addEventListener('click', () => addQrPortRow('127.0.0.1', '', '', 'tcp'));
  document.getElementById('qr-add-vol')?.addEventListener('click', () => addQrVolRow('', '', false));
  document.getElementById('qr-add-env')?.addEventListener('click', () => addQrEnvRow('', ''));

  document.getElementById('qr-preview-btn')?.addEventListener('click', () => {
    setQrError('');
    try {
      const built = buildManagedComposeFromQuickRun(collectQuickRunSpec());
      if (qrPreviewYaml) qrPreviewYaml.textContent = built.composeYAML;
      if (qrPreviewBox) qrPreviewBox.hidden = false;
    } catch (err) {
      setQrError(err?.message || '参数校验失败');
    }
  });

  document.getElementById('qr-to-editor')?.addEventListener('click', () => {
    setQrError('');
    try {
      const built = buildManagedComposeFromQuickRun(collectQuickRunSpec());
      document.getElementById('cp-name').value = built.stackName;
      document.getElementById('cp-yaml').value = built.composeYAML;
      closeQuickRunModal();
      switchTab('compose');
      setStatus(`已将向导配置导出至 Compose 编辑器（栈 ${built.stackName}）`);
    } catch (err) {
      setQrError(err?.message || '参数校验失败');
    }
  });

  document.getElementById('qr-submit')?.addEventListener('click', () => {
    setQrError('');
    let built;
    try {
      built = buildManagedComposeFromQuickRun(collectQuickRunSpec());
    } catch (err) {
      setQrError(err?.message || '参数校验失败');
      return;
    }
    const submitBtn = document.getElementById('qr-submit');
    if (submitBtn) submitBtn.disabled = true;
    void runAction(async () => {
      try {
        setStatus(`正在部署受管容器栈 ${built.stackName}（首次拉取镜像最长支持 10 分钟）…`);
        await invoke('docker.compose.deploy', {
          name: built.stackName,
          compose_yaml: built.composeYAML,
          dry_run: false,
        });
        closeQuickRunModal();
        await refresh();
        setStatus(`受管容器栈 ${built.stackName} 已创建并启动`);
      } catch (err) {
        if (!err?.awaitingApproval) {
          setQrError(err?.message || '部署失败');
        } else {
          closeQuickRunModal();
        }
        throw err;
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  });

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
    if (data.t === 'ui.settings') {
      applyHostVisualSettings(data);
      return;
    }
    if (data.t === 'ui.viewport') {
      const vpTop = Math.max(0, Math.round(Number(data.offsetTopPx ?? data.visibleTop ?? data.scroll_top) || 0));
      const vpH = Math.max(280, Math.round(Number(data.viewportHeightPx ?? data.visibleHeight ?? data.visible_height) || 720));
      root.style.setProperty('--qwq-vp-top', `${vpTop}px`);
      root.style.setProperty('--qwq-vp-h', `${vpH}px`);
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

  function initThemedSelects() {
    const openWraps = new Set();
    const closeAll = (except = null) => {
      for (const w of openWraps) {
        if (w === except) continue;
        w.classList.remove('open', 'drop-up');
        w.querySelector('.qwq-sel-btn')?.setAttribute('aria-expanded', 'false');
        openWraps.delete(w);
      }
    };
    const valDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
    const idxDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex');
    function enhance(sel) {
      if (!sel || sel.dataset.qwqSel === '1' || sel.multiple || sel.size > 1 || !sel.parentNode) return;
      sel.dataset.qwqSel = '1';
      const wrap = document.createElement('div');
      wrap.className = 'qwq-sel';
      sel.parentNode.insertBefore(wrap, sel);
      wrap.appendChild(sel);
      sel.classList.add('qwq-sel-native');
      sel.tabIndex = -1;
      sel.setAttribute('aria-hidden', 'true');
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'qwq-sel-btn';
      btn.setAttribute('aria-haspopup', 'listbox');
      btn.setAttribute('aria-expanded', 'false');
      const lbl = document.createElement('span');
      lbl.className = 'qwq-sel-label';
      btn.appendChild(lbl);
      const menu = document.createElement('div');
      menu.className = 'qwq-sel-menu';
      menu.setAttribute('role', 'listbox');
      wrap.append(btn, menu);
      let syncing = false;
      const sync = () => {
        if (syncing) return;
        syncing = true;
        try {
          btn.disabled = sel.disabled;
          const opts = Array.from(sel.options);
          const cur = sel.selectedIndex >= 0 ? opts[sel.selectedIndex] : opts[0];
          lbl.textContent = cur ? cur.textContent : '';
          menu.replaceChildren();
          opts.forEach((opt, idx) => {
            const it = document.createElement('button');
            it.type = 'button';
            it.className = `qwq-sel-opt${idx === sel.selectedIndex ? ' selected' : ''}`;
            it.setAttribute('role', 'option');
            it.setAttribute('aria-selected', idx === sel.selectedIndex ? 'true' : 'false');
            it.disabled = opt.disabled;
            it.textContent = opt.textContent;
            it.addEventListener('click', () => {
              if (opt.disabled) return;
              const changed = sel.selectedIndex !== idx;
              if (idxDesc?.set) idxDesc.set.call(sel, idx);
              else sel.selectedIndex = idx;
              sync();
              closeAll();
              btn.focus();
              if (changed) {
                sel.dispatchEvent(new Event('input', { bubbles: true }));
                sel.dispatchEvent(new Event('change', { bubbles: true }));
              }
            });
            menu.appendChild(it);
          });
        } finally { syncing = false; }
      };
      if (valDesc?.get && valDesc?.set) {
        Object.defineProperty(sel, 'value', { configurable: true, get() { return valDesc.get.call(this); }, set(v) { valDesc.set.call(this, v); sync(); } });
      }
      if (idxDesc?.get && idxDesc?.set) {
        Object.defineProperty(sel, 'selectedIndex', { configurable: true, get() { return idxDesc.get.call(this); }, set(v) { idxDesc.set.call(this, v); sync(); } });
      }
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (sel.disabled) return;
        const willOpen = !wrap.classList.contains('open');
        closeAll(wrap);
        if (willOpen) {
          sync();
          const r = btn.getBoundingClientRect();
          wrap.classList.toggle('drop-up', window.innerHeight - r.bottom < 220 && r.top > 200);
          wrap.classList.add('open');
          btn.setAttribute('aria-expanded', 'true');
          openWraps.add(wrap);
        } else closeAll();
      });
      sel.addEventListener('change', sync);
      new MutationObserver(sync).observe(sel, { childList: true, subtree: true, attributes: true, characterData: true });
      sync();
    }
    document.querySelectorAll('select').forEach(enhance);
    new MutationObserver((muts) => {
      for (const m of muts) for (const n of m.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.tagName === 'SELECT') enhance(n);
        else if (n.querySelectorAll) n.querySelectorAll('select').forEach(enhance);
      }
    }).observe(document.body, { childList: true, subtree: true });
    document.addEventListener('click', (e) => { if (!e.target.closest?.('.qwq-sel')) closeAll(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeAll(); });
  }
  initThemedSelects();

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
