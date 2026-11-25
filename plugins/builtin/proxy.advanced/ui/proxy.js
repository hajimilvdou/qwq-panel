// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== 高级代理插件沙箱桥接 v2 与四视图控制台 ======================== */
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

  const VALID_ROUTES = ['/proxy', '/proxy/nodes', '/proxy/chains', '/proxy/tuning'];
  const ROUTE_TITLES = {
    '/proxy': '代理与订阅中心',
    '/proxy/nodes': '代理与订阅中心 · 节点管理',
    '/proxy/chains': '代理与订阅中心 · 链式与 WARP',
    '/proxy/tuning': '代理与订阅中心 · 网络调优与 Brutal',
  };

  function detectInitialRoute() {
    const r = hash.get('path') || hash.get('route') || '';
    if (VALID_ROUTES.includes(r)) return r;
    for (const candidate of VALID_ROUTES.slice().reverse()) {
      if (location.pathname.endsWith(candidate)) return candidate;
    }
    return '/proxy';
  }

  let activeRoute = detectInitialRoute();
  let publicOrigin = '';
  const $ = (id) => document.getElementById(id);

  let port;
  let seq = 0;
  const pendingInvoke = new Map();
  const pendingConfirm = new Map();
  const pendingCopy = new Map();

  let cachedUsers = [];
  let cachedPlans = [];
  let cachedChains = [];
  let cachedInbounds = [];
  let cachedWARP = null;
  let cachedWARPPresets = {};
  let cachedNodes = [];
  let detectedPublicHost = '';
  let coreObfsAvailable = null;

  const userCreateModal = { open: false };
  const userSubModal = { open: false, token: '', baseUrl: '' };
  const userHistoryModal = { open: false, userId: '', displayName: '', hours: 24 };
  const planEditModal = { open: false, editingId: '' };
  let xrayStatusLoaded = false;

  const send = (msg) => {
    if (port) port.postMessage(msg);
  };
  const setStatus = (text) => {
    $('status').textContent = text;
  };

  function getPublicOrigin() {
    if (publicOrigin) return publicOrigin.replace(/\/+$/, '');
    if (location.origin && location.origin !== 'null') return location.origin.replace(/\/+$/, '');
    return '';
  }

  function showBanner(msg, kind = 'ok') {
    const el = $('action-banner');
    el.className = `banner show ${kind}`;
    el.textContent = msg;
  }

  function clearNode(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
  }

  function formatBytes(n) {
    if (!Number.isFinite(n) || n <= 0) return '0 B';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let v = n;
    let idx = 0;
    while (v >= 1024 && idx < units.length - 1) {
      v /= 1024;
      idx += 1;
    }
    return `${v.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
  }

  function formatRate(kbps) {
    if (!kbps) return '不限';
    return kbps >= 1000 ? `${(kbps / 1000).toFixed(1)} Mbps` : `${kbps} kbps`;
  }

  function formatLimit(val) {
    return val > 0 ? String(val) : '不限';
  }

  function parseTagList(raw) {
    return String(raw || '')
      .split(/[,，\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 16);
  }

  // ==================== 宿主桥 v2：3-State Invoke / Confirm / Copy ====================

  class PendingStateError extends Error {
    constructor(kind, message) {
      super(message);
      this.name = 'PendingStateError';
      this.kind = kind;
    }
  }

  function invoke(operation, payload = {}) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingInvoke.delete(id);
        reject(new Error(`操作 ${operation} 响应超时`));
      }, 25000);
      pendingInvoke.set(id, { resolve, reject, timer });
      send({ t: 'api.invoke', id, operation, payload });
    });
  }

  function hostConfirm({ title, body, confirmLabel = '确认', danger = false }) {
    if (!port) {
      showBanner('宿主通道未就绪，无法弹出确认框', 'warn');
      return Promise.resolve(false);
    }
    const id = `c-${++seq}`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        pendingConfirm.delete(id);
        resolve(false);
      }, 60000);
      pendingConfirm.set(id, { resolve, timer });
      const msg = {
        t: 'ui.confirm',
        id,
        title: String(title || '确认操作'),
        body: String(body || ''),
        danger: Boolean(danger),
      };
      if (confirmLabel) msg.confirm_label = String(confirmLabel);
      send(msg);
    });
  }

  async function hostCopy(text, label = '已复制到剪贴板') {
    const clean = String(text || '');
    if (!clean) {
      showBanner('没有可复制的内容', 'warn');
      return false;
    }
    if (port && clean.length <= 65536) {
      const id = `cp-${++seq}`;
      const ok = await new Promise((resolve) => {
        const timer = setTimeout(() => {
          pendingCopy.delete(id);
          resolve(false);
        }, 8000);
        pendingCopy.set(id, { resolve, timer });
        const msg = { t: 'ui.copy', id, text: clean };
        if (label) msg.label = String(label);
        send(msg);
      });
      if (ok) {
        showBanner(label || '已复制到剪贴板', 'ok');
        return true;
      }
    }
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(clean);
        showBanner(label || '已复制到剪贴板', 'ok');
        return true;
      }
    } catch {
      // 沙箱降级
    }
    showBanner(`当前环境不支持自动写入剪贴板，请手动复制。`, 'warn');
    return false;
  }

  async function runAction(label, fn) {
    try {
      setStatus(`正在执行：${label}…`);
      const res = await fn();
      setStatus('已连接');
      return res;
    } catch (err) {
      if (err instanceof PendingStateError) {
        if (err.kind === 'approval' && builder.open) {
          closeNodeBuilder();
        }
        showBanner(err.message, 'warn');
        setStatus(err.kind === 'approval' ? '等待审批确认' : '后台执行中');
        return null;
      }
      const msg = err?.message || '未知错误';
      showBanner(`${label}失败：${msg}`, 'err');
      setStatus('操作异常');
      return null;
    }
  }

  function switchRoute(route, notifyHost = true) {
    if (!VALID_ROUTES.includes(route)) return;
    activeRoute = route;
    $('page-title').textContent = ROUTE_TITLES[route] || '高级代理管理';
    for (const btn of document.querySelectorAll('#nav-tabs button')) {
      btn.classList.toggle('active', btn.dataset.route === route);
    }
    for (const sec of document.querySelectorAll('section[data-view]')) {
      sec.classList.toggle('hidden', sec.dataset.view !== route);
    }
    if (notifyHost && port) {
      send({ t: 'ui.navigate', path: route });
    }
    if (port) {
      void refreshActiveView();
    }
  }

  function handleMessage(data) {
    if (!data || typeof data !== 'object') return;

    if (data.t === 'api.result' && data.id !== undefined) {
      const id = String(data.id);
      const req = pendingInvoke.get(id);
      if (!req) return;
      clearTimeout(req.timer);
      pendingInvoke.delete(id);

      if (data.ok !== true) {
        const msg =
          data.problem?.detail ||
          data.error?.message ||
          data.problem?.code ||
          '操作调用失败';
        req.reject(new Error(msg));
        return;
      }

      const env = data.data;
      if (env && typeof env === 'object') {
        if (env.status === 'AWAITING_APPROVAL' || env.approval_id) {
          req.reject(new PendingStateError('approval', '操作已提交，请在右侧审批流中确认'));
          return;
        }
        if ((env.status === 'RUNNING' || env.status === 'PENDING') && !env.result) {
          req.reject(new PendingStateError('running', '操作正在后台执行中，请稍后刷新查看最新结果'));
          return;
        }
        if (env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'CANCELLED' || env.status === 'FAILED' || env.status === 'EXPIRED') {
          const errMsg =
            (env.error && typeof env.error === 'object' ? (env.error.message || env.error.code) : (typeof env.error === 'string' ? env.error : '')) ||
            `操作未执行完成（状态：${env.status}）`;
          req.reject(new Error(errMsg));
          return;
        }
        if (env.error) {
          const errMsg =
            typeof env.error === 'string'
              ? env.error
              : env.error.message || env.error.code || '操作返回异常';
          req.reject(new Error(errMsg));
          return;
        }
        const result = env.result !== undefined ? env.result : env;
        if (!result || typeof result !== 'object') {
          req.reject(new Error('操作返回格式异常'));
        } else {
          req.resolve(result);
        }
      } else {
        req.reject(new Error('操作返回为空'));
      }
      return;
    }

    if (data.t === 'ui.confirm.result' && data.id !== undefined) {
      const id = String(data.id);
      const req = pendingConfirm.get(id);
      if (!req) return;
      clearTimeout(req.timer);
      pendingConfirm.delete(id);
      req.resolve(Boolean(data.ok && data.data?.confirmed));
      return;
    }

    if (data.t === 'ui.copy.result' && data.id !== undefined) {
      const id = String(data.id);
      const req = pendingCopy.get(id);
      if (!req) return;
      clearTimeout(req.timer);
      pendingCopy.delete(id);
      req.resolve(Boolean(data.ok));
      return;
    }

    if (data.t === 'ui.settings') {
      applyHostVisualSettings(data);
      if (typeof data.public_origin === 'string' && data.public_origin.trim()) {
        publicOrigin = data.public_origin.trim();
      }
      return;
    }

    if (data.t === 'ui.viewport') {
      const vpTop = Math.max(0, Math.round(Number(data.offsetTopPx ?? data.visibleTop ?? data.scroll_top) || 0));
      const vpH = Math.max(280, Math.round(Number(data.viewportHeightPx ?? data.visibleHeight ?? data.visible_height) || 720));
      hostViewportTop = vpTop;
      root.style.setProperty('--qwq-vp-top', `${vpTop}px`);
      root.style.setProperty('--qwq-vp-h', `${vpH}px`);
      if (hasOpenModal()) notifyResize();
      return;
    }

    if (data.t === 'ui.route' && typeof data.path === 'string' && VALID_ROUTES.includes(data.path)) {
      switchRoute(data.path, false);
      return;
    }

    if (data.t === 'api.event') {
      void refreshActiveView();
    }
  }

  // ==================== 视图 1: 套餐卡片与多用户渲染 ====================

  function openPlanEditModal(plan = null) {
    planEditModal.open = true;
    planEditModal.editingId = plan ? plan.id : '';
    $('pe-modal-title').textContent = plan ? `编辑套餐 · ${plan.name || plan.id}` : '新建套餐模板';
    const idEl = $('p-id');
    idEl.value = plan ? plan.id : '';
    idEl.readOnly = Boolean(plan);
    $('p-name').value = plan ? (plan.name || '') : '';
    $('p-quota-gb').value = plan
      ? String(plan.quota_bytes > 0 ? Math.round((plan.quota_bytes / (1024 * 1024 * 1024)) * 100) / 100 : 0)
      : '100';
    $('p-reset-day').value = plan ? String(plan.billing_reset_day ?? 1) : '1';
    $('p-down').value = plan ? String(plan.down_limit_kbps ?? 0) : '50000';
    $('p-up').value = plan ? String(plan.up_limit_kbps ?? 0) : '20000';
    $('p-max-conns').value = plan ? String(plan.max_connections ?? 0) : '64';
    $('p-max-ips').value = plan ? String(plan.max_ips ?? 0) : '4';
    $('p-validity').value = plan ? String(plan.validity_days ?? 0) : '30';
    $('plan-edit-modal').classList.remove('hidden');
  }

  function closePlanEditModal() {
    planEditModal.open = false;
    planEditModal.editingId = '';
    $('plan-edit-modal').classList.add('hidden');
  }

  function renderPlans(plans) {
    cachedPlans = plans;
    renderPlanSelects();
    const grid = $('plans-cards');
    if (grid) clearNode(grid);
    $('plans-summary').textContent = `${plans.length} 个套餐`;
    if (!grid) return;
    if (!plans.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-card muted';
      empty.textContent = '暂无套餐模板，点击右上角「+ 新建套餐」创建后即可供多用户复用。';
      grid.appendChild(empty);
      return;
    }
    for (const p of plans) {
      const card = document.createElement('article');
      card.className = 'plan-card';

      const head = document.createElement('div');
      head.className = 'plan-card-head';
      const titleBox = document.createElement('div');
      const title = document.createElement('div');
      title.className = 'plan-card-title';
      title.textContent = p.name || p.id;
      const subId = document.createElement('div');
      subId.className = 'plan-card-id mono';
      subId.textContent = p.id;
      titleBox.append(title, subId);

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'btn xs ghost';
      editBtn.textContent = '编辑';
      editBtn.addEventListener('click', () => openPlanEditModal(p));
      head.append(titleBox, editBtn);

      const kv = document.createElement('div');
      kv.className = 'plan-kv';
      const rows = [
        ['周期流量', p.quota_bytes > 0 ? formatBytes(p.quota_bytes) : '不限流量'],
        ['下 / 上行限速', `${formatRate(p.down_limit_kbps)} / ${formatRate(p.up_limit_kbps)}`],
        ['并发 / IP 上限', `${formatLimit(p.max_connections)} 连接 · ${formatLimit(p.max_ips)} IP`],
        ['周期与重置', `${p.billing_reset_day > 0 ? `每月 ${p.billing_reset_day} 日` : '不重置'} · ${p.validity_days > 0 ? `${p.validity_days} 天` : '长期'}`],
      ];
      for (const [k, v] of rows) {
        const item = document.createElement('div');
        item.className = 'plan-kv-item';
        const span = document.createElement('span');
        span.textContent = k;
        const strong = document.createElement('strong');
        strong.textContent = v;
        item.append(span, strong);
        kv.appendChild(item);
      }

      card.append(head, kv);
      grid.appendChild(card);
    }
  }

  function renderPlanSelects() {
    const sel = $('uc-plan');
    if (!sel) return;
    const prev = sel.value;
    clearNode(sel);
    if (!cachedPlans.length) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '暂无套餐（请切换上方「自定义配额与上下行限速」）';
      sel.appendChild(opt);
    } else {
      for (const p of cachedPlans) {
        const opt = document.createElement('option');
        opt.value = p.id;
        const q = p.quota_bytes > 0 ? formatBytes(p.quota_bytes) : '不限流量';
        opt.textContent = `${p.name} (${p.id} · ${q} · ${formatRate(p.down_limit_kbps)}/${formatRate(p.up_limit_kbps)})`;
        sel.appendChild(opt);
      }
      if (prev && cachedPlans.some((p) => p.id === prev)) sel.value = prev;
    }
  }

  function isLoopbackHost(host) {
    const h = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
    return h === '' || h === '127.0.0.1' || h === 'localhost' || h === '::1';
  }

  function updateUserSubModalUrls() {
    const rawInput = ($('us-host-override')?.value || '').trim();
    let origin = getPublicOrigin();
    let baseProto = 'https:';
    let basePort = '';
    try {
      const parsedBase = new URL(origin);
      baseProto = parsedBase.protocol;
      basePort = parsedBase.port;
    } catch {
      baseProto = location.protocol === 'http:' ? 'http:' : 'https:';
      basePort = location.port || '';
    }
    if (rawInput) {
      if (/^https?:\/\//i.test(rawInput)) {
        try {
          const parsed = new URL(rawInput);
          origin = parsed.origin;
        } catch {
          origin = rawInput.replace(/\/+$/, '');
        }
      } else {
        const cleaned = rawInput.replace(/\/+$/, '');
        const colonCount = (cleaned.match(/:/g) || []).length;
        let hostPart = cleaned;
        let hasExplicitPort = false;
        if (cleaned.startsWith('[')) {
          const closeIdx = cleaned.indexOf(']');
          hasExplicitPort = closeIdx > 0 && /^:\d+$/.test(cleaned.slice(closeIdx + 1));
        } else if (colonCount >= 2) {
          // Bare IPv6 address (e.g. 2001:db8::1): always bracket and preserve panel port.
          hostPart = `[${cleaned}]`;
          hasExplicitPort = false;
        } else if (/:\d+$/.test(cleaned)) {
          hasExplicitPort = true;
        }
        const portSuffix = !hasExplicitPort && basePort ? `:${basePort}` : '';
        origin = `${baseProto}//${hostPart}${portSuffix}`;
      }
    }
    const cleanPath = String(userSubModal.path || `/p/proxy.advanced/sub/${userSubModal.token}`).replace(/^\/+/, '/');
    const baseUrl = `${origin}${cleanPath}`;
    userSubModal.baseUrl = baseUrl;
    $('us-url-clash').value = `${baseUrl}?format=clash`;
    $('us-url-singbox').value = `${baseUrl}?format=singbox`;
    $('us-url-base64').value = `${baseUrl}?format=v2ray`;
  }

  function openUserSubModal({ userId, displayName, token, path, subtitle }) {
    userSubModal.open = true;
    userSubModal.token = String(token || '');
    userSubModal.path = String(path || `/p/proxy.advanced/sub/${token}`);
    $('us-user-label').textContent = `用户 ${displayName || userId} (${userId}) 一次性订阅令牌`;
    $('us-token-code').textContent = userSubModal.token;
    const hostInput = $('us-host-override');
    if (hostInput) {
      // Only prefill detectedPublicHost when the current panel origin is loopback/empty,
      // so a working HTTPS domain or public IP origin is never clobbered.
      let curHostname = '';
      try {
        curHostname = new URL(getPublicOrigin()).hostname;
      } catch {
        curHostname = '';
      }
      hostInput.value = isLoopbackHost(curHostname) && detectedPublicHost ? detectedPublicHost : '';
    }
    updateUserSubModalUrls();
    $('us-meta').textContent = subtitle || '关闭本窗口后明文令牌不再展示';
    $('user-sub-modal').classList.remove('hidden');
  }

  function closeUserSubModal() {
    userSubModal.open = false;
    userSubModal.token = '';
    userSubModal.baseUrl = '';
    $('us-token-code').textContent = '';
    $('us-url-clash').value = '';
    $('us-url-singbox').value = '';
    $('us-url-base64').value = '';
    $('user-sub-modal').classList.add('hidden');
  }

  function updateUserCreatePlanMode() {
    const isCustom = $('uc-plan-mode').value === 'custom';
    $('uc-existing-plan-wrap').classList.toggle('hidden', isCustom);
    $('uc-custom-plan-box').classList.toggle('hidden', !isCustom);
  }

  function openUserCreateModal() {
    userCreateModal.open = true;
    $('uc-id').value = '';
    $('uc-name').value = '';
    $('uc-max-conns').value = '-1';
    $('uc-max-ips').value = '-1';
    $('uc-plan-mode').value = cachedPlans.length > 0 ? 'existing' : 'custom';
    renderPlanSelects();
    renderUserSelects();
    updateUserCreatePlanMode();
    $('user-create-modal').classList.remove('hidden');
  }

  function closeUserCreateModal() {
    userCreateModal.open = false;
    $('user-create-modal').classList.add('hidden');
  }

  function formatHourBucket(ms) {
    if (!ms) return '-';
    const d = new Date(ms);
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:00`;
  }

  async function loadUserUsageHistory(userId, hours) {
    const tbody = $('uh-body');
    clearNode(tbody);
    const loadingTr = document.createElement('tr');
    const loadingTd = document.createElement('td');
    loadingTd.colSpan = 5;
    loadingTd.className = 'muted';
    loadingTd.textContent = '正在加载小时级流量记录…';
    loadingTr.appendChild(loadingTd);
    tbody.appendChild(loadingTr);

    const res = await runAction(`查询 ${userId} 流量历史`, () => invoke('users.usage_history', { user_id: userId, hours }));
    if (!res) return;
    const points = Array.isArray(res.points) ? res.points : [];
    clearNode(tbody);

    let sumUp = 0;
    let sumDown = 0;
    let peak = 0;
    for (const pt of points) {
      const u = Number(pt.up_bytes || 0);
      const d = Number(pt.down_bytes || 0);
      sumUp += u;
      sumDown += d;
      if (u + d > peak) peak = u + d;
    }
    $('uh-summary').textContent = `近 ${hours}h 合计：${formatBytes(sumUp + sumDown)}（上行 ${formatBytes(sumUp)} / 下行 ${formatBytes(sumDown)}）`;
    $('uh-meta').textContent = `共 ${points.length} 个小时桶`;

    if (!points.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'muted';
      td.textContent = '该时间窗口内暂无流量采样记录';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const pt of points.slice().reverse()) {
      const up = Number(pt.up_bytes || 0);
      const down = Number(pt.down_bytes || 0);
      const total = up + down;
      const pct = peak > 0 ? Math.max(1, Math.round((total / peak) * 100)) : 0;

      const tr = document.createElement('tr');
      const c1 = document.createElement('td');
      c1.className = 'mono';
      c1.textContent = formatHourBucket(pt.bucket_hour_ms);
      tr.appendChild(c1);

      const c2 = document.createElement('td');
      c2.textContent = formatBytes(up);
      tr.appendChild(c2);

      const c3 = document.createElement('td');
      c3.textContent = formatBytes(down);
      tr.appendChild(c3);

      const c4 = document.createElement('td');
      c4.textContent = formatBytes(total);
      tr.appendChild(c4);

      const c5 = document.createElement('td');
      const prog = document.createElement('progress');
      prog.className = 'quota-progress';
      prog.max = 100;
      prog.value = pct;
      c5.appendChild(prog);
      tr.appendChild(c5);

      tbody.appendChild(tr);
    }
  }

  function openUserHistoryModal(user) {
    userHistoryModal.open = true;
    userHistoryModal.userId = user.id;
    userHistoryModal.displayName = user.display_name || user.id;
    userHistoryModal.hours = 24;
    $('uh-modal-title').textContent = `小时级流量趋势 · ${userHistoryModal.displayName} (${user.id})`;
    for (const b of document.querySelectorAll('#uh-range-pills button')) {
      b.classList.toggle('active', Number(b.dataset.hours) === 24);
    }
    $('user-history-modal').classList.remove('hidden');
    void loadUserUsageHistory(user.id, 24);
  }

  function closeUserHistoryModal() {
    userHistoryModal.open = false;
    $('user-history-modal').classList.add('hidden');
  }

  function fillUserLimitsForm(u) {
    const det = $('user-limits-details');
    if (det) det.open = true;
    $('ul-user').value = u.id;
    $('ul-conns').value = String(u.max_connections_override ?? -1);
    $('ul-ips').value = String(u.max_ips_override ?? -1);
    $('ul-chain').value = u.chain_id || '';
    $('ul-conns').focus();
    showBanner(`已选中用户 ${u.display_name} (${u.id})，请在下方调整连接/IP/链式绑定后点击「保存用户限制与链式绑定」。`, 'ok');
  }

  function renderUserSelects() {
    const sel = $('ul-user');
    const prev = sel.value;
    clearNode(sel);
    if (!cachedUsers.length) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '暂无用户';
      sel.appendChild(opt);
    } else {
      for (const u of cachedUsers) {
        const opt = document.createElement('option');
        opt.value = u.id;
        opt.textContent = `${u.display_name} (${u.id})`;
        sel.appendChild(opt);
      }
      if (prev && cachedUsers.some((u) => u.id === prev)) sel.value = prev;
    }
    const chainSel = $('ul-chain');
    const prevChain = chainSel.value;
    clearNode(chainSel);
    const emptyOpt = document.createElement('option');
    emptyOpt.value = '';
    emptyOpt.textContent = '（跟随全局默认 / 直连）';
    chainSel.appendChild(emptyOpt);
    for (const c of cachedChains) {
      const opt = document.createElement('option');
      opt.value = c.id;
      opt.textContent = `${c.name} (${c.id})`;
      chainSel.appendChild(opt);
    }
    if (prevChain && cachedChains.some((c) => c.id === prevChain)) chainSel.value = prevChain;

    const ucChain = $('uc-chain');
    if (ucChain) {
      const prevUcChain = ucChain.value;
      clearNode(ucChain);
      const opt0 = document.createElement('option');
      opt0.value = '';
      opt0.textContent = '（跟随默认 / 直连）';
      ucChain.appendChild(opt0);
      for (const c of cachedChains) {
        const opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = `${c.name} (${c.id})`;
        ucChain.appendChild(opt);
      }
      if (prevUcChain && cachedChains.some((c) => c.id === prevUcChain)) ucChain.value = prevUcChain;
    }
  }

  function renderUsers(users) {
    cachedUsers = users;
    renderUserSelects();
    const tbody = $('users-body');
    clearNode(tbody);
    if (!users.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 9;
      td.className = 'muted';
      td.textContent = '暂无代理用户';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const u of users) {
      const tr = document.createElement('tr');

      const tdName = document.createElement('td');
      tdName.textContent = `${u.display_name} (${u.id})`;
      tr.appendChild(tdName);

      const tdPlan = document.createElement('td');
      tdPlan.textContent = u.plan_id;
      tr.appendChild(tdPlan);

      const USER_STATUS_LABELS = {
        active: '活跃',
        disabled: '已停用',
        suspended_quota: '超额暂停',
        expired: '已到期',
      };
      const tdStatus = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${u.status}`;
      badge.textContent = USER_STATUS_LABELS[u.status] || u.status;
      tdStatus.appendChild(badge);
      tr.appendChild(tdStatus);

      const tdUsage = document.createElement('td');
      const used = (u.period_up_bytes || 0) + (u.period_down_bytes || 0);
      const quota = u.quota_bytes || 0;
      const pct = quota > 0 ? Math.min(100, Math.round((used / quota) * 100)) : 0;
      const text = document.createElement('div');
      text.textContent = quota > 0 ? `${formatBytes(used)} / ${formatBytes(quota)} (${pct}%)` : `${formatBytes(used)} / 不限`;
      tdUsage.appendChild(text);
      if (quota > 0) {
        const prog = document.createElement('progress');
        prog.className = 'quota-progress';
        prog.max = 100;
        prog.value = pct;
        tdUsage.appendChild(prog);
      }
      tr.appendChild(tdUsage);

      const tdConns = document.createElement('td');
      tdConns.textContent = `${u.active_connections || 0} / ${formatLimit(u.effective_max_connections || 0)}`;
      tr.appendChild(tdConns);

      const tdIPs = document.createElement('td');
      tdIPs.textContent = `${u.active_ips || 0} / ${formatLimit(u.effective_max_ips || 0)}`;
      tr.appendChild(tdIPs);

      const tdChain = document.createElement('td');
      tdChain.textContent = u.chain_id || '默认/直连';
      tr.appendChild(tdChain);

      const tdMark = document.createElement('td');
      tdMark.className = 'mono';
      tdMark.textContent = u.traffic_mark > 0 ? `0x${u.traffic_mark.toString(16).toUpperCase()}` : '未限速';
      tr.appendChild(tdMark);

      const tdAct = document.createElement('td');
      const actWrap = document.createElement('div');
      actWrap.className = 'actions actions-tight';

      const isActive = u.status === 'active';
      const btnToggle = document.createElement('button');
      btnToggle.type = 'button';
      btnToggle.className = isActive ? 'btn sm ghost' : 'btn sm';
      btnToggle.textContent = isActive ? '停用' : '启用';
      btnToggle.addEventListener('click', async () => {
        const nextStatus = isActive ? 'disabled' : 'active';
        const ok = await hostConfirm({
          title: `${isActive ? '停用' : '启用'}代理用户`,
          body: `确认将用户「${u.display_name} (${u.id})」切换为 ${isActive ? '已停用' : '活跃'} 并同步内置 Xray 引擎与带宽限速？`,
          confirmLabel: isActive ? '确认停用' : '确认启用',
          danger: isActive,
        });
        if (!ok) return;
        const r = await runAction(`${isActive ? '停用' : '启用'}用户 ${u.id}`, () =>
          invoke('users.set_status', {
            user_id: u.id,
            status: nextStatus,
            expected_revision: String(u.revision || ''),
          }));
        if (r) {
          showBanner(`用户 ${u.id} 状态已更新为 ${r.user?.status || nextStatus}`, 'ok');
          void refreshProxyHome();
        }
      });
      actWrap.appendChild(btnToggle);

      const btnRotate = document.createElement('button');
      btnRotate.type = 'button';
      btnRotate.className = 'btn sm ghost';
      btnRotate.textContent = '轮换订阅';
      btnRotate.addEventListener('click', async () => {
        const ok = await hostConfirm({
          title: '轮换用户订阅链接',
          body: `确认轮换用户「${u.display_name} (${u.id})」的公开订阅令牌？旧订阅链接将立即失效，并一次性展示新链接。`,
          confirmLabel: '确认轮换',
          danger: true,
        });
        if (!ok) return;
        const r = await runAction(`轮换 ${u.id} 订阅令牌`, () =>
          invoke('users.rotate_subscription', {
            user_id: u.id,
            expected_revision: String(u.revision || ''),
          }));
        if (r && r.subscription_token) {
          openUserSubModal({
            userId: u.id,
            displayName: u.display_name,
            token: r.subscription_token,
            path: r.subscription_path,
            subtitle: `新订阅修订号 rev ${r.revision || '-'}，旧链接已失效`,
          });
          void refreshProxyHome();
        }
      });
      actWrap.appendChild(btnRotate);

      const btnLimits = document.createElement('button');
      btnLimits.type = 'button';
      btnLimits.className = 'btn sm ghost';
      btnLimits.textContent = '调整限额';
      btnLimits.addEventListener('click', () => fillUserLimitsForm(u));
      actWrap.appendChild(btnLimits);

      const btnHistory = document.createElement('button');
      btnHistory.type = 'button';
      btnHistory.className = 'btn sm ghost';
      btnHistory.textContent = '流量趋势';
      btnHistory.addEventListener('click', () => openUserHistoryModal(u));
      actWrap.appendChild(btnHistory);

      tdAct.appendChild(actWrap);
      tr.appendChild(tdAct);

      tbody.appendChild(tr);
    }
  }

  // ==================== 视图 2: /proxy/nodes 节点管理与双模式构建器 ====================

  const MANAGED_PROTOCOLS = [
    { id: 'vless', label: 'VLESS' },
    { id: 'vmess', label: 'VMESS' },
    { id: 'trojan', label: 'TROJAN' },
    { id: 'shadowsocks', label: 'SHADOWSOCKS' },
    { id: 'shadowsocks2022', label: 'SHADOWSOCKS2022' },
    { id: 'hysteria2', label: 'HYSTERIA2' },
    { id: 'anytls', label: 'ANYTLS' },
    { id: 'socks5', label: 'SOCKS5' },
    { id: 'http', label: 'HTTP' },
  ];

  const MANAGED_PROTOCOL_SET = new Set(MANAGED_PROTOCOLS.map((p) => p.id));

  const TRANSPORT_MATRIX = {
    vless: [
      { id: 'raw', label: 'TCP (RAW)' },
      { id: 'grpc', label: 'GRPC' },
      { id: 'ws', label: 'WSS' },
      { id: 'xhttp', label: 'XHTTP' },
    ],
    trojan: [
      { id: 'raw', label: 'TCP' },
      { id: 'grpc', label: 'GRPC' },
      { id: 'ws', label: 'WSS' },
    ],
    vmess: [
      { id: 'raw', label: 'TCP' },
      { id: 'ws', label: 'WEBSOCKET' },
      { id: 'grpc', label: 'GRPC' },
    ],
  };

  function getSecurityOptions(proto, transport) {
    if (proto === 'vless') {
      if (transport === 'raw') {
        return [
          { key: 'xtls-vision-reality', label: 'XTLS-Vision-REALITY', security_mode: 'reality', flow: 'xtls-rprx-vision' },
          { key: 'reality', label: 'REALITY', security_mode: 'reality', flow: '' },
          { key: 'xtls-vision', label: 'XTLS-Vision', security_mode: 'tls', flow: 'xtls-rprx-vision' },
          { key: 'tls', label: 'TLS', security_mode: 'tls', flow: '' },
          { key: 'enc', label: 'ENC', security_mode: 'none', flow: '' },
        ];
      }
      return [
        { key: 'reality', label: 'REALITY', security_mode: 'reality', flow: '' },
        { key: 'tls', label: 'TLS', security_mode: 'tls', flow: '' },
        { key: 'enc', label: 'ENC', security_mode: 'none', flow: '' },
      ];
    }
    if (proto === 'trojan') {
      return [
        { key: 'reality', label: 'REALITY', security_mode: 'reality', flow: '' },
        { key: 'tls', label: 'TLS', security_mode: 'tls', flow: '' },
      ];
    }
    if (proto === 'vmess') {
      return [
        { key: 'none', label: '无', security_mode: 'none', flow: '' },
        { key: 'tls', label: 'TLS', security_mode: 'tls', flow: '' },
      ];
    }
    if (proto === 'anytls' || proto === 'hysteria2') {
      return [{ key: 'tls', label: 'TLS', security_mode: 'tls', flow: '' }];
    }
    return [];
  }

  function defaultSecurityKey(proto, transport) {
    if (proto === 'vless') return transport === 'raw' ? 'xtls-vision-reality' : 'reality';
    if (proto === 'trojan') return 'tls';
    if (proto === 'vmess') return 'none';
    if (proto === 'anytls' || proto === 'hysteria2') return 'tls';
    return 'none';
  }

  function defaultTransport(proto) {
    if (proto === 'hysteria2') return 'udp';
    if (proto === 'vmess') return 'ws';
    return 'raw';
  }

  const SS_METHODS = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305'];
  const SS2022_METHODS = [
    '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
  ];

  const DEFAULT_SNI_CANDIDATES = [
    'www.microsoft.com',
    'www.apple.com',
    'dl.google.com',
    'www.icloud.com',
    'swdist.apple.com',
    'addons.mozilla.org',
    'www.lovelive-anime.jp',
  ];

  const DEFAULT_ANYTLS_PADDING = [
    'stop=8',
    '0=30-30',
    '1=100-400',
    '2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000',
    '3=9-9,500-1000',
    '4=500-1000',
    '5=500-1000',
    '6=500-1000',
    '7=500-1000',
  ];

  const nodeFilters = {
    protocol: '',
    source: '',
    tag: '',
    search: '',
  };

  let sniProbeResults = DEFAULT_SNI_CANDIDATES.map((domain) => ({
    domain,
    ok: false,
    latency_ms: -1,
    tls13: false,
    tls_version: '',
  }));
  let sniProbedOnce = false;
  let sniProbing = false;

  const builder = {
    open: false,
    editingId: '',
    mode: 'simplified',
    protocol: 'vless',
    transport: 'raw',
    secKey: 'xtls-vision-reality',
    previewTab: 'json',
    previewTimer: null,
    previewSeq: 0,
    lastPreview: null,
  };

  const configViewer = {
    open: false,
    tab: 'json',
    data: null,
  };

  function randomBytes(len) {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return arr;
  }

  function genUUID() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    const b = randomBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function genAlphaNum(len = 24) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const b = randomBytes(len);
    let out = '';
    for (let i = 0; i < len; i += 1) {
      out += alphabet[b[i] % alphabet.length];
    }
    return out;
  }

  function genShortIdHex(byteLen = 4) {
    return Array.from(randomBytes(byteLen), (x) => x.toString(16).padStart(2, '0')).join('');
  }

  function genSS2022Key(method) {
    const n = method === '2022-blake3-aes-256-gcm' || method === '2022-blake3-chacha20-poly1305' ? 32 : 16;
    const bytes = randomBytes(n);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function formatTransportSecurity(node) {
    const t = (node.transport || 'raw').toUpperCase();
    const sec = (node.security_mode || 'none').toLowerCase();
    const cfg = node.config || {};
    if (node.protocol === 'vless') {
      if (sec === 'reality') {
        return cfg.flow === 'xtls-rprx-vision' ? `${t} · XTLS-Vision-REALITY` : `${t} · REALITY`;
      }
      if (sec === 'tls') {
        return cfg.flow === 'xtls-rprx-vision' ? `${t} · XTLS-Vision` : `${t} · TLS`;
      }
      if (cfg.decryption && cfg.decryption !== 'none') return `${t} · VLESS ENC`;
      return `${t} · 无加密`;
    }
    if (node.protocol === 'anytls') {
      const steps = Array.isArray(cfg.padding_scheme) ? cfg.padding_scheme.length : 9;
      return `TLS · Padding(${steps})`;
    }
    if (node.protocol === 'hysteria2') {
      return `UDP · TLS${cfg.obfs_password ? ' · Salamander' : ''}${cfg.port_hopping ? ` · ${cfg.port_hopping}` : ''}`;
    }
    if (node.protocol === 'shadowsocks' || node.protocol === 'shadowsocks2022') {
      return `${cfg.method || 'auto'}${cfg.udp === false ? ' · TCP' : ' · TCP+UDP'}`;
    }
    if (node.protocol === 'socks5' || node.protocol === 'http') {
      return cfg.username ? `认证 (${cfg.username})` : '基础代理';
    }
    if (node.protocol === 'tuic') {
      return `UDP · TLS (${cfg.congestion_control || 'bbr'})`;
    }
    if (node.protocol === 'wireguard') {
      return `UDP · MTU ${cfg.mtu || 1280}`;
    }
    return `${t} · ${sec === 'none' ? '无' : sec.toUpperCase()}`;
  }

  function renderNodesStats(nodes, managedCount, externalCount) {
    $('n-stat-total').textContent = `${nodes.length}`;
    $('n-stat-split').textContent = `托管入站 ${managedCount} · 外部导入 ${externalCount}`;

    const enabledCount = nodes.filter((n) => n.enabled).length;
    const listeningCount = nodes.filter((n) => n.source === 'managed' && n.listening).length;
    $('n-stat-active').textContent = `${enabledCount} / ${listeningCount}`;
    $('n-stat-listen').textContent = `${enabledCount} 个已启用 · ${listeningCount} 个托管端口监听中`;

    const protoSet = new Set(nodes.map((n) => n.protocol));
    $('n-stat-protos').textContent = `${protoSet.size} 种协议`;
    $('n-stat-protos-sub').textContent = protoSet.size
      ? Array.from(protoSet).map((p) => p.toUpperCase()).join(' / ')
      : '点击「+ 添加节点」开始构建';

    const tested = nodes.filter((n) => typeof n.last_latency_ms === 'number' && n.last_latency_ms > 0);
    if (tested.length) {
      const avg = Math.round(tested.reduce((acc, n) => acc + n.last_latency_ms, 0) / tested.length);
      const min = Math.min(...tested.map((n) => n.last_latency_ms));
      $('n-stat-latency').textContent = `${min} ms (均 ${avg} ms)`;
      $('n-stat-latency-sub').textContent = `已测通 ${tested.length} / ${nodes.length} 个节点`;
    } else {
      $('n-stat-latency').textContent = '未测速';
      $('n-stat-latency-sub').textContent = '点击节点「测速」执行真实连通性检测';
    }
  }

  function renderNodeFilterPills() {
    // 协议筛选 Pills
    const protoBox = $('n-proto-filters');
    clearNode(protoBox);
    const counts = new Map();
    for (const n of cachedNodes) {
      counts.set(n.protocol, (counts.get(n.protocol) || 0) + 1);
    }

    const addProtoPill = (proto, label, count) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `pill${nodeFilters.protocol === proto ? ' active' : ''}`;
      btn.dataset.proto = proto;
      const txt = document.createElement('span');
      txt.textContent = label;
      const cnt = document.createElement('span');
      cnt.className = 'pill-count';
      cnt.textContent = `(${count})`;
      btn.appendChild(txt);
      btn.appendChild(cnt);
      protoBox.appendChild(btn);
    };

    addProtoPill('', '全部', cachedNodes.length);
    for (const [proto, count] of counts.entries()) {
      addProtoPill(proto, proto.toUpperCase(), count);
    }

    // 来源 Pills 激活态
    for (const btn of document.querySelectorAll('#n-source-filters button')) {
      btn.classList.toggle('active', (btn.dataset.source || '') === nodeFilters.source);
    }

    // 标签筛选 Pills
    const tagBox = $('n-tag-filters');
    clearNode(tagBox);
    const tagCounts = new Map();
    for (const n of cachedNodes) {
      for (const t of n.tags || []) {
        tagCounts.set(t, (tagCounts.get(t) || 0) + 1);
      }
    }
    const allTagBtn = document.createElement('button');
    allTagBtn.type = 'button';
    allTagBtn.className = `pill${nodeFilters.tag === '' ? ' active' : ''}`;
    allTagBtn.dataset.tag = '';
    allTagBtn.textContent = '全部标签';
    tagBox.appendChild(allTagBtn);

    for (const [tag, count] of tagCounts.entries()) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `pill${nodeFilters.tag === tag ? ' active' : ''}`;
      btn.dataset.tag = tag;
      btn.textContent = `#${tag} (${count})`;
      tagBox.appendChild(btn);
    }
  }

  function getFilteredNodes() {
    const q = nodeFilters.search.trim().toLowerCase();
    return cachedNodes.filter((n) => {
      if (nodeFilters.protocol && n.protocol !== nodeFilters.protocol) return false;
      if (nodeFilters.source && n.source !== nodeFilters.source) return false;
      if (nodeFilters.tag && !(n.tags || []).includes(nodeFilters.tag)) return false;
      if (q) {
        const hay = `${n.id} ${n.name} ${n.protocol} ${n.server} ${n.listen} ${n.port} ${(n.tags || []).join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  function renderNodesTable() {
    renderNodeFilterPills();
    const list = getFilteredNodes();
    const tbody = $('nodes-body');
    clearNode(tbody);

    if (!list.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.className = 'muted';
      td.textContent = cachedNodes.length
        ? '当前筛选条件下无匹配节点，可切换上方筛选条件或清空搜索框。'
        : '暂无代理节点，点击右上角「+ 添加节点」快速创建，或展开上方卡片导入外部 URI。';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const n of list) {
      const tr = document.createElement('tr');

      // 1. 协议徽章
      const tdProto = document.createElement('td');
      const pBadge = document.createElement('span');
      pBadge.className = `proto-badge proto-${n.protocol}`;
      pBadge.textContent = n.protocol.toUpperCase();
      tdProto.appendChild(pBadge);
      tr.appendChild(tdProto);

      // 2. 名称 + 来源 + 标签
      const tdName = document.createElement('td');
      const nameWrap = document.createElement('div');
      nameWrap.className = 'node-name-cell';

      const titleLine = document.createElement('div');
      titleLine.className = 'node-title-line';
      if (n.source === 'managed') {
        const dot = document.createElement('span');
        dot.className = n.listening ? 'dot-live' : 'dot-off';
        dot.title = n.listening ? '监听中' : '未监听';
        titleLine.appendChild(dot);
      }
      const nameSpan = document.createElement('span');
      nameSpan.textContent = n.name || n.id;
      titleLine.appendChild(nameSpan);

      const srcBadge = document.createElement('span');
      srcBadge.className = n.source === 'managed' ? 'badge cocoa' : 'badge info';
      srcBadge.textContent = n.source === 'managed' ? '托管' : '外部导入';
      titleLine.appendChild(srcBadge);
      nameWrap.appendChild(titleLine);

      const tagsLine = document.createElement('div');
      tagsLine.className = 'node-tags-line';
      const idChip = document.createElement('span');
      idChip.className = 'muted mono';
      idChip.textContent = n.id;
      tagsLine.appendChild(idChip);
      for (const t of n.tags || []) {
        const chip = document.createElement('span');
        chip.className = 'tag-chip';
        chip.textContent = t;
        tagsLine.appendChild(chip);
      }
      nameWrap.appendChild(tagsLine);
      tdName.appendChild(nameWrap);
      tr.appendChild(tdName);

      // 3. 地址与端口
      const tdAddr = document.createElement('td');
      tdAddr.className = 'mono';
      const hostDisplay = n.server || n.listen || '0.0.0.0';
      tdAddr.textContent = `${hostDisplay}:${n.port}`;
      tr.appendChild(tdAddr);

      // 4. 传输 / 安全
      const tdTs = document.createElement('td');
      tdTs.className = 'muted';
      tdTs.textContent = formatTransportSecurity(n);
      tr.appendChild(tdTs);

      // 5. 延迟
      const tdLat = document.createElement('td');
      const latBadge = document.createElement('span');
      if (typeof n.last_latency_ms === 'number' && n.last_latency_ms > 0) {
        latBadge.className = n.last_latency_ms < 120 ? 'badge ok' : n.last_latency_ms < 300 ? 'badge warn' : 'badge err';
        latBadge.textContent = `${n.last_latency_ms} ms`;
      } else {
        latBadge.className = 'badge';
        latBadge.textContent = '未测试';
      }
      tdLat.appendChild(latBadge);
      tr.appendChild(tdLat);

      // 6. 状态
      const tdSt = document.createElement('td');
      const stBadge = document.createElement('span');
      stBadge.className = `badge ${n.enabled ? 'ok' : 'warn'}`;
      stBadge.textContent = n.enabled ? '启用' : '停用';
      tdSt.appendChild(stBadge);
      tr.appendChild(tdSt);

      // 7. 操作
      const tdOps = document.createElement('td');
      const ops = document.createElement('div');
      ops.className = 'node-ops';

      const mkBtn = (label, cls, action) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = `btn xs ${cls}`;
        b.textContent = label;
        b.dataset.nodeAction = action;
        b.dataset.nodeId = n.id;
        return b;
      };

      ops.appendChild(mkBtn('测速', 'ghost', 'test'));
      ops.appendChild(mkBtn('复制 URI', 'ghost', 'copy'));
      ops.appendChild(mkBtn('查看配置', 'ghost', 'view'));
      if (n.source === 'managed' && MANAGED_PROTOCOL_SET.has(n.protocol)) {
        ops.appendChild(mkBtn('编辑', 'ghost', 'edit'));
        ops.appendChild(mkBtn(n.enabled ? '停用' : '启用', 'ghost', 'toggle'));
      }
      ops.appendChild(mkBtn('删除', 'danger', 'delete'));

      tdOps.appendChild(ops);
      tr.appendChild(tdOps);
      tbody.appendChild(tr);
    }
  }

  function syncObfsAvailabilityUI() {
    const sel = $('nb-e-obfs-mode');
    if (!sel) return;
    const unavailable = coreObfsAvailable === false;
    for (const opt of sel.options) {
      if (opt.value === 'http' || opt.value === 'tls') {
        opt.disabled = unavailable;
        if (!opt.dataset.baseLabel) opt.dataset.baseLabel = opt.textContent;
        opt.textContent = unavailable ? `${opt.dataset.baseLabel}（当前核心未内置 obfs-server）` : opt.dataset.baseLabel;
      }
    }
    if (unavailable && sel.value !== 'none') {
      sel.value = 'none';
    }
  }

  function renderXrayEngineStatus(eng) {
    const pill = $('xray-engine-pill');
    const pillText = $('xray-engine-text');
    const statVal = $('xray-stat-val');
    const statSub = $('xray-stat-sub');
    if (!eng || typeof eng !== 'object') {
      if (pill) pill.className = 'engine-pill';
      if (pillText) pillText.textContent = '内置 Xray 引擎就绪';
      if (statVal) statVal.textContent = '待检测';
      return;
    }
    xrayStatusLoaded = true;
    const ver = eng.core_version || 'v26.11.9';
    const state = String(eng.state || '').toUpperCase();
    const profiles = Number(eng.active_profiles || 0);
    if (state === 'RUNNING') {
      if (pill) pill.className = 'engine-pill ok';
      if (pillText) pillText.textContent = `内置 Xray ${ver} · 运行中 (${profiles} 节点)`;
      if (statVal) statVal.textContent = `运行中 (${profiles} 入站)`;
      if (statSub) {
        statSub.textContent = `Xray ${ver}${eng.anytls_active ? ' · AnyTLS 活跃' : ''}${eng.revision ? ` · ${eng.revision}` : ''}`;
      }
    } else if (eng.binary_trusted) {
      if (pill) pill.className = 'engine-pill ok';
      if (pillText) pillText.textContent = `内置 Xray ${ver} · 就绪待命`;
      if (statVal) statVal.textContent = '就绪待命';
      if (statSub) statSub.textContent = `Xray ${ver} 已内置，添加并启用节点后自动热启动`;
    } else {
      if (pill) pill.className = 'engine-pill warn';
      if (pillText) pillText.textContent = '内置 Xray 引擎未就绪';
      if (statVal) statVal.textContent = '未就绪';
      if (statSub) statSub.textContent = eng.last_error || '未检测到内嵌 Xray 核心二进制';
    }
  }

  function applyOverviewCapabilities(overview) {
    if (!overview) return;
    if (typeof overview.detected_public_host === 'string' && overview.detected_public_host.trim()) {
      detectedPublicHost = overview.detected_public_host.trim();
    }
    if (typeof overview.core_obfs_available === 'boolean') {
      coreObfsAvailable = overview.core_obfs_available;
      syncObfsAvailabilityUI();
    }
    if (overview.xray_engine) {
      renderXrayEngineStatus(overview.xray_engine);
    }
  }

  async function refreshNodes() {
    const [res, ov] = await Promise.all([
      invoke('nodes.list', {}),
      invoke('proxy.overview', { include_traffic_status: false }).catch(() => null),
    ]);
    applyOverviewCapabilities(ov);
    cachedNodes = Array.isArray(res.nodes) ? res.nodes : [];
    const managedCount = typeof res.managed_count === 'number'
      ? res.managed_count
      : cachedNodes.filter((n) => n.source === 'managed').length;
    const externalCount = typeof res.external_count === 'number'
      ? res.external_count
      : cachedNodes.filter((n) => n.source !== 'managed').length;
    renderNodesStats(cachedNodes, managedCount, externalCount);
    renderNodesTable();
  }

  // ==================== 查看节点配置弹窗 ====================

  function renderConfigViewerContent() {
    const d = configViewer.data;
    const pre = $('nc-code');
    if (!d) {
      pre.textContent = '暂无配置内容';
      return;
    }
    if (configViewer.tab === 'json') {
      pre.textContent = d.native_json || '{}';
    } else if (configViewer.tab === 'uri') {
      pre.textContent = d.share_uri || '（当前节点无可用分享 URI）';
    } else if (configViewer.tab === 'clash') {
      pre.textContent = d.clash_yaml || '# 当前协议暂未生成 Clash YAML 预览';
    } else if (configViewer.tab === 'singbox') {
      pre.textContent = d.singbox_outbound ? JSON.stringify(d.singbox_outbound, null, 2) : '{}';
    }
  }

  async function openConfigViewer(node) {
    configViewer.open = true;
    configViewer.tab = 'json';
    configViewer.data = null;
    $('nc-modal-title').textContent = `节点配置详情 · ${node.name || node.id}`;
    $('nc-meta').textContent = `${node.protocol.toUpperCase()} · ${node.server || node.listen}:${node.port} · ${node.source === 'managed' ? '托管节点' : '外部导入'}`;
    $('nc-code').textContent = '正在生成原生配置与多客户端导出预览…';
    for (const btn of document.querySelectorAll('#nc-tabs button')) {
      btn.classList.toggle('active', btn.dataset.tab === 'json');
    }
    $('node-config-modal').classList.remove('hidden');

    if (node.source === 'managed' && MANAGED_PROTOCOL_SET.has(node.protocol)) {
      const payload = {
        id: node.id,
        mode: 'expert',
        name: node.name,
        protocol: node.protocol,
        transport: node.transport || defaultTransport(node.protocol),
        security_mode: node.security_mode || 'none',
        listen: node.listen || '0.0.0.0',
        server: node.server || '',
        port: Number(node.port) || 0,
        enabled: Boolean(node.enabled),
        tags: Array.isArray(node.tags) ? node.tags : [],
        config: node.config || {},
      };
      const r = await runAction(`加载节点 ${node.id} 配置`, () => invoke('nodes.preview_json', payload));
      if (r && configViewer.open) {
        configViewer.data = {
          native_json: r.native_json || JSON.stringify(r.native_inbound || {}, null, 2),
          share_uri: r.share_uri || node.share_uri || node.raw_uri || '',
          clash_yaml: r.clash_yaml || '',
          singbox_outbound: r.singbox_outbound || null,
        };
        renderConfigViewerContent();
        return;
      }
    }

    // 外部 TUIC / WireGuard 或预览回退
    if (configViewer.open) {
      configViewer.data = {
        native_json: JSON.stringify(node, null, 2),
        share_uri: node.share_uri || node.raw_uri || '',
        clash_yaml: '# 该外部导入协议请直接通过用户多协议订阅地址导出 Clash 配置',
        singbox_outbound: node.config || {},
      };
      renderConfigViewerContent();
    }
  }

  function closeConfigViewer() {
    configViewer.open = false;
    $('node-config-modal').classList.add('hidden');
  }

  // ==================== 添加 / 编辑节点：双模式分栏构建器 ====================

  function getActiveSecurityOpt() {
    const opts = getSecurityOptions(builder.protocol, builder.transport);
    return opts.find((o) => o.key === builder.secKey) || opts[0] || { key: 'none', security_mode: 'none', flow: '' };
  }

  function populateSNISelects(selectedDomain) {
    const selects = [$('nb-s-sni'), $('nb-e-sni-select')];
    const targetDomain = selectedDomain || $('nb-s-sni').value || sniProbeResults[0]?.domain || DEFAULT_SNI_CANDIDATES[0];

    for (const sel of selects) {
      clearNode(sel);
      let matched = false;
      for (const item of sniProbeResults) {
        const opt = document.createElement('option');
        opt.value = item.domain;
        if (item.ok) {
          opt.textContent = `${item.domain} (${item.latency_ms} ms${item.tls13 ? ' · TLS 1.3' : item.tls_version ? ` · ${item.tls_version}` : ''})`;
        } else if (item.error) {
          opt.textContent = `${item.domain} (不可达)`;
        } else {
          opt.textContent = item.domain;
        }
        if (item.domain === targetDomain) matched = true;
        sel.appendChild(opt);
      }
      if (targetDomain && !matched) {
        const customOpt = document.createElement('option');
        customOpt.value = targetDomain;
        customOpt.textContent = `${targetDomain} (自定义)`;
        sel.insertBefore(customOpt, sel.firstChild);
      }
      sel.value = targetDomain;
    }
  }

  async function probeRealitySNI(forceAutoSelect = true) {
    if (sniProbing || !port) return;
    sniProbing = true;
    const btnS = $('nb-s-probe-sni');
    const btnE = $('nb-e-probe-sni');
    btnS.disabled = true;
    btnE.disabled = true;
    btnS.textContent = '探测中…';
    btnE.textContent = '探测中…';
    $('nb-s-sni-hint').textContent = '正在并发探测候选伪装域名的 TLS 1.3 支持与往返延迟…';

    try {
      const r = await invoke('nodes.probe_sni', {});
      if (r && Array.isArray(r.results) && r.results.length) {
        sniProbeResults = r.results;
        sniProbedOnce = true;
        const best = r.recommended || r.results[0].domain;
        const okCount = r.results.filter((x) => x.ok && x.tls13).length;
        $('nb-s-sni-hint').textContent = `探测完成：${okCount}/${r.results.length} 个域名支持 TLS 1.3，推荐最低延迟域名 ${best}`;

        const keepExisting = !forceAutoSelect && builder.editingId && $('nb-e-server-names').value.trim();
        const chosen = keepExisting ? $('nb-e-server-names').value.split(',')[0].trim() : best;
        populateSNISelects(chosen);
        if (!keepExisting) {
          $('nb-e-server-names').value = best;
          $('nb-e-target').value = `${best}:443`;
        }
        schedulePreview();
      }
    } catch (err) {
      $('nb-s-sni-hint').textContent = `SNI 探测暂不可用（${err?.message || '网络受限'}），已保留默认候选列表。`;
    } finally {
      sniProbing = false;
      btnS.disabled = false;
      btnE.disabled = false;
      btnS.textContent = '重新探测';
      btnE.textContent = '重新探测';
    }
  }

  function populateMethodSelects(proto, currentVal) {
    const methods = proto === 'shadowsocks2022' ? SS2022_METHODS : SS_METHODS;
    const chosen = methods.includes(currentVal) ? currentVal : methods[0];
    for (const sel of [$('nb-s-method'), $('nb-e-method')]) {
      clearNode(sel);
      for (const m of methods) {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        sel.appendChild(opt);
      }
      sel.value = chosen;
    }
  }

  function renderBuilderPills() {
    // Step 1: 协议 Pills
    const protoBox = $('nb-proto-pills');
    clearNode(protoBox);
    for (const p of MANAGED_PROTOCOLS) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `pill${builder.protocol === p.id ? ' active' : ''}`;
      btn.dataset.proto = p.id;
      btn.textContent = p.label;
      protoBox.appendChild(btn);
    }

    // Step 2: 传输协议 Pills
    const tList = TRANSPORT_MATRIX[builder.protocol] || [];
    const tStep = $('nb-transport-step');
    const tBox = $('nb-transport-pills');
    clearNode(tBox);
    if (!tList.length) {
      tStep.classList.add('hidden');
    } else {
      tStep.classList.remove('hidden');
      if (!tList.some((x) => x.id === builder.transport)) {
        builder.transport = defaultTransport(builder.protocol);
      }
      for (const t of tList) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `pill${builder.transport === t.id ? ' active' : ''}`;
        btn.dataset.transport = t.id;
        btn.textContent = t.label;
        tBox.appendChild(btn);
      }
    }

    // Step 3: 安全协议 Pills
    const sList = getSecurityOptions(builder.protocol, builder.transport);
    const sStep = $('nb-security-step');
    const sBox = $('nb-security-pills');
    clearNode(sBox);
    if (!sList.length) {
      sStep.classList.add('hidden');
      builder.secKey = 'none';
    } else {
      sStep.classList.remove('hidden');
      if (!sList.some((x) => x.key === builder.secKey)) {
        builder.secKey = defaultSecurityKey(builder.protocol, builder.transport);
      }
      for (const s of sList) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `pill${builder.secKey === s.key ? ' active' : ''}`;
        btn.dataset.seckey = s.key;
        btn.textContent = s.label;
        sBox.appendChild(btn);
      }
    }

    // Step 4: 配置模式分段开关
    for (const btn of document.querySelectorAll('#nb-mode-seg button')) {
      const isAct = btn.dataset.mode === builder.mode;
      btn.classList.toggle('active', isAct);
      btn.setAttribute('aria-selected', isAct ? 'true' : 'false');
    }
  }

  function updateBuilderFieldVisibility() {
    const proto = builder.protocol;
    const trans = builder.transport;
    const secOpt = getActiveSecurityOpt();
    const secMode = secOpt.security_mode;
    const isEnc = proto === 'vless' && builder.secKey === 'enc';

    const isSimplified = builder.mode === 'simplified';
    $('nb-simplified-panel').classList.toggle('hidden', !isSimplified);
    $('nb-expert-panel').classList.toggle('hidden', isSimplified);

    // 简易模式按协议展示精简块
    $('nb-s-reality-box').classList.toggle('hidden', secMode !== 'reality');
    $('nb-s-tls-box').classList.toggle('hidden', secMode !== 'tls');
    $('nb-s-enc-box').classList.toggle('hidden', !isEnc);
    $('nb-s-ss-box').classList.toggle('hidden', proto !== 'shadowsocks' && proto !== 'shadowsocks2022');
    $('nb-s-anytls-box').classList.toggle('hidden', proto !== 'anytls');
    $('nb-s-auth-box').classList.toggle('hidden', proto !== 'socks5' && proto !== 'http');

    if (proto === 'shadowsocks' || proto === 'shadowsocks2022') {
      populateMethodSelects(proto, $('nb-e-method').value || $('nb-s-method').value);
    }

    const autoNotes = {
      vless: secMode === 'reality'
        ? 'UUID、X25519 REALITY 密钥对、ShortID 与随机高位端口将由服务端自动生成。'
        : isEnc
          ? '已选择 VLESS Encryption 模式：UUID 与高位端口自动生成，可填写 decryption / encryption 或留空使用 none。'
          : 'UUID 与高位端口自动生成；填写已签发证书的 binding_ref 后即可自动同步核心。',
      vmess: 'VMess UUID 与随机高位端口自动生成，默认启用流量嗅探。',
      trojan: 'Trojan 24 位强随机密码与高位端口自动生成。',
      shadowsocks: '传统 Shadowsocks 随机强密码与高位端口自动生成，默认同时开启 TCP + UDP。',
      shadowsocks2022: 'SS2022 服务端 Server Key 与用户 PSK 将按所选加密方式自动生成 16/32 字节 Base64 密钥。',
      hysteria2: 'Hysteria2 强密码与随机 UDP 高位端口自动生成；如需 Salamander 混淆或端口跳跃请切至专家模式。',
      anytls: 'AnyTLS 密码与标准 8 段 Padding Scheme 自动预填，仅需补充证书 binding_ref 与 SNI 即可同步生效。',
      socks5: 'SOCKS5 留空用户名默认为 user，密码自动生成 16 位随机密码，默认启用 UDP 转发。',
      http: 'HTTP 代理留空用户名默认为 user，密码自动生成 16 位随机密码。',
    };
    $('nb-s-autofill-note').textContent = autoNotes[proto] || '';

    // 专家模式 · 凭证卡片显隐
    const needUUID = proto === 'vless' || proto === 'vmess';
    const needUser = proto === 'socks5' || proto === 'http';
    const needPass = proto === 'trojan' || proto === 'shadowsocks' || proto === 'hysteria2' || proto === 'anytls' || needUser;
    const needMethod = proto === 'shadowsocks' || proto === 'shadowsocks2022';
    const isSS22 = proto === 'shadowsocks2022';

    $('nb-e-uuid-wrap').classList.toggle('hidden', !needUUID);
    $('nb-e-user-wrap').classList.toggle('hidden', !needUser);
    $('nb-e-pass-wrap').classList.toggle('hidden', !needPass);
    $('nb-e-method-wrap').classList.toggle('hidden', !needMethod);
    $('nb-e-ss22-skey-wrap').classList.toggle('hidden', !isSS22);
    $('nb-e-ss22-ukey-wrap').classList.toggle('hidden', !isSS22);
    $('nb-e-ss22-obfs-wrap').classList.toggle('hidden', !isSS22);
    $('nb-e-ss22-obfshost-wrap').classList.toggle('hidden', !isSS22 || $('nb-e-obfs-mode').value === 'none');

    // 专家模式 · 传输层卡片显隐
    const showFlow = proto === 'vless' && trans === 'raw' && (secMode === 'reality' || secMode === 'tls');
    const showPath = (proto === 'vless' || proto === 'vmess' || proto === 'trojan') && (trans === 'ws' || trans === 'xhttp');
    const showHost = showPath;
    const showSvc = (proto === 'vless' || proto === 'vmess' || proto === 'trojan') && trans === 'grpc';
    const showXhttp = proto === 'vless' && trans === 'xhttp';
    const showUdp = proto === 'shadowsocks' || proto === 'shadowsocks2022' || proto === 'socks5';
    const anyTransportField = showFlow || showPath || showHost || showSvc || showXhttp || showUdp;

    $('nb-e-transport-card').classList.toggle('hidden', !anyTransportField);
    $('nb-e-flow-wrap').classList.toggle('hidden', !showFlow);
    $('nb-e-path-wrap').classList.toggle('hidden', !showPath);
    $('nb-e-host-wrap').classList.toggle('hidden', !showHost);
    $('nb-e-svc-wrap').classList.toggle('hidden', !showSvc);
    $('nb-e-xhttp-mode-wrap').classList.toggle('hidden', !showXhttp);
    $('nb-e-udp-wrap').classList.toggle('hidden', !showUdp);

    if (showFlow) {
      $('nb-e-flow').value = secOpt.flow || '';
    }

    // 专家模式 · 安全层与协议扩展卡片显隐
    const showReality = secMode === 'reality';
    const showTLS = secMode === 'tls';
    const showHy2 = proto === 'hysteria2';
    const showAnyTLS = proto === 'anytls';
    const anySecField = showReality || showTLS || isEnc || showHy2 || showAnyTLS;

    $('nb-e-security-card').classList.toggle('hidden', !anySecField);
    $('nb-e-reality-box').classList.toggle('hidden', !showReality);
    $('nb-e-tls-box').classList.toggle('hidden', !showTLS);
    $('nb-e-enc-box').classList.toggle('hidden', !isEnc);
    $('nb-e-hy2-box').classList.toggle('hidden', !showHy2);
    $('nb-e-anytls-box').classList.toggle('hidden', !showAnyTLS);

    $('nb-footer-hint').textContent = isSimplified
      ? '简易模式：留空项将由服务端自动生成并分配随机高位端口，保存后立即同步核心。'
      : '专家模式：完整应用自定义监听地址、端口（支持 443）、密钥与传输/安全参数。';

    // 若切到 REALITY 且尚未探测过，自动触发一次 SNI 并发探测
    if (showReality && !sniProbedOnce && port && builder.open) {
      void probeRealitySNI(!builder.editingId);
    }
  }

  function syncSimplifiedToExpert() {
    $('nb-e-name').value = $('nb-s-name').value;
    $('nb-e-port').value = $('nb-s-port').value;
    $('nb-e-server').value = $('nb-s-server').value;
    $('nb-e-tags').value = $('nb-s-tags').value;

    const secMode = getActiveSecurityOpt().security_mode;
    if (secMode === 'reality') {
      const sni = $('nb-s-sni').value.trim();
      if (sni) {
        $('nb-e-sni-select').value = sni;
        if (!$('nb-e-server-names').value.trim() || $('nb-e-server-names').value.split(',')[0].trim() !== sni) {
          $('nb-e-server-names').value = sni;
          $('nb-e-target').value = `${sni}:443`;
        }
      }
    }
    if (secMode === 'tls') {
      $('nb-e-binding').value = $('nb-s-binding').value;
      $('nb-e-tls-sni').value = $('nb-s-tls-sni').value;
    }
    if (builder.protocol === 'vless' && builder.secKey === 'enc') {
      $('nb-e-decryption').value = $('nb-s-decryption').value;
      $('nb-e-encryption').value = $('nb-s-encryption').value;
    }
    if (builder.protocol === 'shadowsocks' || builder.protocol === 'shadowsocks2022') {
      $('nb-e-method').value = $('nb-s-method').value;
    }
    if (builder.protocol === 'socks5' || builder.protocol === 'http') {
      $('nb-e-username').value = $('nb-s-username').value;
      $('nb-e-password').value = $('nb-s-password').value;
    }
  }

  function syncExpertToSimplified() {
    $('nb-s-name').value = $('nb-e-name').value;
    $('nb-s-port').value = $('nb-e-port').value;
    $('nb-s-server').value = $('nb-e-server').value;
    $('nb-s-tags').value = $('nb-e-tags').value;

    const firstSNI = $('nb-e-server-names').value.split(',')[0]?.trim();
    if (firstSNI) {
      populateSNISelects(firstSNI);
    }
    $('nb-s-binding').value = $('nb-e-binding').value;
    $('nb-s-tls-sni').value = $('nb-e-tls-sni').value;
    $('nb-s-decryption').value = $('nb-e-decryption').value;
    $('nb-s-encryption').value = $('nb-e-encryption').value;
    if ($('nb-e-method').value) $('nb-s-method').value = $('nb-e-method').value;
    $('nb-s-username').value = $('nb-e-username').value;
    $('nb-s-password').value = $('nb-e-password').value;
  }

  function buildDraftPayload() {
    if (builder.mode === 'simplified') {
      syncSimplifiedToExpert();
    }

    const proto = builder.protocol;
    const trans = TRANSPORT_MATRIX[proto] ? builder.transport : defaultTransport(proto);
    const secOpt = getActiveSecurityOpt();
    const secMode = secOpt.security_mode || 'none';
    const isEnc = proto === 'vless' && builder.secKey === 'enc';

    const cfg = {};
    const put = (key, val) => {
      if (val !== undefined && val !== null && String(val).trim() !== '') {
        cfg[key] = String(val).trim();
      }
    };

    if (proto === 'vless' || proto === 'vmess') {
      put('uuid', $('nb-e-uuid').value);
    }
    if (proto === 'vless') {
      const flowVal = builder.mode === 'expert' ? $('nb-e-flow').value : (secOpt.flow || '');
      if (flowVal) cfg.flow = flowVal;
      if (isEnc) {
        const decVal = $('nb-e-decryption').value.trim();
        if (decVal) {
          put('decryption', decVal);
        } else if (!builder.editingId) {
          put('decryption', 'none');
        }
        const encVal = $('nb-e-encryption').value.trim();
        if (encVal) {
          put('encryption', encVal);
        } else if (!builder.editingId) {
          put('encryption', 'none');
        }
      }
    }
    if (proto === 'trojan' || proto === 'shadowsocks' || proto === 'hysteria2' || proto === 'anytls' || proto === 'socks5' || proto === 'http') {
      put('password', $('nb-e-password').value);
    }
    if (proto === 'socks5' || proto === 'http') {
      put('username', $('nb-e-username').value);
    }
    if (proto === 'shadowsocks' || proto === 'shadowsocks2022') {
      put('method', $('nb-e-method').value);
      cfg.udp = $('nb-e-udp').checked;
    }
    if (proto === 'shadowsocks2022') {
      put('server_key', $('nb-e-server-key').value);
      put('user_key', $('nb-e-user-key').value);
      const obfsMode = $('nb-e-obfs-mode').value || 'none';
      cfg.obfs_mode = obfsMode;
      if (obfsMode !== 'none') put('obfs_host', $('nb-e-obfs-host').value);
    }
    if (proto === 'socks5') {
      cfg.udp = $('nb-e-udp').checked;
    }

    if (proto === 'vless' || proto === 'vmess' || proto === 'trojan') {
      if (trans === 'ws' || trans === 'xhttp') {
        put('path', $('nb-e-path').value);
        put('host', $('nb-e-host').value);
      }
      if (trans === 'grpc') {
        put('service_name', $('nb-e-service-name').value);
      }
      if (proto === 'vless' && trans === 'xhttp') {
        put('xhttp_mode', $('nb-e-xhttp-mode').value || 'auto');
      }
    }

    if (secMode === 'reality') {
      const rawNames = $('nb-e-server-names').value
        .split(/[,，\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const primarySni = rawNames[0] || $('nb-s-sni').value.trim() || DEFAULT_SNI_CANDIDATES[0];
      cfg.sni = primarySni;
      put('target', $('nb-e-target').value || `${primarySni}:443`);
      put('private_key', $('nb-e-private-key').value);
      put('short_id', $('nb-e-short-id').value);
      put('fingerprint', $('nb-e-fp').value || 'chrome');
    } else if (secMode === 'tls') {
      put('binding_ref', $('nb-e-binding').value);
      put('sni', $('nb-e-tls-sni').value);
      cfg.insecure = Boolean($('nb-e-insecure').checked);
    }

    if (proto === 'hysteria2') {
      put('obfs_password', $('nb-e-obfs-pass').value);
      put('port_hopping', $('nb-e-port-hopping').value);
    }

    if (proto === 'anytls') {
      const lines = $('nb-e-padding').value
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      cfg.padding_scheme = lines.length ? lines : DEFAULT_ANYTLS_PADDING.slice();
    }

    cfg.sniffing = $('nb-e-sniffing').checked;

    const payload = {
      mode: builder.mode,
      protocol: proto,
      transport: trans,
      security_mode: secMode,
      enabled: $('nb-e-enabled').checked,
      sync_core: $('nb-e-sync-core').checked,
      config: cfg,
    };

    const idVal = (builder.editingId || $('nb-e-id').value).trim();
    if (idVal) payload.id = idVal;

    const nameVal = $('nb-e-name').value.trim();
    if (nameVal) payload.name = nameVal;

    const listenVal = $('nb-e-listen').value.trim();
    if (listenVal) payload.listen = listenVal;

    const serverVal = $('nb-e-server').value.trim();
    if (serverVal) payload.server = serverVal;

    const rawPort = $('nb-e-port').value.trim();
    if (rawPort !== '') {
      const pNum = Math.floor(Number(rawPort));
      if (Number.isFinite(pNum) && pNum >= 0 && pNum <= 65535) {
        payload.port = pNum;
      }
    }

    const tags = parseTagList($('nb-e-tags').value);
    if (tags.length) payload.tags = tags;

    return payload;
  }

  function renderBuilderPreview() {
    const pre = $('nb-preview-code');
    const p = builder.lastPreview;
    if (!p) return;

    $('nb-preview-engine').textContent = p.engine || 'xray';
    $('nb-preview-port').textContent = `port: ${p.port || 'auto'}`;

    if (builder.previewTab === 'json') {
      pre.textContent = p.native_json || JSON.stringify(p.native_inbound || {}, null, 2);
    } else if (builder.previewTab === 'uri') {
      pre.textContent = p.share_uri || '（暂无分享 URI）';
    } else if (builder.previewTab === 'clash') {
      pre.textContent = p.clash_yaml || '# 当前协议暂未生成 Clash YAML';
    } else if (builder.previewTab === 'singbox') {
      pre.textContent = p.singbox_outbound ? JSON.stringify(p.singbox_outbound, null, 2) : '{}';
    }
  }

  async function runPreviewNow() {
    if (!builder.open || !port) return;
    const mySeq = ++builder.previewSeq;
    $('nb-preview-status').textContent = '正在更新预览…';
    try {
      const payload = buildDraftPayload();
      const res = await invoke('nodes.preview_json', payload);
      if (mySeq !== builder.previewSeq || !builder.open) return;
      builder.lastPreview = res;
      renderBuilderPreview();
      $('nb-preview-status').textContent = '实时预览已同步';
    } catch (err) {
      if (mySeq !== builder.previewSeq || !builder.open) return;
      $('nb-preview-status').textContent = '草稿参数待修正';
      $('nb-preview-code').textContent = `预览校验提示：\n${err?.message || '参数无效'}`;
    }
  }

  function schedulePreview() {
    if (!builder.open) return;
    if (builder.previewTimer) clearTimeout(builder.previewTimer);
    builder.previewTimer = setTimeout(() => {
      builder.previewTimer = null;
      void runPreviewNow();
    }, 250);
  }

  function resetBuilderForm() {
    $('nb-e-id').value = '';
    $('nb-e-id').readOnly = false;
    $('nb-e-name').value = '';
    $('nb-s-name').value = '';
    $('nb-e-listen').value = '0.0.0.0';
    $('nb-e-port').value = '';
    $('nb-s-port').value = '';
    $('nb-e-server').value = detectedPublicHost || '';
    $('nb-s-server').value = detectedPublicHost || '';
    $('nb-e-tags').value = '';
    syncObfsAvailabilityUI();
    $('nb-s-tags').value = '';
    $('nb-e-enabled').checked = true;
    $('nb-e-sniffing').checked = true;
    $('nb-e-sync-core').checked = true;

    $('nb-e-uuid').value = '';
    $('nb-e-username').value = '';
    $('nb-s-username').value = '';
    $('nb-e-password').value = '';
    $('nb-s-password').value = '';
    $('nb-e-server-key').value = '';
    $('nb-e-user-key').value = '';
    $('nb-e-obfs-mode').value = 'none';
    $('nb-e-obfs-host').value = '';

    $('nb-e-flow').value = 'xtls-rprx-vision';
    $('nb-e-path').value = '';
    $('nb-e-host').value = '';
    $('nb-e-service-name').value = '';
    $('nb-e-xhttp-mode').value = 'auto';
    $('nb-e-udp').checked = true;

    const defaultSni = sniProbeResults.find((x) => x.ok && x.tls13)?.domain || DEFAULT_SNI_CANDIDATES[0];
    populateSNISelects(defaultSni);
    $('nb-e-server-names').value = defaultSni;
    $('nb-e-target').value = `${defaultSni}:443`;
    $('nb-e-private-key').value = '';
    $('nb-e-short-id').value = '';
    $('nb-e-fp').value = 'chrome';

    $('nb-e-binding').value = '';
    $('nb-s-binding').value = '';
    $('nb-e-tls-sni').value = '';
    $('nb-s-tls-sni').value = '';
    $('nb-e-insecure').checked = false;

    $('nb-e-decryption').value = '';
    $('nb-s-decryption').value = '';
    $('nb-e-encryption').value = '';
    $('nb-s-encryption').value = '';

    $('nb-e-obfs-pass').value = '';
    $('nb-e-port-hopping').value = '';
    $('nb-e-padding').value = DEFAULT_ANYTLS_PADDING.join('\n');
  }

  function detectSecurityKeyFromNode(node) {
    const p = node.protocol;
    const t = node.transport === 'tcp' ? 'raw' : (node.transport || defaultTransport(p));
    const s = node.security_mode || 'none';
    const flow = node.config?.flow || '';
    if (p === 'vless') {
      if (t === 'raw') {
        if (s === 'reality') return flow === 'xtls-rprx-vision' ? 'xtls-vision-reality' : 'reality';
        if (s === 'tls') return flow === 'xtls-rprx-vision' ? 'xtls-vision' : 'tls';
        return 'enc';
      }
      if (s === 'reality') return 'reality';
      if (s === 'tls') return 'tls';
      return 'enc';
    }
    if (p === 'trojan') return s === 'reality' ? 'reality' : 'tls';
    if (p === 'vmess') return s === 'tls' ? 'tls' : 'none';
    if (p === 'anytls' || p === 'hysteria2') return 'tls';
    return 'none';
  }

  function openNodeBuilder(existingNode = null) {
    resetBuilderForm();
    builder.open = true;
    builder.previewTab = 'json';
    builder.lastPreview = null;

    for (const btn of document.querySelectorAll('#nb-preview-tabs button')) {
      btn.classList.toggle('active', btn.dataset.tab === 'json');
    }

    if (existingNode) {
      builder.editingId = existingNode.id;
      builder.mode = 'expert';
      builder.protocol = MANAGED_PROTOCOL_SET.has(existingNode.protocol) ? existingNode.protocol : 'vless';
      builder.transport = existingNode.transport === 'tcp' ? 'raw' : (existingNode.transport || defaultTransport(builder.protocol));
      builder.secKey = detectSecurityKeyFromNode(existingNode);

      $('nb-modal-title').textContent = `编辑代理节点 · ${existingNode.name || existingNode.id}`;
      $('nb-e-id').value = existingNode.id;
      $('nb-e-id').readOnly = true;
      $('nb-e-name').value = existingNode.name || '';
      $('nb-e-listen').value = existingNode.listen || '0.0.0.0';
      $('nb-e-port').value = existingNode.port ? String(existingNode.port) : '';
      $('nb-e-server').value = existingNode.server || '';
      $('nb-e-tags').value = (existingNode.tags || []).join(', ');
      $('nb-e-enabled').checked = Boolean(existingNode.enabled);

      const c = existingNode.config || {};
      $('nb-e-sniffing').checked = c.sniffing !== false;
      $('nb-e-uuid').value = c.uuid || '';
      $('nb-e-username').value = c.username || '';
      $('nb-e-password').value = c.password || '';
      if (builder.protocol === 'shadowsocks' || builder.protocol === 'shadowsocks2022') {
        populateMethodSelects(builder.protocol, c.method || '');
      }
      $('nb-e-server-key').value = c.server_key || '';
      $('nb-e-user-key').value = c.user_key || '';
      $('nb-e-obfs-mode').value = c.obfs_mode || 'none';
      $('nb-e-obfs-host').value = c.obfs_host || '';

      $('nb-e-flow').value = c.flow || '';
      $('nb-e-path').value = c.path || '';
      $('nb-e-host').value = c.host || '';
      $('nb-e-service-name').value = c.service_name || '';
      $('nb-e-xhttp-mode').value = c.xhttp_mode || 'auto';
      $('nb-e-udp').checked = c.udp !== false;

      if (c.sni) {
        populateSNISelects(c.sni);
        $('nb-e-server-names').value = c.sni;
        $('nb-e-tls-sni').value = c.sni;
      }
      $('nb-e-target').value = c.target || (c.sni ? `${c.sni}:443` : '');
      $('nb-e-private-key').value = c.private_key || '';
      $('nb-e-short-id').value = c.short_id || '';
      $('nb-e-fp').value = c.fingerprint || 'chrome';

      $('nb-e-binding').value = c.binding_ref || '';
      $('nb-e-insecure').checked = Boolean(c.insecure);
      $('nb-e-decryption').value = c.decryption || '';
      $('nb-e-encryption').value = c.encryption || '';
      $('nb-e-obfs-pass').value = c.obfs_password || '';
      $('nb-e-port-hopping').value = c.port_hopping || '';
      if (Array.isArray(c.padding_scheme) && c.padding_scheme.length) {
        $('nb-e-padding').value = c.padding_scheme.join('\n');
      }
      syncExpertToSimplified();
    } else {
      builder.editingId = '';
      builder.mode = 'simplified';
      builder.protocol = 'vless';
      builder.transport = 'raw';
      builder.secKey = 'xtls-vision-reality';
      $('nb-modal-title').textContent = '添加代理节点（简易 / 专家双模式）';
    }

    $('node-builder-modal').classList.remove('hidden');
    renderBuilderPills();
    updateBuilderFieldVisibility();
    void runPreviewNow();
  }

  function closeNodeBuilder() {
    builder.open = false;
    if (builder.previewTimer) {
      clearTimeout(builder.previewTimer);
      builder.previewTimer = null;
    }
    $('node-builder-modal').classList.add('hidden');
  }

  // ==================== 视图 3: 链式代理与 Cloudflare WARP 渲染 ====================

  function renderChains(chains) {
    cachedChains = chains;
    renderUserSelects();

    const nextSel = $('c-next');
    const prevNext = nextSel.value;
    clearNode(nextSel);
    const noneOpt = document.createElement('option');
    noneOpt.value = '';
    noneOpt.textContent = '（无，本节点即为最终落地）';
    nextSel.appendChild(noneOpt);
    for (const c of chains) {
      const opt = document.createElement('option');
      opt.value = c.id;
      opt.textContent = `${c.name} (${c.id})`;
      nextSel.appendChild(opt);
    }
    if (prevNext && chains.some((c) => c.id === prevNext)) nextSel.value = prevNext;

    const tbody = $('chains-body');
    clearNode(tbody);
    if (!chains.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.className = 'muted';
      td.textContent = '暂无链式代理落地节点，可在上方表单添加。';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const c of chains) {
      const tr = document.createElement('tr');

      const tdId = document.createElement('td');
      tdId.textContent = `${c.name} (${c.id})`;
      tr.appendChild(tdId);

      const tdMode = document.createElement('td');
      tdMode.textContent = c.mode;
      tr.appendChild(tdMode);

      const tdAddr = document.createElement('td');
      tdAddr.className = 'mono';
      tdAddr.textContent = `${c.protocol}://${c.server}:${c.port}`;
      tr.appendChild(tdAddr);

      const tdHop = document.createElement('td');
      tdHop.textContent = `${c.next_hop_id ? `-> ${c.next_hop_id}` : '直出'}${c.apply_default ? ' · 默认' : ''}`;
      tr.appendChild(tdHop);

      const tdMask = document.createElement('td');
      tdMask.className = 'muted';
      const masked = c.config_masked || {};
      const parts = [];
      if (masked.username) parts.push(`user=${masked.username}`);
      if (masked.has_password) parts.push('pwd=***');
      if (masked.has_uuid) parts.push('uuid=***');
      if (masked.method) parts.push(masked.method);
      if (masked.tls) parts.push(`TLS${masked.sni ? `(${masked.sni})` : ''}`);
      tdMask.textContent = parts.length ? parts.join(' · ') : '无认证';
      tr.appendChild(tdMask);

      const tdSt = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${c.enabled ? 'ok' : 'warn'}`;
      badge.textContent = c.enabled ? '启用' : '停用';
      tdSt.appendChild(badge);
      tr.appendChild(tdSt);

      const tdOps = document.createElement('td');
      const wrap = document.createElement('div');
      wrap.className = 'actions actions-tight';

      const btnProbe = document.createElement('button');
      btnProbe.type = 'button';
      btnProbe.className = 'btn sm ghost';
      btnProbe.textContent = 'TCP 探测';
      btnProbe.addEventListener('click', async () => {
        const r = await runAction(`探测 ${c.id}`, () => invoke('chains.probe', { id: c.id }));
        if (!r) return;
        if (r.reachable) {
          showBanner(`链式落地 ${c.id} (${r.server}:${r.port}) TCP 连通正常，延迟 ${r.latency_ms} ms`, 'ok');
        } else {
          showBanner(`链式落地 ${c.id} (${r.server}:${r.port}) 不可达：${r.error || '超时'}`, 'warn');
        }
      });
      wrap.appendChild(btnProbe);

      const btnDel = document.createElement('button');
      btnDel.type = 'button';
      btnDel.className = 'btn sm danger';
      btnDel.textContent = '删除';
      btnDel.addEventListener('click', async () => {
        const ok = await hostConfirm({
          title: '删除链式代理节点',
          body: `确认删除链式代理节点 ${c.id}？引用它的用户将回退为直连。`,
          confirmLabel: '确认删除',
          danger: true,
        });
        if (!ok) return;
        const r = await runAction(`删除链式代理 ${c.id}`, () => invoke('chains.delete', { id: c.id }));
        if (r) {
          showBanner(`已删除链式代理节点 ${c.id}`, 'ok');
          void refreshChains();
        }
      });
      wrap.appendChild(btnDel);

      tdOps.appendChild(wrap);
      tr.appendChild(tdOps);
      tbody.appendChild(tr);
    }
  }

  const WARP_MODE_LABELS = {
    bound_ports: '指定端口全流量走 WARP',
    domains: '仅解锁域名走 WARP（其余直连）',
    all: '全部代理端口全局走 WARP',
  };

  function renderWARPStatus(data) {
    const w = data?.warp || {};
    cachedWARP = data;
    cachedWARPPresets = data?.unlock_presets || {};

    $('w-state').textContent = w.registered
      ? (w.enabled ? `已启用 (${(w.account_type || 'free').toUpperCase()})` : '已注册 · 未启用')
      : '未注册';
    $('w-account').textContent = w.registered
      ? `账号 ${w.account_id || '—'}${w.license_key_masked ? ` · License ${w.license_key_masked}` : ''}`
      : '点击下方「一键注册 Cloudflare WARP」自动申请 WireGuard 凭据';
    $('w-addrs').textContent = w.registered
      ? [w.address_v4, w.address_v6].filter(Boolean).join(' / ') || '—'
      : '—';
    $('w-reserved').textContent = w.registered && Array.isArray(w.reserved) && w.reserved.length
      ? `reserved: [${w.reserved.join(', ')}]${w.client_id ? ` (${w.client_id})` : ''}`
      : 'reserved: —';
    $('w-ep-summary').textContent = w.endpoint || 'engage.cloudflareclient.com:2408';
    $('w-mode-summary').textContent = WARP_MODE_LABELS[w.routing_mode] || w.routing_mode || '—';
    $('w-sync-state').textContent = w.registered ? (w.last_synced_rev ? '已同步至内置 Xray 引擎' : '待同步生效') : '未配置';
    $('w-sync-rev').textContent = w.last_synced_rev ? `内置 Xray rev: ${w.last_synced_rev}` : '保存绑定后自动热重载 Xray';

    $('w-endpoint').value = w.endpoint || 'engage.cloudflareclient.com:2408';
    $('w-mode').value = w.routing_mode || 'bound_ports';
    $('w-mtu').value = String(w.mtu || 1280);
    $('w-enabled').checked = w.registered ? Boolean(w.enabled) : true;
    $('w-domains').value = Array.isArray(w.domains) ? w.domains.join('\n') : '';

    const box = $('w-ports-box');
    clearNode(box);
    const inbounds = data?.inbounds || [];
    if (!inbounds.length) {
      const sp = document.createElement('span');
      sp.className = 'muted';
      sp.textContent = '尚未检测到已启用的托管代理入站端口，请先在「节点管理」创建节点，或直接选择“全局/域名模式”。';
      box.appendChild(sp);
    } else {
      for (const ib of inbounds) {
        const lbl = document.createElement('label');
        lbl.className = 'warp-port-chip';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.dataset.warpPort = ib.profile_id;
        cb.checked = Boolean(ib.bound);
        lbl.appendChild(cb);
        const txt = document.createElement('span');
        txt.textContent = `${ib.label}${ib.enabled ? '' : '（已停用）'}`;
        lbl.appendChild(txt);
        box.appendChild(lbl);
      }
    }
  }

  function readSelectedWARPPorts() {
    const out = [];
    for (const cb of document.querySelectorAll('input[data-warp-port]')) {
      if (cb.checked) out.push(cb.dataset.warpPort);
    }
    return out;
  }

  function readWARPDomainsInput() {
    return $('w-domains').value
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function appendWARPPreset(key) {
    const preset = cachedWARPPresets[key] || [];
    const cur = new Set(readWARPDomainsInput());
    for (const d of preset) cur.add(d);
    $('w-domains').value = Array.from(cur).join('\n');
    $('w-mode').value = 'domains';
  }

  // ==================== 视图 4: tcpfit 调优 + TCP Brutal 渲染 ====================

  function updateOversendPreview() {
    const bw = Math.max(1, Number($('b-bw').value) || 100);
    const pct = Math.min(250, Math.max(100, Number($('b-oversend').value) || 125));
    const eff = ((bw * pct) / 100).toFixed(1);
    $('b-eff-preview').textContent = `折算等效发包速率：${eff} Mbps（基准 ${bw} Mbps × ${pct}%）`;
    for (const btn of document.querySelectorAll('#b-oversend-presets button[data-oversend]')) {
      btn.classList.toggle('active', Number(btn.dataset.oversend) === pct);
    }
  }

  function renderTuningPlan(plan) {
    const bdpKB = Math.round((plan.bdp_bytes || 0) / 1024);
    const maxMB = ((plan.max_buffer_bytes || 0) / (1024 * 1024)).toFixed(1);
    const budgetMB = ((plan.mem_budget_bytes || 0) / (1024 * 1024)).toFixed(0);
    $('t-plan-summary').textContent =
      `推导完成：BDP ≈ ${bdpKB} KiB · 安全单流缓冲区上限 ${maxMB} MiB（受物理内存预算 ${budgetMB} MiB 保护）· 选定拥塞算法：${plan.selected_cc}`;

    const swapWarn = $('t-swap-warn');
    if (plan.swap_recommendation) {
      swapWarn.className = 'banner warn show mt-10';
      swapWarn.textContent = plan.swap_recommendation;
    } else {
      swapWarn.className = 'banner warn mt-10';
      swapWarn.textContent = '';
    }

    const tbody = $('t-diff-body');
    clearNode(tbody);
    for (const item of plan.changes || []) {
      const tr = document.createElement('tr');
      for (const val of [item.key, item.current || '（未读到）', item.recommended, item.reason]) {
        const td = document.createElement('td');
        td.textContent = String(val);
        if (val === item.key || val === item.recommended) td.className = 'mono';
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }

    const pre = $('t-conf-preview');
    pre.textContent = plan.rendered_conf || '';
    pre.classList.toggle('hidden', !plan.rendered_conf);
  }

  function renderTuningStatus(data) {
    const p = data.profile || {};
    const cur = p.current_sysctl || {};
    $('t-ram').textContent = `${p.total_ram_mb || 0} MiB / Swap ${p.swap_total_mb || 0} MiB`;
    $('t-kernel').textContent = `${p.os || 'linux'} · ${p.kernel_version || 'unknown'} · ${p.cpus || 1} vCPU`;
    $('t-cc').textContent = `${cur['net.ipv4.tcp_congestion_control'] || '—'} / ${cur['net.core.default_qdisc'] || '—'}`;
    const env = data.brutal_env || {};
    $('t-avail-cc').textContent = `可用算法: ${(env.available_cc || []).join(', ') || '—'}`;
    $('t-iperf-status').textContent = p.iperf3_available ? 'iperf3 可用' : '未安装 iperf3';
    const snaps = data.snapshots || [];
    $('t-snap-count').textContent = `已保存 ${snaps.length} 份可回滚快照`;

    const tbody = $('t-snaps-body');
    clearNode(tbody);
    if (!snaps.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'muted';
      td.textContent = '暂无调优快照，首次演练或应用时将自动保存基线。';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const s of snaps) {
      const tr = document.createElement('tr');
      for (const val of [
        `#r${s.revision}`,
        s.reason,
        `${s.role} · ${s.bandwidth_mbps}Mbps / ${s.rtt_ms}ms`,
        s.applied ? '已生效' : '基线 / 演练',
      ]) {
        const td = document.createElement('td');
        td.textContent = String(val);
        tr.appendChild(td);
      }
      const tdOp = document.createElement('td');
      const btnRb = document.createElement('button');
      btnRb.type = 'button';
      btnRb.className = 'btn sm ghost';
      btnRb.textContent = '回滚至此快照';
      btnRb.addEventListener('click', async () => {
        const ok = await hostConfirm({
          title: '回滚宿主机 sysctl 快照',
          body: `确认回滚宿主机 sysctl 至快照 #r${s.revision} (${s.reason})？`,
          confirmLabel: '确认回滚',
          danger: true,
        });
        if (!ok) return;
        const r = await runAction(`回滚快照 #r${s.revision}`, () =>
          invoke('tuning.rollback', { snapshot_id: s.id, dry_run: false }));
        if (r) {
          showBanner(
            r.applied ? `已回滚并生效至快照 #r${s.revision}` : `已渲染快照 #r${s.revision}（${r.error || r.output}）`,
            r.applied ? 'ok' : 'warn',
          );
          void refreshTuningAndBrutal();
        }
      });
      tdOp.appendChild(btnRb);
      tr.appendChild(tdOp);
      tbody.appendChild(tr);
    }
  }

  function renderBrutalStatus(data) {
    const env = data.env || {};
    $('b-env-status').textContent = env.brutal_available ? '已加载 brutal 模块' : '内核未加载（降级转发）';
    $('b-env-detail').textContent = env.brutal_available
      ? `eBPF=${env.ebpf_pinned ? 'pinned' : 'kmod'} · 安装命令: ${env.install_hint || ''}`
      : `安装提示: ${env.install_hint || ''}`;

    const guide = $('b-guidance');
    if (env.degraded_guidance) {
      guide.className = 'banner warn show';
      guide.textContent = `${env.degraded_guidance} 推荐部署命令：${env.install_hint || ''}`;
    } else {
      guide.className = 'banner warn';
      guide.textContent = '';
    }

    cachedInbounds = data.tcp_inbounds || [];
    const presetSel = $('b-inbound-preset');
    clearNode(presetSel);
    const firstOpt = document.createElement('option');
    firstOpt.value = '';
    firstOpt.textContent = cachedInbounds.length ? '选择已配置的 TCP 订阅入站自动填充…' : '暂无可自动填充的 TCP 入站';
    presetSel.appendChild(firstOpt);
    for (const ib of cachedInbounds) {
      const opt = document.createElement('option');
      opt.value = ib.inbound_tag;
      opt.textContent = ib.label;
      presetSel.appendChild(opt);
    }

    const bindings = data.bindings || [];
    const metrics = data.live_listeners || [];
    $('brutal-mini-count').textContent = `${metrics.filter((m) => m.running).length} / ${bindings.length} 运行`;

    const bBody = $('b-bindings-body');
    clearNode(bBody);
    if (!bindings.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'muted';
      td.textContent = '暂无 Brutal 接管绑定。您可以只为某个 TCP 订阅（如 vless-tcp）创建绑定。';
      tr.appendChild(td);
      bBody.appendChild(tr);
    } else {
      for (const b of bindings) {
        const tr = document.createElement('tr');
        for (const val of [
          `${b.id} (${b.inbound_tag} / ${b.protocol})`,
          `:${b.listen_port} -> 127.0.0.1:${b.target_port}`,
          `${b.bandwidth_mbps} Mbps × ${b.oversend_pct}% = ${Number(b.effective_mbps || 0).toFixed(1)} Mbps`,
          `${b.cwnd_gain} (${(b.cwnd_gain / 10).toFixed(1)}x)`,
          `${b.enable_in_sub ? '订阅自动切端口' : '仅手动接管'} · ${b.enabled ? '启用' : '停用'}`,
        ]) {
          const td = document.createElement('td');
          td.textContent = String(val);
          tr.appendChild(td);
        }
        const tdOp = document.createElement('td');
        const btnDel = document.createElement('button');
        btnDel.type = 'button';
        btnDel.className = 'btn sm danger';
        btnDel.textContent = '删除';
        btnDel.addEventListener('click', async () => {
          const ok = await hostConfirm({
            title: '删除 Brutal 接管绑定',
            body: `确认删除 Brutal 接管绑定 ${b.id}？对应的透明接管端口将会停止监听。`,
            confirmLabel: '确认删除',
            danger: true,
          });
          if (!ok) return;
          const r = await runAction(`删除绑定 ${b.id}`, () => invoke('brutal.binding.delete', { id: b.id }));
          if (r) {
            showBanner(`已删除 Brutal 接管绑定 ${b.id}`, 'ok');
            void refreshTuningAndBrutal();
          }
        });
        tdOp.appendChild(btnDel);
        tr.appendChild(tdOp);
        bBody.appendChild(tr);
      }
    }

    const mBody = $('b-metrics-body');
    clearNode(mBody);
    if (!metrics.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'muted';
      td.textContent = '尚无已启动的透明接管监听，请点击“立即应用 / 热重载所有接管端口”。';
      tr.appendChild(td);
      mBody.appendChild(tr);
    } else {
      for (const m of metrics) {
        const tr = document.createElement('tr');
        for (const val of [
          `${m.binding_id} (${m.inbound_tag})`,
          m.bound_addr || '—',
          `${m.active_conns || 0} / ${m.total_conns || 0}`,
          `${m.brutal_applied_conns || 0} 生效 / ${m.fallback_conns || 0} 回退`,
          `${formatBytes(m.bytes_tx || 0)} / ${formatBytes(m.bytes_rx || 0)}`,
          m.last_sockopt_error || '正常',
        ]) {
          const td = document.createElement('td');
          td.textContent = String(val);
          tr.appendChild(td);
        }
        mBody.appendChild(tr);
      }
    }
  }

  // ==================== 数据拉取调度 ====================

  async function refreshProxyHome() {
    const [overview, plansResp, usersResp, trafficResp, chainsResp, brutalResp] = await Promise.all([
      invoke('proxy.overview', { include_traffic_status: false }),
      invoke('plans.list', { limit: 100 }),
      invoke('users.list', { limit: 256 }),
      invoke('traffic.status', { include_classes: true }),
      invoke('chains.list', {}),
      invoke('brutal.status', {}),
    ]);
    applyOverviewCapabilities(overview);
    $('overview-value').textContent = `${overview.active_users ?? 0} / ${overview.total_users ?? 0} 活跃`;
    $('overview-sub').textContent = overview.sub || '运行正常';
    if (trafficResp.supported) {
      $('traffic-status').textContent = `已启用 (${trafficResp.egress_interface || '默认'})`;
      $('traffic-detail').textContent = `当前下发 ${(trafficResp.classes || []).length} 条规则${trafficResp.uplink_ifb_supported ? '，支持上行 IFB' : '，仅下行整形'}`;
    } else {
      $('traffic-status').textContent = 'HTB 已降级';
      $('traffic-detail').textContent = trafficResp.degraded_reason || '当前内核不支持 HTB 流量整形';
    }
    cachedChains = chainsResp.chains || [];
    renderPlans(plansResp.plans || []);
    renderUsers(usersResp.users || []);
    renderBrutalStatus(brutalResp);
  }

  async function refreshChains() {
    const [chainsRes, warpRes] = await Promise.all([
      invoke('chains.list', {}),
      invoke('warp.status', {}),
    ]);
    renderChains(chainsRes.chains || []);
    renderWARPStatus(warpRes);
    if (!xrayStatusLoaded) {
      invoke('xray.status', {}).then(renderXrayEngineStatus).catch(() => {});
    }
  }

  async function refreshTuningAndBrutal() {
    const [tRes, bRes] = await Promise.all([
      invoke('tuning.status', {}),
      invoke('brutal.status', {}),
    ]);
    renderTuningStatus(tRes);
    renderBrutalStatus(bRes);
    if (!xrayStatusLoaded) {
      invoke('xray.status', {}).then(renderXrayEngineStatus).catch(() => {});
    }
  }

  async function refreshActiveView() {
    if (!port) return;
    setStatus('正在同步状态…');
    try {
      if (activeRoute === '/proxy') await refreshProxyHome();
      else if (activeRoute === '/proxy/nodes') await refreshNodes();
      else if (activeRoute === '/proxy/chains') await refreshChains();
      else if (activeRoute === '/proxy/tuning') await refreshTuningAndBrutal();
      setStatus('已连接');
    } catch (err) {
      setStatus(`读取失败：${err?.message || '未知错误'}`);
    }
  }

  // ==================== 事件绑定：全局与视图 1 ====================

  for (const btn of document.querySelectorAll('#nav-tabs button')) {
    btn.addEventListener('click', () => switchRoute(btn.dataset.route, true));
  }
  $('btn-quick-add-node')?.addEventListener('click', () => {
    if (activeRoute !== '/proxy/nodes') switchRoute('/proxy/nodes', true);
    openNodeBuilder(null);
  });
  $('refresh').addEventListener('click', () => {
    void refreshActiveView();
  });

  $('btn-plan-create-open')?.addEventListener('click', () => openPlanEditModal(null));
  $('pe-close')?.addEventListener('click', closePlanEditModal);
  $('pe-cancel')?.addEventListener('click', closePlanEditModal);
  $('plan-edit-modal')?.addEventListener('click', (e) => {
    if (e.target === $('plan-edit-modal')) closePlanEditModal();
  });

  $('btn-plan-save').addEventListener('click', async () => {
    const id = $('p-id').value.trim();
    const name = $('p-name').value.trim();
    if (!id || !name) {
      showBanner('请填写套餐 ID 与套餐名称', 'warn');
      return;
    }
    const quotaGB = Math.max(0, Number($('p-quota-gb').value) || 0);
    const resetDay = Math.min(28, Math.max(0, Math.floor(Number($('p-reset-day').value) || 0)));
    const validityDays = Math.min(3650, Math.max(0, Math.floor(Number($('p-validity').value) || 0)));
    const payload = {
      id,
      name,
      quota_bytes: Math.round(quotaGB * 1024 * 1024 * 1024),
      down_limit_kbps: Math.max(0, Number($('p-down').value) || 0),
      up_limit_kbps: Math.max(0, Number($('p-up').value) || 0),
      max_connections: Math.max(0, Number($('p-max-conns').value) || 0),
      max_ips: Math.max(0, Number($('p-max-ips').value) || 0),
      billing_reset_day: resetDay,
      validity_days: validityDays,
    };
    const r = await runAction('保存套餐', () => invoke('plans.upsert', payload));
    if (r) {
      closePlanEditModal();
      showBanner(`套餐 ${r.plan?.name || name} (${r.plan?.id || id}) 已保存`, 'ok');
      void refreshProxyHome();
    }
  });

  $('btn-user-limits').addEventListener('click', async () => {
    const userId = $('ul-user').value.trim();
    if (!userId) {
      showBanner('请先选择目标用户', 'warn');
      return;
    }
    const payload = {
      user_id: userId,
      max_connections_override: Number($('ul-conns').value),
      max_ips_override: Number($('ul-ips').value),
      chain_id: $('ul-chain').value,
    };
    const r = await runAction(`更新用户 ${userId} 连接与链式策略`, () => invoke('users.set_limits', payload));
    if (r) {
      showBanner(`用户 ${userId} 生效上限：${formatLimit(r.user?.effective_max_connections || 0)} 连接 / ${formatLimit(r.user?.effective_max_ips || 0)} IP`, 'ok');
      void refreshProxyHome();
    }
  });

  $('btn-nft-preview').addEventListener('click', async () => {
    const r = await runAction('生成 nftables 连接限流规则', () => invoke('users.connections.status', { include_nftables: true }));
    if (r) {
      const pre = $('nft-preview');
      pre.textContent = r.nftables_rules || '# 当前没有需要下发的 nftables 连接限制规则';
      pre.classList.remove('hidden');
    }
  });

  // 新建订阅用户弹窗事件
  $('btn-user-create-open').addEventListener('click', openUserCreateModal);
  $('uc-close').addEventListener('click', closeUserCreateModal);
  $('uc-cancel').addEventListener('click', closeUserCreateModal);
  $('user-create-modal').addEventListener('click', (e) => {
    if (e.target === $('user-create-modal')) closeUserCreateModal();
  });
  $('uc-plan-mode').addEventListener('change', updateUserCreatePlanMode);
  $('uc-submit').addEventListener('click', async () => {
    const id = $('uc-id').value.trim();
    const displayName = $('uc-name').value.trim() || id;
    if (!id) {
      showBanner('请输入小写字母开头的用户 ID', 'warn');
      return;
    }
    const mode = $('uc-plan-mode').value;
    let planId = $('uc-plan').value.trim();
    if (mode === 'custom') {
      const rawCustomId = `custom-${id}`.slice(0, 32);
      const quotaGB = Math.max(0, Number($('uc-custom-quota').value) || 0);
      const resetDay = Math.min(28, Math.max(0, Number($('uc-custom-reset-day').value) || 0));
      const downKbps = Math.max(0, Number($('uc-custom-down').value) || 0);
      const upKbps = Math.max(0, Number($('uc-custom-up').value) || 0);
      const pRes = await runAction(`保存专属套餐 ${rawCustomId}`, () =>
        invoke('plans.upsert', {
          id: rawCustomId,
          name: `${displayName} 专属配额`,
          quota_bytes: Math.round(quotaGB * 1024 * 1024 * 1024),
          down_limit_kbps: downKbps,
          up_limit_kbps: upKbps,
          max_connections: 0,
          max_ips: 0,
          billing_reset_day: resetDay,
          validity_days: 0,
        }));
      if (!pRes) return;
      planId = pRes.plan?.id || rawCustomId;
    }
    if (!planId) {
      showBanner('请选择已有套餐或切换为自定义配额与上下行限速', 'warn');
      return;
    }
    const payload = {
      id,
      display_name: displayName,
      plan_id: planId,
      max_connections_override: Number($('uc-max-conns').value),
      max_ips_override: Number($('uc-max-ips').value),
      chain_id: $('uc-chain').value,
    };
    const r = await runAction(`创建订阅用户 ${id}`, () => invoke('users.create', payload));
    if (!r) return;
    closeUserCreateModal();
    if (r.subscription_token) {
      openUserSubModal({
        userId: r.user?.id || id,
        displayName: r.user?.display_name || displayName,
        token: r.subscription_token,
        path: r.subscription_path,
        subtitle: r.shaping_degraded
          ? `已同步内置 Xray 引擎 (rev ${r.core_revision || '-'}) · 限速降级提示：${r.shaping_degraded_reason}`
          : `已同步内置 Xray 引擎 (rev ${r.core_revision || '-'}) 与内核限速`,
      });
    } else {
      showBanner(`用户 ${id} 已创建`, 'ok');
    }
    void refreshProxyHome();
  });

  // 一次性订阅令牌弹窗事件
  $('us-close').addEventListener('click', closeUserSubModal);
  $('us-close-btn').addEventListener('click', closeUserSubModal);
  $('user-sub-modal').addEventListener('click', (e) => {
    if (e.target === $('user-sub-modal')) closeUserSubModal();
  });
  $('us-copy-token').addEventListener('click', () => {
    void hostCopy(userSubModal.token, '已复制纯订阅 Token');
  });
  $('us-copy-clash').addEventListener('click', () => {
    void hostCopy($('us-url-clash').value, '已复制 Clash 订阅链接');
  });
  $('us-copy-singbox').addEventListener('click', () => {
    void hostCopy($('us-url-singbox').value, '已复制 Sing-box 订阅链接');
  });
  $('us-copy-base64').addEventListener('click', () => {
    void hostCopy($('us-url-base64').value, '已复制 Base64 通用订阅链接');
  });

  // 小时级流量历史抽屉事件
  $('uh-close').addEventListener('click', closeUserHistoryModal);
  $('uh-close-btn').addEventListener('click', closeUserHistoryModal);
  $('user-history-modal').addEventListener('click', (e) => {
    if (e.target === $('user-history-modal')) closeUserHistoryModal();
  });
  $('uh-range-pills').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-hours]');
    if (!btn || !userHistoryModal.userId) return;
    const h = Number(btn.dataset.hours) || 24;
    userHistoryModal.hours = h;
    for (const b of document.querySelectorAll('#uh-range-pills button')) {
      b.classList.toggle('active', Number(b.dataset.hours) === h);
    }
    void loadUserUsageHistory(userHistoryModal.userId, h);
  });

  // ==================== 事件绑定：视图 2（节点管理与双模式构建器） ====================

  $('btn-node-add').addEventListener('click', () => openNodeBuilder(null));
  $('btn-nodes-refresh').addEventListener('click', () => {
    void refreshActiveView();
  });

  $('n-proto-filters').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-proto]');
    if (!btn) return;
    nodeFilters.protocol = btn.dataset.proto || '';
    renderNodesTable();
  });

  $('n-source-filters').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-source]');
    if (!btn) return;
    nodeFilters.source = btn.dataset.source || '';
    renderNodesTable();
  });

  $('n-tag-filters').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tag]');
    if (!btn) return;
    nodeFilters.tag = btn.dataset.tag || '';
    renderNodesTable();
  });

  $('n-search').addEventListener('input', () => {
    nodeFilters.search = $('n-search').value;
    renderNodesTable();
  });

  $('btn-nodes-import-clear').addEventListener('click', () => {
    $('n-import-uris').value = '';
    $('n-import-tags').value = '';
    const fb = $('n-import-feedback');
    fb.className = 'banner mt-10';
    fb.textContent = '';
  });

  $('btn-nodes-import').addEventListener('click', async () => {
    const uris = $('n-import-uris').value.trim();
    if (!uris) {
      showBanner('请先粘贴至少一条节点 URI 或 Base64 订阅内容', 'warn');
      return;
    }
    const payload = {
      uris,
      tags: parseTagList($('n-import-tags').value),
      enabled: $('n-import-enabled').checked,
    };
    const r = await runAction('解析并导入外部节点', () => invoke('nodes.import_uri', payload));
    if (!r) return;
    const importedCount = Number(r.imported_count || 0);
    const errs = Array.isArray(r.errors) ? r.errors : [];
    const fb = $('n-import-feedback');
    if (errs.length) {
      const sample = errs.slice(0, 3).map((x) => `第 ${x.line} 行: ${x.error}`).join('；');
      fb.className = 'banner show warn mt-10';
      fb.textContent = `已导入 ${importedCount} 个节点，另有 ${errs.length} 条解析失败（${sample}）`;
      showBanner(`已导入 ${importedCount} 个外部节点（${errs.length} 条跳过）`, 'warn');
    } else {
      fb.className = 'banner show ok mt-10';
      fb.textContent = `成功解析并导入 ${importedCount} 个外部节点，已纳入多协议订阅汇总。`;
      $('n-import-uris').value = '';
      showBanner(`成功导入 ${importedCount} 个外部节点`, 'ok');
    }
    void refreshNodes();
  });

  // 节点列表行操作委托
  $('nodes-body').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-node-action]');
    if (!btn) return;
    const action = btn.dataset.nodeAction;
    const id = btn.dataset.nodeId;
    const node = cachedNodes.find((x) => x.id === id);
    if (!node) return;

    if (action === 'test') {
      btn.disabled = true;
      btn.textContent = '测速中…';
      try {
        const r = await runAction(`测速节点 ${node.name || node.id}`, () => invoke('nodes.test', { id: node.id }));
        if (r) {
          if (r.ok) {
            showBanner(
              `节点 ${node.name || node.id} (${r.target}) 连通正常，延迟 ${r.latency_ms} ms${r.tls_version ? ` · ${r.tls_version}` : ''}`,
              'ok',
            );
          } else {
            showBanner(`节点 ${node.name || node.id} (${r.target}) 不可达：${r.error || '连接超时'}`, 'warn');
          }
          await refreshNodes();
        }
      } finally {
        btn.disabled = false;
        btn.textContent = '测速';
      }
      return;
    }

    if (action === 'copy') {
      const uri = node.share_uri || node.raw_uri || '';
      if (!uri) {
        showBanner(`节点 ${node.name || node.id} 暂无可复制的分享 URI`, 'warn');
        return;
      }
      await hostCopy(uri, `已复制 ${node.name || node.id} 分享链接`);
      return;
    }

    if (action === 'view') {
      void openConfigViewer(node);
      return;
    }

    if (action === 'edit') {
      openNodeBuilder(node);
      return;
    }

    if (action === 'toggle') {
      const nextEnabled = !node.enabled;
      const payload = {
        id: node.id,
        mode: 'expert',
        name: node.name,
        protocol: node.protocol,
        transport: node.transport || defaultTransport(node.protocol),
        security_mode: node.security_mode || 'none',
        listen: node.listen || '0.0.0.0',
        server: node.server || '',
        port: Number(node.port) || 0,
        enabled: nextEnabled,
        tags: Array.isArray(node.tags) ? node.tags : [],
        config: node.config || {},
        sync_core: true,
      };
      const r = await runAction(`${nextEnabled ? '启用' : '停用'}节点 ${node.name || node.id}`, () => invoke('nodes.upsert', payload));
      if (r) {
        const syncMsg = r.core_synced ? '并已同步内置 Xray 引擎' : (r.core_sync_note || '已更新本地状态');
        showBanner(`节点 ${node.name || node.id} 已${nextEnabled ? '启用' : '停用'}（${syncMsg}）`, 'ok');
        void refreshNodes();
      }
      return;
    }

    if (action === 'delete') {
      const ok = await hostConfirm({
        title: '删除代理节点',
        body: `确认删除节点「${node.name || node.id}」(${node.protocol.toUpperCase()} :${node.port})？${node.source === 'managed' ? '删除后将同步重载内置 Xray 引擎。' : ''}`,
        confirmLabel: '确认删除',
        danger: true,
      });
      if (!ok) return;
      const r = await runAction(`删除节点 ${node.id}`, () => invoke('nodes.delete', { id: node.id, sync_core: true }));
      if (r) {
        showBanner(
          `已删除节点 ${node.name || node.id}${r.core_synced ? `（内置 Xray rev: ${r.core_revision || '最新'}）` : ''}`,
          'ok',
        );
        void refreshNodes();
      }
    }
  });

  // 查看配置弹窗事件
  $('nc-close').addEventListener('click', closeConfigViewer);
  $('nc-close-btn').addEventListener('click', closeConfigViewer);
  $('node-config-modal').addEventListener('click', (e) => {
    if (e.target === $('node-config-modal')) closeConfigViewer();
  });
  $('nc-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    configViewer.tab = btn.dataset.tab;
    for (const b of document.querySelectorAll('#nc-tabs button')) {
      b.classList.toggle('active', b.dataset.tab === configViewer.tab);
    }
    renderConfigViewerContent();
  });
  $('nc-copy').addEventListener('click', () => {
    void hostCopy($('nc-code').textContent, '已复制节点配置内容');
  });

  // 节点构建器弹窗事件
  $('nb-close').addEventListener('click', closeNodeBuilder);
  $('nb-cancel').addEventListener('click', closeNodeBuilder);
  $('node-builder-modal').addEventListener('click', (e) => {
    if (e.target === $('node-builder-modal')) closeNodeBuilder();
  });

  $('nb-proto-pills').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-proto]');
    if (!btn) return;
    const nextProto = btn.dataset.proto;
    if (nextProto === builder.protocol) return;
    builder.protocol = nextProto;
    builder.transport = defaultTransport(nextProto);
    builder.secKey = defaultSecurityKey(nextProto, builder.transport);
    renderBuilderPills();
    updateBuilderFieldVisibility();
    schedulePreview();
  });

  $('nb-transport-pills').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-transport]');
    if (!btn) return;
    const nextTrans = btn.dataset.transport;
    if (nextTrans === builder.transport) return;
    builder.transport = nextTrans;
    const sOpts = getSecurityOptions(builder.protocol, builder.transport);
    if (!sOpts.some((x) => x.key === builder.secKey)) {
      builder.secKey = defaultSecurityKey(builder.protocol, builder.transport);
    }
    renderBuilderPills();
    updateBuilderFieldVisibility();
    schedulePreview();
  });

  $('nb-security-pills').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-seckey]');
    if (!btn) return;
    builder.secKey = btn.dataset.seckey;
    const opt = getActiveSecurityOpt();
    $('nb-e-flow').value = opt.flow || '';
    renderBuilderPills();
    updateBuilderFieldVisibility();
    schedulePreview();
  });

  $('nb-mode-seg').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-mode]');
    if (!btn) return;
    const nextMode = btn.dataset.mode;
    if (nextMode === builder.mode) return;
    if (builder.mode === 'simplified') syncSimplifiedToExpert();
    else syncExpertToSimplified();
    builder.mode = nextMode;
    renderBuilderPills();
    updateBuilderFieldVisibility();
    schedulePreview();
  });

  $('nb-listen-chips').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-listen]');
    if (!btn) return;
    $('nb-e-listen').value = btn.dataset.listen;
    schedulePreview();
  });

  $('nb-s-probe-sni').addEventListener('click', () => {
    void probeRealitySNI(true);
  });
  $('nb-e-probe-sni').addEventListener('click', () => {
    void probeRealitySNI(true);
  });

  $('nb-s-sni').addEventListener('change', () => {
    const v = $('nb-s-sni').value.trim();
    if (v) {
      $('nb-e-sni-select').value = v;
      $('nb-e-server-names').value = v;
      $('nb-e-target').value = `${v}:443`;
    }
    schedulePreview();
  });

  $('nb-e-sni-select').addEventListener('change', () => {
    const v = $('nb-e-sni-select').value.trim();
    if (v) {
      $('nb-s-sni').value = v;
      $('nb-e-server-names').value = v;
      $('nb-e-target').value = `${v}:443`;
    }
    schedulePreview();
  });

  $('nb-e-obfs-mode').addEventListener('change', () => {
    updateBuilderFieldVisibility();
    schedulePreview();
  });
  if ($('us-host-override')) {
    $('us-host-override').addEventListener('input', () => {
      updateUserSubModalUrls();
    });
  }

  $('nb-e-flow').addEventListener('change', () => {
    const flow = $('nb-e-flow').value;
    if (builder.protocol === 'vless' && builder.transport === 'raw') {
      const secMode = getActiveSecurityOpt().security_mode;
      if (secMode === 'reality') builder.secKey = flow === 'xtls-rprx-vision' ? 'xtls-vision-reality' : 'reality';
      else if (secMode === 'tls') builder.secKey = flow === 'xtls-rprx-vision' ? 'xtls-vision' : 'tls';
      renderBuilderPills();
    }
    schedulePreview();
  });

  // 随机凭据生成按钮
  $('nb-gen-uuid').addEventListener('click', () => {
    $('nb-e-uuid').value = genUUID();
    schedulePreview();
  });
  $('nb-gen-pass').addEventListener('click', () => {
    const len = builder.protocol === 'socks5' || builder.protocol === 'http' ? 16 : 24;
    $('nb-e-password').value = genAlphaNum(len);
    $('nb-s-password').value = $('nb-e-password').value;
    schedulePreview();
  });
  $('nb-gen-skey').addEventListener('click', () => {
    $('nb-e-server-key').value = genSS2022Key($('nb-e-method').value);
    schedulePreview();
  });
  $('nb-gen-ukey').addEventListener('click', () => {
    $('nb-e-user-key').value = genSS2022Key($('nb-e-method').value);
    schedulePreview();
  });
  $('nb-gen-shortid').addEventListener('click', () => {
    $('nb-e-short-id').value = genShortIdHex(4);
    schedulePreview();
  });
  $('nb-gen-obfspass').addEventListener('click', () => {
    $('nb-e-obfs-pass').value = genAlphaNum(20);
    schedulePreview();
  });
  $('nb-reset-padding').addEventListener('click', () => {
    $('nb-e-padding').value = DEFAULT_ANYTLS_PADDING.join('\n');
    schedulePreview();
  });

  // 监听构建器所有表单输入变化，250ms 防抖刷新实时预览
  const builderLeft = document.querySelector('#node-builder-modal .builder-left');
  builderLeft.addEventListener('input', (e) => {
    const target = e.target;
    if (target.id === 'nb-s-method') $('nb-e-method').value = target.value;
    if (target.id === 'nb-e-method') $('nb-s-method').value = target.value;
    schedulePreview();
  });
  builderLeft.addEventListener('change', (e) => {
    const target = e.target;
    if (target.id === 'nb-s-method') $('nb-e-method').value = target.value;
    if (target.id === 'nb-e-method') $('nb-s-method').value = target.value;
    schedulePreview();
  });

  // 右侧预览 Tab 切换与复制
  $('nb-preview-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    builder.previewTab = btn.dataset.tab;
    for (const b of document.querySelectorAll('#nb-preview-tabs button')) {
      b.classList.toggle('active', b.dataset.tab === builder.previewTab);
    }
    renderBuilderPreview();
  });

  $('nb-preview-copy').addEventListener('click', () => {
    const labelMap = {
      json: '已复制原生入站 JSON',
      uri: '已复制节点分享 URI',
      clash: '已复制 Clash YAML',
      singbox: '已复制 Sing-box JSON',
    };
    void hostCopy($('nb-preview-code').textContent, labelMap[builder.previewTab] || '已复制预览内容');
  });

  // 保存并应用节点
  $('nb-save').addEventListener('click', async () => {
    const saveBtn = $('nb-save');
    saveBtn.disabled = true;
    try {
      const payload = buildDraftPayload();
      const label = builder.editingId ? `更新节点 ${builder.editingId}` : '创建并应用代理节点';
      const r = await runAction(label, () => invoke('nodes.upsert', payload));
      if (!r) return;
      const saved = r.node || {};
      const syncText = r.core_synced
        ? `已同步至内置 Xray 引擎${r.core_revision ? ` (rev ${r.core_revision})` : ''}${r.core_sync_note ? ` · ${r.core_sync_note}` : ''}`
        : (r.core_sync_note || '已保存到本地节点库');
      showBanner(
        `${r.created ? '已创建' : '已更新'}节点「${saved.name || saved.id}」(${(saved.protocol || payload.protocol).toUpperCase()} :${saved.port || ''}) · ${syncText}`,
        r.core_synced ? 'ok' : 'warn',
      );
      closeNodeBuilder();
      void refreshNodes();
    } finally {
      saveBtn.disabled = false;
    }
  });

  // ==================== 事件绑定：视图 3（WARP 与链式代理） ====================

  $('btn-w-preset-ai').addEventListener('click', () => appendWARPPreset('ai'));
  $('btn-w-preset-stream').addEventListener('click', () => appendWARPPreset('streaming'));
  $('btn-w-preset-google').addEventListener('click', () => appendWARPPreset('google'));

  $('btn-warp-register').addEventListener('click', async () => {
    const payload = {
      license_key: $('w-license').value.trim(),
      endpoint: $('w-endpoint').value.trim(),
      mtu: Number($('w-mtu').value) || 1280,
      enabled: $('w-enabled').checked,
      routing_mode: $('w-mode').value,
      bound_profile_ids: readSelectedWARPPorts(),
      domains: readWARPDomainsInput(),
      sync_core: true,
    };
    const r = await runAction('一键注册 Cloudflare WARP', () => invoke('warp.register', payload));
    if (r) {
      $('w-license').value = '';
      const msg = r.sync_warning
        ? `Cloudflare WARP 注册成功（${r.warp?.address_v4 || ''}），提示：${r.sync_warning}`
        : `Cloudflare WARP 注册成功并已同步至内置 Xray 引擎（IPv4: ${r.warp?.address_v4 || ''}）`;
      showBanner(msg, r.sync_warning ? 'warn' : 'ok');
      void refreshChains();
    }
  });

  $('btn-warp-save').addEventListener('click', async () => {
    const payload = {
      enabled: $('w-enabled').checked,
      routing_mode: $('w-mode').value,
      bound_profile_ids: readSelectedWARPPorts(),
      domains: readWARPDomainsInput(),
      endpoint: $('w-endpoint').value.trim(),
      mtu: Number($('w-mtu').value) || 1280,
      sync_core: true,
    };
    const manualPriv = $('w-manual-priv').value.trim();
    if (manualPriv) {
      payload.private_key = manualPriv;
      payload.peer_public_key = $('w-manual-pub').value.trim();
      payload.address_v4 = $('w-manual-v4').value.trim();
      payload.address_v6 = $('w-manual-v6').value.trim();
      const cid = $('w-manual-cid').value.trim();
      if (cid) {
        if (/^\d+(,\s*\d+){2,3}$/.test(cid)) {
          payload.reserved = cid.split(',').map((n) => Number(n.trim()));
        } else {
          payload.client_id = cid;
        }
      }
    }
    const r = await runAction('保存 WARP 绑定并同步 Xray', () => invoke('warp.configure', payload));
    if (r) {
      $('w-manual-priv').value = '';
      const msg = r.sync_warning
        ? `WARP 配置已保存，提示：${r.sync_warning}`
        : `WARP 端口绑定与分流规则已同步生效（内置 Xray rev: ${r.core_revision || '最新'}）`;
      showBanner(msg, r.sync_warning ? 'warn' : 'ok');
      void refreshChains();
    }
  });

  $('btn-warp-probe').addEventListener('click', async () => {
    const r = await runAction('探测 WARP 端点与本机 IP', () => invoke('warp.probe', {}));
    if (r) {
      if (r.best_endpoint) {
        $('w-endpoint').value = r.best_endpoint;
      }
      const pre = $('warp-output');
      pre.textContent = JSON.stringify(r, null, 2);
      pre.classList.remove('hidden');
      const tr = r.host_trace || {};
      showBanner(
        `探测完成：推荐端点 ${r.best_endpoint || '无'} · 本机出口 ${tr.ip || '未知'} (${tr.loc || '-'} / colo=${tr.colo || '-'} / warp=${tr.warp || 'off'})`,
        r.best_endpoint ? 'ok' : 'warn',
      );
    }
  });

  $('btn-warp-preview').addEventListener('click', () => {
    const pre = $('warp-output');
    pre.textContent = cachedWARP?.xray_preview_json || '{}';
    pre.classList.remove('hidden');
  });

  $('btn-warp-delete').addEventListener('click', async () => {
    const ok = await hostConfirm({
      title: '注销并清除 Cloudflare WARP',
      body: '确认注销并清除本地 Cloudflare WARP 凭据？绑定的代理端口将恢复直连。',
      confirmLabel: '确认清除',
      danger: true,
    });
    if (!ok) return;
    const r = await runAction('清除 Cloudflare WARP', () => invoke('warp.delete', {}));
    if (r) {
      showBanner(r.sync_warning ? `已清除 WARP，提示：${r.sync_warning}` : '已清除 WARP 并恢复直连', r.sync_warning ? 'warn' : 'ok');
      void refreshChains();
    }
  });

  $('btn-chain-save').addEventListener('click', async () => {
    const payload = {
      id: $('c-id').value.trim(),
      name: $('c-name').value.trim(),
      mode: $('c-mode').value,
      protocol: $('c-proto').value,
      server: $('c-server').value.trim(),
      port: Number($('c-port').value) || 0,
      next_hop_id: $('c-next').value,
      apply_default: $('c-default').checked,
      enabled: $('c-enabled').checked,
      config: {
        username: $('c-user').value.trim(),
        password: $('c-pass').value,
        uuid: $('c-uuid').value.trim(),
        method: $('c-method').value.trim(),
        sni: $('c-sni').value.trim(),
        tls: $('c-tls').checked,
      },
    };
    const r = await runAction('保存链式代理节点', () => invoke('chains.upsert', payload));
    if (r) {
      $('c-pass').value = '';
      showBanner(`链式代理节点 ${r.chain?.id || payload.id} 已加密保存`, 'ok');
      void refreshChains();
    }
  });

  $('btn-chain-preview').addEventListener('click', async () => {
    const r = await runAction('预览 Xray 服务端链式出口', () => invoke('chains.preview', {}));
    if (r) {
      const pre = $('chain-xray-preview');
      pre.textContent = r.xray_json || '{}';
      pre.classList.remove('hidden');
    }
  });

  // ==================== 事件绑定：视图 4（tcpfit 与 TCP Brutal） ====================

  function readTcpfitInput() {
    return {
      role: $('t-role').value,
      bandwidth_mbps: Number($('t-bw').value) || 200,
      rtt_ms: Number($('t-rtt').value) || 150,
      mem_budget_pct: Number($('t-mem-pct').value) || 12,
      prefer_cc: $('t-prefer-cc').value,
    };
  }

  $('btn-tuning-plan').addEventListener('click', async () => {
    const r = await runAction('推导 tcpfit 调优方案', () => invoke('tuning.plan', readTcpfitInput()));
    if (r) {
      renderTuningPlan(r);
      showBanner('已完成 tcpfit 动态 BDP 与安全内存预算推导', 'ok');
    }
  });

  $('btn-tuning-dry').addEventListener('click', async () => {
    const r = await runAction('tcpfit 演练与基线保存', () =>
      invoke('tuning.apply', { ...readTcpfitInput(), dry_run: true }));
    if (r) {
      if (r.plan) renderTuningPlan(r.plan);
      showBanner(r.output || '已完成演练并保存宿主机基线快照', 'ok');
      void refreshTuningAndBrutal();
    }
  });

  $('btn-tuning-apply').addEventListener('click', async () => {
    const ok = await hostConfirm({
      title: '应用 tcpfit 内核调优',
      body: '确认将 tcpfit 参数写入 /etc/sysctl.d/99-qwq-tcpfit.conf 并执行 sysctl -p？应用前会自动保留可回滚基线快照。',
      confirmLabel: '确认应用',
      danger: true,
    });
    if (!ok) return;
    const r = await runAction('应用 tcpfit 调优到宿主机', () =>
      invoke('tuning.apply', { ...readTcpfitInput(), dry_run: false }));
    if (r) {
      if (r.plan) renderTuningPlan(r.plan);
      showBanner(
        r.applied ? '已成功应用 tcpfit 内核调优并保存基线快照' : `写入/生效提示：${r.error || r.output}`,
        r.applied ? 'ok' : 'warn',
      );
      void refreshTuningAndBrutal();
    }
  });

  $('btn-tuning-sweep').addEventListener('click', async () => {
    const r = await runAction('运行 iperf3 探测', () => invoke('tuning.sweep', {
      peer_host: $('sw-host').value.trim(),
      peer_port: Number($('sw-port').value) || 5201,
      duration_sec: Number($('sw-dur').value) || 5,
    }));
    if (r) {
      const pre = $('t-sweep-out');
      pre.textContent = JSON.stringify(r, null, 2);
      pre.classList.remove('hidden');
      showBanner(
        r.iperf3_available ? (r.advice || 'iperf3 探测完成') : (r.reason || '宿主机未安装 iperf3'),
        r.iperf3_available && r.ok ? 'ok' : 'warn',
      );
    }
  });

  $('b-inbound-preset').addEventListener('change', () => {
    const tag = $('b-inbound-preset').value;
    const found = cachedInbounds.find((ib) => ib.inbound_tag === tag);
    if (!found) return;
    $('b-id').value = `brutal-${found.inbound_tag}`;
    $('b-tag').value = found.inbound_tag;
    $('b-proto').value = found.protocol || 'tcp';
    $('b-target').value = String(found.target_port || 443);
    $('b-listen').value = String((found.target_port || 443) + 2000);
  });

  $('b-oversend-presets')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-oversend]');
    if (!btn) return;
    $('b-oversend').value = btn.dataset.oversend;
    updateOversendPreview();
  });
  $('b-oversend').addEventListener('input', updateOversendPreview);
  $('b-bw').addEventListener('input', updateOversendPreview);

  $('btn-brutal-save').addEventListener('click', async () => {
    const payload = {
      id: $('b-id').value.trim(),
      inbound_tag: $('b-tag').value.trim(),
      protocol: $('b-proto').value,
      listen_port: Number($('b-listen').value) || 0,
      target_port: Number($('b-target').value) || 0,
      bandwidth_mbps: Number($('b-bw').value) || 100,
      oversend_pct: Number($('b-oversend').value) || 125,
      cwnd_gain: Number($('b-gain').value) || 20,
      enable_in_sub: $('b-sub').checked,
      enabled: $('b-enabled').checked,
    };
    const r = await runAction('保存 Brutal 接管绑定', () => invoke('brutal.binding.upsert', payload));
    if (r) {
      showBanner(
        `已保存 ${r.binding?.id || payload.id}（超发 ${r.binding?.oversend_pct ?? payload.oversend_pct}%，有效 ${Number(r.binding?.effective_mbps || 0).toFixed(1)} Mbps），请点击“立即应用”生效。`,
        'ok',
      );
      void refreshTuningAndBrutal();
    }
  });

  $('btn-brutal-apply').addEventListener('click', async () => {
    const r = await runAction('应用并热重载 Brutal 接管端口', () => invoke('brutal.apply', {}));
    if (r) {
      showBanner(
        r.applied ? `已热重载 ${(r.live_listeners || []).length} 个透明接管端口` : `部分监听启动异常：${r.error}`,
        r.applied ? 'ok' : 'warn',
      );
      void refreshTuningAndBrutal();
    }
  });

  // ==================== 主题同步自定义下拉框 (.qwq-sel) ====================

  let closeAllCustomSelects = () => {};
  function initThemedSelects() {
    const openWraps = new Set();
    const closeAll = (except = null) => {
      for (const w of openWraps) {
        if (w === except) continue;
        w.classList.remove('open', 'drop-up');
        const b = w.querySelector('.qwq-sel-btn');
        if (b) b.setAttribute('aria-expanded', 'false');
        openWraps.delete(w);
      }
    };
    closeAllCustomSelects = closeAll;

    const valDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
    const idxDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex');

    function enhanceSelect(sel) {
      if (!sel || sel.dataset.qwqSel === '1' || sel.multiple || sel.size > 1) return;
      if (!sel.parentNode) return;
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
      const labelEl = document.createElement('span');
      labelEl.className = 'qwq-sel-label';
      btn.appendChild(labelEl);

      const menu = document.createElement('div');
      menu.className = 'qwq-sel-menu';
      menu.setAttribute('role', 'listbox');
      wrap.append(btn, menu);

      let syncing = false;
      function sync() {
        if (syncing) return;
        syncing = true;
        try {
          btn.disabled = sel.disabled;
          const opts = Array.from(sel.options);
          const activeOpt = sel.selectedIndex >= 0 ? opts[sel.selectedIndex] : opts[0];
          labelEl.textContent = activeOpt ? activeOpt.textContent : '';
          menu.replaceChildren();
          for (let idx = 0; idx < opts.length; idx += 1) {
            const opt = opts[idx];
            const item = document.createElement('button');
            item.type = 'button';
            item.className = `qwq-sel-opt${idx === sel.selectedIndex ? ' selected' : ''}`;
            item.setAttribute('role', 'option');
            item.setAttribute('aria-selected', idx === sel.selectedIndex ? 'true' : 'false');
            item.disabled = opt.disabled;
            item.textContent = opt.textContent;
            item.addEventListener('click', () => {
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
            menu.appendChild(item);
          }
        } finally {
          syncing = false;
        }
      }

      if (valDesc && valDesc.get && valDesc.set) {
        Object.defineProperty(sel, 'value', {
          configurable: true,
          get() { return valDesc.get.call(this); },
          set(v) { valDesc.set.call(this, v); sync(); },
        });
      }
      if (idxDesc && idxDesc.get && idxDesc.set) {
        Object.defineProperty(sel, 'selectedIndex', {
          configurable: true,
          get() { return idxDesc.get.call(this); },
          set(v) { idxDesc.set.call(this, v); sync(); },
        });
      }

      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (sel.disabled) return;
        const willOpen = !wrap.classList.contains('open');
        closeAll(wrap);
        if (willOpen) {
          sync();
          const rect = btn.getBoundingClientRect();
          const spaceBelow = window.innerHeight - rect.bottom;
          wrap.classList.toggle('drop-up', spaceBelow < 220 && rect.top > 200);
          wrap.classList.add('open');
          btn.setAttribute('aria-expanded', 'true');
          openWraps.add(wrap);
        } else {
          closeAll();
        }
      });

      btn.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          e.preventDefault();
          if (!wrap.classList.contains('open')) btn.click();
          const items = Array.from(menu.querySelectorAll('.qwq-sel-opt:not(:disabled)'));
          if (items.length) {
            const cur = items.findIndex((x) => x.classList.contains('selected'));
            const next = e.key === 'ArrowDown' ? (cur + 1) % items.length : (cur - 1 + items.length) % items.length;
            items[next]?.focus();
          }
        } else if (e.key === 'Escape' && wrap.classList.contains('open')) {
          e.preventDefault();
          e.stopPropagation();
          closeAll();
          btn.focus();
        }
      });

      sel.addEventListener('change', sync);
      const optMo = new MutationObserver(sync);
      optMo.observe(sel, { childList: true, subtree: true, attributes: true, characterData: true });
      sync();
    }

    document.querySelectorAll('select').forEach(enhanceSelect);
    const bodyMo = new MutationObserver((muts) => {
      for (const m of muts) {
        for (const node of m.addedNodes) {
          if (node.nodeType !== 1) continue;
          if (node.tagName === 'SELECT') enhanceSelect(node);
          else if (node.querySelectorAll) node.querySelectorAll('select').forEach(enhanceSelect);
        }
      }
    });
    bodyMo.observe(document.body, { childList: true, subtree: true });

    document.addEventListener('click', (e) => {
      if (!e.target.closest?.('.qwq-sel')) closeAll();
    });
  }

  // ==================== 键盘 ESC 关闭弹窗 ====================

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (document.querySelector('.qwq-sel.open')) {
      closeAllCustomSelects();
      return;
    }
    if (planEditModal.open) closePlanEditModal();
    else if (userSubModal.open) closeUserSubModal();
    else if (userHistoryModal.open) closeUserHistoryModal();
    else if (userCreateModal.open) closeUserCreateModal();
    else if (configViewer.open) closeConfigViewer();
    else if (builder.open) closeNodeBuilder();
  });

  // ==================== 初始化路由与宿主桥接 ====================

  initThemedSelects();
  switchRoute(activeRoute, false);
  updateOversendPreview();
  populateSNISelects(DEFAULT_SNI_CANDIDATES[0]);

  let hostViewportTop = 0;
  let lastSentHeight = 0;
  const MODAL_BACKDROP_IDS = [
    'plan-edit-modal',
    'user-sub-modal',
    'user-create-modal',
    'user-history-modal',
    'node-config-modal',
    'node-builder-modal',
  ];

  function hasOpenModal() {
    for (const id of MODAL_BACKDROP_IDS) {
      const el = $(id);
      if (el && !el.classList.contains('hidden')) return true;
    }
    return false;
  }

  function notifyResize() {
    const rootEl = $('proxy-root');
    if (!rootEl) return;
    let height = Math.ceil(rootEl.getBoundingClientRect().height) + 56;
    for (const id of MODAL_BACKDROP_IDS) {
      const backdrop = $(id);
      if (backdrop && !backdrop.classList.contains('hidden')) {
        const dialog = backdrop.querySelector('.modal-dialog');
        const modalH = dialog ? Math.ceil(dialog.getBoundingClientRect().height) : 480;
        height = Math.max(height, hostViewportTop + modalH + 72);
      }
    }
    if (Math.abs(height - lastSentHeight) < 2) return;
    lastSentHeight = height;
    send({ t: 'ui.resize', height });
  }

  const observer = new ResizeObserver(() => notifyResize());
  observer.observe($('proxy-root'));

  const modalObserver = new MutationObserver(() => requestAnimationFrame(notifyResize));
  for (const id of MODAL_BACKDROP_IDS) {
    const el = $(id);
    if (el) modalObserver.observe(el, { attributes: true, attributeFilter: ['class', 'hidden'] });
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (msg) => handleMessage(msg.data);
    send({ t: 'ui.ready' });
    send({ t: 'api.subscribe', id: 'sub-changes', subjects: ['*'] });
    void refreshActiveView();
  });

  window.addEventListener('pagehide', () => {
    observer.disconnect();
    modalObserver.disconnect();
    if (builder.previewTimer) clearTimeout(builder.previewTimer);
    for (const req of pendingInvoke.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
    }
    pendingInvoke.clear();
    for (const req of pendingConfirm.values()) {
      clearTimeout(req.timer);
      req.resolve(false);
    }
    pendingConfirm.clear();
    for (const req of pendingCopy.values()) {
      clearTimeout(req.timer);
      req.resolve(false);
    }
    pendingCopy.clear();
    port?.close();
    port = undefined;
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
