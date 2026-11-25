// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== 代理与订阅中心前端工作台（7 独立功能视图 · 对齐妙妙屋 X 体验） ======================== */
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

  const VALID_ROUTES = [
    '/proxy',
    '/proxy/nodes',
    '/proxy/users',
    '/proxy/plans',
    '/proxy/rules',
    '/proxy/chains',
    '/proxy/tuning',
  ];

  const userFilters = { search: '', status: '', plan: '' };
  let chainsSubTab = 'warp';
  let tuningSubTab = 'tcpfit';

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
  const pendingEnsure = new Map();

  let cachedUsers = [];
  let cachedPlans = [];
  let cachedChains = [];
  let cachedInbounds = [];
  let cachedBrutalBindings = [];
  let cachedWARP = null;
  let cachedWARPPresets = {};
  let cachedNodes = [];
  let cachedTLSCerts = { loaded: false, installed: false, certificates: [] };
  let cachedRules = {
    loaded: false,
    config: {
      preset: 'global',
      enable_ad_block: false,
      enable_ai_group: true,
      enable_streaming_group: true,
      custom_direct_domains: [],
      custom_proxy_domains: [],
      custom_reject_domains: [],
    },
    presets: [],
    clash_preview: '',
    singbox_preview: '',
    previewTab: 'clash',
  };
  let detectedPublicHost = '';
  let coreObfsAvailable = null;
  let xrayStatusLoaded = false;

  const userCreateModal = { open: false };
  const userEditModal = { open: false, userId: '', revision: '' };
  const userSubModal = { open: false, token: '', path: '', baseUrl: '' };
  const userHistoryModal = { open: false, userId: '', displayName: '', hours: 24 };
  const planEditModal = { open: false, editingId: '', tab: 'basic', selectedNodeIDs: new Set() };
  const chainEditModal = { open: false, editingId: '' };
  const brutalEditModal = { open: false, editingId: '' };

  const send = (msg) => {
    if (port) port.postMessage(msg);
  };
  const setStatus = (text) => {
    const el = $('status');
    if (el) el.textContent = text;
  };

  function getPublicOrigin() {
    if (publicOrigin) return publicOrigin.replace(/\/+$/, '');
    if (location.origin && location.origin !== 'null') return location.origin.replace(/\/+$/, '');
    return '';
  }

  function showBanner(msg, kind = 'ok') {
    const el = $('action-banner');
    if (!el) return;
    el.className = `banner show ${kind}`;
    el.textContent = msg;
  }

  function clearNode(el) {
    if (!el) return;
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

  function formatBytesShort(n) {
    if (!Number.isFinite(n) || n <= 0) return '0';
    const units = ['B', 'K', 'M', 'G', 'T'];
    let v = n;
    let idx = 0;
    while (v >= 1024 && idx < units.length - 1) {
      v /= 1024;
      idx += 1;
    }
    return `${v >= 100 || idx === 0 ? Math.round(v) : v.toFixed(1)}${units[idx]}`;
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

  function parseDomainLines(raw) {
    return String(raw || '')
      .split(/[\r\n,，;\s]+/)
      .map((s) => s.trim().toLowerCase().replace(/^\.+/, ''))
      .filter(Boolean)
      .slice(0, 200);
  }

  const TRAFFIC_MODE_LABELS = {
    both: '双向统计 (×1)',
    both_2x: '双向倍率 (×2)',
    down_only: '仅计下行',
  };

  const RULE_PRESET_LABELS = {
    '': '跟随全局',
    balanced: '智能分流',
    ai_streaming: 'AI 与流媒体',
    global: '全局代理',
    minimal: '极简模式',
  };

  function calcEffectiveBytes(up, down, trafficMode) {
    const u = Math.max(0, Number(up) || 0);
    const d = Math.max(0, Number(down) || 0);
    if (trafficMode === 'down_only') return d;
    if (trafficMode === 'both_2x') return (u + d) * 2;
    return u + d;
  }

  // ==================== 地区旗帜自动识别与快捷选择 ====================

  const REGION_PRESETS = [
    { flag: '🇭🇰', label: '香港', re: /(^|[\s_\-[\]])(hk|hkg|hong\s*kong)|香港/i },
    { flag: '🇹🇼', label: '台湾', re: /(^|[\s_\-[\]])(tw|tpe|taiwan)|台湾|台北/i },
    { flag: '🇯🇵', label: '日本', re: /(^|[\s_\-[\]])(jp|tyo|nrt|kix|tokyo|osaka|japan)|日本|东京|大阪/i },
    { flag: '🇸🇬', label: '新加坡', re: /(^|[\s_\-[\]])(sg|sin|singapore)|新加坡|狮城/i },
    { flag: '🇺🇸', label: '美国', re: /(^|[\s_\-[\]])(us|usa|lax|sjc|sea|nyc|ord|dfw|mia|los|san|seattle|dallas|miami|vmiss)|美国|美西|美东|洛杉矶|圣何塞/i },
    { flag: '🇰🇷', label: '韩国', re: /(^|[\s_\-[\]])(kr|icn|seoul|korea)|韩国|首尔/i },
    { flag: '🇬🇧', label: '英国', re: /(^|[\s_\-[\]])(uk|gb|lhr|london)|英国|伦敦/i },
    { flag: '🇩🇪', label: '德国', re: /(^|[\s_\-[\]])(de|fra|frankfurt|germany)|德国|法兰克福/i },
    { flag: '🇫🇷', label: '法国', re: /(^|[\s_\-[\]])(fr|cdg|paris|france)|法国|巴黎/i },
    { flag: '🇳🇱', label: '荷兰', re: /(^|[\s_\-[\]])(nl|ams|amsterdam)|荷兰/i },
    { flag: '🇨🇦', label: '加拿大', re: /(^|[\s_\-[\]])(ca|yyz|yvr|canada)|加拿大/i },
    { flag: '🇦🇺', label: '澳洲', re: /(^|[\s_\-[\]])(au|syd|australia)|澳洲|澳大利亚|悉尼/i },
    { flag: '🇷🇺', label: '俄国', re: /(^|[\s_\-[\]])(ru|mow|russia)|俄罗斯/i },
    { flag: '🇹🇷', label: '土耳其', re: /(^|[\s_\-[\]])(tr|ist|turkey)|土耳其/i },
    { flag: '🇮🇳', label: '印度', re: /(^|[\s_\-[\]])(in|bom|india)|印度/i },
  ];

  const FLAG_PREFIX_RE = /^[\u{1F1E6}-\u{1F1FF}]{2}\s*/u;

  function detectRegionFlag(node) {
    const rawName = String(node?.name || '');
    if (FLAG_PREFIX_RE.test(rawName)) return '';
    const hay = `${rawName} ${(node?.tags || []).join(' ')} ${node?.server || ''}`;
    for (const item of REGION_PRESETS) {
      if (item.re.test(hay)) return item.flag;
    }
    return '';
  }

  function applyFlagToNameInput(inputEl, flag) {
    if (!inputEl) return;
    const stripped = String(inputEl.value || '').replace(FLAG_PREFIX_RE, '').trimStart();
    inputEl.value = flag ? `${flag} ${stripped}` : stripped;
    inputEl.dispatchEvent(new Event('input', { bubbles: true }));
  }

  function renderFlagChips(containerId, targetInputId) {
    const box = $(containerId);
    if (!box) return;
    clearNode(box);
    const items = REGION_PRESETS.slice(0, 8);
    for (const item of items) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'flag-chip';
      btn.textContent = `${item.flag} ${item.label}`;
      btn.addEventListener('click', () => applyFlagToNameInput($(targetInputId), item.flag));
      box.appendChild(btn);
    }
    const clr = document.createElement('button');
    clr.type = 'button';
    clr.className = 'flag-chip';
    clr.textContent = '清除旗帜';
    clr.addEventListener('click', () => applyFlagToNameInput($(targetInputId), ''));
    box.appendChild(clr);
  }

  // ==================== 宿主桥 v2：Invoke / Confirm / Copy / OpenPlugin / EnsurePlugins ====================

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
      }, 30000);
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
    showBanner('当前环境不支持自动写入剪贴板，请手动复制。', 'warn');
    return false;
  }

  function openHostPlugin(pluginId, path = '') {
    if (!port) return;
    const msg = { t: 'ui.open_plugin', plugin_id: pluginId };
    if (path) msg.path = path;
    send(msg);
  }

  function ensureHostPlugins(pluginIds) {
    if (!port) return Promise.resolve({ ok: false, message: '宿主通道未就绪' });
    const id = `en-${++seq}`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        pendingEnsure.delete(id);
        resolve({ ok: false, message: '插件启用超时，请前往应用中心查看' });
      }, 90000);
      pendingEnsure.set(id, { resolve, timer });
      send({ t: 'ui.ensure_plugins', id, plugins: pluginIds, reason: '启用证书管理插件以直接选择和申请 TLS 证书' });
    });
  }

  async function runAction(label, fn) {
    try {
      setStatus(`正在执行：${label}…`);
      const res = await fn();
      setStatus('已连接');
      return res;
    } catch (err) {
      if (err instanceof PendingStateError) {
        if (err.kind === 'approval' && builder.open) closeNodeBuilder();
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

  // ==================== 路由与上下文按钮调度 ====================

  function updateContextPrimaryBtn(route) {
    const btn = $('btn-ctx-primary');
    if (!btn) return;
    const labels = {
      '/proxy': '+ 添加节点',
      '/proxy/nodes': '+ 添加节点',
      '/proxy/users': '+ 新建用户',
      '/proxy/plans': '+ 新建套餐',
      '/proxy/rules': '保存分流规则',
      '/proxy/chains': chainsSubTab === 'hops' ? '+ 添加链式节点' : '',
      '/proxy/tuning': tuningSubTab === 'brutal' ? '+ 添加接管绑定' : '',
    };
    const label = labels[route] || '';
    if (label) {
      btn.textContent = label;
      btn.classList.remove('hidden');
    } else {
      btn.classList.add('hidden');
    }
  }

  function setChainsSubTab(tab) {
    chainsSubTab = tab === 'hops' ? 'hops' : 'warp';
    for (const btn of document.querySelectorAll('#chains-subtabs button[data-sub]')) {
      const act = btn.dataset.sub === chainsSubTab;
      btn.classList.toggle('active', act);
      btn.setAttribute('aria-selected', act ? 'true' : 'false');
    }
    for (const pane of document.querySelectorAll('[data-chains-pane]')) {
      pane.classList.toggle('hidden', pane.dataset.chainsPane !== chainsSubTab);
    }
    updateContextPrimaryBtn(activeRoute);
    requestAnimationFrame(() => notifyResize());
  }

  function setTuningSubTab(tab) {
    tuningSubTab = tab === 'brutal' ? 'brutal' : 'tcpfit';
    for (const btn of document.querySelectorAll('#tuning-subtabs button[data-sub]')) {
      const act = btn.dataset.sub === tuningSubTab;
      btn.classList.toggle('active', act);
      btn.setAttribute('aria-selected', act ? 'true' : 'false');
    }
    for (const pane of document.querySelectorAll('[data-tuning-pane]')) {
      pane.classList.toggle('hidden', pane.dataset.tuningPane !== tuningSubTab);
    }
    updateContextPrimaryBtn(activeRoute);
    requestAnimationFrame(() => notifyResize());
  }

  function switchRoute(route, notifyHost = true) {
    if (!VALID_ROUTES.includes(route)) return;
    activeRoute = route;
    updateContextPrimaryBtn(route);
    for (const sec of document.querySelectorAll('section[data-view]')) {
      sec.classList.toggle('hidden', sec.dataset.view !== route);
    }
    if (notifyHost && port) {
      send({ t: 'ui.navigate', path: route });
    }
    requestAnimationFrame(() => notifyResize());
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

    if (data.t === 'ui.ensure_plugins.result' && data.id !== undefined) {
      const id = String(data.id);
      const req = pendingEnsure.get(id);
      if (!req) return;
      clearTimeout(req.timer);
      pendingEnsure.delete(id);
      req.resolve({ ok: Boolean(data.ok), data: data.data, message: data.problem?.detail || data.error?.message || '' });
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

  // ==================== 视图 1: 概览 30 天每日流量 SVG 图 + 告警 + 排行 ====================

  function renderDailyTrafficChart(points) {
    const wrap = $('ov-daily-chart-wrap');
    if (!wrap) return;
    clearNode(wrap);
    if (!Array.isArray(points) || !points.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-card muted';
      empty.textContent = '暂无最近 30 天流量采样记录';
      wrap.appendChild(empty);
      return;
    }

    const total30 = points.reduce((acc, p) => acc + Number(p.total_bytes || 0), 0);
    const subEl = $('ov-daily-sub');
    if (subEl) {
      subEl.textContent = total30 > 0
        ? `近 30 天累计 ${formatBytes(total30)} · 虚线为 7 日滑动均值`
        : '每天的总用量汇总，虚线为 7 日滑动均值（当前尚无流量消耗）';
    }

    const SVG_NS = 'http://www.w3.org/2000/svg';
    const mk = (tag, attrs = {}) => {
      const el = document.createElementNS(SVG_NS, tag);
      for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
      return el;
    };

    const W = 880;
    const H = 215;
    const padL = 54;
    const padR = 14;
    const padT = 14;
    const padB = 28;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;

    let maxVal = 0;
    for (const p of points) {
      maxVal = Math.max(maxVal, Number(p.total_bytes || 0), Number(p.avg7_bytes || 0));
    }
    const yMax = maxVal > 0 ? maxVal * 1.15 : 1024 * 1024;

    const svg = mk('svg', {
      class: 'daily-svg',
      viewBox: `0 0 ${W} ${H}`,
      role: 'img',
      'aria-label': '近 30 天每日流量柱状图与 7 日均值',
    });

    // 水平网格线与 Y 轴刻度
    const ticks = 4;
    for (let i = 0; i <= ticks; i += 1) {
      const ratio = i / ticks;
      const y = padT + plotH * (1 - ratio);
      svg.appendChild(mk('line', {
        class: 'chart-grid-line',
        x1: padL,
        y1: y.toFixed(1),
        x2: W - padR,
        y2: y.toFixed(1),
      }));
      const lbl = mk('text', {
        class: 'chart-axis-text',
        x: padL - 8,
        y: (y + 3.5).toFixed(1),
        'text-anchor': 'end',
      });
      lbl.textContent = formatBytesShort(yMax * ratio);
      svg.appendChild(lbl);
    }

    const step = plotW / points.length;
    const barW = Math.max(6, Math.min(20, step * 0.56));
    const avgCoords = [];

    points.forEach((pt, idx) => {
      const tot = Number(pt.total_bytes || 0);
      const up = Number(pt.up_bytes || 0);
      const down = Number(pt.down_bytes || 0);
      const avg7 = Number(pt.avg7_bytes || 0);
      const cx = padL + idx * step + step / 2;
      const barH = tot > 0 ? Math.max(3, (tot / yMax) * plotH) : 2;
      const y = padT + plotH - barH;
      const isToday = idx === points.length - 1;
      const cls = tot <= 0 ? 'chart-bar-zero' : (isToday ? 'chart-bar chart-bar-today' : 'chart-bar');

      const rect = mk('rect', {
        class: cls,
        x: (cx - barW / 2).toFixed(1),
        y: y.toFixed(1),
        width: barW.toFixed(1),
        height: barH.toFixed(1),
        rx: 3,
      });
      const tip = mk('title');
      tip.textContent = `${pt.date} · 总计 ${formatBytes(tot)}（↑ ${formatBytes(up)} / ↓ ${formatBytes(down)}）· 7日均值 ${formatBytes(avg7)}`;
      rect.appendChild(tip);
      svg.appendChild(rect);

      const avgY = padT + plotH - (avg7 / yMax) * plotH;
      avgCoords.push(`${cx.toFixed(1)},${avgY.toFixed(1)}`);

      if (idx === 0 || idx === points.length - 1 || idx % 4 === 0) {
        const xl = mk('text', {
          class: 'chart-axis-text',
          x: cx.toFixed(1),
          y: H - 8,
          'text-anchor': 'middle',
        });
        xl.textContent = pt.date || '';
        svg.appendChild(xl);
      }
    });

    if (avgCoords.length > 1 && maxVal > 0) {
      svg.appendChild(mk('path', {
        class: 'chart-avg-line',
        d: `M ${avgCoords.join(' L ')}`,
      }));
    }

    wrap.appendChild(svg);
  }

  function renderOverviewAlerts(alerts) {
    const card = $('ov-alerts-card');
    const list = $('ov-alerts-list');
    const countEl = $('ov-alerts-count');
    if (!card || !list) return;
    clearNode(list);
    if (!Array.isArray(alerts) || !alerts.length) {
      card.classList.add('hidden');
      return;
    }
    card.classList.remove('hidden');
    if (countEl) countEl.textContent = `${alerts.length} 项`;
    for (const a of alerts) {
      const row = document.createElement('div');
      row.className = `alert-row level-${a.level || 'info'}`;
      const body = document.createElement('div');
      body.className = 'alert-body';
      const title = document.createElement('div');
      title.className = 'alert-title';
      title.textContent = a.title || '';
      const detail = document.createElement('div');
      detail.className = 'alert-detail';
      detail.textContent = a.detail || '';
      body.append(title, detail);

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn xs ghost';
      btn.textContent = '前往处理 →';
      btn.addEventListener('click', () => {
        if (VALID_ROUTES.includes(a.route)) switchRoute(a.route, true);
      });
      row.append(body, btn);
      list.appendChild(row);
    }
  }

  function renderOverviewWidgets(users, nodes) {
    let totalUp = 0;
    let totalDown = 0;
    for (const u of users) {
      totalUp += Number(u.period_up_bytes || 0);
      totalDown += Number(u.period_down_bytes || 0);
    }
    const trafficVal = $('ov-total-traffic');
    if (trafficVal) trafficVal.textContent = formatBytes(totalUp + totalDown);
    const trafficSub = $('ov-total-traffic-sub');
    if (trafficSub) trafficSub.textContent = `↑ ${formatBytes(totalUp)} / ↓ ${formatBytes(totalDown)}`;

    const managed = nodes.filter((n) => n.source === 'managed').length;
    const external = nodes.length - managed;
    const enabledNodes = nodes.filter((n) => n.enabled).length;
    const nodesVal = $('ov-nodes-val');
    if (nodesVal) nodesVal.textContent = `${enabledNodes} / ${nodes.length}`;
    const nodesSub = $('ov-nodes-sub');
    if (nodesSub) nodesSub.textContent = `托管 ${managed} · 外部导入 ${external}`;

    // 用户用量排行
    const rankBox = $('ov-user-ranking');
    if (rankBox) {
      clearNode(rankBox);
      if (!users.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-card muted';
        empty.textContent = '暂无订阅用户，点击「全部用户」创建账号并签发订阅链接。';
        rankBox.appendChild(empty);
      } else {
        const sorted = users
          .slice()
          .sort((a, b) => calcEffectiveBytes(b.period_up_bytes, b.period_down_bytes, b.traffic_mode) - calcEffectiveBytes(a.period_up_bytes, a.period_down_bytes, a.traffic_mode))
          .slice(0, 6);
        const maxUsed = Math.max(1, ...sorted.map((u) => calcEffectiveBytes(u.period_up_bytes, u.period_down_bytes, u.traffic_mode)));
        for (const u of sorted) {
          const up = Number(u.period_up_bytes || 0);
          const down = Number(u.period_down_bytes || 0);
          const eff = calcEffectiveBytes(up, down, u.traffic_mode);
          const quota = Number(u.quota_bytes || 0);
          const pct = quota > 0 ? Math.min(100, Math.round((eff / quota) * 100)) : Math.round((eff / maxUsed) * 100);

          const row = document.createElement('div');
          row.className = 'rank-item';
          const top = document.createElement('div');
          top.className = 'rank-top';
          const userCol = document.createElement('div');
          userCol.className = 'rank-user';
          const nm = document.createElement('span');
          nm.textContent = u.display_name || u.id;
          const pl = document.createElement('span');
          pl.className = 'badge';
          pl.textContent = u.plan_id || '默认';
          userCol.append(nm, pl);

          const val = document.createElement('span');
          val.className = 'rank-val mono';
          val.textContent = quota > 0 ? `${formatBytes(eff)} / ${formatBytes(quota)}` : formatBytes(eff);
          top.append(userCol, val);

          const prog = document.createElement('progress');
          prog.className = 'quota-progress';
          prog.max = 100;
          prog.value = pct;

          const meta = document.createElement('div');
          meta.className = 'rank-meta';
          const split = document.createElement('span');
          split.textContent = `↑ ${formatBytes(up)} · ↓ ${formatBytes(down)}${u.traffic_mode === 'both_2x' ? ' · ×2' : u.traffic_mode === 'down_only' ? ' · 仅下行' : ''}`;
          const conn = document.createElement('span');
          conn.textContent = `${u.active_connections || 0} 活跃连接`;
          meta.append(split, conn);

          row.append(top, prog, meta);
          rankBox.appendChild(row);
        }
      }
    }

    // 节点状态一览
    const nodeBox = $('ov-node-list');
    if (nodeBox) {
      clearNode(nodeBox);
      if (!nodes.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-card muted';
        empty.textContent = '尚未创建代理节点，点击右上角「+ 添加节点」即可一键生成。';
        nodeBox.appendChild(empty);
      } else {
        for (const n of nodes.slice(0, 6)) {
          const row = document.createElement('div');
          row.className = 'ov-node-row';

          const left = document.createElement('div');
          left.className = 'ov-node-left';
          const dot = document.createElement('span');
          dot.className = (n.enabled && (n.source !== 'managed' || n.listening)) ? 'dot-live' : 'dot-off';
          const pb = document.createElement('span');
          pb.className = `proto-badge proto-${n.protocol}`;
          pb.textContent = n.protocol.toUpperCase();
          const flag = detectRegionFlag(n);
          const nm = document.createElement('span');
          nm.className = 'ov-node-name';
          nm.textContent = `${flag ? `${flag} ` : ''}${n.name || n.id}`;
          left.append(dot, pb, nm);

          const right = document.createElement('div');
          right.className = 'ov-node-right';
          const addr = document.createElement('span');
          addr.className = 'muted mono';
          addr.textContent = `:${n.port}`;
          const st = document.createElement('span');
          if (typeof n.last_latency_ms === 'number' && n.last_latency_ms > 0) {
            st.className = n.last_latency_ms < 120 ? 'badge ok' : n.last_latency_ms < 300 ? 'badge warn' : 'badge err';
            st.textContent = `${n.last_latency_ms} ms`;
          } else {
            st.className = `badge ${n.enabled ? 'ok' : 'warn'}`;
            st.textContent = n.enabled ? '启用' : '停用';
          }
          right.append(addr, st);

          row.append(left, right);
          nodeBox.appendChild(row);
        }
      }
    }
  }

  // ==================== 视图 4: 套餐模板管理 + 4 分组弹窗 ====================

  function setPlanEditTab(tab) {
    planEditModal.tab = ['basic', 'cycle', 'limits', 'nodes'].includes(tab) ? tab : 'basic';
    for (const btn of document.querySelectorAll('#pe-nav button[data-pe-tab]')) {
      btn.classList.toggle('active', btn.dataset.peTab === planEditModal.tab);
    }
    for (const pane of document.querySelectorAll('#plan-edit-modal [data-pe-pane]')) {
      pane.classList.toggle('hidden', pane.dataset.pePane !== planEditModal.tab);
    }
    if (planEditModal.tab === 'nodes') renderPlanNodesChecklist();
  }

  function updatePlanModalNavSubs() {
    const idVal = ($('p-id')?.value || '').trim();
    const quota = Math.max(0, Number($('p-quota-gb')?.value) || 0);
    const mode = $('p-traffic-mode')?.value || 'both';
    const resetDay = Math.min(28, Math.max(0, Math.floor(Number($('p-reset-day')?.value) || 0)));
    const validity = Math.min(3650, Math.max(0, Math.floor(Number($('p-validity')?.value) || 0)));
    const down = Math.max(0, Number($('p-down')?.value) || 0);
    const up = Math.max(0, Number($('p-up')?.value) || 0);
    const conns = Math.max(0, Number($('p-max-conns')?.value) || 0);

    const basicSub = $('pe-nav-basic-sub');
    if (basicSub) basicSub.textContent = `${idVal || '未命名'} · ${quota > 0 ? `${quota} GiB` : '不限'} · ${mode === 'both_2x' ? '×2' : mode === 'down_only' ? '下行' : '双向'}`;
    const cycleSub = $('pe-nav-cycle-sub');
    if (cycleSub) cycleSub.textContent = `${resetDay > 0 ? `每月 ${resetDay} 日` : '不重置'} · ${validity > 0 ? `${validity} 天` : '长期'}`;
    const limitsSub = $('pe-nav-limits-sub');
    if (limitsSub) limitsSub.textContent = `${formatRate(down)}/${formatRate(up)} · ${formatLimit(conns)}连接`;
    const nodesSub = $('pe-nav-nodes-sub');
    const selSize = planEditModal.selectedNodeIDs.size;
    if (nodesSub) nodesSub.textContent = selSize > 0 ? `已绑 ${selSize} 个节点` : '全部节点可用';

    const dh = $('p-down-hint');
    if (dh) dh.textContent = down > 0 ? `≈ ${(down / 8000).toFixed(2)} MB/s` : '不限制下行速度';
    const uh = $('p-up-hint');
    if (uh) uh.textContent = up > 0 ? `≈ ${(up / 8000).toFixed(2)} MB/s` : '不限制上行速度';
  }

  function renderPlanNodesChecklist() {
    const listEl = $('p-nodes-list');
    const cntEl = $('p-nodes-count');
    if (!listEl) return;
    clearNode(listEl);

    const selSize = planEditModal.selectedNodeIDs.size;
    if (cntEl) {
      cntEl.textContent = selSize > 0
        ? `已勾选 ${selSize} / ${cachedNodes.length} 个节点（该套餐用户仅可订阅以下勾选节点）`
        : `当前未勾选特定节点（共 ${cachedNodes.length} 个节点）：默认开放全部已启用节点`;
    }

    const q = ($('p-nodes-search')?.value || '').trim().toLowerCase();
    const filtered = cachedNodes.filter((n) => {
      if (!q) return true;
      return `${n.id} ${n.name || ''} ${n.protocol} ${n.server || ''}`.toLowerCase().includes(q);
    });
    if (!filtered.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-card muted';
      empty.textContent = cachedNodes.length ? '无匹配节点' : '暂无可用节点，请先前往「节点管理」创建节点。';
      listEl.appendChild(empty);
      return;
    }

    for (const n of filtered) {
      const lbl = document.createElement('label');
      lbl.className = 'plan-node-item';
      const left = document.createElement('div');
      left.className = 'plan-node-item-left';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = planEditModal.selectedNodeIDs.has(n.id);
      cb.addEventListener('change', () => {
        if (cb.checked) planEditModal.selectedNodeIDs.add(n.id);
        else planEditModal.selectedNodeIDs.delete(n.id);
        updatePlanModalNavSubs();
        if (cntEl) {
          const sz = planEditModal.selectedNodeIDs.size;
          cntEl.textContent = sz > 0
            ? `已勾选 ${sz} / ${cachedNodes.length} 个节点（该套餐用户仅可订阅以下勾选节点）`
            : `当前未勾选特定节点（共 ${cachedNodes.length} 个节点）：默认开放全部已启用节点`;
        }
      });
      const pb = document.createElement('span');
      pb.className = `proto-badge proto-${n.protocol}`;
      pb.textContent = n.protocol.toUpperCase();
      const flag = detectRegionFlag(n);
      const nm = document.createElement('span');
      nm.className = 'plan-node-item-name';
      nm.textContent = `${flag ? `${flag} ` : ''}${n.name || n.id}`;
      left.append(cb, pb, nm);

      const meta = document.createElement('span');
      meta.className = 'muted mono';
      meta.textContent = `:${n.port}${n.enabled ? '' : ' (停用)'}`;
      lbl.append(left, meta);
      listEl.appendChild(lbl);
    }
  }

  function openPlanEditModal(plan = null) {
    planEditModal.open = true;
    planEditModal.editingId = plan ? plan.id : '';
    planEditModal.selectedNodeIDs = new Set(Array.isArray(plan?.node_ids) ? plan.node_ids : []);
    $('pe-modal-title').textContent = plan ? `编辑套餐 · ${plan.name || plan.id}` : '新建套餐模板';
    const idEl = $('p-id');
    idEl.value = plan ? plan.id : '';
    idEl.readOnly = Boolean(plan);
    $('p-name').value = plan ? (plan.name || '') : '';
    $('p-desc').value = plan ? (plan.description || '') : '';
    $('p-quota-gb').value = plan
      ? String(plan.quota_bytes > 0 ? Math.round((plan.quota_bytes / (1024 * 1024 * 1024)) * 100) / 100 : 0)
      : '100';
    $('p-traffic-mode').value = plan?.traffic_mode || 'both';
    $('p-reset-day').value = plan ? String(plan.billing_reset_day ?? 1) : '1';
    $('p-validity').value = plan ? String(plan.validity_days ?? 0) : '30';
    $('p-rule-preset').value = plan?.rule_preset || '';
    $('p-down').value = plan ? String(plan.down_limit_kbps ?? 0) : '50000';
    $('p-up').value = plan ? String(plan.up_limit_kbps ?? 0) : '20000';
    $('p-max-conns').value = plan ? String(plan.max_connections ?? 0) : '64';
    $('p-max-ips').value = plan ? String(plan.max_ips ?? 0) : '4';
    if ($('p-nodes-search')) $('p-nodes-search').value = '';
    setPlanEditTab('basic');
    updatePlanModalNavSubs();
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
    const sumEl = $('plans-summary');
    if (sumEl) sumEl.textContent = `${plans.length} 个模板`;
    if (!grid) return;
    if (!plans.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-card muted';
      empty.textContent = '暂无套餐模板，点击右上角「+ 新建套餐」创建后即可供多用户复用。';
      grid.appendChild(empty);
      return;
    }
    const usageCount = new Map();
    for (const u of cachedUsers) {
      if (u.plan_id) usageCount.set(u.plan_id, (usageCount.get(u.plan_id) || 0) + 1);
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
      if (p.description) {
        const desc = document.createElement('div');
        desc.className = 'plan-card-desc';
        desc.textContent = p.description;
        titleBox.appendChild(desc);
      }

      const quotaPill = document.createElement('span');
      quotaPill.className = p.quota_bytes > 0 ? 'plan-quota-pill' : 'plan-quota-pill unlimited';
      quotaPill.textContent = p.quota_bytes > 0 ? formatBytes(p.quota_bytes) : '不限流量';
      head.append(titleBox, quotaPill);

      const rowsEl = document.createElement('div');
      rowsEl.className = 'plan-rows';
      const nodeCount = Array.isArray(p.node_ids) ? p.node_ids.length : 0;
      const rows = [
        ['流量统计方式', TRAFFIC_MODE_LABELS[p.traffic_mode] || '双向统计 (×1)'],
        ['下 / 上行限速', `${formatRate(p.down_limit_kbps)} / ${formatRate(p.up_limit_kbps)}`],
        ['并发与在线 IP', `${formatLimit(p.max_connections)} 连接 · ${formatLimit(p.max_ips)} IP`],
        ['重置与有效期', `${p.billing_reset_day > 0 ? `每月 ${p.billing_reset_day} 日` : '不重置'} · ${p.validity_days > 0 ? `${p.validity_days} 天` : '长期有效'}`],
        ['关联节点范围', nodeCount > 0 ? `指定 ${nodeCount} 个节点` : '全部已启用节点'],
        ['订阅分流规则', RULE_PRESET_LABELS[p.rule_preset || ''] || '跟随全局'],
      ];
      for (const [k, v] of rows) {
        const r = document.createElement('div');
        r.className = 'plan-row';
        const ke = document.createElement('span');
        ke.className = 'plan-row-k';
        ke.textContent = k;
        const ve = document.createElement('span');
        ve.className = 'plan-row-v';
        ve.textContent = v;
        r.append(ke, ve);
        rowsEl.appendChild(r);
      }

      const foot = document.createElement('div');
      foot.className = 'plan-card-foot';
      const cnt = usageCount.get(p.id) || 0;
      const boundEl = document.createElement('span');
      boundEl.className = 'muted';
      boundEl.textContent = cnt > 0 ? `${cnt} 位用户使用中` : '暂未绑定用户';

      const footOps = document.createElement('div');
      footOps.className = 'actions actions-tight';
      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'btn xs ghost';
      editBtn.textContent = '编辑';
      editBtn.addEventListener('click', () => openPlanEditModal(p));

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn xs danger';
      delBtn.textContent = '删除';
      delBtn.addEventListener('click', async () => {
        if (cnt > 0) {
          showBanner(`套餐「${p.name || p.id}」仍有 ${cnt} 位绑定用户，请先前往「用户管理」切换用户套餐后再删除。`, 'warn');
          return;
        }
        const ok = await hostConfirm({
          title: '删除代理套餐',
          body: `确认永久删除套餐模板「${p.name || p.id} (${p.id})」？`,
          confirmLabel: '确认删除',
          danger: true,
        });
        if (!ok) return;
        const res = await runAction(`删除套餐 ${p.id}`, () => invoke('plans.delete', { id: p.id }));
        if (res) {
          showBanner(`已删除套餐「${p.name || p.id}」`, 'ok');
          void refreshPlans();
        }
      });

      footOps.append(editBtn, delBtn);
      foot.append(boundEl, footOps);

      card.append(head, rowsEl, foot);
      grid.appendChild(card);
    }
  }

  function renderPlanSelects() {
    for (const selId of ['uc-plan', 'ue-plan']) {
      const sel = $(selId);
      if (!sel) continue;
      const prev = sel.value;
      clearNode(sel);
      if (!cachedPlans.length) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = selId === 'uc-plan' ? '暂无套餐（请切换上方「自定义配额与限速」）' : '暂无可用套餐';
        sel.appendChild(opt);
      } else {
        for (const p of cachedPlans) {
          const opt = document.createElement('option');
          opt.value = p.id;
          const q = p.quota_bytes > 0 ? formatBytes(p.quota_bytes) : '不限流量';
          opt.textContent = `${p.name} (${q} · ${formatRate(p.down_limit_kbps)}/${formatRate(p.up_limit_kbps)})`;
          sel.appendChild(opt);
        }
        if (prev && cachedPlans.some((p) => p.id === prev)) sel.value = prev;
      }
    }
  }

  // ==================== 视图 3: 用户管理、编辑弹窗与一键复制订阅 ====================

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
          origin = new URL(rawInput).origin;
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
          hostPart = `[${cleaned}]`;
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
    $('us-modal-title').textContent = `订阅链接 · ${displayName || userId}`;
    $('us-user-label').textContent = `${displayName || userId} (${userId}) 公开订阅令牌`;
    $('us-token-code').textContent = userSubModal.token;
    const hostInput = $('us-host-override');
    if (hostInput) {
      let curHostname = '';
      try {
        curHostname = new URL(getPublicOrigin()).hostname;
      } catch {
        curHostname = '';
      }
      hostInput.value = isLoopbackHost(curHostname) && detectedPublicHost ? detectedPublicHost : '';
    }
    updateUserSubModalUrls();
    $('us-meta').textContent = subtitle || '支持 Clash / Mihomo / Sing-box / Shadowrocket 自动识别导入';
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
    $('uc-notes').value = '';
    $('uc-max-conns').value = '-1';
    $('uc-max-ips').value = '-1';
    $('uc-plan-mode').value = cachedPlans.length > 0 ? 'existing' : 'custom';
    renderPlanSelects();
    renderUserChainSelects();
    updateUserCreatePlanMode();
    $('user-create-modal').classList.remove('hidden');
  }

  function closeUserCreateModal() {
    userCreateModal.open = false;
    $('user-create-modal').classList.add('hidden');
  }

  function openUserEditModal(u) {
    userEditModal.open = true;
    userEditModal.userId = u.id;
    userEditModal.revision = String(u.revision || '');
    $('ue-modal-title').textContent = `编辑用户 · ${u.display_name || u.id}`;
    $('ue-id').value = u.id;
    $('ue-name').value = u.display_name || '';
    $('ue-notes').value = u.notes || '';
    renderPlanSelects();
    renderUserChainSelects();
    $('ue-plan').value = u.plan_id || '';
    if (u.expires_at && u.expires_at > 0) {
      const d = new Date(u.expires_at);
      const pad = (x) => String(x).padStart(2, '0');
      $('ue-expires').value = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    } else {
      $('ue-expires').value = '';
    }
    $('ue-conns').value = String(u.max_connections_override ?? -1);
    $('ue-ips').value = String(u.max_ips_override ?? -1);
    $('ue-chain').value = u.chain_id || '';
    const nft = $('nft-preview');
    if (nft) nft.classList.add('hidden');
    $('user-edit-modal').classList.remove('hidden');
  }

  function closeUserEditModal() {
    userEditModal.open = false;
    userEditModal.userId = '';
    $('user-edit-modal').classList.add('hidden');
  }

  function renderUserChainSelects() {
    for (const id of ['uc-chain', 'ue-chain']) {
      const sel = $(id);
      if (!sel) continue;
      const prev = sel.value;
      clearNode(sel);
      const opt0 = document.createElement('option');
      opt0.value = '';
      opt0.textContent = '（跟随全局默认 / 直连）';
      sel.appendChild(opt0);
      for (const c of cachedChains) {
        const opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = `${c.name} (${c.id})`;
        sel.appendChild(opt);
      }
      if (prev && cachedChains.some((c) => c.id === prev)) sel.value = prev;
    }
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
      const c2 = document.createElement('td');
      c2.textContent = formatBytes(up);
      const c3 = document.createElement('td');
      c3.textContent = formatBytes(down);
      const c4 = document.createElement('td');
      c4.textContent = formatBytes(total);
      const c5 = document.createElement('td');
      const prog = document.createElement('progress');
      prog.className = 'quota-progress';
      prog.max = 100;
      prog.value = pct;
      c5.appendChild(prog);
      tr.append(c1, c2, c3, c4, c5);
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

  function renderUserPlanFilterPills(users) {
    const box = $('u-plan-filters');
    if (!box) return;
    clearNode(box);
    const counts = new Map();
    for (const u of users) {
      if (u.plan_id) counts.set(u.plan_id, (counts.get(u.plan_id) || 0) + 1);
    }
    const planNameMap = new Map(cachedPlans.map((p) => [p.id, p.name || p.id]));
    const addPill = (val, label, count) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `pill${userFilters.plan === val ? ' active' : ''}`;
      btn.dataset.uplan = val;
      btn.textContent = `${label} (${count})`;
      box.appendChild(btn);
    };
    addPill('', '全部套餐', users.length);
    for (const [pid, cnt] of counts.entries()) {
      addPill(pid, planNameMap.get(pid) || pid, cnt);
    }
  }

  function renderUserStats(users) {
    const active = users.filter((u) => u.status === 'active').length;
    const quota = users.filter((u) => u.status === 'suspended_quota').length;
    const expired = users.filter((u) => u.status === 'expired').length;
    const disabled = users.filter((u) => u.status === 'disabled').length;
    let totalUp = 0;
    let totalDown = 0;
    let totalConns = 0;
    let totalIPs = 0;
    for (const u of users) {
      totalUp += Number(u.period_up_bytes || 0);
      totalDown += Number(u.period_down_bytes || 0);
      totalConns += Number(u.active_connections || 0);
      totalIPs += Number(u.active_ips || 0);
    }
    const set = (id, text) => {
      const el = $(id);
      if (el) el.textContent = text;
    };
    set('u-stat-total', `${users.length} 人`);
    set('u-stat-active-sub', `活跃 ${active} 人`);
    set('u-stat-warn', `${quota + expired + disabled} 人`);
    set('u-stat-disabled-sub', `超额 ${quota} · 到期 ${expired} · 停用 ${disabled}`);
    set('u-stat-usage', formatBytes(totalUp + totalDown));
    set('u-stat-usage-sub', `↑ ${formatBytes(totalUp)} · ↓ ${formatBytes(totalDown)}`);
    set('u-stat-conns', `${totalConns} 连接`);
    set('u-stat-ips-sub', `当前在线 ${totalIPs} 个来源 IP`);

    const counts = { '': users.length, active, suspended_quota: quota, expired, disabled };
    const labels = { '': '全部', active: '活跃', suspended_quota: '超额暂停', expired: '已到期', disabled: '已停用' };
    for (const btn of document.querySelectorAll('#u-status-filters button[data-ustatus]')) {
      const st = btn.dataset.ustatus || '';
      btn.classList.toggle('active', st === userFilters.status);
      btn.textContent = `${labels[st] || st} (${counts[st] ?? 0})`;
    }
    renderUserPlanFilterPills(users);
  }

  async function handleCopyUserSubscription(u) {
    const r = await runAction(`获取 ${u.id} 订阅链接`, () => invoke('users.get_subscription', { user_id: u.id }));
    if (!r) return;
    if (r.available && r.subscription_token) {
      openUserSubModal({
        userId: u.id,
        displayName: u.display_name,
        token: r.subscription_token,
        path: r.subscription_path,
        subtitle: '可直接复制 Clash / Sing-box / Base64 订阅链接导入客户端',
      });
      return;
    }
    const ok = await hostConfirm({
      title: '旧版用户尚未保存加密订阅',
      body: `用户「${u.display_name || u.id}」创建于旧版本（仅保存哈希）。是否立即轮换一次订阅令牌以生成新链接并启用日后一键复制？`,
      confirmLabel: '立即轮换并复制',
      danger: false,
    });
    if (!ok) return;
    const rot = await runAction(`轮换 ${u.id} 订阅令牌`, () =>
      invoke('users.rotate_subscription', { user_id: u.id, expected_revision: String(u.revision || '') }));
    if (rot && rot.subscription_token) {
      openUserSubModal({
        userId: u.id,
        displayName: u.display_name,
        token: rot.subscription_token,
        path: rot.subscription_path,
        subtitle: `新订阅令牌已加密保存（rev ${rot.revision || '-'}），后续可随时一键复制`,
      });
      void refreshUsers();
    }
  }

  function renderUsers(users) {
    cachedUsers = users;
    renderUserChainSelects();
    renderUserStats(users);
    const tbody = $('users-body');
    if (!tbody) return;
    clearNode(tbody);
    const planNameMap = new Map(cachedPlans.map((p) => [p.id, p.name || p.id]));
    const q = userFilters.search.trim().toLowerCase();
    const filtered = users.filter((u) => {
      if (userFilters.status && u.status !== userFilters.status) return false;
      if (userFilters.plan && u.plan_id !== userFilters.plan) return false;
      if (q) {
        const hay = `${u.id} ${u.display_name || ''} ${u.notes || ''} ${u.plan_id || ''} ${u.chain_id || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    if (!filtered.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.className = 'muted';
      td.textContent = users.length ? '当前筛选条件下无匹配用户' : '暂无订阅用户，点击右上角「+ 新建用户」创建';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const USER_STATUS_LABELS = {
      active: '活跃',
      disabled: '已停用',
      suspended_quota: '超额暂停',
      expired: '已到期',
    };

    for (const u of filtered) {
      const tr = document.createElement('tr');

      // 1. 用户 / 备注
      const tdUser = document.createElement('td');
      const uc = document.createElement('div');
      uc.className = 'user-cell';
      const nm = document.createElement('div');
      nm.className = 'user-cell-name';
      nm.textContent = u.display_name || u.id;
      const sub = document.createElement('div');
      sub.className = 'user-cell-sub';
      const idSpan = document.createElement('span');
      idSpan.className = 'mono';
      idSpan.textContent = u.id;
      sub.appendChild(idSpan);
      if (u.notes) {
        const noteSpan = document.createElement('span');
        noteSpan.className = 'tag-chip';
        noteSpan.textContent = u.notes;
        sub.appendChild(noteSpan);
      }
      if (u.chain_id) {
        const ch = document.createElement('span');
        ch.className = 'badge info';
        ch.textContent = `链式:${u.chain_id}`;
        sub.appendChild(ch);
      }
      uc.append(nm, sub);
      tdUser.appendChild(uc);
      tr.appendChild(tdUser);

      // 2. 套餐
      const tdPlan = document.createElement('td');
      const plBadge = document.createElement('span');
      plBadge.className = 'badge cocoa';
      plBadge.textContent = planNameMap.get(u.plan_id) || u.plan_id;
      tdPlan.appendChild(plBadge);
      if (u.traffic_mode === 'both_2x' || u.traffic_mode === 'down_only') {
        const tm = document.createElement('span');
        tm.className = 'badge rose';
        tm.textContent = u.traffic_mode === 'both_2x' ? '×2' : '仅下行';
        tdPlan.appendChild(document.createTextNode(' '));
        tdPlan.appendChild(tm);
      }
      tr.appendChild(tdPlan);

      // 3. 本周期用量 / 配额
      const tdUsage = document.createElement('td');
      tdUsage.className = 'usage-cell';
      const eff = calcEffectiveBytes(u.period_up_bytes, u.period_down_bytes, u.traffic_mode);
      const quota = Number(u.quota_bytes || 0);
      const pct = quota > 0 ? Math.min(100, Math.round((eff / quota) * 100)) : 0;
      const uLine = document.createElement('div');
      uLine.className = 'usage-line';
      uLine.textContent = quota > 0 ? `${formatBytes(eff)} / ${formatBytes(quota)} (${pct}%)` : `${formatBytes(eff)} / 不限`;
      tdUsage.appendChild(uLine);
      if (quota > 0) {
        const prog = document.createElement('progress');
        prog.className = 'quota-progress';
        prog.max = 100;
        prog.value = pct;
        tdUsage.appendChild(prog);
      }
      tr.appendChild(tdUsage);

      // 4. 连接 / IP
      const tdConn = document.createElement('td');
      tdConn.className = 'muted mono';
      tdConn.textContent = `${u.active_connections || 0}/${formatLimit(u.effective_max_connections || 0)} · ${u.active_ips || 0}/${formatLimit(u.effective_max_ips || 0)} IP`;
      tr.appendChild(tdConn);

      // 5. 状态
      const tdSt = document.createElement('td');
      const stBadge = document.createElement('span');
      stBadge.className = `badge ${u.status}`;
      stBadge.textContent = USER_STATUS_LABELS[u.status] || u.status;
      tdSt.appendChild(stBadge);
      tr.appendChild(tdSt);

      // 6. 订阅链接（1-click）
      const tdSub = document.createElement('td');
      const btnSub = document.createElement('button');
      btnSub.type = 'button';
      btnSub.className = 'btn xs soft-rose';
      btnSub.textContent = '复制订阅';
      btnSub.addEventListener('click', () => {
        void handleCopyUserSubscription(u);
      });
      tdSub.appendChild(btnSub);
      tr.appendChild(tdSub);

      // 7. 操作
      const tdAct = document.createElement('td');
      tdAct.className = 'th-right';
      const wrap = document.createElement('div');
      wrap.className = 'row-ops';

      const mkOp = (text, cls, fn) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = `btn xs ${cls}`;
        b.textContent = text;
        b.addEventListener('click', fn);
        return b;
      };

      wrap.appendChild(mkOp('编辑', 'ghost', () => openUserEditModal(u)));
      wrap.appendChild(mkOp('趋势', 'ghost', () => openUserHistoryModal(u)));
      const isActive = u.status === 'active';
      wrap.appendChild(mkOp(isActive ? '停用' : '启用', isActive ? 'ghost' : '', async () => {
        const nextStatus = isActive ? 'disabled' : 'active';
        const ok = await hostConfirm({
          title: `${isActive ? '停用' : '启用'}代理用户`,
          body: `确认将用户「${u.display_name} (${u.id})」切换为 ${isActive ? '已停用' : '活跃'} 并同步内置 Xray 与带宽限速？`,
          confirmLabel: isActive ? '确认停用' : '确认启用',
          danger: isActive,
        });
        if (!ok) return;
        const r = await runAction(`${isActive ? '停用' : '启用'}用户 ${u.id}`, () =>
          invoke('users.set_status', { user_id: u.id, status: nextStatus, expected_revision: String(u.revision || '') }));
        if (r) {
          showBanner(`用户 ${u.id} 状态已更新为 ${r.user?.status || nextStatus}`, 'ok');
          void refreshUsers();
        }
      }));
      wrap.appendChild(mkOp('轮换', 'ghost', async () => {
        const ok = await hostConfirm({
          title: '轮换用户订阅链接',
          body: `确认轮换用户「${u.display_name} (${u.id})」的公开订阅令牌？旧链接将立即失效。`,
          confirmLabel: '确认轮换',
          danger: true,
        });
        if (!ok) return;
        const r = await runAction(`轮换 ${u.id} 订阅令牌`, () =>
          invoke('users.rotate_subscription', { user_id: u.id, expected_revision: String(u.revision || '') }));
        if (r && r.subscription_token) {
          openUserSubModal({
            userId: u.id,
            displayName: u.display_name,
            token: r.subscription_token,
            path: r.subscription_path,
            subtitle: `新订阅修订号 rev ${r.revision || '-'}，旧链接已失效`,
          });
          void refreshUsers();
        }
      }));
      wrap.appendChild(mkOp('删', 'danger', async () => {
        const ok = await hostConfirm({
          title: '删除代理用户',
          body: `确认永久删除用户「${u.display_name} (${u.id})」？将同步移除 Xray 凭据与内核限速规则。`,
          confirmLabel: '确认删除',
          danger: true,
        });
        if (!ok) return;
        const r = await runAction(`删除用户 ${u.id}`, () =>
          invoke('users.delete', { user_id: u.id, expected_revision: String(u.revision || '') }));
        if (r) {
          showBanner(`已删除代理用户 ${u.id}`, 'ok');
          void refreshUsers();
        }
      }));

      tdAct.appendChild(wrap);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    }
  }

  // ==================== 视图 5: 订阅分流规则 (/proxy/rules) ====================

  function renderRulesView() {
    const cfg = cachedRules.config;
    const grid = $('rules-preset-grid');
    if (grid) {
      clearNode(grid);
      const presets = cachedRules.presets.length ? cachedRules.presets : [
        { id: 'balanced', name: '智能分流（国内直连 + 境外代理）', description: '局域网与常见国内站点自动直连、境外流量自动优选节点。', recommended: true },
        { id: 'ai_streaming', name: 'AI 与流媒体分组分流', description: '单独拆分 AI 服务（ChatGPT/Claude/Gemini）与流媒体策略组。', recommended: false },
        { id: 'global', name: '全局代理（全流量走节点）', description: '除私网外全流量走 Proxy 节点，适合客户端自带分流场景。', recommended: false },
        { id: 'minimal', name: '极简模式（仅节点列表）', description: '仅导出代理节点与默认选择组，最小化规则体积。', recommended: false },
      ];
      for (const p of presets) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `preset-card${cfg.preset === p.id ? ' active' : ''}`;
        btn.dataset.rpreset = p.id;
        const hd = document.createElement('div');
        hd.className = 'preset-card-head';
        const nm = document.createElement('span');
        nm.textContent = p.name;
        hd.appendChild(nm);
        if (p.recommended) {
          const b = document.createElement('span');
          b.className = 'badge ok';
          b.textContent = '推荐';
          hd.appendChild(b);
        }
        const desc = document.createElement('div');
        desc.className = 'preset-card-desc';
        desc.textContent = p.description;
        btn.append(hd, desc);
        btn.addEventListener('click', () => {
          cachedRules.config.preset = p.id;
          renderRulesView();
        });
        grid.appendChild(btn);
      }
    }

    if ($('r-adblock')) $('r-adblock').checked = Boolean(cfg.enable_ad_block);
    if ($('r-aigroup')) $('r-aigroup').checked = Boolean(cfg.enable_ai_group);
    if ($('r-streamgroup')) $('r-streamgroup').checked = Boolean(cfg.enable_streaming_group);
    if ($('r-direct')) $('r-direct').value = (cfg.custom_direct_domains || []).join('\n');
    if ($('r-proxy')) $('r-proxy').value = (cfg.custom_proxy_domains || []).join('\n');
    if ($('r-reject')) $('r-reject').value = (cfg.custom_reject_domains || []).join('\n');

    renderRulesPreviewCode();
  }

  function renderRulesPreviewCode() {
    const pre = $('r-preview-code');
    if (!pre) return;
    for (const b of document.querySelectorAll('#r-preview-tabs button[data-rtab]')) {
      b.classList.toggle('active', b.dataset.rtab === cachedRules.previewTab);
    }
    pre.textContent = cachedRules.previewTab === 'singbox'
      ? (cachedRules.singbox_preview || '{}')
      : (cachedRules.clash_preview || '# 暂无预览');
  }

  async function saveRulesConfig() {
    const payload = {
      preset: cachedRules.config.preset || 'global',
      enable_ad_block: Boolean($('r-adblock')?.checked),
      enable_ai_group: Boolean($('r-aigroup')?.checked),
      enable_streaming_group: Boolean($('r-streamgroup')?.checked),
      custom_direct_domains: parseDomainLines($('r-direct')?.value),
      custom_proxy_domains: parseDomainLines($('r-proxy')?.value),
      custom_reject_domains: parseDomainLines($('r-reject')?.value),
    };
    const r = await runAction('保存订阅分流规则', () => invoke('rules.save', payload));
    if (!r) return;
    cachedRules.config = r.config || payload;
    cachedRules.clash_preview = r.clash_preview || '';
    cachedRules.singbox_preview = r.singbox_preview || '';
    renderRulesView();
    showBanner('订阅分流规则已保存，所有用户下次更新订阅时立即生效。', 'ok');
  }

  // ==================== 视图 2: 节点管理、TLS 证书联动与三栏构建器 ====================

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

  const nodeFilters = { protocol: '', source: '', tag: '', search: '' };

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

  const configViewer = { open: false, tab: 'json', data: null };

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
    for (let i = 0; i < len; i += 1) out += alphabet[b[i] % alphabet.length];
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

  function populateTLSCertSelects() {
    const certs = cachedTLSCerts.certificates || [];
    const installed = cachedTLSCerts.installed;
    for (const selId of ['nb-s-cert-select', 'nb-e-cert-select']) {
      const sel = $(selId);
      if (!sel) continue;
      const curBinding = ($('nb-e-binding')?.value || $('nb-s-binding')?.value || '').trim();
      clearNode(sel);
      const first = document.createElement('option');
      first.value = '';
      if (!installed) first.textContent = '尚未启用「证书管理」插件（可手动填写或点击右侧一键启用）';
      else if (!certs.length) first.textContent = '证书管理中暂无已签发证书（点击右侧前往申请）';
      else first.textContent = '— 选择面板已签发的 TLS 证书（自动填充 binding_ref 与 SNI）—';
      sel.appendChild(first);
      for (const c of certs) {
        const opt = document.createElement('option');
        opt.value = c.binding_ref || c.id;
        const primaryDomain = (c.domains && c.domains[0]) || c.id;
        const exp = c.not_after ? ` · 到期 ${String(c.not_after).slice(0, 10)}` : '';
        opt.textContent = `${primaryDomain}${c.issuer ? ` (${c.issuer}${exp})` : exp}`;
        sel.appendChild(opt);
      }
      if (curBinding && certs.some((c) => (c.binding_ref || c.id) === curBinding)) {
        sel.value = curBinding;
      }
    }
    for (const btnId of ['nb-s-cert-action', 'nb-e-cert-action']) {
      const btn = $(btnId);
      if (btn) btn.textContent = installed ? '前往证书管理 →' : '一键启用证书插件';
    }
    const note = $('nb-s-cert-note');
    if (note) {
      if (!installed) {
        note.className = 'info-note amber mt-10';
        note.textContent = '尚未安装或启用「证书管理 (tls.certificates)」插件：点击上方按钮可一键安装并申请免费 Let\'s Encrypt 证书。';
      } else if (!certs.length) {
        note.className = 'info-note amber mt-10';
        note.textContent = '「证书管理」已就绪，但暂无已签发证书；点击「前往证书管理 →」签发域名证书后即可直接下拉绑定。';
      } else {
        note.className = 'info-note jade mt-10';
        note.textContent = `已自动读取面板 ${certs.length} 张已签发 TLS 证书，下拉选择后自动同步 binding_ref 与 SNI。`;
      }
    }
  }

  async function loadAvailableTLSCerts(force = false) {
    if (!port || (cachedTLSCerts.loaded && !force)) {
      populateTLSCertSelects();
      return;
    }
    try {
      const res = await invoke('tls.certs.available', {});
      cachedTLSCerts = {
        loaded: true,
        installed: Boolean(res?.certs_installed),
        certificates: Array.isArray(res?.certificates) ? res.certificates : [],
      };
    } catch {
      cachedTLSCerts = { loaded: true, installed: false, certificates: [] };
    }
    populateTLSCertSelects();
  }

  function onCertSelectChange(bindingRef) {
    if (!bindingRef) return;
    $('nb-s-binding').value = bindingRef;
    $('nb-e-binding').value = bindingRef;
    const cert = (cachedTLSCerts.certificates || []).find((c) => (c.binding_ref || c.id) === bindingRef);
    if (cert && Array.isArray(cert.domains) && cert.domains.length) {
      const dom = String(cert.domains[0]).replace(/^\*\./, '');
      if (dom) {
        $('nb-s-tls-sni').value = dom;
        $('nb-e-tls-sni').value = dom;
      }
    }
    $('nb-s-cert-select').value = bindingRef;
    $('nb-e-cert-select').value = bindingRef;
    schedulePreview();
  }

  async function handleCertActionButton() {
    if (cachedTLSCerts.installed) {
      openHostPlugin('tls.certificates');
      return;
    }
    showBanner('正在为您安装并启用「证书管理 (tls.certificates)」插件…', 'ok');
    const r = await ensureHostPlugins(['tls.certificates']);
    if (r.ok) {
      showBanner('「证书管理」插件已启用，正在刷新证书列表…', 'ok');
      await loadAvailableTLSCerts(true);
    } else {
      showBanner(r.message || '未能自动启用证书管理插件，请在应用中心手动安装。', 'warn');
    }
  }

  function formatTransportSecurity(node) {
    const t = (node.transport || 'raw').toUpperCase();
    const sec = (node.security_mode || 'none').toLowerCase();
    const cfg = node.config || {};
    if (node.protocol === 'vless') {
      if (sec === 'reality') return cfg.flow === 'xtls-rprx-vision' ? `${t} · Vision-REALITY` : `${t} · REALITY`;
      if (sec === 'tls') return cfg.flow === 'xtls-rprx-vision' ? `${t} · Vision-TLS` : `${t} · TLS`;
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
    if (node.protocol === 'tuic') return `UDP · TLS (${cfg.congestion_control || 'bbr'})`;
    if (node.protocol === 'wireguard') return `UDP · MTU ${cfg.mtu || 1280}`;
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
      $('n-stat-latency-sub').textContent = '支持单节点测速与顶部「批量测速」';
    }
  }

  function renderNodeFilterPills() {
    const protoBox = $('n-proto-filters');
    clearNode(protoBox);
    const counts = new Map();
    for (const n of cachedNodes) counts.set(n.protocol, (counts.get(n.protocol) || 0) + 1);

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
      btn.append(txt, cnt);
      protoBox.appendChild(btn);
    };
    addProtoPill('', '全部', cachedNodes.length);
    for (const [proto, count] of counts.entries()) addProtoPill(proto, proto.toUpperCase(), count);

    for (const btn of document.querySelectorAll('#n-source-filters button')) {
      btn.classList.toggle('active', (btn.dataset.source || '') === nodeFilters.source);
    }

    const tagBox = $('n-tag-filters');
    clearNode(tagBox);
    const tagCounts = new Map();
    for (const n of cachedNodes) {
      for (const t of n.tags || []) tagCounts.set(t, (tagCounts.get(t) || 0) + 1);
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

      const tdProto = document.createElement('td');
      const pBadge = document.createElement('span');
      pBadge.className = `proto-badge proto-${n.protocol}`;
      pBadge.textContent = n.protocol.toUpperCase();
      tdProto.appendChild(pBadge);
      tr.appendChild(tdProto);

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
      const flag = detectRegionFlag(n);
      const nameSpan = document.createElement('span');
      nameSpan.textContent = `${flag ? `${flag} ` : ''}${n.name || n.id}`;
      titleLine.appendChild(nameSpan);
      const srcBadge = document.createElement('span');
      srcBadge.className = n.source === 'managed' ? 'badge cocoa' : 'badge info';
      srcBadge.textContent = n.source === 'managed' ? '托管' : '外部';
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

      const tdAddr = document.createElement('td');
      tdAddr.className = 'mono';
      tdAddr.textContent = `${n.server || n.listen || '0.0.0.0'}:${n.port}`;
      tr.appendChild(tdAddr);

      const tdTs = document.createElement('td');
      tdTs.className = 'muted';
      tdTs.textContent = formatTransportSecurity(n);
      tr.appendChild(tdTs);

      const tdLat = document.createElement('td');
      const latBadge = document.createElement('span');
      if (typeof n.last_latency_ms === 'number' && n.last_latency_ms > 0) {
        latBadge.className = n.last_latency_ms < 120 ? 'badge ok' : n.last_latency_ms < 300 ? 'badge warn' : 'badge err';
        latBadge.textContent = `${n.last_latency_ms} ms`;
      } else {
        latBadge.className = 'badge';
        latBadge.textContent = '未测';
      }
      tdLat.appendChild(latBadge);
      tr.appendChild(tdLat);

      const tdSt = document.createElement('td');
      const stBadge = document.createElement('span');
      stBadge.className = `badge ${n.enabled ? 'ok' : 'warn'}`;
      stBadge.textContent = n.enabled ? '启用' : '停用';
      tdSt.appendChild(stBadge);
      tr.appendChild(tdSt);

      const tdOps = document.createElement('td');
      tdOps.className = 'th-right';
      const ops = document.createElement('div');
      ops.className = 'node-ops';
      const mkBtn = (label, cls, action, title) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = `btn xs ${cls}`;
        b.textContent = label;
        b.title = title || label;
        b.dataset.nodeAction = action;
        b.dataset.nodeId = n.id;
        return b;
      };
      ops.appendChild(mkBtn('测速', 'ghost', 'test', '真实 TCP/TLS/UDP 延迟测速'));
      ops.appendChild(mkBtn('复制', 'ghost', 'copy', '复制分享 URI'));
      ops.appendChild(mkBtn('配置', 'ghost', 'view', '查看 JSON / URI / Clash / Sing-box'));
      if (n.source === 'managed' && MANAGED_PROTOCOL_SET.has(n.protocol)) {
        ops.appendChild(mkBtn('编辑', 'ghost', 'edit', '编辑节点参数'));
        ops.appendChild(mkBtn(n.enabled ? '停用' : '启用', 'ghost', 'toggle', n.enabled ? '停用该节点' : '启用该节点'));
      }
      ops.appendChild(mkBtn('删', 'danger', 'delete', '删除节点'));
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
    if (unavailable && sel.value !== 'none') sel.value = 'none';
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
      if (statSub) statSub.textContent = `Xray ${ver}${eng.anytls_active ? ' · AnyTLS 活跃' : ''}${eng.revision ? ` · ${eng.revision}` : ''}`;
    } else if (eng.binary_trusted) {
      if (pill) pill.className = 'engine-pill ok';
      if (pillText) pillText.textContent = `内置 Xray ${ver} · 就绪待命`;
      if (statVal) statVal.textContent = '就绪待命';
      if (statSub) statSub.textContent = `Xray ${ver} 已内置，添加并启用节点后自动热启`;
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
    if (overview.xray_engine) renderXrayEngineStatus(overview.xray_engine);
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
    if (configViewer.tab === 'json') pre.textContent = d.native_json || '{}';
    else if (configViewer.tab === 'uri') pre.textContent = d.share_uri || '（当前节点无可用分享 URI）';
    else if (configViewer.tab === 'clash') pre.textContent = d.clash_yaml || '# 当前协议暂未生成 Clash YAML 预览';
    else if (configViewer.tab === 'singbox') pre.textContent = d.singbox_outbound ? JSON.stringify(d.singbox_outbound, null, 2) : '{}';
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

  // ==================== 节点构建器：简易双栏 / 专家三栏 ====================

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
        if (item.ok) opt.textContent = `${item.domain} (${item.latency_ms} ms${item.tls13 ? ' · TLS 1.3' : item.tls_version ? ` · ${item.tls_version}` : ''})`;
        else if (item.error) opt.textContent = `${item.domain} (不可达)`;
        else opt.textContent = item.domain;
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
    const protoBox = $('nb-proto-pills');
    clearNode(protoBox);
    for (const p of MANAGED_PROTOCOLS) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `pill pill-proto-${p.id}${builder.protocol === p.id ? ' active' : ''}`;
      btn.dataset.proto = p.id;
      btn.textContent = p.label;
      protoBox.appendChild(btn);
    }

    const tList = TRANSPORT_MATRIX[builder.protocol] || [];
    const tStep = $('nb-transport-step');
    const tBox = $('nb-transport-pills');
    clearNode(tBox);
    if (!tList.length) {
      tStep.classList.add('hidden');
    } else {
      tStep.classList.remove('hidden');
      if (!tList.some((x) => x.id === builder.transport)) builder.transport = defaultTransport(builder.protocol);
      for (const t of tList) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `pill${builder.transport === t.id ? ' active' : ''}`;
        btn.dataset.transport = t.id;
        btn.textContent = t.label;
        tBox.appendChild(btn);
      }
    }

    const sList = getSecurityOptions(builder.protocol, builder.transport);
    const sStep = $('nb-security-step');
    const sBox = $('nb-security-pills');
    clearNode(sBox);
    if (!sList.length) {
      sStep.classList.add('hidden');
      builder.secKey = 'none';
    } else {
      sStep.classList.remove('hidden');
      if (!sList.some((x) => x.key === builder.secKey)) builder.secKey = defaultSecurityKey(builder.protocol, builder.transport);
      for (const s of sList) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `pill${builder.secKey === s.key ? ' active' : ''}`;
        btn.dataset.seckey = s.key;
        btn.textContent = s.label;
        sBox.appendChild(btn);
      }
    }

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
    $('nb-dialog')?.classList.toggle('expert-wide', !isSimplified);
    $('nb-workspace')?.classList.toggle('is-expert', !isSimplified);

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
          ? '已选择 VLESS Encryption 模式：UUID 与高位端口自动生成。'
          : 'UUID 与高位端口自动生成；选择或填写证书 binding_ref 后立即同步核心。',
      vmess: 'VMess UUID 与随机高位端口自动生成，默认启用流量嗅探。',
      trojan: 'Trojan 24 位强随机密码与高位端口自动生成。',
      shadowsocks: '传统 Shadowsocks 随机强密码与高位端口自动生成，默认 TCP + UDP。',
      shadowsocks2022: 'SS2022 Server Key 与用户 PSK 将按加密方式自动生成 16/32 字节 Base64 密钥。',
      hysteria2: 'Hysteria2 强密码与随机 UDP 端口自动生成；需 Salamander 混淆或端口跳跃可切专家模式。',
      anytls: 'AnyTLS 密码与标准 8 段 Padding Scheme 自动预填，绑定 TLS 证书后立即同步生效。',
      socks5: 'SOCKS5 留空用户名默认为 user，自动生成 16 位随机密码。',
      http: 'HTTP 代理留空用户名默认为 user，自动生成 16 位随机密码。',
    };
    $('nb-s-autofill-note').textContent = autoNotes[proto] || '';

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
    if (showFlow) $('nb-e-flow').value = secOpt.flow || '';

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
      : '专家模式：三栏全量参数，支持粘贴保留 x-ui / 3x-ui 原有 UUID、Reality 私钥与端口。';

    if (showReality && !sniProbedOnce && port && builder.open) {
      void probeRealitySNI(!builder.editingId);
    }
    if (showTLS && port && builder.open) {
      void loadAvailableTLSCerts(false);
    }
    requestAnimationFrame(() => notifyResize());
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
    if (firstSNI) populateSNISelects(firstSNI);
    $('nb-s-binding').value = $('nb-e-binding').value;
    $('nb-s-tls-sni').value = $('nb-e-tls-sni').value;
    $('nb-s-decryption').value = $('nb-e-decryption').value;
    $('nb-s-encryption').value = $('nb-e-encryption').value;
    if ($('nb-e-method').value) $('nb-s-method').value = $('nb-e-method').value;
    $('nb-s-username').value = $('nb-e-username').value;
    $('nb-s-password').value = $('nb-e-password').value;
  }

  function buildDraftPayload() {
    if (builder.mode === 'simplified') syncSimplifiedToExpert();

    const proto = builder.protocol;
    const trans = TRANSPORT_MATRIX[proto] ? builder.transport : defaultTransport(proto);
    const secOpt = getActiveSecurityOpt();
    const secMode = secOpt.security_mode || 'none';
    const isEnc = proto === 'vless' && builder.secKey === 'enc';

    const cfg = {};
    const put = (key, val) => {
      if (val !== undefined && val !== null && String(val).trim() !== '') cfg[key] = String(val).trim();
    };

    if (proto === 'vless' || proto === 'vmess') put('uuid', $('nb-e-uuid').value);
    if (proto === 'vless') {
      const flowVal = builder.mode === 'expert' ? $('nb-e-flow').value : (secOpt.flow || '');
      if (flowVal) cfg.flow = flowVal;
      if (isEnc) {
        const decVal = $('nb-e-decryption').value.trim();
        if (decVal) put('decryption', decVal);
        else if (!builder.editingId) put('decryption', 'none');
        const encVal = $('nb-e-encryption').value.trim();
        if (encVal) put('encryption', encVal);
        else if (!builder.editingId) put('encryption', 'none');
      }
    }
    if (proto === 'trojan' || proto === 'shadowsocks' || proto === 'hysteria2' || proto === 'anytls' || proto === 'socks5' || proto === 'http') {
      put('password', $('nb-e-password').value);
    }
    if (proto === 'socks5' || proto === 'http') put('username', $('nb-e-username').value);
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
    if (proto === 'socks5') cfg.udp = $('nb-e-udp').checked;

    if (proto === 'vless' || proto === 'vmess' || proto === 'trojan') {
      if (trans === 'ws' || trans === 'xhttp') {
        put('path', $('nb-e-path').value);
        put('host', $('nb-e-host').value);
      }
      if (trans === 'grpc') put('service_name', $('nb-e-service-name').value);
      if (proto === 'vless' && trans === 'xhttp') put('xhttp_mode', $('nb-e-xhttp-mode').value || 'auto');
    }

    if (secMode === 'reality') {
      const rawNames = $('nb-e-server-names').value.split(/[,，\s]+/).map((s) => s.trim()).filter(Boolean);
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
      const lines = $('nb-e-padding').value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
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
      if (Number.isFinite(pNum) && pNum >= 0 && pNum <= 65535) payload.port = pNum;
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
    if (builder.previewTab === 'json') pre.textContent = p.native_json || JSON.stringify(p.native_inbound || {}, null, 2);
    else if (builder.previewTab === 'uri') pre.textContent = p.share_uri || '（暂无分享 URI）';
    else if (builder.previewTab === 'clash') pre.textContent = p.clash_yaml || '# 当前协议暂未生成 Clash YAML';
    else if (builder.previewTab === 'singbox') pre.textContent = p.singbox_outbound ? JSON.stringify(p.singbox_outbound, null, 2) : '{}';
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
    $('nb-s-tags').value = '';
    syncObfsAvailabilityUI();
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
      $('nb-modal-title').textContent = '添加代理节点';
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

  // ==================== 视图 6: 链式代理弹窗 + WARP 渲染 ====================

  function openChainEditModal(chain = null) {
    chainEditModal.open = true;
    chainEditModal.editingId = chain ? chain.id : '';
    $('ce-modal-title').textContent = chain ? `编辑链式落地 · ${chain.name || chain.id}` : '添加链式代理落地节点';
    const idEl = $('c-id');
    idEl.value = chain ? chain.id : '';
    idEl.readOnly = Boolean(chain);
    $('c-name').value = chain ? (chain.name || '') : '';
    $('c-mode').value = chain?.mode || 'client_dialer';
    $('c-proto').value = chain?.protocol || 'socks5';
    $('c-server').value = chain?.server || '';
    $('c-port').value = String(chain?.port || 1080);
    const m = chain?.config_masked || {};
    $('c-user').value = m.username || '';
    $('c-pass').value = '';
    $('c-uuid').value = '';
    $('c-method').value = m.method || '';
    $('c-sni').value = m.sni || '';
    $('c-next').value = chain?.next_hop_id || '';
    $('c-tls').checked = Boolean(m.tls);
    $('c-default').checked = Boolean(chain?.apply_default);
    $('c-enabled').checked = chain ? Boolean(chain.enabled) : true;
    $('chain-edit-modal').classList.remove('hidden');
  }

  function closeChainEditModal() {
    chainEditModal.open = false;
    chainEditModal.editingId = '';
    $('chain-edit-modal').classList.add('hidden');
  }

  function renderChains(chains) {
    cachedChains = chains;
    renderUserChainSelects();

    const nextSel = $('c-next');
    if (nextSel) {
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
    }

    const tbody = $('chains-body');
    clearNode(tbody);
    if (!chains.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.className = 'muted';
      td.textContent = '暂无链式代理落地节点，点击右上角「+ 添加链式节点」新建。';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const c of chains) {
      const tr = document.createElement('tr');

      const tdId = document.createElement('td');
      tdId.textContent = `${c.name} (${c.id})`;
      const tdMode = document.createElement('td');
      tdMode.textContent = c.mode;
      const tdAddr = document.createElement('td');
      tdAddr.className = 'mono';
      tdAddr.textContent = `${c.protocol}://${c.server}:${c.port}`;
      const tdHop = document.createElement('td');
      tdHop.textContent = `${c.next_hop_id ? `-> ${c.next_hop_id}` : '直出'}${c.apply_default ? ' · 默认' : ''}`;

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

      const tdSt = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${c.enabled ? 'ok' : 'warn'}`;
      badge.textContent = c.enabled ? '启用' : '停用';
      tdSt.appendChild(badge);

      const tdOps = document.createElement('td');
      tdOps.className = 'th-right';
      const wrap = document.createElement('div');
      wrap.className = 'row-ops';

      const btnProbe = document.createElement('button');
      btnProbe.type = 'button';
      btnProbe.className = 'btn xs ghost';
      btnProbe.textContent = '测速';
      btnProbe.addEventListener('click', async () => {
        const r = await runAction(`探测 ${c.id}`, () => invoke('chains.probe', { id: c.id }));
        if (!r) return;
        showBanner(
          r.reachable ? `链式落地 ${c.id} 连通正常，延迟 ${r.latency_ms} ms` : `链式落地 ${c.id} 不可达：${r.error || '超时'}`,
          r.reachable ? 'ok' : 'warn',
        );
      });

      const btnEdit = document.createElement('button');
      btnEdit.type = 'button';
      btnEdit.className = 'btn xs ghost';
      btnEdit.textContent = '编辑';
      btnEdit.addEventListener('click', () => openChainEditModal(c));

      const btnDel = document.createElement('button');
      btnDel.type = 'button';
      btnDel.className = 'btn xs danger';
      btnDel.textContent = '删';
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

      wrap.append(btnProbe, btnEdit, btnDel);
      tdOps.appendChild(wrap);
      tr.append(tdId, tdMode, tdAddr, tdHop, tdMask, tdSt, tdOps);
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
    $('w-addrs').textContent = w.registered ? [w.address_v4, w.address_v6].filter(Boolean).join(' / ') || '—' : '—';
    $('w-reserved').textContent = w.registered && Array.isArray(w.reserved) && w.reserved.length
      ? `reserved: [${w.reserved.join(', ')}]${w.client_id ? ` (${w.client_id})` : ''}`
      : 'reserved: —';
    $('w-ep-summary').textContent = w.endpoint || 'engage.cloudflareclient.com:2408';
    $('w-mode-summary').textContent = WARP_MODE_LABELS[w.routing_mode] || w.routing_mode || '—';
    $('w-sync-state').textContent = w.registered ? (w.last_synced_rev ? '已同步至 Xray' : '待同步生效') : '未配置';
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
      sp.textContent = '尚未检测到托管入站端口，请先在「节点管理」创建节点或使用域名/全局模式。';
      box.appendChild(sp);
    } else {
      for (const ib of inbounds) {
        const lbl = document.createElement('label');
        lbl.className = 'warp-port-chip';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.dataset.warpPort = ib.profile_id;
        cb.checked = Boolean(ib.bound);
        const txt = document.createElement('span');
        txt.textContent = `${ib.label}${ib.enabled ? '' : '（已停用）'}`;
        lbl.append(cb, txt);
        box.appendChild(lbl);
      }
    }
  }

  function readSelectedWARPPorts() {
    return Array.from(document.querySelectorAll('input[data-warp-port]'))
      .filter((cb) => cb.checked)
      .map((cb) => cb.dataset.warpPort);
  }

  function readWARPDomainsInput() {
    return $('w-domains').value.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  }

  function appendWARPPreset(key) {
    const preset = cachedWARPPresets[key] || [];
    const cur = new Set(readWARPDomainsInput());
    for (const d of preset) cur.add(d);
    $('w-domains').value = Array.from(cur).join('\n');
    $('w-mode').value = 'domains';
  }

  // ==================== 视图 7: tcpfit 调优 + Brutal 弹窗 ====================

  function openBrutalEditModal(binding = null) {
    brutalEditModal.open = true;
    brutalEditModal.editingId = binding ? binding.id : '';
    $('be-modal-title').textContent = binding ? `编辑 Brutal 接管 · ${binding.id}` : '添加 TCP Brutal 接管绑定';
    const idEl = $('b-id');
    idEl.value = binding ? binding.id : '';
    idEl.readOnly = Boolean(binding);
    $('b-inbound-preset').value = '';
    $('b-tag').value = binding?.inbound_tag || '';
    $('b-proto').value = binding?.protocol || 'vless';
    $('b-listen').value = String(binding?.listen_port || 2443);
    $('b-target').value = String(binding?.target_port || 443);
    $('b-bw').value = String(binding?.bandwidth_mbps || 100);
    $('b-oversend').value = String(binding?.oversend_pct || 125);
    $('b-gain').value = String(binding?.cwnd_gain || 20);
    $('b-sub').checked = binding ? Boolean(binding.enable_in_sub) : true;
    $('b-enabled').checked = binding ? Boolean(binding.enabled) : true;
    updateOversendPreview();
    $('brutal-edit-modal').classList.remove('hidden');
  }

  function closeBrutalEditModal() {
    brutalEditModal.open = false;
    brutalEditModal.editingId = '';
    $('brutal-edit-modal').classList.add('hidden');
  }

  function updateOversendPreview() {
    const bw = Math.max(1, Number($('b-bw')?.value) || 100);
    const pct = Math.min(250, Math.max(100, Number($('b-oversend')?.value) || 125));
    const eff = ((bw * pct) / 100).toFixed(1);
    const el = $('b-eff-preview');
    if (el) el.textContent = `折算等效发包速率：${eff} Mbps（基准 ${bw} Mbps × ${pct}%）`;
    for (const btn of document.querySelectorAll('#b-oversend-presets button[data-oversend]')) {
      btn.classList.toggle('active', Number(btn.dataset.oversend) === pct);
    }
  }

  function renderTuningPlan(plan) {
    const bdpKB = Math.round((plan.bdp_bytes || 0) / 1024);
    const maxMB = ((plan.max_buffer_bytes || 0) / (1024 * 1024)).toFixed(1);
    const budgetMB = ((plan.mem_budget_bytes || 0) / (1024 * 1024)).toFixed(0);
    $('t-plan-summary').textContent =
      `推导完成：BDP ≈ ${bdpKB} KiB · 安全单流缓冲区上限 ${maxMB} MiB（物理内存预算 ${budgetMB} MiB）· 选定拥塞算法：${plan.selected_cc}`;
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
      for (const val of [`#r${s.revision}`, s.reason, `${s.role} · ${s.bandwidth_mbps}Mbps / ${s.rtt_ms}ms`, s.applied ? '已生效' : '基线 / 演练']) {
        const td = document.createElement('td');
        td.textContent = String(val);
        tr.appendChild(td);
      }
      const tdOp = document.createElement('td');
      tdOp.className = 'th-right';
      const btnRb = document.createElement('button');
      btnRb.type = 'button';
      btnRb.className = 'btn xs ghost';
      btnRb.textContent = '回滚快照';
      btnRb.addEventListener('click', async () => {
        const ok = await hostConfirm({
          title: '回滚宿主机 sysctl 快照',
          body: `确认回滚宿主机 sysctl 至快照 #r${s.revision} (${s.reason})？`,
          confirmLabel: '确认回滚',
          danger: true,
        });
        if (!ok) return;
        const r = await runAction(`回滚快照 #r${s.revision}`, () => invoke('tuning.rollback', { snapshot_id: s.id, dry_run: false }));
        if (r) {
          showBanner(r.applied ? `已回滚并生效至快照 #r${s.revision}` : `已渲染快照 #r${s.revision}（${r.error || r.output}）`, r.applied ? 'ok' : 'warn');
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
      ? `eBPF=${env.ebpf_pinned ? 'pinned' : 'kmod'}`
      : (env.install_hint ? `安装提示: ${env.install_hint}` : '未检测到 tcp_brutal 模块');

    const guide = $('b-guidance');
    if (env.degraded_guidance) {
      guide.className = 'banner warn show';
      guide.textContent = `${env.degraded_guidance}${env.install_hint ? ` 推荐命令：${env.install_hint}` : ''}`;
    } else {
      guide.className = 'banner warn';
      guide.textContent = '';
    }

    cachedInbounds = data.tcp_inbounds || [];
    const presetSel = $('b-inbound-preset');
    if (presetSel) {
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
    }

    const bindings = data.bindings || [];
    cachedBrutalBindings = bindings;
    const metrics = data.live_listeners || [];
    const brutalMini = $('brutal-mini-count');
    if (brutalMini) {
      brutalMini.textContent = bindings.length ? ` · Brutal ${metrics.filter((m) => m.running).length}/${bindings.length}` : '';
    }

    const bBody = $('b-bindings-body');
    clearNode(bBody);
    if (!bindings.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'muted';
      td.textContent = '暂无 Brutal 接管绑定，点击右上角「+ 添加接管绑定」配置。';
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
          `${b.enable_in_sub ? '自动切端口' : '仅接管'} · ${b.enabled ? '启用' : '停用'}`,
        ]) {
          const td = document.createElement('td');
          td.textContent = String(val);
          tr.appendChild(td);
        }
        const tdOp = document.createElement('td');
        tdOp.className = 'th-right';
        const wrap = document.createElement('div');
        wrap.className = 'row-ops';
        const btnEdit = document.createElement('button');
        btnEdit.type = 'button';
        btnEdit.className = 'btn xs ghost';
        btnEdit.textContent = '编辑';
        btnEdit.addEventListener('click', () => openBrutalEditModal(b));
        const btnDel = document.createElement('button');
        btnDel.type = 'button';
        btnDel.className = 'btn xs danger';
        btnDel.textContent = '删';
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
        wrap.append(btnEdit, btnDel);
        tdOp.appendChild(wrap);
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
      td.textContent = '尚无运行中的接管监听器，点击「热重载所有接管端口」即可启动。';
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

  // ==================== 数据拉取调度（7 视图按需拉取） ====================

  async function refreshOverview() {
    const [overview, plansResp, usersResp, nodesResp, trafficResp, brutalResp] = await Promise.all([
      invoke('proxy.overview', { include_traffic_status: false }),
      invoke('plans.list', { limit: 100 }),
      invoke('users.list', { limit: 256 }),
      invoke('nodes.list', {}),
      invoke('traffic.status', { include_classes: true }),
      invoke('brutal.status', {}),
    ]);
    applyOverviewCapabilities(overview);
    cachedPlans = plansResp.plans || [];
    cachedUsers = usersResp.users || [];
    cachedNodes = Array.isArray(nodesResp.nodes) ? nodesResp.nodes : [];
    const ovVal = $('overview-value');
    if (ovVal) ovVal.textContent = `${overview.active_users ?? 0} / ${overview.total_users ?? 0} 活跃`;
    const ovSub = $('overview-sub');
    if (ovSub) ovSub.textContent = overview.sub || '运行正常';
    const ps = $('plans-summary');
    if (ps) ps.textContent = `${cachedPlans.length} 个模板`;
    if (trafficResp.supported) {
      $('traffic-status').textContent = 'HTB 正常';
      $('traffic-detail').textContent = `${trafficResp.egress_interface || '默认'} · ${(trafficResp.classes || []).length} 条规则`;
    } else {
      $('traffic-status').textContent = 'HTB 已降级';
      $('traffic-detail').textContent = trafficResp.degraded_reason || '不支持 HTB';
    }
    renderBrutalStatus(brutalResp);
    renderDailyTrafficChart(overview.daily_traffic || []);
    renderOverviewWidgets(cachedUsers, cachedNodes);
    renderOverviewAlerts(overview.alerts || []);
  }

  async function refreshUsers() {
    const [overview, plansResp, usersResp, chainsResp] = await Promise.all([
      invoke('proxy.overview', { include_traffic_status: false }),
      invoke('plans.list', { limit: 100 }),
      invoke('users.list', { limit: 256 }),
      invoke('chains.list', {}),
    ]);
    applyOverviewCapabilities(overview);
    cachedChains = chainsResp.chains || [];
    cachedPlans = plansResp.plans || [];
    renderPlanSelects();
    renderUsers(usersResp.users || []);
  }

  async function refreshPlans() {
    const [overview, plansResp, usersResp, nodesResp] = await Promise.all([
      invoke('proxy.overview', { include_traffic_status: false }).catch(() => null),
      invoke('plans.list', { limit: 100 }),
      invoke('users.list', { limit: 256 }).catch(() => ({ users: cachedUsers })),
      invoke('nodes.list', {}).catch(() => ({ nodes: cachedNodes })),
    ]);
    applyOverviewCapabilities(overview);
    cachedUsers = usersResp.users || [];
    cachedNodes = Array.isArray(nodesResp.nodes) ? nodesResp.nodes : cachedNodes;
    renderPlans(plansResp.plans || []);
  }

  async function refreshRules() {
    const r = await invoke('rules.get', {});
    cachedRules.loaded = true;
    cachedRules.config = r.config || cachedRules.config;
    cachedRules.presets = Array.isArray(r.presets) ? r.presets : [];
    cachedRules.clash_preview = r.clash_preview || '';
    cachedRules.singbox_preview = r.singbox_preview || '';
    renderRulesView();
    if (!xrayStatusLoaded) invoke('xray.status', {}).then(renderXrayEngineStatus).catch(() => {});
  }

  async function refreshChains() {
    const [chainsRes, warpRes] = await Promise.all([
      invoke('chains.list', {}),
      invoke('warp.status', {}),
    ]);
    renderChains(chainsRes.chains || []);
    renderWARPStatus(warpRes);
    if (!xrayStatusLoaded) invoke('xray.status', {}).then(renderXrayEngineStatus).catch(() => {});
  }

  async function refreshTuningAndBrutal() {
    const [tRes, bRes] = await Promise.all([
      invoke('tuning.status', {}),
      invoke('brutal.status', {}),
    ]);
    renderTuningStatus(tRes);
    renderBrutalStatus(bRes);
    if (!xrayStatusLoaded) invoke('xray.status', {}).then(renderXrayEngineStatus).catch(() => {});
  }

  async function refreshActiveView() {
    if (!port) return;
    setStatus('正在同步状态…');
    try {
      if (activeRoute === '/proxy') await refreshOverview();
      else if (activeRoute === '/proxy/nodes') await refreshNodes();
      else if (activeRoute === '/proxy/users') await refreshUsers();
      else if (activeRoute === '/proxy/plans') await refreshPlans();
      else if (activeRoute === '/proxy/rules') await refreshRules();
      else if (activeRoute === '/proxy/chains') await refreshChains();
      else if (activeRoute === '/proxy/tuning') await refreshTuningAndBrutal();
      setStatus('已连接');
    } catch (err) {
      setStatus(`读取失败：${err?.message || '未知错误'}`);
    }
  }

  // ==================== 全局事件绑定 ====================

  $('btn-ctx-primary')?.addEventListener('click', () => {
    if (activeRoute === '/proxy/users') openUserCreateModal();
    else if (activeRoute === '/proxy/plans') openPlanEditModal(null);
    else if (activeRoute === '/proxy/rules') void saveRulesConfig();
    else if (activeRoute === '/proxy/chains') openChainEditModal(null);
    else if (activeRoute === '/proxy/tuning') openBrutalEditModal(null);
    else {
      if (activeRoute !== '/proxy/nodes') switchRoute('/proxy/nodes', true);
      openNodeBuilder(null);
    }
  });

  for (const btn of document.querySelectorAll('[data-go-route]')) {
    btn.addEventListener('click', () => switchRoute(btn.dataset.goRoute, true));
  }

  $('refresh')?.addEventListener('click', () => void refreshActiveView());

  $('chains-subtabs')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-sub]');
    if (btn) setChainsSubTab(btn.dataset.sub);
  });

  $('tuning-subtabs')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-sub]');
    if (btn) setTuningSubTab(btn.dataset.sub);
  });

  // 用户筛选与弹窗事件
  $('u-search')?.addEventListener('input', () => {
    userFilters.search = $('u-search').value;
    renderUsers(cachedUsers);
  });
  $('u-status-filters')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-ustatus]');
    if (!btn) return;
    userFilters.status = btn.dataset.ustatus || '';
    renderUsers(cachedUsers);
  });
  $('u-plan-filters')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-uplan]');
    if (!btn) return;
    userFilters.plan = btn.dataset.uplan || '';
    renderUsers(cachedUsers);
  });

  $('btn-user-create-open')?.addEventListener('click', openUserCreateModal);
  $('uc-close')?.addEventListener('click', closeUserCreateModal);
  $('uc-cancel')?.addEventListener('click', closeUserCreateModal);
  $('user-create-modal')?.addEventListener('click', (e) => { if (e.target === $('user-create-modal')) closeUserCreateModal(); });
  $('uc-plan-mode')?.addEventListener('change', updateUserCreatePlanMode);
  $('uc-submit')?.addEventListener('click', async () => {
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
      showBanner('请选择已有套餐或切换为自定义配额与限速', 'warn');
      return;
    }
    const payload = {
      id,
      display_name: displayName,
      notes: $('uc-notes').value.trim(),
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
          ? `已同步 Xray (rev ${r.core_revision || '-'}) · 限速降级：${r.shaping_degraded_reason}`
          : `已同步内置 Xray (rev ${r.core_revision || '-'}) 与内核限速`,
      });
    } else {
      showBanner(`用户 ${id} 已创建`, 'ok');
    }
    void refreshUsers();
  });

  // 编辑用户弹窗事件
  $('ue-close')?.addEventListener('click', closeUserEditModal);
  $('ue-cancel')?.addEventListener('click', closeUserEditModal);
  $('user-edit-modal')?.addEventListener('click', (e) => { if (e.target === $('user-edit-modal')) closeUserEditModal(); });
  $('ue-save')?.addEventListener('click', async () => {
    const uid = userEditModal.userId;
    if (!uid) return;
    const expStr = ($('ue-expires').value || '').trim();
    const expiresAt = expStr ? Date.parse(`${expStr}T23:59:59Z`) : 0;
    const payload = {
      user_id: uid,
      display_name: $('ue-name').value.trim() || uid,
      notes: $('ue-notes').value.trim(),
      plan_id: $('ue-plan').value.trim(),
      expires_at: Number.isFinite(expiresAt) && expiresAt > 0 ? expiresAt : 0,
      max_connections_override: Number($('ue-conns').value),
      max_ips_override: Number($('ue-ips').value),
      chain_id: $('ue-chain').value,
      expected_revision: userEditModal.revision,
    };
    const r = await runAction(`更新用户 ${uid}`, () => invoke('users.set_limits', payload));
    if (r) {
      closeUserEditModal();
      showBanner(`用户 ${r.user?.display_name || uid} 资料与套餐策略已更新`, 'ok');
      void refreshUsers();
    }
  });

  $('btn-nft-preview')?.addEventListener('click', async () => {
    const r = await runAction('生成 nftables 连接限流规则', () => invoke('users.connections.status', { include_nftables: true }));
    if (r) {
      const pre = $('nft-preview');
      pre.textContent = r.nftables_rules || '# 当前没有需要下发的 nftables 连接限制规则';
      pre.classList.remove('hidden');
    }
  });

  // 订阅复制弹窗事件
  $('us-close')?.addEventListener('click', closeUserSubModal);
  $('us-close-btn')?.addEventListener('click', closeUserSubModal);
  $('user-sub-modal')?.addEventListener('click', (e) => { if (e.target === $('user-sub-modal')) closeUserSubModal(); });
  $('us-host-override')?.addEventListener('input', updateUserSubModalUrls);
  $('us-copy-token')?.addEventListener('click', () => void hostCopy(userSubModal.token, '已复制纯订阅 Token'));
  $('us-copy-clash')?.addEventListener('click', () => void hostCopy($('us-url-clash').value, '已复制 Clash 订阅链接'));
  $('us-copy-singbox')?.addEventListener('click', () => void hostCopy($('us-url-singbox').value, '已复制 Sing-box 订阅链接'));
  $('us-copy-base64')?.addEventListener('click', () => void hostCopy($('us-url-base64').value, '已复制 Base64 订阅链接'));

  // 流量历史弹窗事件
  $('uh-close')?.addEventListener('click', closeUserHistoryModal);
  $('uh-close-btn')?.addEventListener('click', closeUserHistoryModal);
  $('user-history-modal')?.addEventListener('click', (e) => { if (e.target === $('user-history-modal')) closeUserHistoryModal(); });
  $('uh-range-pills')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-hours]');
    if (!btn || !userHistoryModal.userId) return;
    const h = Number(btn.dataset.hours) || 24;
    userHistoryModal.hours = h;
    for (const b of document.querySelectorAll('#uh-range-pills button')) {
      b.classList.toggle('active', Number(b.dataset.hours) === h);
    }
    void loadUserUsageHistory(userHistoryModal.userId, h);
  });

  // 套餐弹窗事件
  $('btn-plan-create-open')?.addEventListener('click', () => openPlanEditModal(null));
  $('pe-close')?.addEventListener('click', closePlanEditModal);
  $('pe-cancel')?.addEventListener('click', closePlanEditModal);
  $('plan-edit-modal')?.addEventListener('click', (e) => { if (e.target === $('plan-edit-modal')) closePlanEditModal(); });
  $('pe-nav')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-pe-tab]');
    if (btn) setPlanEditTab(btn.dataset.peTab);
  });
  $('plan-edit-modal')?.addEventListener('input', updatePlanModalNavSubs);
  $('plan-edit-modal')?.addEventListener('change', updatePlanModalNavSubs);
  $('p-nodes-search')?.addEventListener('input', renderPlanNodesChecklist);
  $('p-nodes-select-all')?.addEventListener('click', () => {
    for (const n of cachedNodes) planEditModal.selectedNodeIDs.add(n.id);
    updatePlanModalNavSubs();
    renderPlanNodesChecklist();
  });
  $('p-nodes-clear')?.addEventListener('click', () => {
    planEditModal.selectedNodeIDs.clear();
    updatePlanModalNavSubs();
    renderPlanNodesChecklist();
  });
  $('btn-plan-save')?.addEventListener('click', async () => {
    const id = $('p-id').value.trim();
    const name = $('p-name').value.trim();
    if (!id || !name) {
      setPlanEditTab('basic');
      showBanner('请填写套餐 ID 与套餐名称', 'warn');
      return;
    }
    const quotaGB = Math.max(0, Number($('p-quota-gb').value) || 0);
    const payload = {
      id,
      name,
      description: $('p-desc').value.trim(),
      quota_bytes: Math.round(quotaGB * 1024 * 1024 * 1024),
      traffic_mode: $('p-traffic-mode').value || 'both',
      down_limit_kbps: Math.max(0, Number($('p-down').value) || 0),
      up_limit_kbps: Math.max(0, Number($('p-up').value) || 0),
      max_connections: Math.max(0, Number($('p-max-conns').value) || 0),
      max_ips: Math.max(0, Number($('p-max-ips').value) || 0),
      billing_reset_day: Math.min(28, Math.max(0, Math.floor(Number($('p-reset-day').value) || 0))),
      validity_days: Math.min(3650, Math.max(0, Math.floor(Number($('p-validity').value) || 0))),
      node_ids: Array.from(planEditModal.selectedNodeIDs),
      rule_preset: $('p-rule-preset').value || '',
    };
    const r = await runAction('保存套餐', () => invoke('plans.upsert', payload));
    if (r) {
      closePlanEditModal();
      showBanner(`套餐「${r.plan?.name || name}」已保存`, 'ok');
      void refreshPlans();
    }
  });

  // 订阅分流规则事件
  $('btn-rules-save')?.addEventListener('click', () => void saveRulesConfig());
  $('r-preview-tabs')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-rtab]');
    if (!btn) return;
    cachedRules.previewTab = btn.dataset.rtab;
    renderRulesPreviewCode();
  });
  $('btn-rules-copy')?.addEventListener('click', () => {
    void hostCopy($('r-preview-code').textContent, '已复制分流规则预览');
  });

  // 节点管理事件（含批量测速、清理重复、TLS 证书联动）
  $('btn-node-add')?.addEventListener('click', () => openNodeBuilder(null));
  $('btn-nodes-batch-test')?.addEventListener('click', async () => {
    const btn = $('btn-nodes-batch-test');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '批量测速中…';
    }
    try {
      const r = await runAction('一键批量节点测速', () => invoke('nodes.batch_test', { only_enabled: true, timeout_ms: 2500 }));
      if (r) {
        showBanner(`批量测速完成：共测试 ${r.tested} 个节点，${r.reachable} 个连通正常，${r.failed} 个不可达`, r.failed > 0 ? 'warn' : 'ok');
        await refreshNodes();
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '批量测速';
      }
    }
  });

  $('btn-nodes-dedup')?.addEventListener('click', async () => {
    const dry = await runAction('检测重复节点', () => invoke('nodes.deduplicate', { dry_run: true }));
    if (!dry) return;
    if (!dry.removed_count) {
      showBanner('所有节点均为唯一配置，未发现重复节点。', 'ok');
      return;
    }
    const ok = await hostConfirm({
      title: '清理重复代理节点',
      body: `共检测到 ${dry.removed_count} 个完全重复的节点（将优先保留托管节点与较早创建的节点），确认一键清理？`,
      confirmLabel: `清理 ${dry.removed_count} 个重复节点`,
      danger: true,
    });
    if (!ok) return;
    const r = await runAction('清理重复节点', () => invoke('nodes.deduplicate', { dry_run: false }));
    if (r) {
      showBanner(`已清理 ${r.removed_count} 个重复节点`, 'ok');
      void refreshNodes();
    }
  });

  $('n-proto-filters')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-proto]');
    if (!btn) return;
    nodeFilters.protocol = btn.dataset.proto || '';
    renderNodesTable();
  });
  $('n-source-filters')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-source]');
    if (!btn) return;
    nodeFilters.source = btn.dataset.source || '';
    renderNodesTable();
  });
  $('n-tag-filters')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tag]');
    if (!btn) return;
    nodeFilters.tag = btn.dataset.tag || '';
    renderNodesTable();
  });
  $('n-search')?.addEventListener('input', () => {
    nodeFilters.search = $('n-search').value;
    renderNodesTable();
  });

  $('btn-nodes-import-clear')?.addEventListener('click', () => {
    $('n-import-uris').value = '';
    $('n-import-tags').value = '';
    const fb = $('n-import-feedback');
    fb.className = 'banner mt-10';
    fb.textContent = '';
  });
  $('btn-nodes-import')?.addEventListener('click', async () => {
    const uris = $('n-import-uris').value.trim();
    if (!uris) {
      showBanner('请先粘贴至少一条节点 URI 或 Base64 订阅内容', 'warn');
      return;
    }
    const r = await runAction('解析并导入外部节点', () => invoke('nodes.import_uri', {
      uris,
      tags: parseTagList($('n-import-tags').value),
      enabled: $('n-import-enabled').checked,
    }));
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

  $('nodes-body')?.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-node-action]');
    if (!btn) return;
    const action = btn.dataset.nodeAction;
    const node = cachedNodes.find((x) => x.id === btn.dataset.nodeId);
    if (!node) return;

    if (action === 'test') {
      btn.disabled = true;
      btn.textContent = '…';
      try {
        const r = await runAction(`测速 ${node.name || node.id}`, () => invoke('nodes.test', { id: node.id }));
        if (r) {
          showBanner(
            r.ok ? `节点 ${node.name || node.id} 连通正常，延迟 ${r.latency_ms} ms` : `节点 ${node.name || node.id} 不可达：${r.error || '超时'}`,
            r.ok ? 'ok' : 'warn',
          );
          await refreshNodes();
        }
      } finally {
        btn.disabled = false;
        btn.textContent = '测速';
      }
    } else if (action === 'copy') {
      const uri = node.share_uri || node.raw_uri || '';
      if (!uri) showBanner(`节点 ${node.name || node.id} 暂无可复制的分享 URI`, 'warn');
      else await hostCopy(uri, `已复制 ${node.name || node.id} 分享链接`);
    } else if (action === 'view') {
      void openConfigViewer(node);
    } else if (action === 'edit') {
      openNodeBuilder(node);
    } else if (action === 'toggle') {
      const nextEnabled = !node.enabled;
      const r = await runAction(`${nextEnabled ? '启用' : '停用'}节点 ${node.name || node.id}`, () => invoke('nodes.upsert', {
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
      }));
      if (r) {
        showBanner(`节点 ${node.name || node.id} 已${nextEnabled ? '启用' : '停用'}`, 'ok');
        void refreshNodes();
      }
    } else if (action === 'delete') {
      const ok = await hostConfirm({
        title: '删除代理节点',
        body: `确认删除节点「${node.name || node.id}」(${node.protocol.toUpperCase()} :${node.port})？`,
        confirmLabel: '确认删除',
        danger: true,
      });
      if (!ok) return;
      const r = await runAction(`删除节点 ${node.id}`, () => invoke('nodes.delete', { id: node.id, sync_core: true }));
      if (r) {
        showBanner(`已删除节点 ${node.name || node.id}`, 'ok');
        void refreshNodes();
      }
    }
  });

  // 查看配置弹窗事件
  $('nc-close')?.addEventListener('click', closeConfigViewer);
  $('nc-close-btn')?.addEventListener('click', closeConfigViewer);
  $('node-config-modal')?.addEventListener('click', (e) => { if (e.target === $('node-config-modal')) closeConfigViewer(); });
  $('nc-tabs')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    configViewer.tab = btn.dataset.tab;
    for (const b of document.querySelectorAll('#nc-tabs button')) b.classList.toggle('active', b.dataset.tab === configViewer.tab);
    renderConfigViewerContent();
  });
  $('nc-copy')?.addEventListener('click', () => void hostCopy($('nc-code').textContent, '已复制节点配置内容'));

  // 节点构建器事件
  $('nb-close')?.addEventListener('click', closeNodeBuilder);
  $('nb-cancel')?.addEventListener('click', closeNodeBuilder);
  $('node-builder-modal')?.addEventListener('click', (e) => { if (e.target === $('node-builder-modal')) closeNodeBuilder(); });
  $('nb-proto-pills')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-proto]');
    if (!btn || btn.dataset.proto === builder.protocol) return;
    builder.protocol = btn.dataset.proto;
    builder.transport = defaultTransport(builder.protocol);
    builder.secKey = defaultSecurityKey(builder.protocol, builder.transport);
    renderBuilderPills();
    updateBuilderFieldVisibility();
    schedulePreview();
  });
  $('nb-transport-pills')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-transport]');
    if (!btn || btn.dataset.transport === builder.transport) return;
    builder.transport = btn.dataset.transport;
    const sOpts = getSecurityOptions(builder.protocol, builder.transport);
    if (!sOpts.some((x) => x.key === builder.secKey)) builder.secKey = defaultSecurityKey(builder.protocol, builder.transport);
    renderBuilderPills();
    updateBuilderFieldVisibility();
    schedulePreview();
  });
  $('nb-security-pills')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-seckey]');
    if (!btn) return;
    builder.secKey = btn.dataset.seckey;
    $('nb-e-flow').value = getActiveSecurityOpt().flow || '';
    renderBuilderPills();
    updateBuilderFieldVisibility();
    schedulePreview();
  });
  $('nb-mode-seg')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-mode]');
    if (!btn || btn.dataset.mode === builder.mode) return;
    if (builder.mode === 'simplified') syncSimplifiedToExpert();
    else syncExpertToSimplified();
    builder.mode = btn.dataset.mode;
    renderBuilderPills();
    updateBuilderFieldVisibility();
    schedulePreview();
  });
  $('nb-listen-chips')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-listen]');
    if (!btn) return;
    $('nb-e-listen').value = btn.dataset.listen;
    schedulePreview();
  });
  $('nb-s-probe-sni')?.addEventListener('click', () => void probeRealitySNI(true));
  $('nb-e-probe-sni')?.addEventListener('click', () => void probeRealitySNI(true));
  $('nb-s-sni')?.addEventListener('change', () => {
    const v = $('nb-s-sni').value.trim();
    if (v) {
      $('nb-e-sni-select').value = v;
      $('nb-e-server-names').value = v;
      $('nb-e-target').value = `${v}:443`;
    }
    schedulePreview();
  });
  $('nb-e-sni-select')?.addEventListener('change', () => {
    const v = $('nb-e-sni-select').value.trim();
    if (v) {
      $('nb-s-sni').value = v;
      $('nb-e-server-names').value = v;
      $('nb-e-target').value = `${v}:443`;
    }
    schedulePreview();
  });
  $('nb-s-cert-select')?.addEventListener('change', () => onCertSelectChange($('nb-s-cert-select').value));
  $('nb-e-cert-select')?.addEventListener('change', () => onCertSelectChange($('nb-e-cert-select').value));
  $('nb-s-cert-action')?.addEventListener('click', () => void handleCertActionButton());
  $('nb-e-cert-action')?.addEventListener('click', () => void handleCertActionButton());
  $('nb-e-obfs-mode')?.addEventListener('change', () => { updateBuilderFieldVisibility(); schedulePreview(); });
  $('nb-e-flow')?.addEventListener('change', () => {
    const flow = $('nb-e-flow').value;
    if (builder.protocol === 'vless' && builder.transport === 'raw') {
      const secMode = getActiveSecurityOpt().security_mode;
      if (secMode === 'reality') builder.secKey = flow === 'xtls-rprx-vision' ? 'xtls-vision-reality' : 'reality';
      else if (secMode === 'tls') builder.secKey = flow === 'xtls-rprx-vision' ? 'xtls-vision' : 'tls';
      renderBuilderPills();
    }
    schedulePreview();
  });

  $('nb-gen-uuid')?.addEventListener('click', () => { $('nb-e-uuid').value = genUUID(); schedulePreview(); });
  $('nb-gen-pass')?.addEventListener('click', () => {
    const len = builder.protocol === 'socks5' || builder.protocol === 'http' ? 16 : 24;
    $('nb-e-password').value = genAlphaNum(len);
    $('nb-s-password').value = $('nb-e-password').value;
    schedulePreview();
  });
  $('nb-gen-skey')?.addEventListener('click', () => { $('nb-e-server-key').value = genSS2022Key($('nb-e-method').value); schedulePreview(); });
  $('nb-gen-ukey')?.addEventListener('click', () => { $('nb-e-user-key').value = genSS2022Key($('nb-e-method').value); schedulePreview(); });
  $('nb-gen-shortid')?.addEventListener('click', () => { $('nb-e-short-id').value = genShortIdHex(4); schedulePreview(); });
  $('nb-gen-obfspass')?.addEventListener('click', () => { $('nb-e-obfs-pass').value = genAlphaNum(20); schedulePreview(); });
  $('nb-reset-padding')?.addEventListener('click', () => { $('nb-e-padding').value = DEFAULT_ANYTLS_PADDING.join('\n'); schedulePreview(); });

  const builderLeft = document.querySelector('#node-builder-modal .builder-left');
  builderLeft?.addEventListener('input', (e) => {
    if (e.target.id === 'nb-s-method') $('nb-e-method').value = e.target.value;
    if (e.target.id === 'nb-e-method') $('nb-s-method').value = e.target.value;
    schedulePreview();
  });
  builderLeft?.addEventListener('change', (e) => {
    if (e.target.id === 'nb-s-method') $('nb-e-method').value = e.target.value;
    if (e.target.id === 'nb-e-method') $('nb-s-method').value = e.target.value;
    schedulePreview();
  });

  $('nb-preview-tabs')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    builder.previewTab = btn.dataset.tab;
    for (const b of document.querySelectorAll('#nb-preview-tabs button')) b.classList.toggle('active', b.dataset.tab === builder.previewTab);
    renderBuilderPreview();
  });
  $('nb-preview-copy')?.addEventListener('click', () => void hostCopy($('nb-preview-code').textContent, '已复制节点预览内容'));
  $('nb-save')?.addEventListener('click', async () => {
    const saveBtn = $('nb-save');
    saveBtn.disabled = true;
    try {
      const payload = buildDraftPayload();
      const r = await runAction(builder.editingId ? `更新节点 ${builder.editingId}` : '创建并应用代理节点', () => invoke('nodes.upsert', payload));
      if (!r) return;
      const saved = r.node || {};
      const syncText = r.core_synced ? `已同步内置 Xray${r.core_revision ? ` (${r.core_revision})` : ''}` : (r.core_sync_note || '已保存到节点库');
      showBanner(`${r.created ? '已创建' : '已更新'}节点「${saved.name || saved.id}」(${(saved.protocol || payload.protocol).toUpperCase()} :${saved.port || ''}) · ${syncText}`, r.core_synced ? 'ok' : 'warn');
      closeNodeBuilder();
      void refreshNodes();
    } finally {
      saveBtn.disabled = false;
    }
  });

  // WARP 与链式代理弹窗事件
  $('btn-w-preset-ai')?.addEventListener('click', () => appendWARPPreset('ai'));
  $('btn-w-preset-stream')?.addEventListener('click', () => appendWARPPreset('streaming'));
  $('btn-w-preset-google')?.addEventListener('click', () => appendWARPPreset('google'));
  $('btn-warp-register')?.addEventListener('click', async () => {
    const r = await runAction('一键注册 Cloudflare WARP', () => invoke('warp.register', {
      license_key: $('w-license').value.trim(),
      endpoint: $('w-endpoint').value.trim(),
      mtu: Number($('w-mtu').value) || 1280,
      enabled: $('w-enabled').checked,
      routing_mode: $('w-mode').value,
      bound_profile_ids: readSelectedWARPPorts(),
      domains: readWARPDomainsInput(),
      sync_core: true,
    }));
    if (r) {
      $('w-license').value = '';
      showBanner(r.sync_warning ? `WARP 注册成功，提示：${r.sync_warning}` : `Cloudflare WARP 注册成功并已同步 Xray（${r.warp?.address_v4 || ''}）`, r.sync_warning ? 'warn' : 'ok');
      void refreshChains();
    }
  });
  $('btn-warp-save')?.addEventListener('click', async () => {
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
        if (/^\d+(,\s*\d+){2,3}$/.test(cid)) payload.reserved = cid.split(',').map((n) => Number(n.trim()));
        else payload.client_id = cid;
      }
    }
    const r = await runAction('保存 WARP 绑定并同步 Xray', () => invoke('warp.configure', payload));
    if (r) {
      $('w-manual-priv').value = '';
      showBanner(r.sync_warning ? `WARP 配置已保存，提示：${r.sync_warning}` : 'WARP 绑定与分流规则已同步生效', r.sync_warning ? 'warn' : 'ok');
      void refreshChains();
    }
  });
  $('btn-warp-probe')?.addEventListener('click', async () => {
    const r = await runAction('探测 WARP 端点与本机 IP', () => invoke('warp.probe', {}));
    if (r) {
      if (r.best_endpoint) $('w-endpoint').value = r.best_endpoint;
      const pre = $('warp-output');
      pre.textContent = JSON.stringify(r, null, 2);
      pre.classList.remove('hidden');
      const tr = r.host_trace || {};
      showBanner(`探测完成：推荐端点 ${r.best_endpoint || '无'} · 本机出口 ${tr.ip || '未知'} (${tr.loc || '-'})`, r.best_endpoint ? 'ok' : 'warn');
    }
  });
  $('btn-warp-preview')?.addEventListener('click', () => {
    const pre = $('warp-output');
    pre.textContent = cachedWARP?.xray_preview_json || '{}';
    pre.classList.remove('hidden');
  });
  $('btn-warp-delete')?.addEventListener('click', async () => {
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

  $('btn-chain-add')?.addEventListener('click', () => openChainEditModal(null));
  $('ce-close')?.addEventListener('click', closeChainEditModal);
  $('ce-cancel')?.addEventListener('click', closeChainEditModal);
  $('chain-edit-modal')?.addEventListener('click', (e) => { if (e.target === $('chain-edit-modal')) closeChainEditModal(); });
  $('btn-chain-save')?.addEventListener('click', async () => {
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
      closeChainEditModal();
      showBanner(`链式代理节点 ${r.chain?.id || payload.id} 已加密保存`, 'ok');
      void refreshChains();
    }
  });
  $('btn-chain-preview')?.addEventListener('click', async () => {
    const r = await runAction('预览 Xray 服务端链式出口', () => invoke('chains.preview', {}));
    if (r) {
      const pre = $('chain-xray-preview');
      pre.textContent = r.xray_json || '{}';
      pre.classList.remove('hidden');
    }
  });

  // tcpfit 与 Brutal 弹窗事件
  function readTcpfitInput() {
    return {
      role: $('t-role').value,
      bandwidth_mbps: Number($('t-bw').value) || 200,
      rtt_ms: Number($('t-rtt').value) || 150,
      mem_budget_pct: Number($('t-mem-pct').value) || 12,
      prefer_cc: $('t-prefer-cc').value,
    };
  }
  $('btn-tuning-plan')?.addEventListener('click', async () => {
    const r = await runAction('推导 tcpfit 调优方案', () => invoke('tuning.plan', readTcpfitInput()));
    if (r) {
      renderTuningPlan(r);
      showBanner('已完成 tcpfit 动态 BDP 与安全内存预算推导', 'ok');
    }
  });
  $('btn-tuning-dry')?.addEventListener('click', async () => {
    const r = await runAction('tcpfit 演练与基线保存', () => invoke('tuning.apply', { ...readTcpfitInput(), dry_run: true }));
    if (r) {
      if (r.plan) renderTuningPlan(r.plan);
      showBanner(r.output || '已完成演练并保存宿主机基线快照', 'ok');
      void refreshTuningAndBrutal();
    }
  });
  $('btn-tuning-apply')?.addEventListener('click', async () => {
    const ok = await hostConfirm({
      title: '应用 tcpfit 内核调优',
      body: '确认将 tcpfit 参数写入 /etc/sysctl.d/99-qwq-tcpfit.conf 并执行 sysctl -p？应用前会自动保留可回滚基线快照。',
      confirmLabel: '确认应用',
      danger: true,
    });
    if (!ok) return;
    const r = await runAction('应用 tcpfit 调优到宿主机', () => invoke('tuning.apply', { ...readTcpfitInput(), dry_run: false }));
    if (r) {
      if (r.plan) renderTuningPlan(r.plan);
      showBanner(r.applied ? '已成功应用 tcpfit 内核调优并保存基线快照' : `写入提示：${r.error || r.output}`, r.applied ? 'ok' : 'warn');
      void refreshTuningAndBrutal();
    }
  });
  $('btn-tuning-sweep')?.addEventListener('click', async () => {
    const r = await runAction('运行 iperf3 探测', () => invoke('tuning.sweep', {
      peer_host: $('sw-host').value.trim(),
      peer_port: Number($('sw-port').value) || 5201,
      duration_sec: Number($('sw-dur').value) || 5,
    }));
    if (r) {
      const pre = $('t-sweep-out');
      pre.textContent = JSON.stringify(r, null, 2);
      pre.classList.remove('hidden');
      showBanner(r.iperf3_available ? (r.advice || 'iperf3 探测完成') : (r.reason || '宿主机未安装 iperf3'), r.iperf3_available && r.ok ? 'ok' : 'warn');
    }
  });

  $('btn-brutal-add')?.addEventListener('click', () => openBrutalEditModal(null));
  $('be-close')?.addEventListener('click', closeBrutalEditModal);
  $('be-cancel')?.addEventListener('click', closeBrutalEditModal);
  $('brutal-edit-modal')?.addEventListener('click', (e) => { if (e.target === $('brutal-edit-modal')) closeBrutalEditModal(); });
  $('b-inbound-preset')?.addEventListener('change', () => {
    const found = cachedInbounds.find((ib) => ib.inbound_tag === $('b-inbound-preset').value);
    if (!found) return;
    if (!brutalEditModal.editingId) $('b-id').value = `brutal-${found.inbound_tag}`;
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
  $('b-oversend')?.addEventListener('input', updateOversendPreview);
  $('b-bw')?.addEventListener('input', updateOversendPreview);
  $('btn-brutal-save')?.addEventListener('click', async () => {
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
      closeBrutalEditModal();
      showBanner(`已保存 ${r.binding?.id || payload.id}（超发 ${r.binding?.oversend_pct ?? payload.oversend_pct}%），请点击「热重载所有接管端口」生效。`, 'ok');
      void refreshTuningAndBrutal();
    }
  });
  $('btn-brutal-apply')?.addEventListener('click', async () => {
    const r = await runAction('热重载 Brutal 接管端口', () => invoke('brutal.apply', {}));
    if (r) {
      showBanner(r.applied ? `已热重载 ${(r.live_listeners || []).length} 个透明接管端口` : `部分监听异常：${r.error}`, r.applied ? 'ok' : 'warn');
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

      if (valDesc?.get && valDesc?.set) {
        Object.defineProperty(sel, 'value', {
          configurable: true,
          get() { return valDesc.get.call(this); },
          set(v) { valDesc.set.call(this, v); sync(); },
        });
      }
      if (idxDesc?.get && idxDesc?.set) {
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
          wrap.classList.toggle('drop-up', (window.innerHeight - rect.bottom) < 220 && rect.top > 200);
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
      new MutationObserver(sync).observe(sel, { childList: true, subtree: true, attributes: true, characterData: true });
      sync();
    }

    document.querySelectorAll('select').forEach(enhanceSelect);
    new MutationObserver((muts) => {
      for (const m of muts) {
        for (const node of m.addedNodes) {
          if (node.nodeType !== 1) continue;
          if (node.tagName === 'SELECT') enhanceSelect(node);
          else if (node.querySelectorAll) node.querySelectorAll('select').forEach(enhanceSelect);
        }
      }
    }).observe(document.body, { childList: true, subtree: true });

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
    if (brutalEditModal.open) closeBrutalEditModal();
    else if (chainEditModal.open) closeChainEditModal();
    else if (planEditModal.open) closePlanEditModal();
    else if (userEditModal.open) closeUserEditModal();
    else if (userSubModal.open) closeUserSubModal();
    else if (userHistoryModal.open) closeUserHistoryModal();
    else if (userCreateModal.open) closeUserCreateModal();
    else if (configViewer.open) closeConfigViewer();
    else if (builder.open) closeNodeBuilder();
  });

  // ==================== 初始化、自适应高度与宿主桥接 ====================

  initThemedSelects();
  renderFlagChips('nb-s-flag-chips', 'nb-s-name');
  renderFlagChips('nb-e-flag-chips', 'nb-e-name');
  switchRoute(activeRoute, false);
  updateOversendPreview();
  populateSNISelects(DEFAULT_SNI_CANDIDATES[0]);

  let hostViewportTop = 0;
  let lastSentHeight = 0;
  const MODAL_BACKDROP_IDS = [
    'brutal-edit-modal',
    'chain-edit-modal',
    'plan-edit-modal',
    'user-edit-modal',
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
    for (const req of pendingEnsure.values()) {
      clearTimeout(req.timer);
      req.resolve({ ok: false });
    }
    pendingEnsure.clear();
    port?.close();
    port = undefined;
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
