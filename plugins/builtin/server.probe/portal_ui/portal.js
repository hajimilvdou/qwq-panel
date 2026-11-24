// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const root = document.documentElement;
  let view = 'orb-cards';
  let userPickedView = false;
  let visitorToken = '';
  let snapshot = { nodes: [], service_monitors: [] };
  let lastBgURL = '';
  let lastLqip = '';
  let lastCustomCSS = '';
  let pointerRaf = 0;

  const scriptSrc = document.currentScript?.src || '';
  const portalRoot = (() => {
    if (scriptSrc) {
      try {
        const u = new URL(scriptSrc, window.location.href);
        return u.pathname.replace(/\/portal\.js$/i, '').replace(/\/+$/, '');
      } catch {
        // fallback below
      }
    }
    return window.location.pathname.replace(/\/index\.html$/i, '').replace(/\/+$/, '');
  })();

  function resolvePortalPath(sub) {
    const suffix = String(sub || '').replace(/^\/+/, '');
    return `${portalRoot}/${suffix}`;
  }

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

  function fmtBps(bps) {
    const mbps = Number(bps || 0) / 1e6;
    if (mbps >= 1000) return (mbps / 1000).toFixed(2) + ' Gbps';
    return mbps.toFixed(2) + ' Mbps';
  }

  function applyCustomCSS(cssText) {
    const next = typeof cssText === 'string' ? cssText : '';
    if (next === lastCustomCSS) return;
    lastCustomCSS = next;
    let el = document.getElementById('probe-custom-css');
    if (!next.trim()) {
      if (el) el.remove();
      return;
    }
    if (!el) {
      el = document.createElement('style');
      el.id = 'probe-custom-css';
      document.head.appendChild(el);
    }
    el.textContent = next;
  }

  function resolveGlassTint(app) {
    const pref = app.glass_tint || 'auto';
    if (pref === 'light' || pref === 'dark') return pref;
    const bg = app.background || {};
    if (bg.mode && bg.mode !== 'none' && Number.isFinite(bg.luminance) && bg.luminance >= 0) {
      return bg.luminance > 145 ? 'light' : 'dark';
    }
    return root.dataset.theme === 'dark' ? 'dark' : 'light';
  }

  function applyWallpaper(bgUrl, bgCfg) {
    const lqipImg = $('bg-lqip');
    const hdImg = $('bg-hd');
    const lqip = (bgCfg && typeof bgCfg.lqip_data_url === 'string' && bgCfg.lqip_data_url.startsWith('data:image/'))
      ? bgCfg.lqip_data_url
      : '';

    if (!bgUrl) {
      lastBgURL = '';
      lastLqip = '';
      lqipImg.hidden = true;
      lqipImg.removeAttribute('src');
      hdImg.hidden = true;
      hdImg.classList.remove('is-loaded');
      hdImg.removeAttribute('src');
      return;
    }

    if (lqip && lqip !== lastLqip) {
      lastLqip = lqip;
      lqipImg.src = lqip;
      lqipImg.hidden = false;
    } else if (!lqip) {
      lastLqip = '';
      lqipImg.hidden = true;
    }

    if (bgUrl !== lastBgURL) {
      lastBgURL = bgUrl;
      hdImg.classList.remove('is-loaded');
      hdImg.hidden = false;
      const resolved = bgUrl.startsWith('./') ? resolvePortalPath(bgUrl.slice(2)) : bgUrl;
      hdImg.onload = () => {
        const done = () => {
          hdImg.classList.add('is-loaded');
        };
        if (typeof hdImg.decode === 'function') {
          hdImg.decode().then(done).catch(done);
        } else {
          done();
        }
      };
      hdImg.onerror = () => {
        hdImg.hidden = true;
        hdImg.classList.remove('is-loaded');
        lqipImg.hidden = true;
      };
      hdImg.src = resolved;
    }
  }

  function applyAppearance(snap) {
    const activeTheme = snap.active_theme || 'builtin:classic';
    const isLiquid = activeTheme === 'builtin:liquid-glass';
    root.dataset.style = isLiquid ? 'liquid-glass' : 'classic';

    const app = snap.appearance || {};
    const opacity = Number.isFinite(app.glass_opacity) ? app.glass_opacity : 0.26;
    const blurPx = Number.isFinite(app.glass_blur_px) ? app.glass_blur_px : 20;
    const veil = Number.isFinite(app.veil_opacity) ? app.veil_opacity : 0.22;
    const bg = app.background || {};
    const fx = Number.isFinite(bg.focal_x) ? bg.focal_x : 50;
    const fy = Number.isFinite(bg.focal_y) ? bg.focal_y : 50;

    root.dataset.glassTint = resolveGlassTint(app);
    root.dataset.motion = app.motion_enabled === false ? 'off' : 'on';

    root.style.setProperty('--glass-opacity', String(opacity));
    root.style.setProperty('--glass-blur', `${blurPx}px`);
    root.style.setProperty('--veil-opacity', String(veil));
    root.style.setProperty('--bg-fx', `${fx}%`);
    root.style.setProperty('--bg-fy', `${fy}%`);
    if (app.accent_color) {
      root.style.setProperty('--accent', app.accent_color);
    } else {
      root.style.removeProperty('--accent');
    }

    if (isLiquid) {
      applyWallpaper(snap.bg_url || '', bg);
    } else {
      applyWallpaper('', null);
    }
    applyCustomCSS(app.custom_css || '');

    const allowTheme = snap.allow_theme !== false;
    $('theme-toggle').hidden = !allowTheme;
  }

  function buildSLABars(ribbon) {
    const list = Array.isArray(ribbon) ? ribbon.slice(-45) : [];
    const pad = Math.max(0, 45 - list.length);
    const out = [];
    for (let i = 0; i < pad; i++) {
      out.push('<i class="sla-empty" title="暂无记录"></i>');
    }
    for (const b of list) {
      const pct = Number(b.uptime_pct ?? 100);
      let cls = '';
      if (pct < 95) cls = 'sla-down';
      else if (pct < 99.5) cls = 'sla-warn';
      out.push(`<i class="${cls}" title="${esc(b.day)}: ${pct.toFixed(2)}%"></i>`);
    }
    return out.join('');
  }

  async function loadPublic() {
    try {
      const headers = {};
      if (visitorToken) headers['X-Probe-Visitor-Token'] = visitorToken;
      const resp = await fetch(resolvePortalPath('api/public/snapshot'), { headers });
      if (resp.status === 423) {
        const locked = await resp.json().catch(() => ({}));
        if (locked.site_title) $('site-title').textContent = locked.site_title;
        if (locked.message) $('visitor-lock-msg').textContent = locked.message;
        $('visitor-lock-modal').hidden = false;
        return;
      }
      if (!resp.ok) return;
      $('visitor-lock-modal').hidden = true;
      snapshot = await resp.json();
      if (snapshot.site_title) {
        $('site-title').textContent = snapshot.site_title;
        document.title = snapshot.site_title;
      }
      if (snapshot.site_subtitle) $('site-sub').textContent = snapshot.site_subtitle;
      if (snapshot.banner_text) $('banner-text').textContent = snapshot.banner_text;
      if (snapshot.banner_level) $('status-banner').dataset.level = snapshot.banner_level;
      if (!userPickedView && snapshot.default_view) {
        view = snapshot.default_view;
        document.querySelectorAll('[data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
      }
      applyAppearance(snapshot);
      renderShowcase();
    } catch {
      // 网络抖动时保持上一帧状态
    }
  }

  function renderShowcase() {
    const nodes = Array.isArray(snapshot.nodes) ? snapshot.nodes : [];
    const online = nodes.filter((n) => n.online).length;
    $('fleet-summary').textContent = `在线 ${online} / ${nodes.length} 台`;

    $('tty-container').hidden = view !== 'tty-terminal';
    $('nodes-container').hidden = view === 'tty-terminal';
    $('nodes-container').classList.toggle('compact-list', view === 'compact-list');

    if (view === 'tty-terminal') {
      if (!$('tty-output').textContent) {
        $('tty-output').textContent = 'qwq-probe Monitor TTY v1.0 (read-only sandbox)\nType "help", "ls", "top", "admin", or "clear".\n';
      }
      return;
    }

    if (nodes.length === 0) {
      $('nodes-container').innerHTML = '<div class="card empty-state">暂无公开展示节点，请前往管理后台添加或同步服务器。</div>';
      return;
    }

    $('nodes-container').innerHTML = nodes.map((n) => {
      const cpu = Number(n.live?.cpu_pct || 0).toFixed(1);
      const memPct = n.mem_total_bytes
        ? ((Number(n.live?.mem_used_bytes || 0) / n.mem_total_bytes) * 100).toFixed(1)
        : '0.0';
      const rx = fmtBps(n.live?.net_rx_bps);
      const tx = fmtBps(n.live?.net_tx_bps);
      const quotaText = `${fmtBytes(n.quota_used_bytes)} / ${n.quota_bytes ? fmtBytes(n.quota_bytes) : '不限'}`;
      const stateCls = n.online ? '' : ' offline';
      const stateText = n.online ? '● 在线' : '○ 离线';
      const rawSla = Number(n.uptime_90d_pct);
      const slaText = Number.isFinite(rawSla) && rawSla >= 0 ? `${rawSla.toFixed(2)}%` : '—';
      const bars = buildSLABars(n.sla_ribbon);
      return `<article class="card">
        <div class="card-head">
          <div class="node-title">
            <span class="region-tag">${esc(n.region_code || 'UN')}</span>
            <span>${esc(n.name)}</span>
          </div>
          <span class="state-pill${stateCls}">${stateText} · ${slaText}</span>
        </div>
        <div class="metric-grid">
          <div class="metric-chip">
            <span class="metric-label">CPU 占用</span>
            <span class="metric-val">${cpu}%</span>
          </div>
          <div class="metric-chip">
            <span class="metric-label">内存使用</span>
            <span class="metric-val">${memPct}%</span>
          </div>
          <div class="metric-chip">
            <span class="metric-label">实时下行 / 上行</span>
            <span class="metric-val">↓ ${rx} / ↑ ${tx}</span>
          </div>
          <div class="metric-chip">
            <span class="metric-label">月流量配额</span>
            <span class="metric-val">${esc(quotaText)}</span>
          </div>
        </div>
        <div class="node-meta">
          <span>${esc(n.os_name || n.virt_type || 'Linux')} ${n.cpu_cores ? '· ' + esc(n.cpu_cores) + 'C' : ''}</span>
          <span>${n.billing_badge ? esc(n.billing_badge) : esc(n.group_name || '')}</span>
        </div>
        <div class="sla-bar" aria-label="近期在线率状态条">${bars}</div>
      </article>`;
    }).join('');
  }

  // 独立 /admin 隔离入口链接标准化（同时兼容 /p/server.probe/portal 与独立域名）
  const adminHref = resolvePortalPath('admin');
  $('admin-switch-btn').setAttribute('href', adminHref);
  $('lock-admin-link').setAttribute('href', adminHref);

  document.querySelectorAll('[data-view]').forEach((btn) => {
    btn.addEventListener('click', () => {
      view = btn.dataset.view;
      userPickedView = true;
      document.querySelectorAll('[data-view]').forEach((b) => b.classList.toggle('active', b === btn));
      renderShowcase();
    });
  });

  $('theme-toggle').addEventListener('click', () => {
    const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    applyAppearance(snapshot);
  });

  $('visitor-lock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('visitor-lock-err').hidden = true;
    const password = $('visitor-password').value;
    const resp = await fetch(resolvePortalPath('api/public/unlock'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    if (!resp.ok) {
      $('visitor-lock-err').textContent = '访客口令不正确，请重试。';
      $('visitor-lock-err').hidden = false;
      return;
    }
    const data = await resp.json();
    visitorToken = data.visitor_token || '';
    $('visitor-password').value = '';
    $('visitor-lock-modal').hidden = true;
    void loadPublic();
  });

  $('tty-input').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const cmd = $('tty-input').value.trim();
    $('tty-input').value = '';
    let out = `\n$ ${cmd}\n`;
    if (cmd === 'help') out += 'Commands: ls, top, ping, admin, clear\n';
    else if (cmd === 'clear') { $('tty-output').textContent = ''; return; }
    else if (cmd === 'admin' || cmd === 'login') {
      window.location.href = adminHref;
      return;
    } else if (cmd === 'ls' || cmd === 'top') {
      out += (snapshot.nodes || []).map((n) => `${String(n.id || '').padEnd(14)} [${n.region_code}] CPU:${Number(n.live?.cpu_pct || 0).toFixed(1)}% UP:${n.online}`).join('\n') + '\n';
    } else if (cmd === 'ping') {
      out += (snapshot.nodes || []).map((n) => `${String(n.id || '').padEnd(14)} CT:${n.live?.carrier_ping_ms?.ct ?? '-'}ms CU:${n.live?.carrier_ping_ms?.cu ?? '-'}ms CM:${n.live?.carrier_ping_ms?.cm ?? '-'}ms`).join('\n') + '\n';
    } else {
      out += `Unknown command: ${cmd} (type help)\n`;
    }
    $('tty-output').textContent += out;
  });

  // 水玻璃指针跟随微光折射（仅 Liquid Glass + 动效开启时生效）
  document.addEventListener('pointermove', (e) => {
    if (root.dataset.style !== 'liquid-glass' || root.dataset.motion !== 'on') return;
    const card = e.target && e.target.closest ? e.target.closest('.card, .topbar') : null;
    if (!card || pointerRaf) return;
    pointerRaf = requestAnimationFrame(() => {
      pointerRaf = 0;
      const rect = card.getBoundingClientRect();
      card.style.setProperty('--mx', `${Math.round(e.clientX - rect.left)}px`);
      card.style.setProperty('--my', `${Math.round(e.clientY - rect.top)}px`);
    });
  }, { passive: true });

  window.addEventListener('keydown', (e) => {
    if (e.altKey && (e.key === 'm' || e.key === 'M')) {
      e.preventDefault();
      window.location.href = adminHref;
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
