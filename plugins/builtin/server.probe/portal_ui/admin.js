// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const root = document.documentElement;
  const TOKEN_KEY = 'qwq_probe_admin_token';

  const scriptSrc = document.currentScript?.src || '';
  const adminBase = (() => {
    if (scriptSrc) {
      try {
        const u = new URL(scriptSrc, window.location.href);
        return u.pathname.replace(/\/(?:admin\/)?admin\.js$/i, '').replace(/\/+$/, '');
      } catch {
        // fallback below
      }
    }
    return window.location.pathname.replace(/\/admin(?:\/.*)?$/, '').replace(/\/+$/, '');
  })();
  const apiUrl = (p) => `${adminBase}${p}`;
  const portalHref = adminBase ? `${adminBase}/` : '/';

  let adminToken = sessionStorage.getItem(TOKEN_KEY) || '';
  let state = {
    active_theme_id: 'builtin:classic',
    themes: [],
    appearance: {
      glass_opacity: 0.26,
      glass_blur_px: 20,
      glass_tint: 'auto',
      veil_opacity: 0.22,
      motion_enabled: true,
      accent_color: '',
      custom_css: '',
      background: { mode: 'none', focal_x: 50, focal_y: 50, luminance: -1 }
    },
    theme_settings: {},
    bg_url: '',
    nodes: [],
    settings: {}
  };
  let toastTimer = 0;

  $('back-portal-link').setAttribute('href', portalHref);

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function showToast(msg, isErr = false) {
    const bar = $('toast-bar');
    bar.textContent = msg;
    bar.classList.toggle('is-error', Boolean(isErr));
    bar.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { bar.hidden = true; }, 4500);
  }

  function fmtKB(bytes) {
    const kb = Number(bytes || 0) / 1024;
    if (kb >= 1024) return (kb / 1024).toFixed(2) + ' MB';
    return Math.max(1, Math.round(kb)) + ' KB';
  }

  async function apiFetch(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    if (adminToken) headers['X-Probe-Admin-Token'] = adminToken;
    const resp = await fetch(apiUrl(path), Object.assign({}, opts, { headers }));
    if (resp.status === 401) {
      adminToken = '';
      sessionStorage.removeItem(TOKEN_KEY);
      renderAuthView();
      throw new Error('管理员会话已过期，请重新登录');
    }
    const contentType = resp.headers.get('Content-Type') || '';
    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`;
      if (contentType.includes('application/json')) {
        const j = await resp.json().catch(() => ({}));
        detail = j.error || detail;
      }
      throw new Error(detail);
    }
    if (contentType.includes('application/json')) return resp.json();
    return resp;
  }

  function renderAuthView() {
    const unlocked = Boolean(adminToken);
    $('login-view').hidden = unlocked;
    $('console-view').hidden = !unlocked;
    $('logout-btn').hidden = !unlocked;
  }

  async function loadAdminState() {
    if (!adminToken) {
      renderAuthView();
      return;
    }
    try {
      const data = await apiFetch('/api/admin/state');
      state = Object.assign({}, state, data);
      renderAuthView();
      renderThemes();
      renderAppearanceControls();
      renderNodes();
      renderSiteAndDomain();
    } catch (err) {
      showToast(err.message || '加载后台状态失败', true);
    }
  }

  function renderThemes() {
    const list = Array.isArray(state.themes) ? state.themes : [];
    const activeId = state.active_theme_id || 'builtin:classic';
    $('theme-list').innerHTML = list.map((t) => {
      const isActive = t.id === activeId;
      const tagText = isActive ? '当前启用' : (t.builtin ? '官方内置' : '自定义包');
      const tagCls = isActive ? 'theme-tag active' : 'theme-tag';
      const delBtn = t.builtin
        ? ''
        : `<button type="button" class="btn danger" data-delete-theme="${esc(t.id)}">删除</button>`;
      return `<div class="theme-card${isActive ? ' is-active' : ''}">
        <div>
          <div class="theme-card-top">
            <strong>${esc(t.name)}</strong>
            <span class="${tagCls}">${tagText}</span>
          </div>
          <div class="theme-meta">ID: <code>${esc(t.id)}</code> · v${esc(t.version || '1.0.0')} · ${esc(t.author || 'unknown')}</div>
          <p class="muted small">${esc(t.description || '无描述')}</p>
        </div>
        <div class="theme-actions">
          ${delBtn}
          <button type="button" class="btn ${isActive ? 'ghost' : 'primary'}" data-activate-theme="${esc(t.id)}" ${isActive ? 'disabled' : ''}>
            ${isActive ? '已启用' : '启用此主题'}
          </button>
        </div>
      </div>`;
    }).join('');

    const activeTheme = list.find((t) => t.id === activeId);
    const schema = activeTheme && Array.isArray(activeTheme.settings_schema) ? activeTheme.settings_schema : [];
    const tsCard = $('theme-settings-card');
    if (schema.length === 0) {
      tsCard.hidden = true;
      $('theme-settings-form').innerHTML = '';
      return;
    }
    tsCard.hidden = false;
    const vals = state.theme_settings || {};
    $('theme-settings-form').innerHTML = schema.map((f) => {
      const cur = vals[f.key] !== undefined ? vals[f.key] : f.default;
      if (f.type === 'boolean') {
        return `<label class="field check-box-card">
          <input type="checkbox" data-ts-key="${esc(f.key)}" data-ts-type="boolean" ${cur ? 'checked' : ''}>
          <span>${esc(f.label)}</span>
        </label>`;
      }
      if (f.type === 'select' && Array.isArray(f.options)) {
        const opts = f.options.map((o) => `<option value="${esc(o)}" ${String(cur ?? '') === String(o) ? 'selected' : ''}>${esc(o)}</option>`).join('');
        return `<label class="field"><span>${esc(f.label)}</span><select data-ts-key="${esc(f.key)}" data-ts-type="select">${opts}</select></label>`;
      }
      const inputType = f.type === 'color' ? 'color' : (f.type === 'number' ? 'number' : 'text');
      const fallback = f.type === 'color' ? '#38bdf8' : '';
      return `<label class="field">
        <span>${esc(f.label)}</span>
        <input type="${inputType}" data-ts-key="${esc(f.key)}" data-ts-type="${esc(f.type)}" value="${esc(cur ?? fallback)}">
      </label>`;
    }).join('');
  }

  function updateMiniPreview() {
    const stage = $('mini-preview-stage');
    const opacity = Number($('opt-glass-opacity').value) / 100;
    const blur = Number($('opt-glass-blur').value);
    const veil = Number($('opt-veil-opacity').value) / 100;
    const tintPref = $('opt-glass-tint').value;
    const lum = state.appearance?.background?.luminance ?? -1;
    const resolvedTint = tintPref === 'auto'
      ? (lum > 145 ? 'light' : 'dark')
      : tintPref;

    $('val-glass-opacity').textContent = `${Math.round(opacity * 100)}%`;
    $('val-glass-blur').textContent = `${blur}px`;
    $('val-veil-opacity').textContent = `${Math.round(veil * 100)}%`;

    stage.style.setProperty('--pv-opacity', String(opacity));
    stage.style.setProperty('--pv-blur', `${blur}px`);
    stage.style.setProperty('--pv-veil', String(veil));
    stage.style.setProperty('--pv-rgb', resolvedTint === 'light' ? '255, 255, 255' : '15, 23, 42');
    stage.style.setProperty('--pv-text', resolvedTint === 'light' ? '#101828' : '#f8fafc');
  }

  function renderAppearanceControls() {
    const app = state.appearance || {};
    const bg = app.background || {};
    $('opt-glass-opacity').value = String(Math.round((app.glass_opacity ?? 0.26) * 100));
    $('opt-glass-blur').value = String(app.glass_blur_px ?? 20);
    $('opt-veil-opacity').value = String(Math.round((app.veil_opacity ?? 0.22) * 100));
    $('opt-glass-tint').value = app.glass_tint || 'auto';
    $('opt-motion-enabled').checked = app.motion_enabled !== false;
    $('opt-accent-enable').checked = Boolean(app.accent_color);
    if (app.accent_color) $('opt-accent-color').value = app.accent_color;
    $('opt-custom-css').value = app.custom_css || '';
    $('bg-external-url').value = bg.external_url || '';

    const fx = String(bg.focal_x ?? 50);
    const fy = String(bg.focal_y ?? 50);
    const prevImg = $('bg-preview-img');
    prevImg.dataset.fx = fx;
    prevImg.dataset.fy = fy;
    if (state.bg_url) {
      prevImg.src = state.bg_url.startsWith('./') ? apiUrl('/' + state.bg_url.slice(2)) : state.bg_url;
      prevImg.hidden = false;
    } else if (bg.lqip_data_url) {
      prevImg.src = bg.lqip_data_url;
      prevImg.hidden = false;
    } else {
      prevImg.hidden = true;
      prevImg.removeAttribute('src');
    }

    document.querySelectorAll('#focal-grid .focal-dot').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.fx === fx && btn.dataset.fy === fy);
    });
    updateMiniPreview();
  }

  function renderNodes() {
    const nodes = Array.isArray(state.nodes) ? state.nodes : [];
    $('adm-nodes-list').innerHTML = nodes.map((n) => {
      const quotaGB = n.QuotaBytes ? `${Math.round(Number(n.QuotaBytes) / (1024 ** 3))} GB` : '不限';
      const expStr = n.ExpiresAt ? new Date(Number(n.ExpiresAt) * 1000).toISOString().slice(0, 10) : '长期';
      return `<div class="node-item">
        <div>
          <strong>[${esc(n.RegionCode || 'UN')}] ${esc(n.Name)}</strong>
          <div class="muted small">ID: <code>${esc(n.ID)}</code> · 状态: ${esc(n.OnlineState || 'pending')}</div>
          <div class="muted small">配额: ${esc(quotaGB)} (${esc(n.QuotaMode || 'both')}) · 重置日: ${Number(n.ResetDay || 1)} · 到期: ${esc(expStr)}</div>
        </div>
        <div class="row-gap">
          <button type="button" class="btn ghost" data-adm-edit-node="${esc(n.ID)}">编辑</button>
          ${n.IsLocal ? '' : `<button type="button" class="btn danger" data-adm-del-node="${esc(n.ID)}">删除</button>`}
        </div>
      </div>`;
    }).join('') || '<p class="muted">暂无节点</p>';
  }

  function renderSiteAndDomain() {
    const s = state.settings || {};
    $('set-site-title').value = s.site_title || '';
    $('set-site-sub').value = s.site_subtitle || '';
    $('set-default-view').value = s.default_view || 'orb-cards';
    $('set-mask-ip').checked = s.mask_node_ip !== false;
    $('set-expose-billing').checked = s.expose_billing_cost !== false;
    $('set-expose-isp').checked = s.expose_isp_carrier !== false;

    $('standalone-dnc-msg').textContent = state.dnc_capabilities?.fallback_reason || '已连接面板域名/证书能力';
    if (s.custom_domain) $('adm-domain').value = s.custom_domain;
    if (s.binding_track) $('adm-track').value = s.binding_track;
    if (s.builtin_acme_email) $('adm-email').value = s.builtin_acme_email;
    if (state.proxy_snippets?.nginx_baota_conf) {
      $('adm-snippet').hidden = false;
      $('adm-snippet').textContent = state.proxy_snippets.nginx_baota_conf;
    }
  }

  // ===== 3A 浏览器端 Canvas 智能背景优化器 =====
  function readFileAsDataURL(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(String(fr.result || ''));
      fr.onerror = () => reject(new Error('文件读取失败'));
      fr.readAsDataURL(file);
    });
  }

  function blobToDataURL(blob) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(String(fr.result || ''));
      fr.onerror = () => reject(new Error('转码结果读取失败'));
      fr.readAsDataURL(blob);
    });
  }

  function loadImageFromURL(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('无法解码所选图片，请确认是有效的 JPG/PNG/WebP'));
      img.src = src;
    });
  }

  function encodeCanvasBest(canvas) {
    return new Promise((resolve, reject) => {
      canvas.toBlob((webpBlob) => {
        if (webpBlob && webpBlob.type === 'image/webp' && webpBlob.size > 0) {
          resolve({ blob: webpBlob, mime: 'image/webp' });
          return;
        }
        canvas.toBlob((jpgBlob) => {
          if (jpgBlob && jpgBlob.size > 0) {
            resolve({ blob: jpgBlob, mime: 'image/jpeg' });
          } else {
            reject(new Error('浏览器 Canvas 图片编码失败'));
          }
        }, 'image/jpeg', 0.85);
      }, 'image/webp', 0.82);
    });
  }

  async function processSmartBackgroundImage(file) {
    if (!file) return;
    const rawDataUrl = await readFileAsDataURL(file);
    const img = await loadImageFromURL(rawDataUrl);

    // 1. 等比缩放至最大边 1920px
    const maxDim = 1920;
    const scale = Math.min(1, maxDim / Math.max(img.naturalWidth || 1, img.naturalHeight || 1));
    const dstW = Math.max(1, Math.round((img.naturalWidth || 1) * scale));
    const dstH = Math.max(1, Math.round((img.naturalHeight || 1) * scale));
    const hdCanvas = document.createElement('canvas');
    hdCanvas.width = dstW;
    hdCanvas.height = dstH;
    const hdCtx = hdCanvas.getContext('2d');
    hdCtx.drawImage(img, 0, 0, dstW, dstH);

    // 2. 64x64 像素采样计算平均感知亮度 (0..255) 与主色调 RGB
    const sampleCanvas = document.createElement('canvas');
    sampleCanvas.width = 64;
    sampleCanvas.height = 64;
    const sCtx = sampleCanvas.getContext('2d', { willReadFrequently: true });
    sCtx.drawImage(img, 0, 0, 64, 64);
    const pixels = sCtx.getImageData(0, 0, 64, 64).data;
    let sumR = 0;
    let sumG = 0;
    let sumB = 0;
    let sumLum = 0;
    const total = pixels.length / 4;
    for (let i = 0; i < pixels.length; i += 4) {
      const r = pixels[i];
      const g = pixels[i + 1];
      const b = pixels[i + 2];
      sumR += r;
      sumG += g;
      sumB += b;
      sumLum += 0.299 * r + 0.587 * g + 0.114 * b;
    }
    const luminance = Math.round(sumLum / total);
    const domRGB = `${Math.round(sumR / total)},${Math.round(sumG / total)},${Math.round(sumB / total)}`;

    // 3. 编码高清 WebP/JPEG（如 > 1.9MB 降质量二次压缩保 2MB 内）
    let encoded = await encodeCanvasBest(hdCanvas);
    if (encoded.blob.size > 1.9 * 1024 * 1024) {
      encoded = await new Promise((resolve, reject) => {
        hdCanvas.toBlob((b) => (b ? resolve({ blob: b, mime: 'image/jpeg' }) : reject(new Error('二次压缩失败'))), 'image/jpeg', 0.72);
      });
    }
    const hdDataUrl = await blobToDataURL(encoded.blob);

    // 4. 生成 32px 极简 LQIP 模糊占位图
    const lqipW = 32;
    const lqipH = Math.max(18, Math.round((dstH / dstW) * 32));
    const lqipCanvas = document.createElement('canvas');
    lqipCanvas.width = lqipW;
    lqipCanvas.height = lqipH;
    lqipCanvas.getContext('2d').drawImage(hdCanvas, 0, 0, lqipW, lqipH);
    const lqipUrl = lqipCanvas.toDataURL('image/jpeg', 0.55);

    const isLight = luminance > 145;
    const recTint = isLight ? 'light' : 'dark';
    const recVeil = isLight ? 28 : 20;

    const badge = $('bg-analysis-badge');
    badge.hidden = false;
    badge.textContent = `${isLight ? '亮色图' : '暗色图'}（亮度 ${luminance}/255）· 已推荐${isLight ? '浅冰玻璃' : '深曜玻璃'} + 护眼遮罩 ${recVeil}% · 压缩 ${fmtKB(file.size)} → ${fmtKB(encoded.blob.size)} (${encoded.mime.replace('image/', '').toUpperCase()})`;

    const focalX = Number($('bg-preview-img').dataset.fx || 50);
    const focalY = Number($('bg-preview-img').dataset.fy || 50);

    const res = await apiFetch('/api/admin/background', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'local',
        image_base64: hdDataUrl,
        mime_type: encoded.mime,
        lqip_data_url: lqipUrl,
        focal_x: focalX,
        focal_y: focalY,
        luminance,
        dominant_rgb: domRGB
      })
    });

    const recommendedAppearance = Object.assign({}, res.appearance || {}, {
      glass_tint: 'auto',
      veil_opacity: recVeil / 100
    });
    state.appearance = recommendedAppearance;
    state.bg_url = res.bg_url;
    try {
      const act = await apiFetch('/api/admin/themes/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          theme_id: state.active_theme_id,
          appearance: recommendedAppearance
        })
      });
      if (act && act.appearance) state.appearance = act.appearance;
    } catch {
      // 保留本地推荐参数待手动保存
    }
    renderAppearanceControls();
    showToast(`智能壁纸上传成功并已应用推荐参数（${recTint === 'light' ? '浅冰玻璃' : '深曜玻璃'} · 护眼遮罩 ${recVeil}%）`);
  }

  async function uploadThemeZipFile(file) {
    if (!file) return;
    if (file.size > 3 * 1024 * 1024) {
      showToast('主题压缩包不能超过 3 MiB', true);
      return;
    }
    const res = await apiFetch('/api/admin/themes/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/zip',
        'X-Theme-Filename': encodeURIComponent(file.name || 'theme.qwqtheme.zip')
      },
      body: file
    });
    state.themes = res.themes || state.themes;
    renderThemes();
    showToast(`主题「${res.installed?.name || file.name}」安装成功，可随时点击启用`);
  }

  // ===== 事件绑定 =====
  $('theme-mode-btn').addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
  });

  $('logout-btn').addEventListener('click', () => {
    const tok = adminToken;
    if (tok) {
      void fetch(apiUrl('/api/admin/logout'), {
        method: 'POST',
        headers: { 'X-Probe-Admin-Token': tok }
      }).catch(() => {});
    }
    adminToken = '';
    sessionStorage.removeItem(TOKEN_KEY);
    renderAuthView();
  });

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('login-error').hidden = true;
    try {
      const resp = await fetch(apiUrl('/api/admin/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: $('login-password').value })
      });
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        $('login-error').textContent = j.error === 'TOO_MANY_ATTEMPTS'
          ? '尝试次数过多，请稍后再试'
          : '管理口令不正确，请重试';
        $('login-error').hidden = false;
        return;
      }
      const data = await resp.json();
      adminToken = data.admin_token || '';
      sessionStorage.setItem(TOKEN_KEY, adminToken);
      $('login-password').value = '';
      await loadAdminState();
    } catch {
      $('login-error').textContent = '网络连接异常，请重试';
      $('login-error').hidden = false;
    }
  });

  document.querySelectorAll('.tabs .tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const name = tab.dataset.tab;
      document.querySelectorAll('.tabs .tab').forEach((b) => b.classList.toggle('active', b === tab));
      document.querySelectorAll('.tab-panel').forEach((p) => { p.hidden = p.id !== `panel-${name}`; });
    });
  });

  $('theme-list').addEventListener('click', async (e) => {
    const actBtn = e.target.closest('[data-activate-theme]');
    if (actBtn) {
      const themeId = actBtn.dataset.activateTheme;
      try {
        const res = await apiFetch('/api/admin/themes/activate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ theme_id: themeId })
        });
        state.active_theme_id = res.active_theme_id;
        state.appearance = res.appearance || state.appearance;
        state.theme_settings = res.theme_settings || {};
        renderThemes();
        showToast(`已切换前台主题为 ${themeId}`);
      } catch (err) {
        showToast(err.message || '切换主题失败', true);
      }
      return;
    }
    const delBtn = e.target.closest('[data-delete-theme]');
    if (delBtn) {
      const themeId = delBtn.dataset.deleteTheme;
      try {
        const res = await apiFetch(`/api/admin/themes/${encodeURIComponent(themeId)}`, { method: 'DELETE' });
        state.themes = res.themes || [];
        state.active_theme_id = res.active_theme_id || 'builtin:classic';
        renderThemes();
        showToast(`已卸载主题 ${themeId}`);
      } catch (err) {
        showToast(err.message || '删除主题失败', true);
      }
    }
  });

  $('save-theme-settings-btn').addEventListener('click', async () => {
    const nextSettings = {};
    document.querySelectorAll('#theme-settings-form [data-ts-key]').forEach((el) => {
      const key = el.dataset.tsKey;
      const typ = el.dataset.tsType;
      if (typ === 'boolean') nextSettings[key] = Boolean(el.checked);
      else if (typ === 'number') nextSettings[key] = Number(el.value || 0);
      else nextSettings[key] = el.value;
    });
    try {
      const res = await apiFetch('/api/admin/themes/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ theme_id: state.active_theme_id, theme_settings: nextSettings })
      });
      state.theme_settings = res.theme_settings || nextSettings;
      showToast('主题专属参数已保存');
    } catch (err) {
      showToast(err.message || '保存主题参数失败', true);
    }
  });

  $('download-starter-btn').addEventListener('click', async () => {
    try {
      const resp = await apiFetch('/api/admin/themes/starter.zip');
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'qwq-probe-theme-starter.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      showToast(err.message || '下载主题模板失败', true);
    }
  });

  function wireDropzone(zoneEl, inputEl, handler) {
    zoneEl.addEventListener('click', () => inputEl.click());
    zoneEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inputEl.click(); }
    });
    zoneEl.addEventListener('dragover', (e) => { e.preventDefault(); zoneEl.classList.add('is-dragover'); });
    zoneEl.addEventListener('dragleave', () => zoneEl.classList.remove('is-dragover'));
    zoneEl.addEventListener('drop', (e) => {
      e.preventDefault();
      zoneEl.classList.remove('is-dragover');
      const f = e.dataTransfer?.files?.[0];
      if (f) void handler(f).catch((err) => showToast(err.message || '处理失败', true));
    });
    inputEl.addEventListener('change', () => {
      const f = inputEl.files?.[0];
      inputEl.value = '';
      if (f) void handler(f).catch((err) => showToast(err.message || '处理失败', true));
    });
  }

  wireDropzone($('theme-dropzone'), $('theme-file-input'), uploadThemeZipFile);
  wireDropzone($('bg-dropzone'), $('bg-file-input'), processSmartBackgroundImage);

  $('theme-url-install-btn').addEventListener('click', async () => {
    const url = $('theme-url-input').value.trim();
    if (!url) return;
    try {
      const res = await apiFetch('/api/admin/themes/install-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      state.themes = res.themes || state.themes;
      $('theme-url-input').value = '';
      renderThemes();
      showToast(`已从远程安装主题「${res.installed?.name || ''}」`);
    } catch (err) {
      showToast(err.message || '远程安装主题失败', true);
    }
  });

  $('focal-grid').addEventListener('click', async (e) => {
    const dot = e.target.closest('.focal-dot');
    if (!dot) return;
    const fx = Number(dot.dataset.fx);
    const fy = Number(dot.dataset.fy);
    $('bg-preview-img').dataset.fx = String(fx);
    $('bg-preview-img').dataset.fy = String(fy);
    document.querySelectorAll('#focal-grid .focal-dot').forEach((b) => b.classList.toggle('active', b === dot));

    const mode = state.appearance?.background?.mode || 'none';
    if (mode === 'local' || mode === 'url') {
      try {
        const res = await apiFetch('/api/admin/background', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mode,
            focal_x: fx,
            focal_y: fy,
            external_url: mode === 'url' ? state.appearance.background.external_url : undefined
          })
        });
        state.appearance = res.appearance;
        showToast(`壁纸焦点已更新 (${fx}%, ${fy}%)`);
      } catch (err) {
        showToast(err.message || '焦点更新失败', true);
      }
    }
  });

  $('apply-bg-url-btn').addEventListener('click', async () => {
    const extUrl = $('bg-external-url').value.trim();
    if (!extUrl) return;
    const fx = Number($('bg-preview-img').dataset.fx || 50);
    const fy = Number($('bg-preview-img').dataset.fy || 50);
    try {
      const res = await apiFetch('/api/admin/background', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'url', external_url: extUrl, focal_x: fx, focal_y: fy })
      });
      state.appearance = res.appearance;
      state.bg_url = res.bg_url;
      renderAppearanceControls();
      showToast('已应用外链 HTTPS 壁纸');
    } catch (err) {
      showToast(err.message || '外链壁纸设置失败', true);
    }
  });

  $('clear-bg-btn').addEventListener('click', async () => {
    try {
      const res = await apiFetch('/api/admin/background', { method: 'DELETE' });
      state.appearance = res.appearance;
      state.bg_url = '';
      $('bg-analysis-badge').hidden = true;
      renderAppearanceControls();
      showToast('背景壁纸已清除，已回退为默认动态极光');
    } catch (err) {
      showToast(err.message || '清除背景失败', true);
    }
  });

  ['opt-glass-opacity', 'opt-glass-blur', 'opt-veil-opacity', 'opt-glass-tint'].forEach((id) => {
    $(id).addEventListener('input', updateMiniPreview);
    $(id).addEventListener('change', updateMiniPreview);
  });

  function collectAppearancePayload() {
    return {
      glass_opacity: Number($('opt-glass-opacity').value) / 100,
      glass_blur_px: Number($('opt-glass-blur').value),
      glass_tint: $('opt-glass-tint').value,
      veil_opacity: Number($('opt-veil-opacity').value) / 100,
      motion_enabled: $('opt-motion-enabled').checked,
      accent_color: $('opt-accent-enable').checked ? $('opt-accent-color').value : '',
      custom_css: $('opt-custom-css').value,
      background: Object.assign({}, state.appearance?.background || { mode: 'none' }, {
        focal_x: Number($('bg-preview-img').dataset.fx || 50),
        focal_y: Number($('bg-preview-img').dataset.fy || 50)
      })
    };
  }

  $('activate-liquid-btn').addEventListener('click', async () => {
    try {
      const res = await apiFetch('/api/admin/themes/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          theme_id: 'builtin:liquid-glass',
          appearance: collectAppearancePayload()
        })
      });
      state.active_theme_id = res.active_theme_id;
      state.appearance = res.appearance;
      renderThemes();
      showToast('已启用「动态透明水玻璃（Liquid Glass）」并保存光学参数');
    } catch (err) {
      showToast(err.message || '启用水玻璃风格失败', true);
    }
  });

  $('save-appearance-btn').addEventListener('click', async () => {
    try {
      const res = await apiFetch('/api/admin/themes/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          theme_id: state.active_theme_id,
          appearance: collectAppearancePayload()
        })
      });
      state.appearance = res.appearance;
      showToast('水玻璃光学外观与自定义 CSS 已保存');
    } catch (err) {
      showToast(err.message || '保存外观配置失败', true);
    }
  });

  function resetAdminNodeForm() {
    $('adm-node-id').value = '';
    $('adm-node-name').value = '';
    $('adm-node-region').value = 'HK';
    $('adm-node-quota-mode').value = 'both';
    $('adm-node-quota-gb').value = '0';
    $('adm-node-reset-day').value = '1';
    $('adm-node-expires-at').value = '';
    $('adm-node-form-title').textContent = '新增监控服务器 & 生成单向 Agent 安装命令';
    $('adm-add-node').textContent = '生成单向安全探针命令';
    $('adm-cancel-edit-node').hidden = true;
  }

  $('adm-cancel-edit-node').addEventListener('click', resetAdminNodeForm);

  $('adm-nodes-list').addEventListener('click', async (e) => {
    const editBtn = e.target.closest('[data-adm-edit-node]');
    if (editBtn) {
      const nodeId = editBtn.dataset.admEditNode;
      const node = (state.nodes || []).find((x) => x.ID === nodeId);
      if (!node) return;
      $('adm-node-id').value = node.ID;
      $('adm-node-name').value = node.Name || '';
      $('adm-node-region').value = node.RegionCode || 'HK';
      $('adm-node-quota-mode').value = node.QuotaMode || 'both';
      $('adm-node-quota-gb').value = node.QuotaBytes ? String(Math.round(Number(node.QuotaBytes) / (1024 ** 3))) : '0';
      $('adm-node-reset-day').value = String(node.ResetDay || 1);
      $('adm-node-expires-at').value = node.ExpiresAt ? new Date(Number(node.ExpiresAt) * 1000).toISOString().slice(0, 10) : '';
      $('adm-node-form-title').textContent = `编辑节点：${node.Name} (${node.ID})`;
      $('adm-add-node').textContent = '保存节点配置';
      $('adm-cancel-edit-node').hidden = false;
      $('adm-node-name').focus();
      return;
    }
    const delBtn = e.target.closest('[data-adm-del-node]');
    if (delBtn) {
      const nodeId = delBtn.dataset.admDelNode;
      try {
        await apiFetch(`/api/admin/nodes/${encodeURIComponent(nodeId)}`, { method: 'DELETE' });
        showToast(`已移除节点 ${nodeId}`);
        if ($('adm-node-id').value === nodeId) resetAdminNodeForm();
        void loadAdminState();
      } catch (err) {
        showToast(err.message || '删除节点失败', true);
      }
    }
  });

  $('adm-add-node').addEventListener('click', async () => {
    const id = $('adm-node-id').value.trim();
    const name = $('adm-node-name').value.trim();
    if (!name) return;
    const quotaGB = Math.max(0, Number($('adm-node-quota-gb').value || 0));
    const resetDay = Math.min(31, Math.max(1, Math.floor(Number($('adm-node-reset-day').value || 1))));
    const expStr = $('adm-node-expires-at').value.trim();
    const expiresAt = expStr ? Math.floor(new Date(expStr + 'T00:00:00Z').getTime() / 1000) : 0;
    const payload = {
      name,
      region_code: $('adm-node-region').value.trim() || 'HK',
      quota_mode: $('adm-node-quota-mode').value,
      quota_bytes: Math.floor(quotaGB * (1024 ** 3)),
      reset_day: resetDay,
      expires_at: Number.isFinite(expiresAt) && expiresAt > 0 ? expiresAt : 0,
      public_origin: window.location.origin
    };
    if (id) payload.id = id;
    try {
      const res = await apiFetch('/api/admin/nodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.linux_install) {
        $('adm-install-cmd').hidden = false;
        $('adm-install-cmd').textContent = res.linux_install;
      }
      showToast(id ? `已更新节点「${name}」` : `已创建节点「${name}」`);
      resetAdminNodeForm();
      void loadAdminState();
    } catch (err) {
      showToast(err.message || '保存节点失败', true);
    }
  });

  $('save-site-settings-btn').addEventListener('click', async () => {
    try {
      const saved = await apiFetch('/api/admin/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_title: $('set-site-title').value.trim(),
          site_subtitle: $('set-site-sub').value.trim(),
          default_view: $('set-default-view').value,
          mask_node_ip: $('set-mask-ip').checked,
          expose_billing_cost: $('set-expose-billing').checked,
          expose_isp_carrier: $('set-expose-isp').checked
        })
      });
      state.settings = saved;
      showToast('站点标题与隐私策略已保存');
    } catch (err) {
      showToast(err.message || '保存站点设置失败', true);
    }
  });

  $('adm-save-domain').addEventListener('click', async () => {
    try {
      const res = await apiFetch('/api/admin/domain/bind', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          custom_domain: $('adm-domain').value.trim(),
          binding_track: $('adm-track').value,
          acme_email: $('adm-email').value.trim()
        })
      });
      if (res.proxy_snippets?.nginx_baota_conf) {
        $('adm-snippet').hidden = false;
        $('adm-snippet').textContent = res.proxy_snippets.nginx_baota_conf;
      }
      showToast('独立域名与证书策略已应用');
    } catch (err) {
      showToast(err.message || '域名绑定失败', true);
    }
  });

  renderAuthView();
  if (adminToken) void loadAdminState();
})();
