// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const initial = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(initial.get('theme'), ['light', 'dark'], 'light');
  root.style.colorScheme = root.dataset.theme;
  root.dataset.motion = pick(initial.get('motion'), ['full', 'reduced', 'off'], 'reduced');
  root.dataset.density = pick(initial.get('density'), ['comfortable', 'compact'], 'comfortable');

  const $ = (id) => document.getElementById(id);
  let port = null;
  let seq = 0;
  let mode = 'admin';
  let latest = null;
  let publicOrigin = '';
  let panelTlsMode = '';
  let panelTlsSha256 = '';
  const pending = new Map();
  const pendingConfirm = new Map();
  const pendingCopy = new Map();

  function isLoopbackOrigin(origin) {
    if (!origin) return false;
    try {
      const host = new URL(origin).hostname.toLowerCase().replace(/^\[|\]$/g, '');
      return host === '127.0.0.1' || host === 'localhost' || host === '::1';
    } catch {
      return false;
    }
  }

  function updateLoopbackOriginWarning() {
    const el = $('loopback-origin-warn');
    if (!el) return;
    const customDomain = latest?.settings?.custom_domain;
    const override = normalizeOrigin($('node-public-origin')?.value || '');
    const effective = override || publicOrigin;
    el.hidden = Boolean(customDomain) || !isLoopbackOrigin(effective);
  }

  function formatSlaPercent(val) {
    const num = Number(val);
    if (!Number.isFinite(num) || num < 0) return '— (待接入)';
    return `${num.toFixed(2)}%`;
  }

  function send(msg) {
    if (port) port.postMessage(msg);
  }

  function normalizeOrigin(raw) {
    if (typeof raw !== 'string') return '';
    const trimmed = raw.trim().replace(/\/+$/, '');
    return /^https?:\/\/[^/\s]+$/i.test(trimmed) ? trimmed : '';
  }

  function formatInstallCmd(rawCmd) {
    if (typeof rawCmd !== 'string') return '已创建节点';
    if (!publicOrigin) return rawCmd;
    return rawCmd.replace(/(['"\s])\/p\/server\.probe\//g, `$1${publicOrigin}/p/server.probe/`);
  }

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function invoke(operation, payload = {}, timeoutMs = 15000) {
    if (!port) return Promise.reject(new Error('尚未建立宿主通道'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        pending.delete(id);
        reject(new Error('宿主响应超时'));
      }, timeoutMs);
      pending.set(id, { resolve, reject, deadline });
      send({ t: 'api.invoke', id, operation, payload });
    });
  }

  function hostCopy(text, label) {
    if (!port) return Promise.reject(new Error('尚未建立宿主通道'));
    if (!text) return Promise.reject(new Error('没有可复制的内容'));
    const id = `cp_${++seq}`;
    return new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        pendingCopy.delete(id);
        reject(new Error('复制响应超时'));
      }, 8000);
      pendingCopy.set(id, { resolve, reject, deadline });
      const msg = { t: 'ui.copy', id, text: String(text) };
      if (label) msg.label = label;
      send(msg);
    });
  }

  function esc(str) {
    return String(str ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function fmtKB(bytes) {
    const kb = Number(bytes || 0) / 1024;
    if (kb >= 1024) return (kb / 1024).toFixed(2) + ' MB';
    return Math.max(1, Math.round(kb)) + ' KB';
  }

  function toast(text) {
    $('conn-status').textContent = text;
    send({ t: 'ui.toast', text });
  }

  // ===== 零依赖纯 JS STORE ZIP 打包器（用于沙箱内直接下载官方起步主题模板） =====
  function crc32(bytes) {
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
      c ^= bytes[i];
      for (let k = 0; k < 8; k++) {
        c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
      }
    }
    return (c ^ 0xffffffff) >>> 0;
  }

  function buildStoreZip(entries) {
    const enc = new TextEncoder();
    const locals = [];
    const centrals = [];
    let offset = 0;

    for (const [name, content] of entries) {
      const nameBytes = enc.encode(name);
      const dataBytes = enc.encode(content);
      const crc = crc32(dataBytes);

      const lh = new Uint8Array(30 + nameBytes.length);
      const lv = new DataView(lh.buffer);
      lv.setUint32(0, 0x04034b50, true);
      lv.setUint16(4, 20, true);
      lv.setUint32(14, crc, true);
      lv.setUint32(18, dataBytes.length, true);
      lv.setUint32(22, dataBytes.length, true);
      lv.setUint16(26, nameBytes.length, true);
      lh.set(nameBytes, 30);
      locals.push(lh, dataBytes);

      const ch = new Uint8Array(46 + nameBytes.length);
      const cv = new DataView(ch.buffer);
      cv.setUint32(0, 0x02014b50, true);
      cv.setUint16(4, 20, true);
      cv.setUint16(6, 20, true);
      cv.setUint32(16, crc, true);
      cv.setUint32(20, dataBytes.length, true);
      cv.setUint32(24, dataBytes.length, true);
      cv.setUint16(28, nameBytes.length, true);
      cv.setUint32(42, offset, true);
      ch.set(nameBytes, 46);
      centrals.push(ch);

      offset += lh.length + dataBytes.length;
    }

    const centralLen = centrals.reduce((s, a) => s + a.length, 0);
    const eocd = new Uint8Array(22);
    const ev = new DataView(eocd.buffer);
    ev.setUint32(0, 0x06054b50, true);
    ev.setUint16(8, entries.length, true);
    ev.setUint16(10, entries.length, true);
    ev.setUint32(12, centralLen, true);
    ev.setUint32(16, offset, true);

    return new Blob([...locals, ...centrals, eocd], { type: 'application/zip' });
  }

  function downloadStarterZipClientSide() {
    const starterEntries = [
      ['theme.json', JSON.stringify({
        id: 'starter-glass-demo',
        name: '起步水玻璃自定义主题',
        version: '1.0.0',
        author: 'your-name',
        description: '基于 qwq 公开数据契约与 appearance 参数的自定义前台模板。',
        api_version: '1',
        entry: 'index.html',
        settings_schema: [
          { key: 'accent', label: '品牌强调色', type: 'color', default: '#38bdf8' },
          { key: 'show_subtitle', label: '显示副标题', type: 'boolean', default: true }
        ]
      }, null, 2) + '\n'],
      ['index.html', '<!doctype html>\n<html lang="zh-CN">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>qwq Probe Custom Theme</title>\n  <link rel="stylesheet" href="style.css">\n  <script src="app.js" defer></script>\n</head>\n<body>\n  <main class="shell">\n    <header class="bar"><h1 id="title">qwq Probe</h1><a href="./admin">管理后台</a></header>\n    <section id="grid" class="grid"></section>\n  </main>\n</body>\n</html>\n'],
      ['style.css', 'body{margin:0;min-height:100vh;background:#0f172a;color:#f8fafc;font-family:sans-serif}.shell{max-width:1080px;margin:0 auto;padding:24px}.bar,.node{background:rgba(15,23,42,.45);backdrop-filter:blur(18px);border:1px solid rgba(255,255,255,.2);border-radius:16px;padding:16px}.bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}\n'],
      ['app.js', '(() => {\n  const esc = (s) => String(s ?? "").replace(/[&<>"\']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","\'":"&#39;"}[c]));\n  async function load() {\n    const r = await fetch("./api/public/snapshot");\n    if (!r.ok) return;\n    const d = await r.json();\n    document.getElementById("title").textContent = d.site_title || "qwq Probe";\n    document.getElementById("grid").innerHTML = (d.nodes || []).map((n) => "<article class=\\"node\\"><strong>" + esc(n.name) + "</strong><div>CPU " + Number(n.live?.cpu_pct || 0).toFixed(1) + "%</div></article>").join("");\n  }\n  void load();\n  setInterval(() => { if (!document.hidden) void load(); }, 3000);\n})();\n']
    ];
    const blob = buildStoreZip(starterEntries);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'qwq-probe-theme-starter.zip';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast('已生成并下载官方主题模板 qwq-probe-theme-starter.zip');
  }

  function renderThemesSection(data) {
    const themes = Array.isArray(data.themes) ? data.themes : [];
    const activeId = data.active_theme_id || data.settings?.active_theme_id || 'builtin:classic';
    $('preview-style-badge').textContent = activeId === 'builtin:liquid-glass' ? 'Liquid Glass' : activeId;

    $('panel-theme-grid').innerHTML = themes.map((t) => {
      const isActive = t.id === activeId;
      const badgeCls = isActive ? 'badge berry-badge' : 'badge';
      const badgeTxt = isActive ? '当前启用' : (t.builtin ? '官方内置' : '自定义包');
      const delBtn = t.builtin
        ? ''
        : `<button type="button" class="btn danger" data-del-theme="${esc(t.id)}">删除</button>`;
      return `<div class="theme-item${isActive ? ' is-active' : ''}">
        <div>
          <div class="node-card-head">
            <strong>${esc(t.name)}</strong>
            <span class="${badgeCls}">${badgeTxt}</span>
          </div>
          <div class="node-card-metrics">ID: <code>${esc(t.id)}</code> · v${esc(t.version || '1.0.0')}</div>
          <p class="theme-item-desc">${esc(t.description || '')}</p>
        </div>
        <div class="theme-item-actions">
          ${delBtn}
          <button type="button" class="btn ${isActive ? 'ghost' : 'primary'}" data-use-theme="${esc(t.id)}" ${isActive ? 'disabled' : ''}>
            ${isActive ? '已启用' : '启用'}
          </button>
        </div>
      </div>`;
    }).join('');

    const activeTheme = themes.find((t) => t.id === activeId);
    const schema = activeTheme && Array.isArray(activeTheme.settings_schema) ? activeTheme.settings_schema : [];
    const wrap = $('panel-theme-settings-wrap');
    if (schema.length === 0) {
      wrap.hidden = true;
      $('panel-theme-settings-form').innerHTML = '';
    } else {
      wrap.hidden = false;
      const ts = data.theme_settings || {};
      $('panel-theme-settings-form').innerHTML = schema.map((f) => {
        const cur = ts[f.key] !== undefined ? ts[f.key] : f.default;
        if (f.type === 'boolean') {
          return `<label class="ts-check"><input type="checkbox" data-pts-key="${esc(f.key)}" data-pts-type="boolean" ${cur ? 'checked' : ''}><span>${esc(f.label)}</span></label>`;
        }
        if (f.type === 'select' && Array.isArray(f.options)) {
          const opts = f.options.map((o) => `<option value="${esc(o)}" ${String(cur ?? '') === String(o) ? 'selected' : ''}>${esc(o)}</option>`).join('');
          return `<label class="ts-field"><span>${esc(f.label)}</span><select data-pts-key="${esc(f.key)}" data-pts-type="select">${opts}</select></label>`;
        }
        const typ = f.type === 'color' ? 'color' : (f.type === 'number' ? 'number' : 'text');
        return `<label class="ts-field"><span>${esc(f.label)}</span><input type="${typ}" data-pts-key="${esc(f.key)}" data-pts-type="${esc(f.type)}" value="${esc(cur ?? '')}"></label>`;
      }).join('');
    }

    const app = data.appearance || data.settings?.appearance || {};
    const bg = app.background || {};
    $('p-opt-opacity').value = String(Math.round((app.glass_opacity ?? 0.26) * 100));
    $('p-opt-blur').value = String(app.glass_blur_px ?? 20);
    $('p-opt-veil').value = String(Math.round((app.veil_opacity ?? 0.22) * 100));
    $('p-opt-tint').value = app.glass_tint || 'auto';
    $('p-opt-motion').checked = app.motion_enabled !== false;
    $('p-opt-css').value = app.custom_css || '';
    $('panel-bg-url').value = bg.external_url || '';

    const fx = String(bg.focal_x ?? 50);
    const fy = String(bg.focal_y ?? 50);
    const prevImg = $('panel-bg-preview');
    prevImg.dataset.fx = fx;
    prevImg.dataset.fy = fy;
    if (bg.lqip_data_url) {
      prevImg.src = bg.lqip_data_url;
      prevImg.hidden = false;
    } else if (bg.mode === 'url' && bg.external_url) {
      prevImg.hidden = true;
    } else {
      prevImg.hidden = true;
      prevImg.removeAttribute('src');
    }
    document.querySelectorAll('#panel-focal-grid .focal-dot').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.fx === fx && btn.dataset.fy === fy);
    });
    updateSliderLabels();
  }

  function updateSliderLabels() {
    $('p-val-opacity').textContent = `${$('p-opt-opacity').value}%`;
    $('p-val-blur').textContent = `${$('p-opt-blur').value}px`;
    $('p-val-veil').textContent = `${$('p-opt-veil').value}%`;
    const tint = $('p-opt-tint').value;
    const lum = latest?.appearance?.background?.luminance ?? -1;
    const resolved = tint === 'auto' ? (lum > 145 ? 'light' : 'dark') : tint;
    $('panel-preview-frame').dataset.tint = resolved;
  }

  function render(data) {
    latest = data;
    const caps = data.dnc_capabilities || {};
    $('dnc-track-hint').textContent = caps.tls_certificates_ready
      ? '已探测到面板证书套件就绪：可直接借用 domain.dns 解析与 certbind_* 自动续期证书'
      : (caps.fallback_reason || '未安装面板域名插件：已启用探针自身独立域名与 HTTPS 绑定闭环');
    $('track-badge').textContent = caps.tls_certificates_ready ? '轨道 A 可借用' : '轨道 B 自闭环';

    const nodes = Array.isArray(data.public_nodes) ? data.public_nodes : [];
    const renderNodeCard = (n, editable) => {
      const cpu = Number(n.live?.cpu_pct || 0).toFixed(1);
      const rxMbps = (Number(n.live?.net_rx_bps || 0) / 1e6).toFixed(2);
      const txMbps = (Number(n.live?.net_tx_bps || 0) / 1e6).toFixed(2);
      const quotaGB = n.quota_bytes ? (Number(n.quota_bytes) / (1024 ** 3)).toFixed(0) + ' GB' : '不限流量';
      const expText = typeof n.expires_in_days === 'number' ? ` · 剩余 ${n.expires_in_days} 天` : '';
      const actions = editable
        ? `<div class="theme-item-actions">
            <button type="button" class="btn ghost" data-edit-node="${esc(n.id)}">编辑</button>
            ${n.is_local ? '' : `<button type="button" class="btn danger" data-remove-node="${esc(n.id)}">删除</button>`}
          </div>`
        : '';
      return `<div class="node-card">
        <div class="node-card-head">
          <strong>[${esc(n.region_code)}] ${esc(n.name)}</strong>
          <span class="badge ${n.online ? '' : 'warn'}">${n.online ? '在线' : '离线'}</span>
        </div>
        <div class="node-card-metrics">
          CPU ${cpu}% · ↓ ${rxMbps} Mbps / ↑ ${txMbps} Mbps · 90天在线 ${esc(formatSlaPercent(n.uptime_90d_pct))}
        </div>
        <div class="node-card-metrics">
          配额 ${esc(quotaGB)} (${esc(n.quota_mode || 'both')}) · 每月 ${Number(n.reset_day || 1)} 日重置${esc(expText)}
        </div>
        ${actions}
      </div>`;
    };
    $('admin-nodes-grid').innerHTML = nodes.map((n) => renderNodeCard(n, true)).join('');
    $('visitor-nodes-grid').innerHTML = nodes.map((n) => renderNodeCard(n, false)).join('');
    renderMonitors(data.service_monitors);
    updateLoopbackOriginWarning();
    if (data.settings?.site_title) {
      $('preview-title').textContent = data.settings.site_title;
    }
    if (data.proxy_snippets?.nginx_baota_conf) {
      $('proxy-snippet-actions').hidden = false;
      $('proxy-snippet-box').hidden = false;
      $('proxy-snippet-box').textContent = data.proxy_snippets.nginx_baota_conf;
    }
    renderThemesSection(data);
  }

  async function refresh() {
    try {
      const res = await invoke('probe.overview', {});
      $('conn-status').textContent = '已连接 qwq 插件沙箱运行时 · 实时遥测同步中';
      render(res);
    } catch (err) {
      $('conn-status').textContent = err.message || '等待宿主连接';
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
      fr.onerror = () => reject(new Error('图片编码读取失败'));
      fr.readAsDataURL(blob);
    });
  }

  function loadImageFromURL(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('无法解码图片，请选择有效 JPG/PNG/WebP'));
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
          if (jpgBlob && jpgBlob.size > 0) resolve({ blob: jpgBlob, mime: 'image/jpeg' });
          else reject(new Error('浏览器 Canvas 压缩失败'));
        }, 'image/jpeg', 0.85);
      }, 'image/webp', 0.82);
    });
  }

  async function handleSmartBackgroundFile(file) {
    if (!file) return;
    const rawUrl = await readFileAsDataURL(file);
    const img = await loadImageFromURL(rawUrl);

    const maxDim = 1920;
    const scale = Math.min(1, maxDim / Math.max(img.naturalWidth || 1, img.naturalHeight || 1));
    const dstW = Math.max(1, Math.round((img.naturalWidth || 1) * scale));
    const dstH = Math.max(1, Math.round((img.naturalHeight || 1) * scale));
    const hdCanvas = document.createElement('canvas');
    hdCanvas.width = dstW;
    hdCanvas.height = dstH;
    hdCanvas.getContext('2d').drawImage(img, 0, 0, dstW, dstH);

    const sCanvas = document.createElement('canvas');
    sCanvas.width = 64;
    sCanvas.height = 64;
    const sCtx = sCanvas.getContext('2d', { willReadFrequently: true });
    sCtx.drawImage(img, 0, 0, 64, 64);
    const px = sCtx.getImageData(0, 0, 64, 64).data;
    let rSum = 0;
    let gSum = 0;
    let bSum = 0;
    let lSum = 0;
    const cnt = px.length / 4;
    for (let i = 0; i < px.length; i += 4) {
      rSum += px[i];
      gSum += px[i + 1];
      bSum += px[i + 2];
      lSum += 0.299 * px[i] + 0.587 * px[i + 1] + 0.114 * px[i + 2];
    }
    const luminance = Math.round(lSum / cnt);
    const dominantRGB = `${Math.round(rSum / cnt)},${Math.round(gSum / cnt)},${Math.round(bSum / cnt)}`;

    let encoded = await encodeCanvasBest(hdCanvas);
    if (encoded.blob.size > 1.9 * 1024 * 1024) {
      encoded = await new Promise((resolve, reject) => {
        hdCanvas.toBlob((b) => (b ? resolve({ blob: b, mime: 'image/jpeg' }) : reject(new Error('二次压缩失败'))), 'image/jpeg', 0.72);
      });
    }
    const hdDataUrl = await blobToDataURL(encoded.blob);

    const lqipW = 32;
    const lqipH = Math.max(18, Math.round((dstH / dstW) * 32));
    const lqipCanvas = document.createElement('canvas');
    lqipCanvas.width = lqipW;
    lqipCanvas.height = lqipH;
    lqipCanvas.getContext('2d').drawImage(hdCanvas, 0, 0, lqipW, lqipH);
    const lqipDataUrl = lqipCanvas.toDataURL('image/jpeg', 0.55);

    const isLight = luminance > 145;
    const recVeil = isLight ? 28 : 20;
    const badge = $('panel-bg-badge');
    badge.hidden = false;
    badge.textContent = `${isLight ? '亮色图' : '暗色图'}（亮度 ${luminance}/255）· 已推荐${isLight ? '浅冰玻璃' : '深曜玻璃'} · ${fmtKB(file.size)} → ${fmtKB(encoded.blob.size)}`;

    const prevImg = $('panel-bg-preview');
    prevImg.src = hdDataUrl;
    prevImg.hidden = false;
    $('p-opt-veil').value = String(recVeil);
    $('p-opt-tint').value = 'auto';
    updateSliderLabels();

    try {
      await invoke('probe.background.set', {
        mode: 'local',
        image_base64: hdDataUrl,
        mime_type: encoded.mime,
        lqip_data_url: lqipDataUrl,
        focal_x: Number(prevImg.dataset.fx || 50),
        focal_y: Number(prevImg.dataset.fy || 50),
        luminance,
        dominant_rgb: dominantRGB
      }, 25000);
      toast(`智能压缩壁纸已上传，已预填推荐遮罩 ${recVeil}%，点击“保存外观配置”即可生效`);
      await refresh();
      $('p-opt-veil').value = String(recVeil);
      $('p-opt-tint').value = 'auto';
      updateSliderLabels();
    } catch (err) {
      if (err && err.awaitingApproval) toast('壁纸上传已提交，请在宿主审批确认');
      else toast('壁纸上传失败：' + (err.message || '未知错误'));
    }
  }

  const MAX_BRIDGE_ZIP_BYTES = Math.floor(2.9 * 1024 * 1024);

  async function handleThemeZipFile(file) {
    if (!file) return;
    if (file.size > 16 * 1024 * 1024) {
      toast('主题包不能超过 16 MiB');
      return;
    }
    if (file.size > MAX_BRIDGE_ZIP_BYTES) {
      toast('面板内嵌桥接通道单次上限约 2.9 MiB；3–16 MiB 主题包请前往独立 /admin 后台直传或使用 HTTPS URL 安装');
      return;
    }
    const dataUrl = await readFileAsDataURL(file);
    try {
      const res = await invoke('probe.themes.install', { filename: file.name, zip_base64: dataUrl }, 25000);
      toast(`主题「${res.installed?.name || file.name}」安装成功`);
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('主题安装已提交，等待宿主审批确认');
      else toast('主题安装失败：' + (err.message || '未知错误'));
    }
  }

  function wireDropzone(zoneEl, inputEl, fn) {
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
      if (f) void fn(f).catch((err) => toast(err.message || '处理失败'));
    });
    inputEl.addEventListener('change', () => {
      const f = inputEl.files?.[0];
      inputEl.value = '';
      if (f) void fn(f).catch((err) => toast(err.message || '处理失败'));
    });
  }

  wireDropzone($('panel-theme-dropzone'), $('panel-theme-file'), handleThemeZipFile);
  wireDropzone($('panel-bg-dropzone'), $('panel-bg-file'), handleSmartBackgroundFile);

  document.querySelectorAll('[data-mode]').forEach((btn) => {
    btn.addEventListener('click', () => {
      mode = btn.dataset.mode;
      document.querySelectorAll('[data-mode]').forEach((b) => b.setAttribute('aria-pressed', String(b === btn)));
      $('admin-pane').hidden = mode !== 'admin';
      $('themes-pane').hidden = mode !== 'themes';
      $('visitor-pane').hidden = mode !== 'visitor-preview';
    });
  });

  $('panel-starter-zip-btn').addEventListener('click', downloadStarterZipClientSide);

  $('panel-theme-grid').addEventListener('click', async (e) => {
    const useBtn = e.target.closest('[data-use-theme]');
    if (useBtn) {
      const themeId = useBtn.dataset.useTheme;
      try {
        await invoke('probe.themes.activate', { theme_id: themeId });
        toast(`已启用前台主题 ${themeId}`);
        void refresh();
      } catch (err) {
        if (err && err.awaitingApproval) toast('主题切换已提交，等待宿主审批确认');
        else toast('切换主题失败：' + (err.message || '未知错误'));
      }
      return;
    }
    const delBtn = e.target.closest('[data-del-theme]');
    if (delBtn) {
      const themeId = delBtn.dataset.delTheme;
      try {
        await invoke('probe.themes.delete', { theme_id: themeId });
        toast(`已删除主题 ${themeId}`);
        void refresh();
      } catch (err) {
        if (err && err.awaitingApproval) toast('主题删除已提交，等待宿主审批确认');
        else toast('删除主题失败：' + (err.message || '未知错误'));
      }
    }
  });

  $('panel-save-ts-btn').addEventListener('click', async () => {
    const nextSettings = {};
    document.querySelectorAll('#panel-theme-settings-form [data-pts-key]').forEach((el) => {
      const k = el.dataset.ptsKey;
      const t = el.dataset.ptsType;
      if (t === 'boolean') nextSettings[k] = Boolean(el.checked);
      else if (t === 'number') nextSettings[k] = Number(el.value || 0);
      else nextSettings[k] = el.value;
    });
    try {
      await invoke('probe.themes.activate', {
        theme_id: latest?.active_theme_id || 'builtin:classic',
        theme_settings: nextSettings
      });
      toast('主题专属配置已保存');
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('主题配置变更已提交审批');
      else toast('保存主题配置失败：' + (err.message || '未知错误'));
    }
  });

  $('panel-theme-url-btn').addEventListener('click', async () => {
    const url = $('panel-theme-url').value.trim();
    if (!url) return;
    try {
      const res = await invoke('probe.themes.install', { url }, 25000);
      $('panel-theme-url').value = '';
      toast(`已从远程安装主题「${res.installed?.name || ''}」`);
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('远程主题安装已提交审批');
      else toast('远程安装失败：' + (err.message || '未知错误'));
    }
  });

  $('panel-focal-grid').addEventListener('click', async (e) => {
    const dot = e.target.closest('.focal-dot');
    if (!dot) return;
    const fx = Number(dot.dataset.fx);
    const fy = Number(dot.dataset.fy);
    $('panel-bg-preview').dataset.fx = String(fx);
    $('panel-bg-preview').dataset.fy = String(fy);
    document.querySelectorAll('#panel-focal-grid .focal-dot').forEach((b) => b.classList.toggle('active', b === dot));

    const bg = latest?.appearance?.background || {};
    if (bg.mode === 'local' || bg.mode === 'url') {
      try {
        await invoke('probe.background.set', {
          mode: bg.mode,
          focal_x: fx,
          focal_y: fy,
          external_url: bg.mode === 'url' ? bg.external_url : undefined
        });
        toast(`焦点已更新 (${fx}%, ${fy}%)`);
      } catch (err) {
        if (err && err.awaitingApproval) toast('焦点变更已提交审批');
        else toast('焦点更新失败：' + (err.message || '未知错误'));
      }
    }
  });

  $('panel-bg-url-btn').addEventListener('click', async () => {
    const externalUrl = $('panel-bg-url').value.trim();
    if (!externalUrl) return;
    try {
      await invoke('probe.background.set', {
        mode: 'url',
        external_url: externalUrl,
        focal_x: Number($('panel-bg-preview').dataset.fx || 50),
        focal_y: Number($('panel-bg-preview').dataset.fy || 50)
      });
      toast('已应用外链 HTTPS 背景图');
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('外链壁纸已提交审批');
      else toast('外链壁纸失败：' + (err.message || '未知错误'));
    }
  });

  $('panel-clear-bg-btn').addEventListener('click', async () => {
    try {
      await invoke('probe.background.set', { mode: 'none' });
      $('panel-bg-badge').hidden = true;
      toast('背景图已清除');
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('清除背景已提交审批');
      else toast('清除背景失败：' + (err.message || '未知错误'));
    }
  });

  ['p-opt-opacity', 'p-opt-blur', 'p-opt-veil', 'p-opt-tint'].forEach((id) => {
    $(id).addEventListener('input', updateSliderLabels);
    $(id).addEventListener('change', updateSliderLabels);
  });

  function buildPanelAppearance() {
    return {
      glass_opacity: Number($('p-opt-opacity').value) / 100,
      glass_blur_px: Number($('p-opt-blur').value),
      glass_tint: $('p-opt-tint').value,
      veil_opacity: Number($('p-opt-veil').value) / 100,
      motion_enabled: $('p-opt-motion').checked,
      accent_color: latest?.appearance?.accent_color || '',
      custom_css: $('p-opt-css').value,
      background: Object.assign({}, latest?.appearance?.background || { mode: 'none' }, {
        focal_x: Number($('panel-bg-preview').dataset.fx || 50),
        focal_y: Number($('panel-bg-preview').dataset.fy || 50)
      })
    };
  }

  $('panel-use-glass-btn').addEventListener('click', async () => {
    try {
      await invoke('probe.themes.activate', {
        theme_id: 'builtin:liquid-glass',
        appearance: buildPanelAppearance()
      });
      toast('已启用「动态透明水玻璃（Liquid Glass）」');
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('切换水玻璃已提交审批');
      else toast('切换水玻璃失败：' + (err.message || '未知错误'));
    }
  });

  $('panel-save-appearance-btn').addEventListener('click', async () => {
    try {
      await invoke('probe.themes.activate', {
        theme_id: latest?.active_theme_id || 'builtin:classic',
        appearance: buildPanelAppearance()
      });
      toast('水玻璃外观参数已保存');
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('外观配置已提交审批');
      else toast('保存外观失败：' + (err.message || '未知错误'));
    }
  });

  function resetNodeForm() {
    $('node-id').value = '';
    $('node-name').value = '';
    $('node-region').value = 'JP';
    $('node-quota-mode').value = 'both';
    $('node-quota-gb').value = '';
    $('node-reset-day').value = '1';
    $('node-expires-at').value = '';
    $('add-node-btn').textContent = '添加节点并生成安装命令';
    $('cancel-edit-node-btn').hidden = true;
  }

  function hostConfirm(title, message) {
    if (!port) return Promise.resolve(false);
    const id = `cf_${++seq}`;
    return new Promise((resolve) => {
      pendingConfirm.set(id, { resolve });
      send({ t: 'ui.confirm', id, title, body: message, danger: true });
    });
  }

  $('cancel-edit-node-btn').addEventListener('click', resetNodeForm);

  $('admin-nodes-grid').addEventListener('click', async (e) => {
    const editBtn = e.target.closest('[data-edit-node]');
    if (editBtn) {
      const nodeId = editBtn.dataset.editNode;
      const node = (latest?.public_nodes || []).find((x) => x.id === nodeId);
      if (!node) return;
      $('node-id').value = node.id;
      $('node-name').value = node.name || '';
      $('node-region').value = node.region_code || 'HK';
      $('node-quota-mode').value = node.quota_mode || 'both';
      $('node-quota-gb').value = node.quota_bytes ? String(Math.round(Number(node.quota_bytes) / (1024 ** 3))) : '0';
      $('node-reset-day').value = String(node.reset_day || 1);
      if (typeof node.expires_in_days === 'number') {
        const dt = new Date(Date.now() + node.expires_in_days * 86400 * 1000);
        $('node-expires-at').value = dt.toISOString().slice(0, 10);
      } else {
        $('node-expires-at').value = '';
      }
      $('add-node-btn').textContent = `保存节点编辑 (${node.id})`;
      $('cancel-edit-node-btn').hidden = false;
      $('node-name').focus();
      return;
    }
    const delBtn = e.target.closest('[data-remove-node]');
    if (delBtn) {
      const nodeId = delBtn.dataset.removeNode;
      const ok = await hostConfirm('删除探针节点', `确认移除节点 ${nodeId} 并立即吊销其上报令牌？`);
      if (!ok) return;
      try {
        await invoke('probe.nodes.remove', { id: nodeId });
        toast(`已移除节点 ${nodeId}`);
        if ($('node-id').value === nodeId) resetNodeForm();
        void refresh();
      } catch (err) {
        if (err && err.awaitingApproval) toast('节点删除已提交，等待审批确认');
        else toast('移除节点失败：' + (err.message || '未知错误'));
      }
    }
  });

  function renderMonitors(monitors) {
    const grid = $('admin-monitors-grid');
    if (!grid) return;
    const list = Array.isArray(monitors) ? monitors : [];
    if (list.length === 0) {
      grid.innerHTML = '<div class="node-card"><div class="node-card-metrics">暂未配置三网或服务拨测目标，可点击右上角「一键添加三网参考目标」。</div></div>';
      return;
    }
    const carrierLabel = { ct: '电信 CT', cu: '联通 CU', cm: '移动 CM', global: '全球 Global', custom: '自定义' };
    grid.innerHTML = list.map((m) => {
      const st = m.last_status || 'unknown';
      const badgeCls = st === 'up' ? '' : 'warn';
      const stTxt = st === 'up' ? `正常 · ${Number(m.last_latency_ms || 0)}ms` : (st === 'degraded' ? `慢速 · ${Number(m.last_latency_ms || 0)}ms` : (st === 'down' ? '不可达' : '待检测'));
      return `<div class="node-card">
        <div class="node-card-head">
          <strong>[${esc(carrierLabel[m.carrier_tag] || m.carrier_tag || 'global')}] ${esc(m.name)}</strong>
          <span class="badge ${badgeCls}">${esc(stTxt)}</span>
        </div>
        <div class="node-card-metrics">${esc(String(m.kind || 'tcp').toUpperCase())} · <code>${esc(m.target_addr)}</code> · 每 ${Number(m.interval_sec || 30)}s</div>
        <div class="theme-item-actions">
          <button type="button" class="btn danger" data-remove-monitor="${esc(m.id)}">删除</button>
        </div>
      </div>`;
    }).join('');
  }

  $('node-public-origin')?.addEventListener('input', updateLoopbackOriginWarning);

  $('add-monitor-btn')?.addEventListener('click', async () => {
    const name = $('mon-name').value.trim();
    const kind = $('mon-kind').value;
    const carrier_tag = $('mon-carrier').value;
    const target_addr = $('mon-target').value.trim();
    const interval_sec = Math.min(600, Math.max(10, Math.floor(Number($('mon-interval').value || 30))));
    if (!name || !target_addr) {
      toast('请填写拨测目标名称与地址');
      return;
    }
    try {
      await invoke('probe.monitors.upsert', { name, kind, carrier_tag, target_addr, interval_sec, public_visible: true, enabled: true });
      $('mon-name').value = '';
      $('mon-target').value = '';
      toast(`拨测目标「${name}」已保存`);
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('拨测目标已提交，等待审批确认');
      else toast('添加拨测目标失败：' + (err.message || '未知错误'));
    }
  });

  $('preset-carriers-btn')?.addEventListener('click', async () => {
    const presets = [
      { id: 'carrier-ct', name: '电信骨干参考 (CT)', kind: 'tcp', carrier_tag: 'ct', target_addr: '202.96.128.86:53', interval_sec: 30, public_visible: true, enabled: true },
      { id: 'carrier-cu', name: '联通骨干参考 (CU)', kind: 'tcp', carrier_tag: 'cu', target_addr: '221.5.88.88:53', interval_sec: 30, public_visible: true, enabled: true },
      { id: 'carrier-cm', name: '移动骨干参考 (CM)', kind: 'tcp', carrier_tag: 'cm', target_addr: '211.136.192.6:53', interval_sec: 30, public_visible: true, enabled: true },
      { id: 'carrier-global', name: 'Cloudflare 全球参考', kind: 'tcp', carrier_tag: 'global', target_addr: '1.1.1.1:443', interval_sec: 30, public_visible: true, enabled: true }
    ];
    let okCount = 0;
    for (const p of presets) {
      try {
        await invoke('probe.monitors.upsert', p);
        okCount++;
      } catch (err) {
        if (err && err.awaitingApproval) {
          toast('三网参考目标已提交审批');
          return;
        }
      }
    }
    toast(`已配置 ${okCount} 个三网参考拨测目标`);
    void refresh();
  });

  $('admin-monitors-grid')?.addEventListener('click', async (e) => {
    const delBtn = e.target.closest('[data-remove-monitor]');
    if (!delBtn) return;
    const monId = delBtn.dataset.removeMonitor;
    const ok = await hostConfirm('删除拨测目标', `确认删除拨测目标 ${monId}？`);
    if (!ok) return;
    try {
      await invoke('probe.monitors.remove', { id: monId });
      toast(`已删除拨测目标 ${monId}`);
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) toast('删除拨测目标已提交审批');
      else toast('删除失败：' + (err.message || '未知错误'));
    }
  });

  $('add-node-btn').addEventListener('click', async () => {
    const id = $('node-id').value.trim();
    const name = $('node-name').value.trim();
    const region = $('node-region').value.trim() || 'HK';
    const quotaMode = $('node-quota-mode').value;
    const quotaGB = Math.max(0, Number($('node-quota-gb').value || 0));
    const resetDay = Math.min(31, Math.max(1, Math.floor(Number($('node-reset-day').value || 1))));
    const expDateStr = $('node-expires-at').value.trim();
    const expiresAt = expDateStr ? Math.floor(new Date(expDateStr + 'T00:00:00Z').getTime() / 1000) : 0;
    const overrideOrigin = normalizeOrigin($('node-public-origin')?.value || '');
    const effectiveOrigin = overrideOrigin || publicOrigin;
    if (!name) return;
    const payload = {
      name,
      region_code: region,
      quota_mode: quotaMode,
      quota_bytes: Math.floor(quotaGB * (1024 ** 3)),
      reset_day: resetDay,
      expires_at: Number.isFinite(expiresAt) && expiresAt > 0 ? expiresAt : 0
    };
    if (id) payload.id = id;
    if (effectiveOrigin) payload.public_origin = effectiveOrigin;
    if (
      panelTlsMode === 'self_signed' &&
      panelTlsSha256 &&
      !latest?.settings?.custom_domain &&
      (!effectiveOrigin || effectiveOrigin === publicOrigin)
    ) {
      payload.ca_sha256 = panelTlsSha256;
    }
    try {
      const res = await invoke('probe.nodes.upsert', payload);
      if (res.linux_install) {
        $('install-cmd-actions').hidden = false;
        $('install-cmd-box').hidden = false;
        $('install-cmd-box').textContent = formatInstallCmd(res.linux_install);
      }
      toast(id ? `节点「${name}」已更新` : `节点「${name}」已创建`);
      resetNodeForm();
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) {
        toast('节点变更已提交，等待审批确认');
      } else {
        $('conn-status').textContent = '节点操作失败：' + (err.message || '未知错误');
      }
    }
  });

  $('bind-domain-btn').addEventListener('click', async () => {
    const customDomain = $('domain-input').value.trim();
    const bindingTrack = $('track-select').value;
    if (!customDomain) return;
    try {
      const res = await invoke('probe.domain.bind', { custom_domain: customDomain, binding_track: bindingTrack });
      if (res.proxy_snippets?.nginx_baota_conf) {
        $('proxy-snippet-actions').hidden = false;
        $('proxy-snippet-box').hidden = false;
        $('proxy-snippet-box').textContent = res.proxy_snippets.nginx_baota_conf;
      }
      void refresh();
    } catch (err) {
      if (err && err.awaitingApproval) {
        toast('域名绑定已提交，等待审批确认');
      } else {
        $('conn-status').textContent = '域名绑定校验提示：' + (err.message || '未知错误');
      }
    }
  });

  $('copy-install-cmd-btn').addEventListener('click', () => {
    void hostCopy($('install-cmd-box').textContent || '', '已复制 Agent 安装命令').catch((err) => {
      $('conn-status').textContent = '复制失败：' + (err.message || '未知错误');
    });
  });

  $('copy-proxy-snippet-btn').addEventListener('click', () => {
    void hostCopy($('proxy-snippet-box').textContent || '', '已复制反代配置').catch((err) => {
      $('conn-status').textContent = '复制失败：' + (err.message || '未知错误');
    });
  });

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

  let lastSentHeight = 0;
  const ro = new ResizeObserver(() => {
    const height = Math.ceil($('probe-app').getBoundingClientRect().height) + 52;
    if (Math.abs(height - lastSentHeight) < 2) return;
    lastSentHeight = height;
    send({ t: 'ui.resize', height });
  });
  ro.observe($('probe-app'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent) return;
    if (event.data?.t === 'plugin.port' && event.ports[0] && !port) {
      port = event.ports[0];
      port.onmessage = (msg) => {
        const d = msg.data;
        if (!d || typeof d !== 'object') return;
        if (d.t === 'api.result' && pending.has(d.id)) {
          const req = pending.get(d.id);
          clearTimeout(req.deadline);
          pending.delete(d.id);
          if (d.ok === true) {
            const env = d.data;
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
            req.reject(new Error(extractErrorMessage(d.problem || d.error, '调用失败')));
          }
          return;
        }
        if (d.t === 'ui.confirm.result' && pendingConfirm.has(d.id)) {
          const req = pendingConfirm.get(d.id);
          pendingConfirm.delete(d.id);
          req.resolve(Boolean(d.ok && d.data?.confirmed));
          return;
        }
        if (d.t === 'ui.copy.result' && pendingCopy.has(d.id)) {
          const req = pendingCopy.get(d.id);
          clearTimeout(req.deadline);
          pendingCopy.delete(d.id);
          if (d.ok) req.resolve(true);
          else req.reject(new Error(extractErrorMessage(d.problem || d.error, '复制失败')));
          return;
        }
        if (d.t === 'ui.settings') {
          if (d.theme === 'light' || d.theme === 'dark') {
            root.dataset.theme = d.theme;
            root.style.colorScheme = d.theme;
          }
          if (d.motion === 'full' || d.motion === 'reduced' || d.motion === 'off') {
            root.dataset.motion = d.motion;
          }
          if (d.density === 'comfortable' || d.density === 'compact') {
            root.dataset.density = d.density;
          }
          if (d.tokens && typeof d.tokens === 'object') {
            if (d.tokens['--accent']) {
              root.style.setProperty('--cocoa', d.tokens['--accent']);
              root.style.setProperty('--berry', d.tokens['--accent']);
            }
            if (d.tokens['--on-accent']) root.style.setProperty('--on-cocoa', d.tokens['--on-accent']);
          }
          const nextOrigin = normalizeOrigin(d.public_origin);
          if (nextOrigin) publicOrigin = nextOrigin;
          if (typeof d.panel_tls_mode === 'string') panelTlsMode = d.panel_tls_mode;
          if (typeof d.panel_tls_sha256 === 'string') panelTlsSha256 = d.panel_tls_sha256;
          updateLoopbackOriginWarning();
        }
      };
      send({ t: 'ui.ready' });
      void refresh();
    }
  });

  window.addEventListener('pagehide', () => {
    ro.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.deadline);
      req.reject(new Error('页面已关闭'));
    }
    pending.clear();
    for (const req of pendingConfirm.values()) req.resolve(false);
    pendingConfirm.clear();
    for (const req of pendingCopy.values()) {
      clearTimeout(req.deadline);
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
  if (latest === null) {
    render({ public_nodes: [], dnc_capabilities: {}, themes: [] });
  }
})();
