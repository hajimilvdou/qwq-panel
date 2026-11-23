// SPDX-License-Identifier: AGPL-3.0-only
// 升级版探针主题隔离沙箱桥（替换 plugins/builtin/server.probe/portal_ui/theme-bridge.js）
//
// 核心修复与优化（对应 R2-BUG-13）：
//  1. 透明拦截 ./api/public/snapshot 响应，自动识别本地上传壁纸相对路径（./api/public/bg...），
//     经 postMessage 受控桥拉取图片二进制并转换为同沙箱内可直接渲染的 blob: URL；
//  2. 按原始 bg_url 强缓存复用 blob: URL，壁纸 revision 更新或页面卸载时自动调用 URL.revokeObjectURL 释放内存；
//  3. 使得任何自定义主题直接写 element.style.backgroundImage = `url("${snap.bg_url}")` 或 <img src>
//     即可在无同源 sandbox="allow-scripts" 隔离帧中 100% 正常渲染本地高清壁纸！
(() => {
  'use strict';

  const origFetch = window.fetch ? window.fetch.bind(window) : null;
  const pending = new Map();
  let seq = 0;

  let cachedBgSource = '';
  let cachedBgBlobUrl = '';
  let inflightBgPromise = null;

  const PUBLIC_API_RE = /(?:^|\/)(?:\.\/)?(api\/public\/(?:snapshot|unlock|bg))(\?.*)?$/;

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent) return;
    const msg = event.data;
    if (!msg || msg.type !== 'qwq-probe:fetch-result' || !pending.has(msg.id)) return;
    const entry = pending.get(msg.id);
    clearTimeout(entry.timer);
    pending.delete(msg.id);
    const headers = new Headers();
    if (msg.contentType) headers.set('Content-Type', msg.contentType);
    const payload = msg.bodyBuffer instanceof ArrayBuffer ? msg.bodyBuffer : String(msg.bodyText ?? '');
    entry.resolve(new Response(payload, { status: Number(msg.status || 200), headers }));
  });

  function extractHeaders(raw) {
    const out = {};
    if (!raw) return out;
    if (raw instanceof Headers) {
      raw.forEach((v, k) => { out[k] = v; });
      return out;
    }
    if (Array.isArray(raw)) {
      for (const pair of raw) {
        if (Array.isArray(pair) && pair.length >= 2) out[String(pair[0])] = String(pair[1]);
      }
      return out;
    }
    if (typeof raw === 'object') {
      for (const [k, v] of Object.entries(raw)) {
        out[k] = String(v);
      }
    }
    return out;
  }

  function matchPublicPath(input) {
    const rawUrl = typeof input === 'string'
      ? input
      : (input && typeof input.url === 'string' ? input.url : '');
    if (!rawUrl) return null;
    const cleaned = rawUrl.replace(/^https?:\/\/[^/]+/i, '');
    const m = PUBLIC_API_RE.exec(cleaned);
    if (!m) return null;
    return m[1] + (m[2] || '');
  }

  function rawBridgeFetch(publicPath, method, headers, body) {
    const id = 'qf_' + (++seq);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new TypeError('qwq theme bridge fetch timeout'));
      }, 15000);
      pending.set(id, { resolve, reject, timer });
      window.parent.postMessage({
        type: 'qwq-probe:fetch',
        id,
        path: publicPath,
        method,
        headers,
        body
      }, '*');
    });
  }

  async function resolveLocalBgBlobUrl(bgPath) {
    if (bgPath === cachedBgSource && cachedBgBlobUrl) {
      return cachedBgBlobUrl;
    }
    if (inflightBgPromise && bgPath === cachedBgSource) {
      return inflightBgPromise;
    }
    const normalized = matchPublicPath(bgPath);
    if (!normalized) return bgPath;

    const prevBlobUrl = cachedBgBlobUrl;
    cachedBgSource = bgPath;
    inflightBgPromise = (async () => {
      try {
        const resp = await rawBridgeFetch(normalized, 'GET', { Accept: 'image/*' }, undefined);
        if (!resp.ok) return '';
        const ct = resp.headers.get('Content-Type') || 'image/webp';
        const buf = await resp.arrayBuffer();
        const blobUrl = URL.createObjectURL(new Blob([buf], { type: ct }));
        cachedBgBlobUrl = blobUrl;
        if (prevBlobUrl && prevBlobUrl !== blobUrl) {
          URL.revokeObjectURL(prevBlobUrl);
        }
        return blobUrl;
      } catch {
        return '';
      } finally {
        inflightBgPromise = null;
      }
    })();
    return inflightBgPromise;
  }

  window.fetch = async function qwqSandboxedFetch(input, init = {}) {
    const publicPath = matchPublicPath(input);
    if (!publicPath) {
      if (origFetch) return origFetch(input, init);
      throw new TypeError('fetch unavailable in theme sandbox');
    }

    const method = (init && init.method) || (input && typeof input === 'object' && input.method) || 'GET';
    const headers = extractHeaders((init && init.headers) || (input && typeof input === 'object' && input.headers));
    const body = init && typeof init.body === 'string' ? init.body : undefined;

    const resp = await rawBridgeFetch(publicPath, method, headers, body);
    if (!resp.ok || !publicPath.startsWith('api/public/snapshot')) {
      return resp;
    }

    // 自动将本地壁纸相对路径升级为同沙箱可用的 blob: URL
    try {
      const cloned = resp.clone();
      const snap = await cloned.json();
      if (snap && typeof snap === 'object' && typeof snap.bg_url === 'string' && matchPublicPath(snap.bg_url)) {
        const blobUrl = await resolveLocalBgBlobUrl(snap.bg_url);
        if (blobUrl) {
          snap.bg_url = blobUrl;
          return new Response(JSON.stringify(snap), {
            status: resp.status,
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }
      } else if (cachedBgBlobUrl && (!snap || !snap.bg_url)) {
        URL.revokeObjectURL(cachedBgBlobUrl);
        cachedBgBlobUrl = '';
        cachedBgSource = '';
      }
    } catch {
      // 解析异常时回退原始响应
    }
    return resp;
  };

  window.addEventListener('pagehide', () => {
    if (cachedBgBlobUrl) {
      URL.revokeObjectURL(cachedBgBlobUrl);
      cachedBgBlobUrl = '';
      cachedBgSource = '';
    }
    for (const entry of pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(new TypeError('page closed'));
    }
    pending.clear();
  });

  // 将第三方主题中指向 ./admin 的导航链接安全转发给官方父页面跳转
  document.addEventListener('click', (event) => {
    const link = event.target && event.target.closest ? event.target.closest('a[href]') : null;
    if (!link) return;
    const href = (link.getAttribute('href') || '').trim();
    if (href === './admin' || href === 'admin' || href === '/admin' || href.endsWith('/admin')) {
      event.preventDefault();
      window.parent.postMessage({ type: 'qwq-probe:open-admin' }, '*');
    }
  });
})();
