// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';

  const origFetch = window.fetch ? window.fetch.bind(window) : null;
  const pending = new Map();
  let seq = 0;

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

  window.fetch = function qwqSandboxedFetch(input, init = {}) {
    const publicPath = matchPublicPath(input);
    if (!publicPath) {
      if (origFetch) return origFetch(input, init);
      return Promise.reject(new TypeError('fetch unavailable'));
    }

    const method = (init && init.method) || (input && typeof input === 'object' && input.method) || 'GET';
    const headers = extractHeaders((init && init.headers) || (input && typeof input === 'object' && input.headers));
    const body = init && typeof init.body === 'string' ? init.body : undefined;
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
  };

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
