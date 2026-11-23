// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';

  const scriptSrc = document.currentScript?.src || '';
  const portalRoot = (() => {
    if (scriptSrc) {
      try {
        const u = new URL(scriptSrc, window.location.href);
        return u.pathname.replace(/\/theme-sandbox\.js$/i, '').replace(/\/+$/, '');
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

  const iframe = document.getElementById('theme-frame');
  if (!iframe) return;

  const rawEntry = (iframe.dataset.entry || 'index.html').replace(/^\/+/, '');
  const safeEntry = rawEntry && !rawEntry.includes('..') && !rawEntry.includes('\\') ? rawEntry : 'index.html';
  iframe.src = resolvePortalPath(`theme-frame/${safeEntry}`);

  const ALLOWED_PUBLIC_PATH = /^api\/public\/(snapshot|unlock|bg)(\?[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%-]*)?$/;

  window.addEventListener('message', async (event) => {
    if (event.source !== iframe.contentWindow) return;
    const msg = event.data;
    if (!msg || typeof msg !== 'object') return;

    if (msg.type === 'qwq-probe:open-admin') {
      window.location.assign(resolvePortalPath('admin'));
      return;
    }

    if (msg.type === 'qwq-probe:title' && typeof msg.title === 'string') {
      const cleanTitle = msg.title.trim().slice(0, 120);
      if (cleanTitle) document.title = cleanTitle;
      return;
    }

    if (msg.type !== 'qwq-probe:fetch' || typeof msg.id !== 'string') return;
    const id = msg.id;
    const rawPath = String(msg.path || '').replace(/^\.\//, '').replace(/^\/+/, '');
    const m = ALLOWED_PUBLIC_PATH.exec(rawPath);
    if (!m) {
      iframe.contentWindow.postMessage({
        type: 'qwq-probe:fetch-result',
        id,
        ok: false,
        status: 403,
        contentType: 'application/json; charset=utf-8',
        bodyText: JSON.stringify({ error: 'SANDBOX_ROUTE_FORBIDDEN' })
      }, '*');
      return;
    }

    const endpoint = m[1];
    const method = String(msg.method || 'GET').toUpperCase();
    if ((endpoint === 'snapshot' && method !== 'GET') ||
        (endpoint === 'unlock' && method !== 'POST') ||
        (endpoint === 'bg' && method !== 'GET' && method !== 'HEAD')) {
      iframe.contentWindow.postMessage({
        type: 'qwq-probe:fetch-result',
        id,
        ok: false,
        status: 405,
        contentType: 'application/json; charset=utf-8',
        bodyText: JSON.stringify({ error: 'METHOD_NOT_ALLOWED' })
      }, '*');
      return;
    }

    const reqHeaders = {};
    if (msg.headers && typeof msg.headers === 'object') {
      for (const [k, v] of Object.entries(msg.headers)) {
        const lk = String(k).toLowerCase();
        if (lk === 'x-probe-visitor-token' || lk === 'content-type' || lk === 'accept') {
          reqHeaders[k] = String(v);
        }
      }
    }

    const fetchOpts = {
      method,
      headers: reqHeaders,
      credentials: 'omit',
      cache: endpoint === 'bg' ? 'default' : 'no-store'
    };
    if (endpoint === 'unlock' && typeof msg.body === 'string') {
      fetchOpts.body = msg.body;
    }

    try {
      const resp = await fetch(resolvePortalPath(rawPath), fetchOpts);
      const contentType = resp.headers.get('Content-Type') || 'application/octet-stream';
      if (endpoint === 'bg') {
        const buf = await resp.arrayBuffer();
        iframe.contentWindow.postMessage({
          type: 'qwq-probe:fetch-result',
          id,
          ok: resp.ok,
          status: resp.status,
          contentType,
          bodyBuffer: buf
        }, '*', [buf]);
        return;
      }
      const bodyText = await resp.text();
      iframe.contentWindow.postMessage({
        type: 'qwq-probe:fetch-result',
        id,
        ok: resp.ok,
        status: resp.status,
        contentType,
        bodyText
      }, '*');
    } catch {
      iframe.contentWindow.postMessage({
        type: 'qwq-probe:fetch-result',
        id,
        ok: false,
        status: 502,
        contentType: 'application/json; charset=utf-8',
        bodyText: JSON.stringify({ error: 'BRIDGE_FETCH_FAILED' })
      }, '*');
    }
  });
})();
