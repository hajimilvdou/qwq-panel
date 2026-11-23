// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== 轻量沙箱宿主桥接与只读摘要展示 ======================== */
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, opts, fb) => (opts.includes(v) ? v : fb);
  const initial = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(initial.get('theme'), ['light', 'dark'], 'light');
  root.dataset.motion = pick(initial.get('motion'), ['full', 'reduced', 'off'], 'reduced');

  const $ = (id) => document.getElementById(id);
  let port;
  let seq = 0;
  const pending = new Map();

  const send = (msg) => { if (port) port.postMessage(msg); };
  const setStatus = (text) => { $('status').textContent = text; };

  function invoke(operation, payload = {}) {
    if (!port || pending.size >= 2) return Promise.reject(new Error('宿主通道未就绪'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        pending.delete(id);
        reject(new Error('宿主响应超时'));
      }, 5000);
      pending.set(id, { resolve, reject, deadline });
      send({ t: 'api.invoke', id, operation, payload });
    });
  }

  function render(data) {
    $('enabled-count').textContent = String(typeof data.enabled === 'number' ? data.enabled : 0);
    $('total-count').textContent = String(typeof data.total === 'number' ? data.total : 0);
    $('zone-count').textContent = String(typeof data.zones === 'number' ? data.zones : 0);
    $('summary-sub').textContent = typeof data.sub === 'string' && data.sub ? data.sub : '暂无同步记录';
  }

  async function refresh() {
    setStatus('正在读取本地摘要...');
    try {
      const data = await invoke('providers.status', {});
      render(data);
      setStatus('已连接');
    } catch (err) {
      if (err && err.awaitingApproval) {
        setStatus('等待审批确认');
      } else {
        setStatus(err?.message ? `摘要暂不可用：${err.message}` : '摘要暂不可用');
      }
    }
  }

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function accept(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.t === 'api.result' && pending.has(msg.id)) {
      const req = pending.get(msg.id);
      clearTimeout(req.deadline);
      pending.delete(msg.id);
      if (msg.ok === true) {
        const env = msg.data;
        if (env && typeof env === 'object' && (env.status === 'AWAITING_APPROVAL' || env.approval_id)) {
          const err = new Error('等待审批确认');
          err.awaitingApproval = true;
          err.approvalId = env.approval_id;
          req.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'EXPIRED')) {
          req.reject(new Error(extractErrorMessage(env.error, '摘要无效')));
          return;
        }
        const result = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        if (!result || typeof result !== 'object') req.reject(new Error('摘要无效'));
        else req.resolve(result);
      } else {
        req.reject(new Error(extractErrorMessage(msg.problem || msg.error, '宿主拒绝请求')));
      }
    }
    if (msg.t === 'ui.settings') {
      root.dataset.theme = pick(msg.theme, ['light', 'dark'], root.dataset.theme);
      root.dataset.motion = pick(msg.motion, ['full', 'reduced', 'off'], 'reduced');
    }
  }

  $('refresh').addEventListener('click', () => { void refresh(); });
  const observer = new ResizeObserver(() => {
    send({ t: 'ui.resize', height: Math.ceil($('dns-app').getBoundingClientRect().height) + 8 });
  });
  observer.observe($('dns-app'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (e) => accept(e.data);
    send({ t: 'ui.ready' });
    void refresh();
  });

  window.addEventListener('pagehide', () => {
    observer.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.deadline);
      req.reject(new Error('页面已关闭'));
    }
    pending.clear();
    port?.close();
    port = undefined;
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
