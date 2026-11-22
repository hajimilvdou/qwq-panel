// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== 宿主桥接与有限轮询 ======================== */
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (value, options, fallback) => options.includes(value) ? value : fallback;
  const initial = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(initial.get('theme'), ['light', 'dark'], 'light');
  root.dataset.motion = pick(initial.get('motion'), ['full', 'reduced', 'off'], 'reduced');
  const $ = (id) => document.getElementById(id);
  let port, timer, paused = false, visible = true, busy = false, pendingRefresh = false, range = '5m', sequence = 0;
  const pending = new Map();
  const canRefresh = () => !paused && visible && Boolean(port);
  const value = (n) => typeof n === 'number' && Number.isFinite(n) && n >= 0 ? n : null;
  const status = (message) => { $('status').textContent = message; };
  const send = (message) => { if (port) port.postMessage(message); };

  function invoke(operation, payload = {}) {
    if (!port || pending.size >= 2) return Promise.reject(new Error('连接暂不可用'));
    const id = String(++sequence);
    return new Promise((resolve, reject) => {
      const deadline = setTimeout(() => { pending.delete(id); reject(new Error('宿主响应超时')); }, 5000);
      pending.set(id, { resolve, reject, deadline });
      send({ t: 'api.invoke', id, operation, payload });
    });
  }

  function accept(data) {
    if (!data || typeof data !== 'object') return;
    if (data.t === 'api.result' && typeof data.id === 'string') {
      const request = pending.get(data.id);
      if (!request) return;
      clearTimeout(request.deadline);
      pending.delete(data.id);
      if (data.ok === true) {
        const result = data.data?.result ?? data.data;
        if (!result || typeof result !== 'object' || data.data?.error) request.reject(new Error('指标暂不可用'));
        else request.resolve(result);
      } else request.reject(new Error('宿主指标暂不可用'));
    }
    if (data.t === 'ui.settings') {
      root.dataset.theme = pick(data.theme, ['light', 'dark'], root.dataset.theme);
      root.dataset.motion = pick(data.motion, ['full', 'reduced', 'off'], 'reduced');
      if (typeof data.visible === 'boolean') visible = data.visible;
      schedule();
    }
  }

  function meter(name, raw) {
    const n = value(raw), element = $(name + '-meter');
    $(name + '-value').textContent = n === null ? '—' : n.toFixed(1) + '%';
    element.style.setProperty('--fill', (n === null ? 0 : Math.min(n, 100)) + '%');
    if (n === null) element.removeAttribute('aria-valuenow');
    else element.setAttribute('aria-valuenow', String(Math.min(n, 100)));
  }

  function points(raw) {
    if (!Array.isArray(raw)) return [];
    return raw.slice(-720).filter((p) => p && value(p.t) !== null).sort((a,b) => a.t - b.t);
  }

  function plot(id, source, fields, maximum, divisor = 1) {
    const rows = points(source), svg = $(id), lines = svg.querySelectorAll('path.line');
    const numbers = rows.flatMap((p) => fields.map((f) => value(p[f]))).filter((n) => n !== null);
    const max = maximum ?? Math.max(1, ...numbers.map((n) => n / divisor));
    const first = rows[0]?.t ?? 0, last = rows.at(-1)?.t ?? first;
    fields.forEach((field, index) => {
      const data = [];
      let connected = false;
      // --------------------------------------------------------------------
      // 每个指标独立分段，空值后的有效点必须重新起笔，不能跨停机区间连线。
      // --------------------------------------------------------------------
      for (const p of rows) {
        const n = value(p[field]);
        if (n === null) { connected = false; continue; }
        const x = last === first ? 0 : (p.t-first)/(last-first)*600;
        const y = 160-Math.min(1,n/divisor/max)*140;
        data.push((connected ? 'L' : 'M')+x.toFixed(2)+','+y.toFixed(2));
        connected = true;
      }
      lines[index].setAttribute('d', data.join(' '));
    });
    if (id === 'net-chart') $('net-note').textContent = numbers.length ? '峰值刻度 '+max.toFixed(1)+' Mbps' : '等待连续的网络采样';
  }

  async function refresh() {
    if (!canRefresh()) return;
    if (busy) { pendingRefresh = true; return; }
    clearTimeout(timer);
    busy = true;
    pendingRefresh = false;
    const requestedRange = range;
    try {
      const snapshot = await invoke('monitor.snapshot');
      if (!canRefresh() || requestedRange !== range) return;
      const history = requestedRange === '1h' ? (await invoke('monitor.history', { range:'1h' })).points : snapshot.points;
      if (!canRefresh() || requestedRange !== range) return;
      const current = snapshot.current ?? {};
      meter('cpu', current.cpu_pct); meter('mem', current.mem_pct); meter('disk', current.disk_pct);
      const mount = typeof snapshot.primary_disk_mount === 'string' ? snapshot.primary_disk_mount : '';
      $('disk-title').textContent = mount === '/' ? '根盘' : '磁盘';
      $('disk-note').textContent = mount ? mount+' 挂载点使用率' : '等待挂载点采样';
      const rx = value(current.net_rx_bps), tx = value(current.net_tx_bps);
      $('rx-value').textContent = rx === null ? '—' : (rx/1e6).toFixed(2);
      $('tx-value').textContent = tx === null ? '—' : (tx/1e6).toFixed(2);
      const at = value(current.t);
      $('sample-time').textContent = at ? '最近采样 '+new Date(at).toLocaleTimeString() : '等待宿主采样';
      status(snapshot.status === 'ready' ? '采集中' : '等待有效采样');
      plot('net-chart', history, ['net_rx_bps','net_tx_bps'], null, 1e6);
      plot('resource-chart', history, ['cpu_pct','mem_pct'], 100);
    } catch { if (canRefresh() && requestedRange === range) status('指标暂不可用，请稍后重试'); }
    finally {
      busy = false;
      // 忙碌期间的刷新合并成一个最新请求；暂停、隐藏或卸载时不继续排队。
      if (pendingRefresh && canRefresh()) void refresh();
      else schedule();
    }
  }

  function schedule() {
    clearTimeout(timer);
    if (canRefresh()) timer = setTimeout(refresh, 1500);
  }
  $('pause').addEventListener('click', () => {
    paused = !paused;
    $('pause').textContent = paused ? '继续' : '暂停';
    $('pause').setAttribute('aria-pressed', String(paused));
    if (paused) status('已暂停'); else void refresh();
    schedule();
  });
  document.querySelectorAll('[data-range]').forEach((button) => button.addEventListener('click', () => {
    range = button.dataset.range;
    document.querySelectorAll('[data-range]').forEach((other) => other.setAttribute('aria-pressed', String(other === button)));
    void refresh();
  }));
  const observer = new ResizeObserver(() => send({ t:'ui.resize', height:Math.ceil($('monitor').getBoundingClientRect().height)+8 }));
  observer.observe($('monitor'));
  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0]; port.onmessage = (message) => accept(message.data);
    send({ t:'ui.ready' }); void refresh();
  });
  window.addEventListener('pagehide', () => {
    pendingRefresh = false;
    clearTimeout(timer); observer.disconnect();
    for (const request of pending.values()) { clearTimeout(request.deadline); request.reject(new Error('页面已关闭')); }
    pending.clear(); port?.close(); port = undefined;
  });
  window.parent.postMessage({ t:'plugin.hello', kit_major:1 }, '*');
})();
