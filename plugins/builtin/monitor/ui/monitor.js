// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== 宿主桥接与有限轮询 ======================== */
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (value, options, fallback) => options.includes(value) ? value : fallback;
  const initial = new URLSearchParams(location.hash.slice(1));
  const initialTheme = pick(initial.get('theme'), ['light', 'dark'], 'light');
  root.dataset.theme = initialTheme;
  root.style.colorScheme = initialTheme;
  root.dataset.motion = pick(initial.get('motion'), ['full', 'reduced', 'off'], 'reduced');
  root.dataset.density = pick(initial.get('density'), ['comfortable', 'compact'], 'comfortable');
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

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function accept(data) {
    if (!data || typeof data !== 'object') return;
    if (data.t === 'api.result' && pending.has(data.id)) {
      const request = pending.get(data.id);
      clearTimeout(request.deadline);
      pending.delete(data.id);
      if (data.ok === true) {
        const env = data.data;
        if (env && typeof env === 'object' && (env.status === 'AWAITING_APPROVAL' || env.approval_id)) {
          const err = new Error('等待审批确认');
          err.awaitingApproval = true;
          err.approvalId = env.approval_id;
          request.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'EXPIRED')) {
          request.reject(new Error(extractErrorMessage(env.error, '指标暂不可用')));
          return;
        }
        const result = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        if (!result || typeof result !== 'object') request.reject(new Error('指标暂不可用'));
        else request.resolve(result);
      } else request.reject(new Error(extractErrorMessage(data.problem || data.error, '宿主指标暂不可用')));
    }
    if (data.t === 'ui.settings') {
      const nextTheme = pick(data.theme, ['light', 'dark'], root.dataset.theme);
      root.dataset.theme = nextTheme;
      root.style.colorScheme = nextTheme;
      root.dataset.motion = pick(data.motion, ['full', 'reduced', 'off'], 'reduced');
      if (data.density === 'comfortable' || data.density === 'compact') {
        root.dataset.density = data.density;
      }
      if (data.tokens && typeof data.tokens === 'object') {
        for (const [k, v] of Object.entries(data.tokens)) {
          if (k.startsWith('--') && typeof v === 'string' && !/[;{}<>]/.test(v)) {
            root.style.setProperty(k, v.trim());
          }
        }
      }
      if (typeof data.visible === 'boolean') visible = data.visible;
      schedule();
    }
  }

  function meter(name, raw, level) {
    const n = value(raw), element = $(name + '-meter'), card = $(name + '-card');
    $(name + '-value').textContent = n === null ? '—' : n.toFixed(1) + '%';
    element.style.setProperty('--fill', (n === null ? 0 : Math.min(n, 100)) + '%');
    if (n === null) element.removeAttribute('aria-valuenow');
    else element.setAttribute('aria-valuenow', String(Math.min(n, 100)));
    if (card) {
      card.dataset.level = pick(level, ['ok', 'warn', 'bad', 'unavailable'], n === null ? 'unavailable' : 'ok');
    }
  }

  function formatUptime(sec) {
    const s = value(sec);
    if (s === null) return '—';
    const total = Math.floor(s);
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const mins = Math.floor((total % 3600) / 60);
    if (days > 0) return `${days} 天 ${hours} 小时 ${mins} 分`;
    if (hours > 0) return `${hours} 小时 ${mins} 分`;
    return `${mins} 分 ${total % 60} 秒`;
  }

  function points(raw) {
    if (!Array.isArray(raw)) return [];
    return raw.slice(-720).filter((p) => p && value(p.t) !== null).sort((a, b) => a.t - b.t);
  }

  function plot(id, source, fields, maximum, divisor = 1) {
    const rows = points(source), svg = $(id), lines = svg.querySelectorAll('path.line');
    const numbers = rows.flatMap((p) => fields.map((f) => value(p[f]))).filter((n) => n !== null);
    const max = maximum ?? Math.max(1, ...numbers.map((n) => n / divisor));
    const first = rows[0]?.t ?? 0, last = rows.at(-1)?.t ?? first;
    fields.forEach((field, index) => {
      if (!lines[index]) return;
      const data = [];
      let connected = false;
      // 每个指标独立分段，空值后的有效点必须重新起笔，不能跨停机区间连线。
      for (const p of rows) {
        const n = value(p[field]);
        if (n === null) { connected = false; continue; }
        const x = last === first ? 0 : (p.t - first) / (last - first) * 600;
        const y = 160 - Math.min(1, n / divisor / max) * 140;
        data.push((connected ? 'L' : 'M') + x.toFixed(2) + ',' + y.toFixed(2));
        connected = true;
      }
      lines[index].setAttribute('d', data.join(' '));
    });
    if (id === 'net-chart') $('net-note').textContent = numbers.length ? '峰值刻度 ' + max.toFixed(1) + ' Mbps' : '等待连续的网络采样';
    if (id === 'disk-io-chart') $('disk-io-note').textContent = numbers.length ? '峰值刻度 ' + max.toFixed(2) + ' MB/s' : '等待连续磁盘块设备采样';
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
      const history = requestedRange === '1h' ? (await invoke('monitor.history', { range: '1h' })).points : snapshot.points;
      if (!canRefresh() || requestedRange !== range) return;
      const current = snapshot.current ?? {};
      const levels = snapshot.levels ?? {};
      const primaryDisk = Array.isArray(snapshot.disks)
        ? snapshot.disks.find((d) => d.mount === snapshot.primary_disk_mount) || snapshot.disks[0]
        : null;

      meter('cpu', current.cpu_pct, levels.cpu);
      meter('mem', current.mem_pct, levels.mem);
      meter('swap', current.swap_percent, levels.swap);
      meter('disk', current.disk_pct, levels.disk || primaryDisk?.level);

      const iowait = value(current.cpu_iowait_percent);
      $('cpu-note').textContent = iowait === null ? '处理器使用率 · IOWait —' : `处理器使用率 · IOWait ${iowait.toFixed(1)}%`;
      $('iowait-value').textContent = iowait === null ? '—' : `${iowait.toFixed(1)}%`;

      const swapUsedMB = value(current.swap_used_mb);
      $('swap-note').textContent = swapUsedMB === null ? '未启用 Swap 或等待采样' : `已用 ${swapUsedMB.toFixed(1)} MiB`;

      const mount = typeof snapshot.primary_disk_mount === 'string' ? snapshot.primary_disk_mount : '';
      $('disk-title').textContent = mount === '/' ? '根盘' : '磁盘';
      const extraMounts = Array.isArray(snapshot.disks) && snapshot.disks.length > 1 ? ` (共 ${snapshot.disks.length} 挂载点)` : '';
      $('disk-note').textContent = mount ? `${mount} 挂载点使用率${extraMounts}` : '等待挂载点采样';

      const l1 = value(current.load1), l5 = value(current.load5), l15 = value(current.load15);
      $('load-value').textContent = `${l1 === null ? '—' : l1.toFixed(2)} / ${l5 === null ? '—' : l5.toFixed(2)} / ${l15 === null ? '—' : l15.toFixed(2)}`;
      $('uptime-value').textContent = formatUptime(snapshot.uptime_seconds);

      const rx = value(current.net_rx_bps), tx = value(current.net_tx_bps);
      $('rx-value').textContent = rx === null ? '—' : (rx / 1e6).toFixed(2);
      $('tx-value').textContent = tx === null ? '—' : (tx / 1e6).toFixed(2);

      const dRead = value(current.disk_read_bps), dWrite = value(current.disk_write_bps);
      const readMBs = dRead === null ? null : dRead / (1024 * 1024);
      const writeMBs = dWrite === null ? null : dWrite / (1024 * 1024);
      $('disk-read-value').textContent = readMBs === null ? '—' : readMBs.toFixed(2);
      $('disk-write-value').textContent = writeMBs === null ? '—' : writeMBs.toFixed(2);
      $('disk-io-value').textContent = (readMBs === null && writeMBs === null)
        ? '—'
        : `读 ${readMBs === null ? '—' : readMBs.toFixed(2)} / 写 ${writeMBs === null ? '—' : writeMBs.toFixed(2)} MB/s`;

      const at = value(current.t);
      $('sample-time').textContent = at ? '最近采样 ' + new Date(at).toLocaleTimeString() : '等待宿主采样';
      status(snapshot.status === 'ready' ? '采集中' : '等待有效采样');
      syncThresholdsFromSnapshot(snapshot.thresholds);
      plot('net-chart', history, ['net_rx_bps', 'net_tx_bps'], null, 1e6);
      plot('resource-chart', history, ['cpu_pct', 'mem_pct', 'cpu_iowait_percent'], 100);
      plot('disk-io-chart', history, ['disk_read_bps', 'disk_write_bps'], null, 1024 * 1024);
    } catch { if (canRefresh() && requestedRange === range) status('指标暂不可用，请稍后重试'); }
    finally {
      busy = false;
      // 忙碌期间的刷新合并成一个最新请求；暂停、隐藏或卸载时不继续排队。
      if (pendingRefresh && canRefresh()) void refresh();
      else schedule();
    }
  }

  let thresholdsHydrated = false;
  function syncThresholdsFromSnapshot(th) {
    if (!th || typeof th !== 'object' || thresholdsHydrated) return;
    if (th.cpu) {
      if (typeof th.cpu.warn === 'number') $('th-cpu-warn').value = String(th.cpu.warn);
      if (typeof th.cpu.crit === 'number') $('th-cpu-crit').value = String(th.cpu.crit);
    }
    if (th.mem) {
      if (typeof th.mem.warn === 'number') $('th-mem-warn').value = String(th.mem.warn);
      if (typeof th.mem.crit === 'number') $('th-mem-crit').value = String(th.mem.crit);
    }
    if (th.disk) {
      if (typeof th.disk.warn === 'number') $('th-disk-warn').value = String(th.disk.warn);
      if (typeof th.disk.crit === 'number') $('th-disk-crit').value = String(th.disk.crit);
    }
    thresholdsHydrated = true;
  }

  $('btn-save-thresholds')?.addEventListener('click', async () => {
    const payload = {
      cpu: { warn: Number($('th-cpu-warn').value), crit: Number($('th-cpu-crit').value) },
      mem: { warn: Number($('th-mem-warn').value), crit: Number($('th-mem-crit').value) },
      disk: { warn: Number($('th-disk-warn').value), crit: Number($('th-disk-crit').value) },
    };
    for (const [label, lv] of [['CPU', payload.cpu], ['内存', payload.mem], ['磁盘', payload.disk]]) {
      if (!Number.isFinite(lv.warn) || !Number.isFinite(lv.crit) || lv.warn < 0 || lv.warn >= lv.crit || lv.crit > 100) {
        $('th-status').textContent = `${label} 阈值无效：需满足 0 ≤ 警告 < 严重 ≤ 100`;
        return;
      }
    }
    $('th-status').textContent = '保存中…';
    try {
      await invoke('monitor.thresholds.set', payload);
      $('th-status').textContent = '告警阈值已保存并热生效';
      void refresh();
    } catch (err) {
      $('th-status').textContent = '保存失败：' + (err?.message || '请确认拥有写入权限');
    }
  });

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
  const observer = new ResizeObserver(() => send({ t: 'ui.resize', height: Math.ceil($('monitor').getBoundingClientRect().height) + 8 }));
  observer.observe($('monitor'));
  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0]; port.onmessage = (message) => accept(message.data);
    send({ t: 'ui.ready' }); void refresh();
  });
  window.addEventListener('pagehide', () => {
    pendingRefresh = false;
    clearTimeout(timer); observer.disconnect();
    for (const request of pending.values()) { clearTimeout(request.deadline); request.reject(new Error('页面已关闭')); }
    pending.clear(); port?.close(); port = undefined;
  });
  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
