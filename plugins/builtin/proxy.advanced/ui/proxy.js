// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== 高级代理插件沙箱桥接与三视图控制台 ======================== */
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const hash = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(hash.get('theme'), ['light', 'dark'], 'light');

  const VALID_ROUTES = ['/proxy', '/proxy/chains', '/proxy/tuning'];
  const ROUTE_TITLES = {
    '/proxy': '高级代理管理 · 用户配额与连接限制',
    '/proxy/chains': '链式代理管理 · 服务端出口与客户端多跳',
    '/proxy/tuning': '网络调优 & TCP Brutal 端口透明接管',
  };

  function detectInitialRoute() {
    const r = hash.get('route') || '';
    if (VALID_ROUTES.includes(r)) return r;
    for (const candidate of VALID_ROUTES.slice().reverse()) {
      if (location.pathname.endsWith(candidate)) return candidate;
    }
    return '/proxy';
  }

  let activeRoute = detectInitialRoute();
  const $ = (id) => document.getElementById(id);
  let port;
  let seq = 0;
  const pending = new Map();
  let cachedUsers = [];
  let cachedChains = [];
  let cachedInbounds = [];
  let cachedWARP = null;
  let cachedWARPPresets = {};

  const send = (msg) => { if (port) port.postMessage(msg); };
  const setStatus = (text) => { $('status').textContent = text; };

  function showBanner(msg, kind = 'ok') {
    const el = $('action-banner');
    el.className = `banner show ${kind}`;
    el.textContent = msg;
  }

  function clearNode(el) {
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

  function formatRate(kbps) {
    if (!kbps) return '不限';
    return kbps >= 1000 ? `${(kbps / 1000).toFixed(1)} Mbps` : `${kbps} kbps`;
  }

  function formatLimit(val) {
    return val > 0 ? String(val) : '不限';
  }

  function invoke(operation, payload = {}) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`操作 ${operation} 响应超时`));
      }, 20000);
      pending.set(id, { resolve, reject, timer });
      send({ t: 'api.invoke', id, operation, payload });
    });
  }

  async function runAction(label, fn) {
    try {
      setStatus(`正在执行：${label}…`);
      const res = await fn();
      setStatus('已连接');
      return res;
    } catch (err) {
      const msg = err?.message || '未知错误';
      showBanner(`${label}失败：${msg}`, 'err');
      setStatus('操作异常');
      return null;
    }
  }

  function switchRoute(route) {
    if (!VALID_ROUTES.includes(route)) return;
    activeRoute = route;
    $('page-title').textContent = ROUTE_TITLES[route] || '高级代理管理';
    for (const btn of document.querySelectorAll('#nav-tabs button')) {
      btn.classList.toggle('active', btn.dataset.route === route);
    }
    for (const sec of document.querySelectorAll('section[data-view]')) {
      sec.classList.toggle('hidden', sec.dataset.view !== route);
    }
    if (port) {
      void refreshActiveView();
    }
  }

  function handleMessage(data) {
    if (!data || typeof data !== 'object') return;
    if (data.t === 'api.result' && typeof data.id === 'string') {
      const req = pending.get(data.id);
      if (!req) return;
      clearTimeout(req.timer);
      pending.delete(data.id);
      if (data.ok === true) {
        const result = data.data?.result ?? data.data;
        if (!result || typeof result !== 'object' || data.data?.error) {
          req.reject(new Error(data.data?.error?.message || '操作返回异常'));
        } else {
          req.resolve(result);
        }
      } else {
        req.reject(new Error(data.error?.message || '操作调用失败'));
      }
    }
    if (data.t === 'ui.settings' && data.theme) {
      root.dataset.theme = pick(data.theme, ['light', 'dark'], root.dataset.theme);
    }
    if (data.t === 'ui.route' && typeof data.path === 'string' && VALID_ROUTES.includes(data.path)) {
      switchRoute(data.path);
    }
  }

  // ==================== 视图 1: 套餐与多用户渲染 ====================

  function renderPlans(plans) {
    const tbody = $('plans-body');
    clearNode(tbody);
    $('plans-summary').textContent = `${plans.length} 个套餐`;
    $('plans-detail').textContent = plans.length ? '含流量、速率、最大连接数与在线 IP 默认策略' : '尚未配置套餐';
    if (!plans.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'muted';
      td.textContent = '暂无套餐';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const p of plans) {
      const tr = document.createElement('tr');
      const cells = [
        p.id,
        p.name,
        p.quota_bytes > 0 ? formatBytes(p.quota_bytes) : '不限',
        `${formatRate(p.down_limit_kbps)} / ${formatRate(p.up_limit_kbps)}`,
        `${formatLimit(p.max_connections)} 连接 / ${formatLimit(p.max_ips)} IP`,
        `${p.billing_reset_day > 0 ? `每月 ${p.billing_reset_day} 日` : '不重置'} / ${p.validity_days > 0 ? `${p.validity_days} 天` : '长期'}`,
      ];
      for (const text of cells) {
        const td = document.createElement('td');
        td.textContent = String(text);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      $('copy-feedback').textContent = `已复制 ${label} 的订阅路径提示。`;
    } catch {
      $('copy-feedback').textContent = `请手动复制：${text}`;
    }
  }

  function renderUserSelects() {
    const sel = $('ul-user');
    const prev = sel.value;
    clearNode(sel);
    if (!cachedUsers.length) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '暂无用户';
      sel.appendChild(opt);
    } else {
      for (const u of cachedUsers) {
        const opt = document.createElement('option');
        opt.value = u.id;
        opt.textContent = `${u.display_name} (${u.id})`;
        sel.appendChild(opt);
      }
      if (prev && cachedUsers.some((u) => u.id === prev)) sel.value = prev;
    }
    const chainSel = $('ul-chain');
    const prevChain = chainSel.value;
    clearNode(chainSel);
    const emptyOpt = document.createElement('option');
    emptyOpt.value = '';
    emptyOpt.textContent = '（跟随全局默认 / 直连）';
    chainSel.appendChild(emptyOpt);
    for (const c of cachedChains) {
      const opt = document.createElement('option');
      opt.value = c.id;
      opt.textContent = `${c.name} (${c.id})`;
      chainSel.appendChild(opt);
    }
    if (prevChain && cachedChains.some((c) => c.id === prevChain)) chainSel.value = prevChain;
  }

  function renderUsers(users) {
    cachedUsers = users;
    renderUserSelects();
    const tbody = $('users-body');
    clearNode(tbody);
    if (!users.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 9;
      td.className = 'muted';
      td.textContent = '暂无代理用户';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const u of users) {
      const tr = document.createElement('tr');

      const tdName = document.createElement('td');
      tdName.textContent = `${u.display_name} (${u.id})`;
      tr.appendChild(tdName);

      const tdPlan = document.createElement('td');
      tdPlan.textContent = u.plan_id;
      tr.appendChild(tdPlan);

      const tdStatus = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${u.status}`;
      badge.textContent = u.status;
      tdStatus.appendChild(badge);
      tr.appendChild(tdStatus);

      const tdUsage = document.createElement('td');
      const used = (u.period_up_bytes || 0) + (u.period_down_bytes || 0);
      const quota = u.quota_bytes || 0;
      const pct = quota > 0 ? Math.min(100, Math.round((used / quota) * 100)) : 0;
      const text = document.createElement('div');
      text.textContent = quota > 0 ? `${formatBytes(used)} / ${formatBytes(quota)} (${pct}%)` : `${formatBytes(used)} / 不限`;
      tdUsage.appendChild(text);
      if (quota > 0) {
        const bar = document.createElement('div');
        bar.className = 'bar';
        const fill = document.createElement('span');
        fill.style.width = `${pct}%`;
        bar.appendChild(fill);
        tdUsage.appendChild(bar);
      }
      tr.appendChild(tdUsage);

      const tdConns = document.createElement('td');
      tdConns.textContent = `${u.active_connections || 0} / ${formatLimit(u.effective_max_connections || 0)}`;
      tr.appendChild(tdConns);

      const tdIPs = document.createElement('td');
      tdIPs.textContent = `${u.active_ips || 0} / ${formatLimit(u.effective_max_ips || 0)}`;
      tr.appendChild(tdIPs);

      const tdChain = document.createElement('td');
      tdChain.textContent = u.chain_id || '默认/直连';
      tr.appendChild(tdChain);

      const tdMark = document.createElement('td');
      tdMark.className = 'mono';
      tdMark.textContent = u.traffic_mark > 0 ? `0x${u.traffic_mark.toString(16).toUpperCase()}` : '未限速';
      tr.appendChild(tdMark);

      const tdAct = document.createElement('td');
      const btnCopy = document.createElement('button');
      btnCopy.type = 'button';
      btnCopy.className = 'btn sm ghost';
      btnCopy.textContent = '复制订阅说明';
      btnCopy.addEventListener('click', () => {
        void copyText(`${location.origin}/p/proxy.advanced/sub/<创建或轮换时一次性颁发的令牌>`, u.id);
      });
      tdAct.appendChild(btnCopy);
      tr.appendChild(tdAct);

      tbody.appendChild(tr);
    }
  }

  // ==================== 视图 2: 链式代理渲染 ====================

  function renderChains(chains) {
    cachedChains = chains;
    renderUserSelects();

    const nextSel = $('c-next');
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

    const tbody = $('chains-body');
    clearNode(tbody);
    if (!chains.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.className = 'muted';
      td.textContent = '暂无链式代理落地节点，可在上方表单添加。';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const c of chains) {
      const tr = document.createElement('tr');

      const tdId = document.createElement('td');
      tdId.textContent = `${c.name} (${c.id})`;
      tr.appendChild(tdId);

      const tdMode = document.createElement('td');
      tdMode.textContent = c.mode;
      tr.appendChild(tdMode);

      const tdAddr = document.createElement('td');
      tdAddr.className = 'mono';
      tdAddr.textContent = `${c.protocol}://${c.server}:${c.port}`;
      tr.appendChild(tdAddr);

      const tdHop = document.createElement('td');
      tdHop.textContent = `${c.next_hop_id ? `-> ${c.next_hop_id}` : '直出'}${c.apply_default ? ' · 默认' : ''}`;
      tr.appendChild(tdHop);

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
      tr.appendChild(tdMask);

      const tdSt = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${c.enabled ? 'ok' : 'warn'}`;
      badge.textContent = c.enabled ? '启用' : '停用';
      tdSt.appendChild(badge);
      tr.appendChild(tdSt);

      const tdOps = document.createElement('td');
      const wrap = document.createElement('div');
      wrap.className = 'actions';
      wrap.style.marginTop = '0';

      const btnProbe = document.createElement('button');
      btnProbe.type = 'button';
      btnProbe.className = 'btn sm ghost';
      btnProbe.textContent = 'TCP 探测';
      btnProbe.addEventListener('click', async () => {
        const r = await runAction(`探测 ${c.id}`, () => invoke('chains.probe', { id: c.id }));
        if (!r) return;
        if (r.reachable) {
          showBanner(`链式落地 ${c.id} (${r.server}:${r.port}) TCP 连通正常，延迟 ${r.latency_ms} ms`, 'ok');
        } else {
          showBanner(`链式落地 ${c.id} (${r.server}:${r.port}) 不可达：${r.error || '超时'}`, 'warn');
        }
      });
      wrap.appendChild(btnProbe);

      const btnDel = document.createElement('button');
      btnDel.type = 'button';
      btnDel.className = 'btn sm danger';
      btnDel.textContent = '删除';
      btnDel.addEventListener('click', async () => {
        if (!window.confirm(`确认删除链式代理节点 ${c.id}？引用它的用户将回退为直连。`)) return;
        const r = await runAction(`删除链式代理 ${c.id}`, () => invoke('chains.delete', { id: c.id }));
        if (r) {
          showBanner(`已删除链式代理节点 ${c.id}`, 'ok');
          void refreshChains();
        }
      });
      wrap.appendChild(btnDel);

      tdOps.appendChild(wrap);
      tr.appendChild(tdOps);
      tbody.appendChild(tr);
    }
  }

  // ==================== 视图 3: tcpfit 调优 + TCP Brutal 渲染 ====================

  function updateOversendPreview() {
    const bw = Math.max(1, Number($('b-bw').value) || 100);
    const pct = Math.min(250, Math.max(100, Number($('b-oversend').value) || 125));
    const eff = ((bw * pct) / 100).toFixed(1);
    $('b-eff-preview').textContent = `折算等效发包速率：${eff} Mbps（基准 ${bw} Mbps × ${pct}%）`;
  }

  function renderTuningPlan(plan) {
    const bdpKB = Math.round((plan.bdp_bytes || 0) / 1024);
    const maxMB = ((plan.max_buffer_bytes || 0) / (1024 * 1024)).toFixed(1);
    const budgetMB = ((plan.mem_budget_bytes || 0) / (1024 * 1024)).toFixed(0);
    $('t-plan-summary').textContent =
      `推导完成：BDP ≈ ${bdpKB} KiB · 安全单流缓冲区上限 ${maxMB} MiB（受物理内存预算 ${budgetMB} MiB 保护）· 选定拥塞算法：${plan.selected_cc}`;

    const swapWarn = $('t-swap-warn');
    if (plan.swap_recommendation) {
      swapWarn.className = 'banner warn show';
      swapWarn.textContent = plan.swap_recommendation;
    } else {
      swapWarn.className = 'banner warn';
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
      for (const val of [
        `#r${s.revision}`,
        s.reason,
        `${s.role} · ${s.bandwidth_mbps}Mbps / ${s.rtt_ms}ms`,
        s.applied ? '已生效' : '基线 / 演练',
      ]) {
        const td = document.createElement('td');
        td.textContent = String(val);
        tr.appendChild(td);
      }
      const tdOp = document.createElement('td');
      const btnRb = document.createElement('button');
      btnRb.type = 'button';
      btnRb.className = 'btn sm ghost';
      btnRb.textContent = '回滚至此快照';
      btnRb.addEventListener('click', async () => {
        if (!window.confirm(`确认回滚宿主机 sysctl 至快照 #r${s.revision} (${s.reason})？`)) return;
        const r = await runAction(`回滚快照 #r${s.revision}`, () =>
          invoke('tuning.rollback', { snapshot_id: s.id, dry_run: false }));
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
      ? `eBPF=${env.ebpf_pinned ? 'pinned' : 'kmod'} · 安装命令: ${env.install_hint || ''}`
      : `安装提示: ${env.install_hint || ''}`;

    const guide = $('b-guidance');
    if (env.degraded_guidance) {
      guide.className = 'banner warn show';
      guide.textContent = `${env.degraded_guidance} 推荐部署命令：${env.install_hint || ''}`;
    } else {
      guide.className = 'banner warn';
      guide.textContent = '';
    }

    cachedInbounds = data.tcp_inbounds || [];
    const presetSel = $('b-inbound-preset');
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

    const bindings = data.bindings || [];
    const metrics = data.live_listeners || [];
    $('brutal-mini-count').textContent = `${metrics.filter((m) => m.running).length} / ${bindings.length} 运行`;

    const bBody = $('b-bindings-body');
    clearNode(bBody);
    if (!bindings.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'muted';
      td.textContent = '暂无 Brutal 接管绑定。您可以只为某个 TCP 订阅（如 vless-tcp）创建绑定。';
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
          `${b.enable_in_sub ? '订阅自动切端口' : '仅手动接管'} · ${b.enabled ? '启用' : '停用'}`,
        ]) {
          const td = document.createElement('td');
          td.textContent = String(val);
          tr.appendChild(td);
        }
        const tdOp = document.createElement('td');
        const btnDel = document.createElement('button');
        btnDel.type = 'button';
        btnDel.className = 'btn sm danger';
        btnDel.textContent = '删除';
        btnDel.addEventListener('click', async () => {
          if (!window.confirm(`确认删除 Brutal 接管绑定 ${b.id}？`)) return;
          const r = await runAction(`删除绑定 ${b.id}`, () => invoke('brutal.binding.delete', { id: b.id }));
          if (r) {
            showBanner(`已删除 Brutal 接管绑定 ${b.id}`, 'ok');
            void refreshTuningAndBrutal();
          }
        });
        tdOp.appendChild(btnDel);
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
      td.textContent = '尚无已启动的透明接管监听，请点击“立即应用 / 热重载所有接管端口”。';
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

  // ==================== 数据拉取 ====================

  async function refreshProxyHome() {
    const [overview, plansResp, usersResp, trafficResp, chainsResp, brutalResp] = await Promise.all([
      invoke('proxy.overview', { include_traffic_status: false }),
      invoke('plans.list', { limit: 100 }),
      invoke('users.list', { limit: 256 }),
      invoke('traffic.status', { include_classes: true }),
      invoke('chains.list', {}),
      invoke('brutal.status', {}),
    ]);
    $('overview-value').textContent = `${overview.active_users ?? 0} / ${overview.total_users ?? 0} 活跃`;
    $('overview-sub').textContent = overview.sub || '运行正常';
    if (trafficResp.supported) {
      $('traffic-status').textContent = `已启用 (${trafficResp.egress_interface || '默认'})`;
      $('traffic-detail').textContent = `当前下发 ${(trafficResp.classes || []).length} 条规则${trafficResp.uplink_ifb_supported ? '，支持上行 IFB' : '，仅下行整形'}`;
    } else {
      $('traffic-status').textContent = 'HTB 已降级';
      $('traffic-detail').textContent = trafficResp.degraded_reason || '当前内核不支持 HTB 流量整形';
    }
    cachedChains = chainsResp.chains || [];
    renderPlans(plansResp.plans || []);
    renderUsers(usersResp.users || []);
    renderBrutalStatus(brutalResp);
  }

  // ==================== Cloudflare WARP 渲染与绑定 ====================

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
      ? (w.enabled ? `已启用 (${(w.account_type || 'free').toUpperCase()})` : `已注册 · 未启用`)
      : '未注册';
    $('w-account').textContent = w.registered
      ? `账号 ${w.account_id || '—'}${w.license_key_masked ? ` · License ${w.license_key_masked}` : ''}`
      : '点击下方「一键注册 Cloudflare WARP」自动申请 WireGuard 凭据';
    $('w-addrs').textContent = w.registered
      ? [w.address_v4, w.address_v6].filter(Boolean).join(' / ') || '—'
      : '—';
    $('w-reserved').textContent = w.registered && Array.isArray(w.reserved) && w.reserved.length
      ? `reserved: [${w.reserved.join(', ')}]${w.client_id ? ` (${w.client_id})` : ''}`
      : 'reserved: —';
    $('w-ep-summary').textContent = w.endpoint || 'engage.cloudflareclient.com:2408';
    $('w-mode-summary').textContent = WARP_MODE_LABELS[w.routing_mode] || w.routing_mode || '—';
    $('w-sync-state').textContent = w.registered ? (w.last_synced_rev ? '已同步至 core.xray' : '待同步生效') : '未配置';
    $('w-sync-rev').textContent = w.last_synced_rev ? `core.xray rev: ${w.last_synced_rev}` : '保存绑定后自动热重载 Xray';

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
      sp.textContent = '尚未检测到 core.xray 代理入站端口，请先初始化代理核心或直接选择“全局/域名模式”。';
      box.appendChild(sp);
    } else {
      for (const ib of inbounds) {
        const lbl = document.createElement('label');
        lbl.className = 'check';
        lbl.style.padding = '6px 10px';
        lbl.style.border = '1px solid var(--line)';
        lbl.style.borderRadius = '8px';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.dataset.warpPort = ib.profile_id;
        cb.checked = Boolean(ib.bound);
        lbl.appendChild(cb);
        const txt = document.createElement('span');
        txt.textContent = ` ${ib.label}${ib.enabled ? '' : '（已停用）'}`;
        lbl.appendChild(txt);
        box.appendChild(lbl);
      }
    }
  }

  function readSelectedWARPPorts() {
    const out = [];
    for (const cb of document.querySelectorAll('input[data-warp-port]')) {
      if (cb.checked) out.push(cb.dataset.warpPort);
    }
    return out;
  }

  function readWARPDomainsInput() {
    return $('w-domains').value
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function appendWARPPreset(key) {
    const preset = cachedWARPPresets[key] || [];
    const cur = new Set(readWARPDomainsInput());
    for (const d of preset) cur.add(d);
    $('w-domains').value = Array.from(cur).join('\n');
    $('w-mode').value = 'domains';
  }

  async function refreshChains() {
    const [chainsRes, warpRes] = await Promise.all([
      invoke('chains.list', {}),
      invoke('warp.status', {}),
    ]);
    renderChains(chainsRes.chains || []);
    renderWARPStatus(warpRes);
  }

  async function refreshTuningAndBrutal() {
    const [tRes, bRes] = await Promise.all([
      invoke('tuning.status', {}),
      invoke('brutal.status', {}),
    ]);
    renderTuningStatus(tRes);
    renderBrutalStatus(bRes);
  }

  async function refreshActiveView() {
    if (!port) return;
    setStatus('正在同步状态…');
    try {
      if (activeRoute === '/proxy') await refreshProxyHome();
      else if (activeRoute === '/proxy/chains') await refreshChains();
      else if (activeRoute === '/proxy/tuning') await refreshTuningAndBrutal();
      setStatus('已连接');
    } catch (err) {
      setStatus(`读取失败：${err.message || '未知错误'}`);
    }
  }

  // ==================== 交互事件绑定 ====================

  for (const btn of document.querySelectorAll('#nav-tabs button')) {
    btn.addEventListener('click', () => switchRoute(btn.dataset.route));
  }
  $('refresh').addEventListener('click', () => { void refreshActiveView(); });

  $('btn-plan-save').addEventListener('click', async () => {
    const id = $('p-id').value.trim();
    const name = $('p-name').value.trim();
    const quotaGB = Math.max(0, Number($('p-quota-gb').value) || 0);
    const payload = {
      id,
      name,
      quota_bytes: Math.round(quotaGB * 1024 * 1024 * 1024),
      down_limit_kbps: Math.max(0, Number($('p-down').value) || 0),
      up_limit_kbps: Math.max(0, Number($('p-up').value) || 0),
      max_connections: Math.max(0, Number($('p-max-conns').value) || 0),
      max_ips: Math.max(0, Number($('p-max-ips').value) || 0),
      billing_reset_day: 1,
      validity_days: 30,
    };
    const r = await runAction('保存套餐', () => invoke('plans.upsert', payload));
    if (r) {
      showBanner(`套餐 ${r.plan?.id || id} 已保存（默认最大连接 ${r.plan?.max_connections ?? 0} / 最大 IP ${r.plan?.max_ips ?? 0}）`, 'ok');
      void refreshProxyHome();
    }
  });

  $('btn-user-limits').addEventListener('click', async () => {
    const userId = $('ul-user').value.trim();
    if (!userId) {
      showBanner('请先选择目标用户', 'warn');
      return;
    }
    const payload = {
      user_id: userId,
      max_connections_override: Number($('ul-conns').value),
      max_ips_override: Number($('ul-ips').value),
      chain_id: $('ul-chain').value,
    };
    const r = await runAction(`更新用户 ${userId} 连接与链式策略`, () => invoke('users.set_limits', payload));
    if (r) {
      showBanner(`用户 ${userId} 生效上限：${formatLimit(r.user?.effective_max_connections || 0)} 连接 / ${formatLimit(r.user?.effective_max_ips || 0)} IP`, 'ok');
      void refreshProxyHome();
    }
  });

  $('btn-nft-preview').addEventListener('click', async () => {
    const r = await runAction('生成 nftables 连接限流规则', () => invoke('users.connections.status', { include_nftables: true }));
    if (r) {
      const pre = $('nft-preview');
      pre.textContent = r.nftables_rules || '# 当前没有需要下发的 nftables 连接限制规则';
      pre.classList.remove('hidden');
    }
  });

  $('btn-w-preset-ai').addEventListener('click', () => appendWARPPreset('ai'));
  $('btn-w-preset-stream').addEventListener('click', () => appendWARPPreset('streaming'));
  $('btn-w-preset-google').addEventListener('click', () => appendWARPPreset('google'));

  $('btn-warp-register').addEventListener('click', async () => {
    const payload = {
      license_key: $('w-license').value.trim(),
      endpoint: $('w-endpoint').value.trim(),
      mtu: Number($('w-mtu').value) || 1280,
      enabled: $('w-enabled').checked,
      routing_mode: $('w-mode').value,
      bound_profile_ids: readSelectedWARPPorts(),
      domains: readWARPDomainsInput(),
      sync_core: true,
    };
    const r = await runAction('一键注册 Cloudflare WARP', () => invoke('warp.register', payload));
    if (r) {
      $('w-license').value = '';
      const msg = r.sync_warning
        ? `Cloudflare WARP 注册成功（${r.warp?.address_v4 || ''}），提示：${r.sync_warning}`
        : `Cloudflare WARP 注册成功并已同步至 core.xray（IPv4: ${r.warp?.address_v4 || ''}）`;
      showBanner(msg, r.sync_warning ? 'warn' : 'ok');
      void refreshChains();
    }
  });

  $('btn-warp-save').addEventListener('click', async () => {
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
        if (/^\d+(,\s*\d+){2,3}$/.test(cid)) {
          payload.reserved = cid.split(',').map((n) => Number(n.trim()));
        } else {
          payload.client_id = cid;
        }
      }
    }
    const r = await runAction('保存 WARP 绑定并同步 Xray', () => invoke('warp.configure', payload));
    if (r) {
      $('w-manual-priv').value = '';
      const msg = r.sync_warning
        ? `WARP 配置已保存，提示：${r.sync_warning}`
        : `WARP 端口绑定与分流规则已同步生效（core.xray rev: ${r.core_revision || '最新'}）`;
      showBanner(msg, r.sync_warning ? 'warn' : 'ok');
      void refreshChains();
    }
  });

  $('btn-warp-probe').addEventListener('click', async () => {
    const r = await runAction('探测 WARP 端点与本机 IP', () => invoke('warp.probe', {}));
    if (r) {
      if (r.best_endpoint) {
        $('w-endpoint').value = r.best_endpoint;
      }
      const pre = $('warp-output');
      pre.textContent = JSON.stringify(r, null, 2);
      pre.classList.remove('hidden');
      const tr = r.host_trace || {};
      showBanner(
        `探测完成：推荐端点 ${r.best_endpoint || '无'} · 本机出口 ${tr.ip || '未知'} (${tr.loc || '-'} / colo=${tr.colo || '-'} / warp=${tr.warp || 'off'})`,
        r.best_endpoint ? 'ok' : 'warn',
      );
    }
  });

  $('btn-warp-preview').addEventListener('click', () => {
    const pre = $('warp-output');
    pre.textContent = cachedWARP?.xray_preview_json || '{}';
    pre.classList.remove('hidden');
  });

  $('btn-warp-delete').addEventListener('click', async () => {
    if (!window.confirm('确认注销并清除本地 Cloudflare WARP 凭据？绑定的代理端口将恢复直连。')) return;
    const r = await runAction('清除 Cloudflare WARP', () => invoke('warp.delete', {}));
    if (r) {
      showBanner(r.sync_warning ? `已清除 WARP，提示：${r.sync_warning}` : '已清除 WARP 并恢复直连', r.sync_warning ? 'warn' : 'ok');
      void refreshChains();
    }
  });

  $('btn-chain-save').addEventListener('click', async () => {
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
      $('c-pass').value = '';
      showBanner(`链式代理节点 ${r.chain?.id || payload.id} 已加密保存`, 'ok');
      void refreshChains();
    }
  });

  $('btn-chain-preview').addEventListener('click', async () => {
    const r = await runAction('预览 Xray 服务端链式出口', () => invoke('chains.preview', {}));
    if (r) {
      const pre = $('chain-xray-preview');
      pre.textContent = r.xray_json || '{}';
      pre.classList.remove('hidden');
    }
  });

  function readTcpfitInput() {
    return {
      role: $('t-role').value,
      bandwidth_mbps: Number($('t-bw').value) || 200,
      rtt_ms: Number($('t-rtt').value) || 150,
      mem_budget_pct: Number($('t-mem-pct').value) || 12,
      prefer_cc: $('t-prefer-cc').value,
    };
  }

  $('btn-tuning-plan').addEventListener('click', async () => {
    const r = await runAction('推导 tcpfit 调优方案', () => invoke('tuning.plan', readTcpfitInput()));
    if (r) {
      renderTuningPlan(r);
      showBanner('已完成 tcpfit 动态 BDP 与安全内存预算推导', 'ok');
    }
  });

  $('btn-tuning-dry').addEventListener('click', async () => {
    const r = await runAction('tcpfit 演练与基线保存', () =>
      invoke('tuning.apply', { ...readTcpfitInput(), dry_run: true }));
    if (r) {
      if (r.plan) renderTuningPlan(r.plan);
      showBanner(r.output || '已完成演练并保存宿主机基线快照', 'ok');
      void refreshTuningAndBrutal();
    }
  });

  $('btn-tuning-apply').addEventListener('click', async () => {
    if (!window.confirm('确认将 tcpfit 参数写入 /etc/sysctl.d/99-qwq-tcpfit.conf 并执行 sysctl -p？应用前会自动保留可回滚基线快照。')) return;
    const r = await runAction('应用 tcpfit 调优到宿主机', () =>
      invoke('tuning.apply', { ...readTcpfitInput(), dry_run: false }));
    if (r) {
      if (r.plan) renderTuningPlan(r.plan);
      showBanner(r.applied ? '已成功应用 tcpfit 内核调优并保存基线快照' : `写入/生效提示：${r.error || r.output}`, r.applied ? 'ok' : 'warn');
      void refreshTuningAndBrutal();
    }
  });

  $('btn-tuning-sweep').addEventListener('click', async () => {
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

  $('b-inbound-preset').addEventListener('change', () => {
    const tag = $('b-inbound-preset').value;
    const found = cachedInbounds.find((ib) => ib.inbound_tag === tag);
    if (!found) return;
    $('b-id').value = `brutal-${found.inbound_tag}`;
    $('b-tag').value = found.inbound_tag;
    $('b-proto').value = found.protocol || 'tcp';
    $('b-target').value = String(found.target_port || 443);
    $('b-listen').value = String((found.target_port || 443) + 2000);
  });

  $('b-oversend-range').addEventListener('input', () => {
    $('b-oversend').value = $('b-oversend-range').value;
    updateOversendPreview();
  });
  $('b-oversend').addEventListener('input', () => {
    $('b-oversend-range').value = $('b-oversend').value;
    updateOversendPreview();
  });
  $('b-bw').addEventListener('input', updateOversendPreview);

  $('btn-brutal-save').addEventListener('click', async () => {
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
      showBanner(`已保存 ${r.binding?.id || payload.id}（超发 ${r.binding?.oversend_pct ?? payload.oversend_pct}%，有效 ${Number(r.binding?.effective_mbps || 0).toFixed(1)} Mbps），请点击“立即应用”生效。`, 'ok');
      void refreshTuningAndBrutal();
    }
  });

  $('btn-brutal-apply').addEventListener('click', async () => {
    const r = await runAction('应用并热重载 Brutal 接管端口', () => invoke('brutal.apply', {}));
    if (r) {
      showBanner(r.applied ? `已热重载 ${(r.live_listeners || []).length} 个透明接管端口` : `部分监听启动异常：${r.error}`, r.applied ? 'ok' : 'warn');
      void refreshTuningAndBrutal();
    }
  });

  // 初始化路由与宿主桥接
  switchRoute(activeRoute);
  updateOversendPreview();

  const observer = new ResizeObserver(() => {
    const height = Math.ceil($('proxy-root').getBoundingClientRect().height) + 16;
    send({ t: 'ui.resize', height });
  });
  observer.observe($('proxy-root'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (msg) => handleMessage(msg.data);
    send({ t: 'ui.ready' });
    void refreshActiveView();
  });

  window.addEventListener('pagehide', () => {
    observer.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
    }
    pending.clear();
    port?.close();
    port = undefined;
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
