// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== TLS 证书插件完整控制台 ======================== */
(() => {
  'use strict';

  const root = document.documentElement;
  const pick = (v, opts, fb) => (opts.includes(v) ? v : fb);
  const initial = new URLSearchParams(location.hash.slice(1));
  const applyVisualSettings = (s) => {
    if (!s) return;
    const theme = pick(s.theme, ['light', 'dark'], root.dataset.theme || 'light');
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    if (s.motion) root.dataset.motion = pick(s.motion, ['full', 'reduced', 'off'], 'reduced');
    if (s.density) root.dataset.density = pick(s.density, ['comfortable', 'compact'], 'comfortable');
    if (s.tokens && typeof s.tokens === 'object') {
      for (const [k, v] of Object.entries(s.tokens)) {
        if (k.startsWith('--') && typeof v === 'string') {
          root.style.setProperty(k, v);
          if (k === '--accent') root.style.setProperty('--cocoa', v);
        }
      }
    }
  };
  applyVisualSettings({
    theme: initial.get('theme') || 'light',
    motion: initial.get('motion') || 'reduced',
    density: initial.get('density') || 'comfortable',
  });

  const $ = (id) => document.getElementById(id);

  let port = null;
  let seq = 0;
  const pending = new Map();

  const state = {
    tab: 'list',
    certificates: [],
    selectedCertId: '',
    detailCert: null,
    lastRenewal: null,
    filterText: '',
    confirmAction: null,
  };

  function send(msg) {
    if (port) port.postMessage(msg);
  }

  function setStatus(text) {
    $('status').textContent = text;
  }

  function showBanner(message, tone) {
    const el = $('feedback-banner');
    el.textContent = message;
    el.dataset.tone = tone || '';
    el.classList.remove('hidden');
  }

  function clearBanner() {
    const el = $('feedback-banner');
    el.textContent = '';
    delete el.dataset.tone;
    el.classList.add('hidden');
  }

  function makeAttemptId(prefix) {
    const rand = Math.random().toString(36).slice(2, 8);
    return `${prefix}-${Date.now()}-${rand}`;
  }

  function parseList(raw) {
    return String(raw || '')
      .split(/[\n,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function defaultExpiryRFC3339() {
    const d = new Date(Date.now() + 90 * 24 * 3600 * 1000);
    return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.title || errObj.code || fallback;
  }

  function invoke(operation, payload = {}, timeoutMs = 45000, opts = null) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`操作 ${operation} 响应超时`));
      }, timeoutMs);
      pending.set(id, { resolve, reject, deadline });
      const msg = { t: 'api.invoke', id, operation, payload };
      if (opts && opts.subject) msg.subject = opts.subject;
      if (opts && opts.expected_revision) msg.expected_revision = opts.expected_revision;
      send(msg);
    });
  }

  function certInvokeOpts(certId, allowCreate = false) {
    const existing = (state.certificates || []).find((c) => c.id === certId)
      || (state.detailCert && state.detailCert.id === certId ? state.detailCert : null);
    const rev = existing?.revision || (allowCreate ? 'absent' : '');
    const opts = { subject: `plugins/tls.certificates/resources/certificates/${certId}` };
    if (rev) opts.expected_revision = rev;
    return opts;
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
          const err = new Error(`操作已提交，等待宿主审批确认（审批单：${env.approval_id || '待确认'}）`);
          err.awaitingApproval = true;
          err.approvalId = env.approval_id || '';
          req.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'EXPIRED')) {
          req.reject(new Error(extractErrorMessage(env.error, `任务状态异常：${env.status || 'FAILED'}`)));
          return;
        }
        const result = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        req.resolve(result && typeof result === 'object' ? result : {});
      } else {
        req.reject(new Error(extractErrorMessage(msg.problem || msg.error, '宿主拒绝请求')));
      }
      return;
    }
    if (msg.t === 'ui.settings') {
      applyVisualSettings(msg);
      return;
    }
    if (msg.t === 'ui.viewport') {
      const vpTop = Math.max(0, Math.round(Number(msg.offsetTopPx ?? msg.visibleTop ?? msg.scroll_top) || 0));
      state.viewportTop = vpTop;
      root.style.setProperty('--host-modal-top', `${Math.max(16, vpTop + 24)}px`);
      notifyResize();
    }
  }

  function handleActionError(prefix, err) {
    if (err && err.awaitingApproval) {
      showBanner(err.message, 'warn');
      setStatus('等待宿主审批');
      return;
    }
    const msg = err && err.message ? err.message : '未知错误';
    showBanner(`${prefix}：${msg}`, 'bad');
    setStatus(`操作异常：${msg}`);
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }

  function latestGenerationOf(cert) {
    const gens = Array.isArray(cert.generations) ? cert.generations : [];
    if (!gens.length) return null;
    const matched = gens.find((g) => g.number === cert.latest_generation);
    return matched || gens[gens.length - 1];
  }

  function expiryInfo(notAfterStr) {
    if (!notAfterStr) return { text: '未签发', tone: 'warn', sub: '—' };
    const ts = Date.parse(notAfterStr);
    if (!Number.isFinite(ts)) return { text: notAfterStr, tone: '', sub: '' };
    const days = Math.floor((ts - Date.now()) / (24 * 3600 * 1000));
    const dateLabel = notAfterStr.slice(0, 10);
    if (days < 0) return { text: `已过期 ${Math.abs(days)} 天`, tone: 'bad', sub: dateLabel };
    if (days <= 14) return { text: `剩余 ${days} 天`, tone: 'bad', sub: dateLabel };
    if (days <= 30) return { text: `剩余 ${days} 天`, tone: 'warn', sub: dateLabel };
    return { text: `剩余 ${days} 天`, tone: 'ok', sub: dateLabel };
  }

  function statusBadgeTone(status) {
    const s = String(status || '').toLowerCase();
    if (s === 'ready' || s === 'active' || s === 'verified' || s === 'deployed') return 'badge-ok';
    if (s.includes('fail') || s.includes('error') || s.includes('revok') || s === 'not_ready') return 'badge-bad';
    if (s.includes('pending') || s.includes('warn') || s.includes('wait')) return 'badge-warn';
    return 'badge-accent';
  }

  function shortFingerprint(fp) {
    if (!fp) return '—';
    const clean = String(fp);
    return clean.length > 22 ? `${clean.slice(0, 22)}…` : clean;
  }

  function switchTab(tabName) {
    state.tab = tabName;
    const buttons = document.querySelectorAll('.tab-btn');
    for (const btn of buttons) {
      const active = btn.dataset.tab === tabName;
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
    }
    const panels = [
      ['list', 'panel-list'],
      ['issue', 'panel-issue'],
      ['bindings', 'panel-bindings'],
    ];
    for (const [key, id] of panels) {
      $(id).hidden = key !== tabName;
    }
    notifyResize();
  }

  function renderSummary(summary) {
    const total = typeof summary.total === 'number' ? summary.total : state.certificates.length;
    const ready = typeof summary.ready === 'number' ? summary.ready : 0;
    const attention = typeof summary.attention === 'number' ? summary.attention : 0;
    $('total-count').textContent = String(total);
    $('ready-count').textContent = String(ready);
    $('attention-count').textContent = String(attention);
    $('summary-sub').textContent = typeof summary.sub === 'string' && summary.sub ? summary.sub : '暂无证书记录';

    $('kpi-ready-card').dataset.level = ready > 0 ? 'ok' : '';
    $('kpi-attention-card').dataset.level = attention > 0 ? 'bad' : '';
  }

  function renderCertSelectors() {
    const selects = [$('bind-cert-id'), $('renew-cert-id')];
    for (const sel of selects) {
      const prev = sel.value;
      sel.textContent = '';
      if (!state.certificates.length) {
        const opt = el('option', '', '（暂无已登记证书）');
        opt.value = '';
        sel.appendChild(opt);
        continue;
      }
      for (const cert of state.certificates) {
        const sansText = Array.isArray(cert.sans) && cert.sans.length ? ` (${cert.sans[0]})` : '';
        const opt = el('option', '', `${cert.id}${sansText} · gen#${cert.latest_generation || 0}`);
        opt.value = cert.id;
        sel.appendChild(opt);
      }
      if (prev && state.certificates.some((c) => c.id === prev)) {
        sel.value = prev;
      }
    }
    syncBindGenerationFromSelectedCert();
  }

  function syncBindGenerationFromSelectedCert() {
    const certId = $('bind-cert-id').value;
    const cert = state.certificates.find((c) => c.id === certId);
    if (cert && cert.latest_generation >= 1) {
      $('bind-generation').value = String(cert.latest_generation);
    }
  }

  function renderCertTable() {
    const tbody = $('cert-tbody');
    tbody.textContent = '';

    let totalBindings = 0;
    for (const c of state.certificates) {
      totalBindings += Array.isArray(c.bindings) ? c.bindings.length : 0;
    }
    $('binding-count').textContent = String(totalBindings);

    const kw = state.filterText.trim().toLowerCase();
    const list = state.certificates.filter((cert) => {
      if (!kw) return true;
      if (String(cert.id || '').toLowerCase().includes(kw)) return true;
      const sans = Array.isArray(cert.sans) ? cert.sans : [];
      return sans.some((s) => String(s).toLowerCase().includes(kw));
    });

    if (!list.length) {
      const tr = el('tr');
      const td = el('td', 'empty-state', state.certificates.length ? '没有匹配筛选条件的证书' : '尚未登记任何 TLS 证书，可前往「申请 ACME 证书 / 导入 PEM」创建。');
      td.colSpan = 7;
      tr.appendChild(td);
      tbody.appendChild(tr);
      notifyResize();
      return;
    }

    for (const cert of list) {
      const gen = latestGenerationOf(cert);
      const exp = expiryInfo(gen ? gen.not_after : '');
      const bindings = Array.isArray(cert.bindings) ? cert.bindings : [];

      const tr = el('tr');

      // ID & Purpose
      const tdId = el('td');
      tdId.appendChild(el('div', 'mono', cert.id));
      const metaRow = el('div', 'pill-list');
      metaRow.appendChild(el('span', `badge ${statusBadgeTone(cert.status)}`, cert.status || 'unknown'));
      metaRow.appendChild(el('span', 'badge', cert.purpose || 'tls_server'));
      metaRow.appendChild(el('span', 'badge', `gen#${cert.latest_generation || 0}`));
      tdId.appendChild(metaRow);
      tr.appendChild(tdId);

      // SANs
      const tdSans = el('td');
      const sanList = el('div', 'pill-list');
      for (const s of (cert.sans || [])) {
        sanList.appendChild(el('span', 'badge mono', s));
      }
      tdSans.appendChild(sanList);
      tr.appendChild(tdSans);

      // Issuer
      const tdIssuer = el('td');
      tdIssuer.appendChild(el('div', '', gen ? (gen.issuer || '—') : '尚未签发'));
      if (gen && gen.trust) {
        tdIssuer.appendChild(el('div', 'muted', `信任级别：${gen.trust}`));
      }
      tr.appendChild(tdIssuer);

      // Expiry
      const tdExp = el('td');
      const expCls = exp.tone ? `badge badge-${exp.tone}` : 'badge';
      tdExp.appendChild(el('span', expCls, exp.text));
      if (exp.sub) {
        tdExp.appendChild(el('div', 'muted', exp.sub));
      }
      tr.appendChild(tdExp);

      // Fingerprint
      const tdFp = el('td');
      const fpSpan = el('span', 'mono', shortFingerprint(gen ? gen.fingerprint : ''));
      if (gen && gen.fingerprint) fpSpan.title = gen.fingerprint;
      tdFp.appendChild(fpSpan);
      tr.appendChild(tdFp);

      // Consumers
      const tdBind = el('td');
      tdBind.appendChild(el('span', bindings.length ? 'badge badge-accent' : 'badge', `${bindings.length} 个消费者`));
      if (bindings.length) {
        const plugins = Array.from(new Set(bindings.map((b) => b.plugin_id).filter(Boolean)));
        tdBind.appendChild(el('div', 'muted', plugins.join(', ')));
      }
      tr.appendChild(tdBind);

      // Actions
      const tdAct = el('td');
      const actRow = el('div', 'actions-row');

      const btnDetail = el('button', 'btn btn-sm', '详情');
      btnDetail.type = 'button';
      btnDetail.addEventListener('click', () => { void loadCertificateDetail(cert.id); });
      actRow.appendChild(btnDetail);

      const btnTest = el('button', 'btn btn-sm', '测试签发');
      btnTest.type = 'button';
      btnTest.addEventListener('click', () => { void runTestCertificate(cert); });
      actRow.appendChild(btnTest);

      const btnRenew = el('button', 'btn btn-sm', '立即续期');
      btnRenew.type = 'button';
      btnRenew.addEventListener('click', () => { openRenewModal(cert.id); });
      actRow.appendChild(btnRenew);

      const btnRemove = el('button', 'btn btn-sm btn-danger', '删除');
      btnRemove.type = 'button';
      btnRemove.addEventListener('click', () => {
        openConfirm(
          `删除证书 ${cert.id}`,
          `确认永久删除证书资源「${cert.id}」及其全部加密材料？若仍存在消费者绑定引用，宿主将拒绝删除。`,
          () => removeCertificate(cert.id)
        );
      });
      actRow.appendChild(btnRemove);

      tdAct.appendChild(actRow);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    }

    notifyResize();
  }

  function renderDetailCard(cert) {
    const card = $('cert-detail-card');
    if (!cert) {
      card.classList.add('hidden');
      notifyResize();
      return;
    }
    state.detailCert = cert;
    state.selectedCertId = cert.id;
    card.classList.remove('hidden');
    $('detail-title').textContent = `证书详情：${cert.id}`;
    $('detail-sub').textContent = `版本 ${cert.revision || '—'} · 用途 ${cert.purpose || '—'} · 状态 ${cert.status || '—'}`;

    const meta = $('detail-meta');
    meta.textContent = '';
    const pairs = [
      ['证书 ID', cert.id],
      ['综合状态', cert.status || '—'],
      ['最新证书代', `gen#${cert.latest_generation || 0}`],
      ['SAN 域名', (cert.sans || []).join(', ') || '—'],
      ['消费者数量', String((cert.bindings || []).length)],
    ];
    for (const [k, v] of pairs) {
      const box = el('div');
      box.appendChild(el('div', 'detail-kv-label', k));
      box.appendChild(el('div', 'detail-kv-value mono', v));
      meta.appendChild(box);
    }

    // Generations table
    const genBody = $('detail-gen-tbody');
    genBody.textContent = '';
    const gens = Array.isArray(cert.generations) ? cert.generations : [];
    if (!gens.length) {
      const tr = el('tr');
      const td = el('td', 'empty-state', '尚无已签发证书代');
      td.colSpan = 7;
      tr.appendChild(td);
      genBody.appendChild(tr);
    } else {
      for (const g of gens) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', `#${g.number}${g.number === cert.latest_generation ? ' (最新)' : ''}`));
        tr.appendChild(el('td', '', g.trust || '—'));
        tr.appendChild(el('td', '', g.issuer || '—'));
        tr.appendChild(el('td', 'mono', g.not_before || '—'));
        tr.appendChild(el('td', 'mono', g.not_after || '—'));
        const tdFp = el('td', 'mono', shortFingerprint(g.fingerprint));
        tdFp.title = g.fingerprint || '';
        tr.appendChild(tdFp);

        const tdAct = el('td');
        if (g.number !== cert.latest_generation) {
          const btnDelGen = el('button', 'btn btn-sm btn-danger', '清理历史代');
          btnDelGen.type = 'button';
          btnDelGen.addEventListener('click', () => {
            openConfirm(
              `删除历史证书代 #${g.number}`,
              `确认删除证书「${cert.id}」的历史代 #${g.number}？仅当该代未被任何消费者引用时才会被宿主删除。`,
              () => removeGeneration(cert.id, g.number)
            );
          });
          tdAct.appendChild(btnDelGen);
        } else {
          tdAct.appendChild(el('span', 'muted', '当前代'));
        }
        tr.appendChild(tdAct);
        genBody.appendChild(tr);
      }
    }

    // Bindings table
    const bindBody = $('detail-bind-tbody');
    bindBody.textContent = '';
    const bindings = Array.isArray(cert.bindings) ? cert.bindings : [];
    if (!bindings.length) {
      const tr = el('tr');
      const td = el('td', 'empty-state', '此证书尚未绑定任何消费者');
      td.colSpan = 6;
      tr.appendChild(td);
      bindBody.appendChild(tr);
    } else {
      for (const b of bindings) {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', b.binding_ref));
        tr.appendChild(el('td', 'mono', b.plugin_id));
        tr.appendChild(el('td', 'mono', `${b.node_id || '-'} / ${b.profile_id || '-'} / ${b.server_name || '-'}`));
        tr.appendChild(el('td', 'mono', `目标 #${b.generation} · 运行 #${b.running_generation}`));
        const tdStatus = el('td');
        tdStatus.appendChild(el('span', `badge ${statusBadgeTone(b.status)}`, b.status));
        tr.appendChild(tdStatus);

        const tdAct = el('td');
        const row = el('div', 'actions-row');
        const btnDep = el('button', 'btn btn-sm', '部署最新代');
        btnDep.type = 'button';
        btnDep.addEventListener('click', () => {
          void mutateBinding('bindings.deploy', cert.id, b.binding_ref, cert.latest_generation || b.generation || 1);
        });
        row.appendChild(btnDep);

        const btnRb = el('button', 'btn btn-sm', '回滚');
        btnRb.type = 'button';
        btnRb.addEventListener('click', () => {
          void mutateBinding('bindings.rollback', cert.id, b.binding_ref, b.previous_generation || b.running_generation || 1);
        });
        row.appendChild(btnRb);

        const btnUn = el('button', 'btn btn-sm btn-danger', '解绑');
        btnUn.type = 'button';
        btnUn.addEventListener('click', () => {
          openConfirm(
            `解除消费者绑定 ${b.binding_ref}`,
            `确认解除 ${b.plugin_id} (${b.server_name}) 对证书 ${cert.id} 的绑定并清理私有证书材料？`,
            () => mutateBinding('bindings.unbind', cert.id, b.binding_ref, b.running_generation || b.generation || 1)
          );
        });
        row.appendChild(btnUn);

        tdAct.appendChild(row);
        tr.appendChild(tdAct);
        bindBody.appendChild(tr);
      }
    }

    notifyResize();
  }

  function renderAllBindingsTable() {
    const tbody = $('all-bindings-tbody');
    tbody.textContent = '';
    const pluginFilter = $('bind-plugin').value;
    const rows = [];
    for (const cert of state.certificates) {
      for (const b of (cert.bindings || [])) {
        if (pluginFilter !== 'all' && b.plugin_id !== pluginFilter) continue;
        rows.push({ cert, binding: b });
      }
    }

    if (!rows.length) {
      const tr = el('tr');
      const td = el('td', 'empty-state', pluginFilter === 'all' ? '暂无已登记消费者绑定' : `暂无属于 ${pluginFilter} 的消费者绑定`);
      td.colSpan = 7;
      tr.appendChild(td);
      tbody.appendChild(tr);
      notifyResize();
      return;
    }

    for (const { cert, binding: b } of rows) {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', b.plugin_id));
      tr.appendChild(el('td', 'mono', cert.id));
      tr.appendChild(el('td', 'mono', b.binding_ref));
      tr.appendChild(el('td', 'mono', `${b.server_name || '-'} (${b.node_id || '-'})`));
      tr.appendChild(el('td', 'mono', `#${b.generation} / #${b.running_generation}`));
      const tdSt = el('td');
      tdSt.appendChild(el('span', `badge ${statusBadgeTone(b.status)}`, b.status));
      tr.appendChild(tdSt);

      const tdPick = el('td');
      const btn = el('button', 'btn btn-sm', '填入表单');
      btn.type = 'button';
      btn.addEventListener('click', () => {
        $('bind-cert-id').value = cert.id;
        $('bind-ref').value = b.binding_ref;
        $('bind-generation').value = String(cert.latest_generation || b.generation || 1);
        $('renew-cert-id').value = cert.id;
        const currentRefs = parseList($('renew-bindings').value);
        if (!currentRefs.includes(b.binding_ref)) {
          currentRefs.push(b.binding_ref);
          $('renew-bindings').value = currentRefs.join(', ');
        }
        showBanner(`已选中绑定 ${b.binding_ref}（${b.plugin_id}）`, 'ok');
      });
      tdPick.appendChild(btn);
      tr.appendChild(tdPick);
      tbody.appendChild(tr);
    }

    notifyResize();
  }

  function renderRenewalStatus(renewal) {
    const box = $('renewal-status-box');
    if (!renewal) {
      box.classList.add('hidden');
      box.textContent = '';
      notifyResize();
      return;
    }
    state.lastRenewal = renewal;
    box.classList.remove('hidden');
    box.textContent = '';
    const fields = [
      ['策略 ID', renewal.id || '—'],
      ['证书 ID', renewal.certificate_id || '—'],
      ['策略版本', renewal.revision || '—'],
      ['后台续期', renewal.enabled ? '已启用' : '未启用'],
      ['当前状态', renewal.status || '—'],
      ['下次计划', renewal.next_at || '—'],
      ['授权截止', renewal.expires_at || '—'],
      ['连续重试', String(renewal.attempts ?? 0)],
    ];
    if (renewal.last_error) fields.push(['最近错误', renewal.last_error]);
    if (renewal.alert) fields.push(['告警提示', renewal.alert]);
    for (const [k, v] of fields) {
      const item = el('div');
      item.appendChild(el('div', 'detail-kv-label', k));
      item.appendChild(el('div', 'detail-kv-value mono', v));
      box.appendChild(item);
    }
    notifyResize();
  }

  async function refreshAll() {
    setStatus('正在同步证书摘要与完整列表...');
    try {
      const [summaryRes, listRes] = await Promise.allSettled([
        invoke('certificates.summary', {}, 10000),
        invoke('certificates.list', {}, 20000, { subject: 'plugins/tls.certificates/resources/certificates' }),
      ]);
      if (listRes.status === 'fulfilled') {
        state.certificates = Array.isArray(listRes.value.certificates) ? listRes.value.certificates : [];
      }
      if (summaryRes.status === 'fulfilled') {
        renderSummary(summaryRes.value);
      } else {
        const ready = state.certificates.filter((c) => c.status === 'ready').length;
        renderSummary({
          total: state.certificates.length,
          ready,
          attention: Math.max(0, state.certificates.length - ready),
          sub: '已从证书清单同步',
        });
      }
      renderCertSelectors();
      renderCertTable();
      renderAllBindingsTable();
      if (state.selectedCertId) {
        const match = state.certificates.find((c) => c.id === state.selectedCertId);
        renderDetailCard(match || null);
      }
      if (listRes.status === 'rejected') {
        handleActionError('拉取证书列表失败', listRes.reason);
      } else {
        setStatus(`已连接 · 共 ${state.certificates.length} 份证书`);
      }
    } catch (err) {
      handleActionError('同步失败', err);
    }
  }

  async function loadCertificateDetail(certId) {
    setStatus(`正在查询证书 ${certId} 详情...`);
    try {
      const res = await invoke('certificates.get', { certificate_id: certId }, 20000, {
        subject: `plugins/tls.certificates/resources/certificates/${certId}`,
      });
      renderDetailCard(res.certificate || null);
      setStatus(`已加载证书 ${certId} 详情`);
    } catch (err) {
      handleActionError(`读取证书 ${certId} 失败`, err);
    }
  }

  async function runTestCertificate(cert) {
    clearBanner();
    setStatus(`正在为 ${cert.id} 生成受控自签名测试代...`);
    try {
      const res = await invoke('certificates.test', {
        certificate_id: cert.id,
        attempt_id: makeAttemptId('test'),
        spec: {
          sans: Array.isArray(cert.sans) && cert.sans.length ? cert.sans : ['test.local'],
          purpose: 'tls_server_test',
        },
      }, 65000, certInvokeOpts(cert.id, true));
      showBanner(`测试证书作业已完成：${res.state || res.task_id || cert.id}`, 'ok');
      await refreshAll();
    } catch (err) {
      handleActionError('测试签发失败', err);
    }
  }

  async function removeCertificate(certId) {
    clearBanner();
    setStatus(`正在删除证书 ${certId}...`);
    try {
      await invoke('certificates.remove', {
        certificate_id: certId,
        attempt_id: makeAttemptId('rm'),
      }, 35000, certInvokeOpts(certId, false));
      if (state.selectedCertId === certId) {
        state.selectedCertId = '';
        renderDetailCard(null);
      }
      showBanner(`已删除证书资源 ${certId}`, 'ok');
      await refreshAll();
    } catch (err) {
      handleActionError('删除证书失败', err);
    }
  }

  async function removeGeneration(certId, generation) {
    clearBanner();
    setStatus(`正在清理证书 ${certId} 历史代 #${generation}...`);
    try {
      const res = await invoke('generations.remove', {
        certificate_id: certId,
        attempt_id: makeAttemptId('rmgen'),
        generation: Number(generation),
      }, 35000, certInvokeOpts(certId, false));
      if (res.certificate) renderDetailCard(res.certificate);
      showBanner(`已清理证书 ${certId} 历史代 #${generation}`, 'ok');
      await refreshAll();
    } catch (err) {
      handleActionError('清理历史代失败', err);
    }
  }

  async function mutateBinding(op, certId, bindingRef, generation) {
    clearBanner();
    if (!certId || !bindingRef) {
      showBanner('请选择目标证书 ID 并填写 binding_ref', 'warn');
      return;
    }
    const genNum = Math.max(1, Number.parseInt(String(generation || '1'), 10) || 1);
    setStatus(`正在执行 ${op} (${bindingRef})...`);
    try {
      const res = await invoke(op, {
        certificate_id: certId,
        binding_ref: bindingRef,
        attempt_id: makeAttemptId(op.replace(/\./g, '-')),
        generation: genNum,
      }, 65000, certInvokeOpts(certId, false));
      if (res.certificate && state.selectedCertId === certId) {
        renderDetailCard(res.certificate);
      }
      showBanner(`操作 ${op} 已完成（binding_ref: ${bindingRef}，代 #${genNum}）`, 'ok');
      await refreshAll();
    } catch (err) {
      handleActionError(`操作 ${op} 失败`, err);
    }
  }

  function syncAcmeChallengeMode() {
    const mode = $('acme-challenge-type')?.value || 'http-01';
    const isHTTP01 = mode === 'http-01';
    if ($('acme-http01-hint')) $('acme-http01-hint').hidden = !isHTTP01;
    if ($('acme-provider-field')) $('acme-provider-field').hidden = isHTTP01;
    if ($('acme-zone-field')) $('acme-zone-field').hidden = isHTTP01;
    if ($('acme-provider-id')) $('acme-provider-id').required = !isHTTP01;
    if ($('acme-zone-id')) $('acme-zone-id').required = !isHTTP01;
    notifyResize();
  }

  async function submitAcmeForm(event) {
    event.preventDefault();
    clearBanner();
    const certId = $('acme-cert-id').value.trim();
    const challengeType = $('acme-challenge-type')?.value || 'http-01';
    const sans = parseList($('acme-sans').value);
    const providerId = $('acme-provider-id').value.trim();
    const zoneId = $('acme-zone-id').value.trim();
    const ca = $('acme-ca').value;
    const purpose = $('acme-purpose').value;
    const acceptTerms = $('acme-tos').checked;
    if (!sans.length) {
      showBanner('请至少填写一个 SAN 域名', 'warn');
      return;
    }
    if (challengeType === 'http-01' && sans.some((s) => s.startsWith('*.'))) {
      showBanner('HTTP-01 验证不支持泛域名（*.example.com），请切换为 DNS-01 或填写精确域名', 'warn');
      return;
    }
    if (challengeType === 'dns-01' && (!providerId || !zoneId)) {
      showBanner('DNS-01 模式必须填写 DNS 服务商 ID 与 Zone ID', 'warn');
      return;
    }
    if (!acceptTerms) {
      showBanner('必须勾选同意受控 ACME CA 服务条款后才可签发', 'warn');
      return;
    }
    $('acme-submit').disabled = true;
    setStatus(`正在提交 ACME ${challengeType.toUpperCase()} 签发任务 (${certId})...`);
    try {
      const payload = {
        certificate_id: certId,
        attempt_id: makeAttemptId('acme'),
        challenge_type: challengeType,
        spec: { sans, purpose },
        ca,
        accept_terms: true,
      };
      if (challengeType === 'dns-01') {
        payload.provider_id = providerId;
        payload.zone_id = zoneId;
      }
      const res = await invoke('certificates.issue', payload, 300000, certInvokeOpts(certId, true));
      showBanner(`ACME 签发任务已提交：${res.task_id || certId}（状态：${res.state || 'submitted'}）`, 'ok');
      await refreshAll();
      switchTab('list');
    } catch (err) {
      handleActionError('ACME 签发失败', err);
    } finally {
      $('acme-submit').disabled = false;
    }
  }

  async function submitImportForm(event) {
    event.preventDefault();
    clearBanner();
    const certId = $('import-cert-id').value.trim();
    const sans = parseList($('import-sans').value);
    const chainPem = $('import-chain').value.trim();
    const privateKey = $('import-key').value.trim();
    const trust = $('import-trust').value;
    const purpose = $('import-purpose').value;
    if (!sans.length || !chainPem || !privateKey) {
      showBanner('请完整填写 SAN 域名、PEM 证书链与配对私钥', 'warn');
      return;
    }
    $('import-submit').disabled = true;
    setStatus(`正在导入外部 PEM 证书 (${certId})...`);
    try {
      const res = await invoke('certificates.import', {
        certificate_id: certId,
        attempt_id: makeAttemptId('import'),
        spec: { sans, purpose },
        chain_pem: chainPem,
        private_key: privateKey,
        trust,
      }, 125000, certInvokeOpts(certId, true));
      $('import-key').value = '';
      showBanner(`外部 PEM 证书导入已提交：${res.task_id || certId}（状态：${res.state || 'submitted'}）`, 'ok');
      await refreshAll();
      switchTab('list');
    } catch (err) {
      handleActionError('导入外部 PEM 失败', err);
    } finally {
      $('import-submit').disabled = false;
    }
  }

  async function submitTestCertForm(event) {
    event.preventDefault();
    clearBanner();
    const certId = $('test-cert-id').value.trim();
    const sans = parseList($('test-cert-sans').value);
    const purpose = $('test-cert-purpose').value;
    if (!sans.length) {
      showBanner('请填写测试证书 SAN 域名', 'warn');
      return;
    }
    $('test-cert-submit').disabled = true;
    setStatus(`正在签发受控自签名测试证书 (${certId})...`);
    try {
      const res = await invoke('certificates.test', {
        certificate_id: certId,
        attempt_id: makeAttemptId('test'),
        spec: { sans, purpose },
      }, 65000, certInvokeOpts(certId, true));
      showBanner(`受控测试证书任务已完成：${res.task_id || certId}`, 'ok');
      await refreshAll();
      switchTab('list');
    } catch (err) {
      handleActionError('签发测试证书失败', err);
    } finally {
      $('test-cert-submit').disabled = false;
    }
  }

  function policyInvokeOpts(policyId, allowCreate = false) {
    const rev = state.lastRenewal && state.lastRenewal.id === policyId && state.lastRenewal.revision
      ? state.lastRenewal.revision
      : (allowCreate ? 'absent' : '');
    const opts = { subject: `plugins/tls.certificates/resources/policies/${policyId}` };
    if (rev) opts.expected_revision = rev;
    return opts;
  }

  function syncRenewChallengeMode() {
    const mode = $('renew-challenge-type')?.value || 'http-01';
    const isHTTP01 = mode === 'http-01';
    if ($('renew-provider-field')) $('renew-provider-field').hidden = isHTTP01;
    if ($('renew-zone-field')) $('renew-zone-field').hidden = isHTTP01;
    if ($('renew-provider-id')) $('renew-provider-id').required = !isHTTP01;
    if ($('renew-zone-id')) $('renew-zone-id').required = !isHTTP01;
    notifyResize();
  }

  async function saveRenewalPolicy(event) {
    event.preventDefault();
    clearBanner();
    const policyId = $('renew-policy-id').value.trim();
    const certId = $('renew-cert-id').value.trim();
    const challengeType = $('renew-challenge-type')?.value || 'http-01';
    const providerId = $('renew-provider-id').value.trim();
    const zoneId = $('renew-zone-id').value.trim();
    const ca = $('renew-ca').value;
    const expiresAt = $('renew-expires').value.trim();
    const bindingRefs = parseList($('renew-bindings').value);
    if (!certId || !bindingRefs.length) {
      showBanner('请选择关联证书并至少填写一个 binding_ref', 'warn');
      return;
    }
    if (challengeType === 'dns-01' && (!providerId || !zoneId)) {
      showBanner('DNS-01 自动续期必须填写 DNS 服务商 ID 与 Zone ID', 'warn');
      return;
    }
    setStatus(`正在保存自动续期策略 ${policyId}...`);
    try {
      const payload = {
        policy_id: policyId,
        certificate_id: certId,
        challenge_type: challengeType,
        ca,
        binding_refs: bindingRefs,
        expires_at: expiresAt,
      };
      if (challengeType === 'dns-01') {
        payload.provider_id = providerId;
        payload.zone_id = zoneId;
      }
      const res = await invoke('renewal.configure', payload, 35000, policyInvokeOpts(policyId, true));
      renderRenewalStatus(res.renewal || null);
      showBanner(`自动续期策略 ${policyId} 已保存`, 'ok');
    } catch (err) {
      handleActionError('保存续期策略失败', err);
    }
  }

  async function queryRenewalPolicy() {
    clearBanner();
    const policyId = $('renew-policy-id').value.trim();
    const certId = $('renew-cert-id').value.trim();
    if (!policyId || !certId) {
      showBanner('请填写续期策略 ID 与关联证书 ID 后再查询', 'warn');
      return;
    }
    setStatus(`正在查询续期策略 ${policyId}...`);
    try {
      const res = await invoke('renewal.get', {
        policy_id: policyId,
        certificate_id: certId,
      }, 20000, { subject: `plugins/tls.certificates/resources/policies/${policyId}` });
      renderRenewalStatus(res.renewal || null);
      showBanner(`已加载续期策略 ${policyId} 状态`, 'ok');
    } catch (err) {
      handleActionError('查询续期策略失败', err);
    }
  }

  async function revokeRenewalPolicy() {
    clearBanner();
    const policyId = $('renew-policy-id').value.trim();
    const certId = $('renew-cert-id').value.trim();
    if (!policyId || !certId) {
      showBanner('请填写续期策略 ID 与关联证书 ID', 'warn');
      return;
    }
    setStatus(`正在撤销续期策略 ${policyId}...`);
    try {
      const res = await invoke('renewal.revoke', {
        policy_id: policyId,
        certificate_id: certId,
      }, 35000, policyInvokeOpts(policyId, false));
      renderRenewalStatus(res.renewal || null);
      showBanner(`已撤销续期策略 ${policyId}`, 'ok');
    } catch (err) {
      handleActionError('撤销续期策略失败', err);
    }
  }

  async function executeRenewExisting(certId, policyId, policyRevision) {
    clearBanner();
    let rev = (policyRevision || '').trim();
    if (!rev) {
      setStatus(`正在获取策略 ${policyId} 当前版本...`);
      const info = await invoke('renewal.get', {
        policy_id: policyId,
        certificate_id: certId,
      }, 20000, { subject: `plugins/tls.certificates/resources/policies/${policyId}` });
      if (info && info.renewal) {
        renderRenewalStatus(info.renewal);
        rev = info.renewal.revision || '';
      }
      if (!rev) {
        throw new Error('未能获取到策略版本，请先配置或手动填写 policy_revision');
      }
    }
    setStatus(`正在执行既有证书续期 ${certId}...`);
    const res = await invoke('renew_existing', {
      policy_id: policyId,
      policy_revision: rev,
      certificate_id: certId,
      run_attempt_id: makeAttemptId('run'),
      attempt_id: makeAttemptId('renew'),
    }, 300000, { subject: `plugins/tls.certificates/resources/certificates/${certId}`, expected_revision: rev });
    if (res.certificate && state.selectedCertId === certId) {
      renderDetailCard(res.certificate);
    }
    showBanner(`既有证书续期作业已提交（证书：${certId}，策略：${policyId}）`, 'ok');
    await refreshAll();
  }

  function openConfirm(title, message, action) {
    state.confirmAction = action;
    $('confirm-title').textContent = title;
    $('confirm-message').textContent = message;
    $('confirm-backdrop').hidden = false;
    requestAnimationFrame(notifyResize);
  }

  function closeConfirm() {
    state.confirmAction = null;
    $('confirm-backdrop').hidden = true;
    notifyResize();
  }

  function openRenewModal(certId) {
    $('modal-renew-cert').value = certId;
    const defaultPol = state.lastRenewal && state.lastRenewal.certificate_id === certId
      ? state.lastRenewal.id
      : `pol-${certId}`;
    $('modal-renew-policy').value = defaultPol;
    $('modal-renew-rev').value = state.lastRenewal && state.lastRenewal.certificate_id === certId
      ? (state.lastRenewal.revision || '')
      : '';
    $('renew-modal-backdrop').hidden = false;
    requestAnimationFrame(notifyResize);
  }

  function closeRenewModal() {
    $('renew-modal-backdrop').hidden = true;
    notifyResize();
  }

  function notifyResize() {
    const app = $('certs-app');
    if (!app) return;
    let height = Math.ceil(app.getBoundingClientRect().height) + 16;
    const vpTop = Number(state.viewportTop) || 0;
    for (const id of ['renew-modal-backdrop', 'confirm-backdrop']) {
      const backdrop = $(id);
      if (backdrop && !backdrop.hidden) {
        const box = backdrop.querySelector('.modal');
        const boxH = box ? Math.ceil(box.getBoundingClientRect().height) : 320;
        height = Math.max(height, vpTop + boxH + 64);
      }
    }
    send({ t: 'ui.resize', height });
  }

  function bindEvents() {
    for (const btn of document.querySelectorAll('.tab-btn')) {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    }

    $('refresh-all').addEventListener('click', () => { void refreshAll(); });
    $('reload-list').addEventListener('click', () => { void refreshAll(); });
    $('cert-filter').addEventListener('input', (e) => {
      state.filterText = e.target.value;
      renderCertTable();
    });

    $('detail-refresh').addEventListener('click', () => {
      if (state.selectedCertId) void loadCertificateDetail(state.selectedCertId);
    });
    $('detail-close').addEventListener('click', () => {
      state.selectedCertId = '';
      renderDetailCard(null);
    });

    $('acme-challenge-type')?.addEventListener('change', syncAcmeChallengeMode);
    syncAcmeChallengeMode();
    $('renew-challenge-type')?.addEventListener('change', syncRenewChallengeMode);
    syncRenewChallengeMode();
    $('acme-form').addEventListener('submit', (e) => { void submitAcmeForm(e); });
    $('import-form').addEventListener('submit', (e) => { void submitImportForm(e); });
    $('test-cert-form').addEventListener('submit', (e) => { void submitTestCertForm(e); });

    $('bind-plugin').addEventListener('change', () => renderAllBindingsTable());
    $('bind-cert-id').addEventListener('change', () => syncBindGenerationFromSelectedCert());

    $('btn-bind').addEventListener('click', () => {
      void mutateBinding('bindings.bind', $('bind-cert-id').value, $('bind-ref').value.trim(), $('bind-generation').value);
    });
    $('btn-deploy').addEventListener('click', () => {
      void mutateBinding('bindings.deploy', $('bind-cert-id').value, $('bind-ref').value.trim(), $('bind-generation').value);
    });
    $('btn-rollback').addEventListener('click', () => {
      void mutateBinding('bindings.rollback', $('bind-cert-id').value, $('bind-ref').value.trim(), $('bind-generation').value);
    });
    $('btn-unbind').addEventListener('click', () => {
      const certId = $('bind-cert-id').value;
      const ref = $('bind-ref').value.trim();
      const gen = $('bind-generation').value;
      if (!certId || !ref) {
        showBanner('请填写证书 ID 与 binding_ref', 'warn');
        return;
      }
      openConfirm(
        `解除消费者绑定 ${ref}`,
        `确认解除消费者绑定「${ref}」并清理其私有隔离目录？`,
        () => mutateBinding('bindings.unbind', certId, ref, gen)
      );
    });

    $('renewal-form').addEventListener('submit', (e) => { void saveRenewalPolicy(e); });
    $('btn-renew-query').addEventListener('click', () => { void queryRenewalPolicy(); });
    $('btn-renew-now').addEventListener('click', () => {
      const policyId = $('renew-policy-id').value.trim();
      const certId = $('renew-cert-id').value.trim();
      if (!policyId || !certId) {
        showBanner('请先填写续期策略 ID 与关联证书 ID', 'warn');
        return;
      }
      const rev = state.lastRenewal && state.lastRenewal.id === policyId ? state.lastRenewal.revision : '';
      void executeRenewExisting(certId, policyId, rev).catch((err) => handleActionError('执行续期失败', err));
    });
    $('btn-renew-revoke').addEventListener('click', () => {
      const policyId = $('renew-policy-id').value.trim();
      if (!policyId) {
        showBanner('请填写续期策略 ID', 'warn');
        return;
      }
      openConfirm(
        `撤销自动续期策略 ${policyId}`,
        `确认撤销续期策略「${policyId}」并停止后台自动续期调度？不影响当前已部署证书。`,
        () => revokeRenewalPolicy()
      );
    });

    $('confirm-cancel').addEventListener('click', closeConfirm);
    $('confirm-ok').addEventListener('click', () => {
      const fn = state.confirmAction;
      closeConfirm();
      if (typeof fn === 'function') void fn();
    });

    $('renew-modal-cancel').addEventListener('click', closeRenewModal);
    $('renew-modal-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const certId = $('modal-renew-cert').value.trim();
      const policyId = $('modal-renew-policy').value.trim();
      const rev = $('modal-renew-rev').value.trim();
      closeRenewModal();
      void executeRenewExisting(certId, policyId, rev).catch((err) => handleActionError('执行续期失败', err));
    });

    $('renew-expires').value = defaultExpiryRFC3339();
  }

  bindEvents();

  const observer = new ResizeObserver(() => notifyResize());
  observer.observe($('certs-app'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (e) => accept(e.data);
    send({ t: 'ui.ready' });
    void refreshAll();
  });

  window.addEventListener('pagehide', () => {
    observer.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.deadline);
      req.reject(new Error('页面已关闭'));
    }
    pending.clear();
    port?.close();
    port = null;
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
