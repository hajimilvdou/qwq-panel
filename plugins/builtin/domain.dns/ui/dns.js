// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== DNS 托管插件完整管理 UI ======================== */
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, opts, fb) => (opts.includes(v) ? v : fb);
  const initial = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(initial.get('theme'), ['light', 'dark'], 'light');
  root.style.colorScheme = root.dataset.theme;
  root.dataset.motion = pick(initial.get('motion'), ['full', 'reduced', 'off'], 'reduced');
  root.dataset.density = pick(initial.get('density'), ['comfortable', 'compact'], 'comfortable');

  const $ = (id) => document.getElementById(id);
  const SUBJECT_PREFIX = 'plugins/domain.dns/resources/';
  let port;
  let seq = 0;
  let refreshTimer = null;
  const pending = new Map();
  const pendingConfirm = new Map();

  let providers = [];
  let zonesByProvider = new Map();
  let currentRecords = [];
  let currentZoneRevision = '';

  const send = (msg) => { if (port) port.postMessage(msg); };
  const dnsSubject = (rel) => {
    const clean = String(rel || '').replace(/^\/+/, '');
    return clean.startsWith('plugins/') ? clean : SUBJECT_PREFIX + clean;
  };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  function applyHostVisualSettings(msg) {
    const theme = pick(msg.theme, ['light', 'dark'], root.dataset.theme);
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    root.dataset.motion = pick(msg.motion, ['full', 'reduced', 'off'], 'reduced');
    if (msg.density === 'comfortable' || msg.density === 'compact') {
      root.dataset.density = msg.density;
    }
    if (msg.tokens && typeof msg.tokens === 'object') {
      for (const [k, v] of Object.entries(msg.tokens)) {
        if (k.startsWith('--') && typeof v === 'string' && !/[;{}<>]/.test(v)) {
          root.style.setProperty(k, v.trim());
        }
      }
    }
  }

  function normalizeFQDN(inputName, zoneApex) {
    const name = String(inputName || '').trim().toLowerCase().replace(/\.+$/, '');
    const apex = String(zoneApex || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!apex) return name;
    if (!name || name === '@' || name === apex) return apex;
    if (name.endsWith('.' + apex)) return name;
    return `${name}.${apex}`;
  }

  function findZoneApex(providerId, zoneId) {
    const list = zonesByProvider.get(providerId) || [];
    const hit = list.find((z) => z.zone_id === zoneId);
    return hit?.name || '';
  }

  function clearRegisterSecrets() {
    $('reg-cf-token').value = '';
    $('reg-ali-secret').value = '';
    if ($('reg-dnspod-key')) $('reg-dnspod-key').value = '';
    $('register-modal').hidden = true;
  }

  function setStatus(text, level = '') {
    const el = $('status');
    el.textContent = text;
    el.className = level ? `badge ${level}` : 'badge';
  }

  function showNotice(text, kind = '') {
    const bar = $('notice-bar');
    if (!text) {
      bar.hidden = true;
      return;
    }
    bar.textContent = text;
    bar.className = kind ? `banner ${kind}` : 'banner';
    bar.hidden = false;
  }

  function makeAttemptID(prefix) {
    const rnd = Math.random().toString(36).slice(2, 8);
    return `${prefix}-${Date.now()}-${rnd}`;
  }

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function invoke(operation, payload = {}, timeoutMs = 35000, opts = undefined) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        pending.delete(id);
        reject(new Error('宿主响应超时'));
      }, timeoutMs);
      pending.set(id, { resolve, reject, deadline });
      const msg = { t: 'api.invoke', id, operation, payload };
      if (Array.isArray(opts) && opts.length > 0 && opts[0]) {
        if (opts[0].subject) msg.subject = dnsSubject(opts[0].subject);
        if (opts[0].revision) msg.expected_revision = opts[0].revision;
      } else if (opts && typeof opts === 'object') {
        if (opts.subject) msg.subject = dnsSubject(opts.subject);
        if (opts.expected_revision) msg.expected_revision = opts.expected_revision;
      }
      send(msg);
    });
  }

  function hostConfirm(title, message) {
    if (!port) return Promise.resolve(false);
    const id = `cf_${++seq}`;
    return new Promise((resolve) => {
      pendingConfirm.set(id, { resolve });
      send({ t: 'ui.confirm', id, title, body: message, danger: true });
    });
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
          const err = new Error('已提交宿主审批，请在顶部审批卡片确认执行');
          err.awaitingApproval = true;
          err.approvalId = env.approval_id;
          req.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'EXPIRED')) {
          req.reject(new Error(extractErrorMessage(env.error, '操作未完成')));
          return;
        }
        const result = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        req.resolve(result && typeof result === 'object' ? result : {});
      } else {
        req.reject(new Error(extractErrorMessage(msg.problem || msg.error, '宿主拒绝请求')));
      }
      return;
    }
    if (msg.t === 'ui.confirm.result' && pendingConfirm.has(msg.id)) {
      const req = pendingConfirm.get(msg.id);
      pendingConfirm.delete(msg.id);
      req.resolve(Boolean(msg.ok && msg.data?.confirmed));
      return;
    }
    if (msg.t === 'ui.settings') {
      applyHostVisualSettings(msg);
      return;
    }
    if (msg.t === 'api.event') {
      if (refreshTimer) clearTimeout(refreshTimer);
      refreshTimer = setTimeout(() => {
        refreshTimer = null;
        void refreshSummaryAndProviders();
      }, 400);
    }
  }

  function renderSummary(data) {
    $('enabled-count').textContent = String(typeof data.enabled === 'number' ? data.enabled : 0);
    $('total-count').textContent = String(typeof data.total === 'number' ? data.total : 0);
    $('zone-count').textContent = String(typeof data.zones === 'number' ? data.zones : 0);
    if (typeof data.sub === 'string' && data.sub) {
      $('summary-sub').textContent = data.sub;
    }
  }

  function renderProviders() {
    const tbody = $('providers-tbody');
    if (!providers.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">暂无已登记 DNS 服务商，请点击右上角「+ 添加服务商」</td></tr>';
    } else {
      tbody.innerHTML = providers.map((p) => {
        const badge = p.enabled ? '<span class="badge ok">已启用</span>' : '<span class="badge warn">已撤销</span>';
        const errHint = p.last_error ? `<div class="muted">${esc(p.last_error)}</div>` : '';
        return `<tr>
          <td><code>${esc(p.id)}</code></td>
          <td>${esc(p.name)}${errHint}</td>
          <td>${esc(p.kind)}</td>
          <td>${badge}</td>
          <td>${Number(p.zone_count || 0)}</td>
          <td class="actions-row">
            <button type="button" class="btn sm" data-inspect-zones="${esc(p.id)}">查看域名</button>
            ${p.enabled ? `<button type="button" class="btn sm danger" data-revoke-provider="${esc(p.id)}" data-rev="${esc(p.revision || '')}">吊销</button>` : ''}
          </td>
        </tr>`;
      }).join('');
    }
    syncProviderAndZoneSelectors();
  }

  function syncProviderAndZoneSelectors() {
    const provSel = $('zone-provider-select');
    const prevProv = provSel.value;
    provSel.innerHTML = providers.map((p) => `<option value="${esc(p.id)}">${esc(p.name)} (${esc(p.id)})</option>`).join('') || '<option value="">无可用服务商</option>';
    if (prevProv && providers.some((p) => p.id === prevProv)) provSel.value = prevProv;

    const allAuthZones = [];
    for (const [pid, zlist] of zonesByProvider.entries()) {
      for (const z of zlist) {
        if (z.authorized) allAuthZones.push({ provider_id: pid, zone_id: z.zone_id, name: z.name });
      }
    }
    const recSel = $('rec-zone-select');
    const prevRec = recSel.value;
    recSel.innerHTML = allAuthZones.map((z) => `<option value="${esc(z.provider_id)}|${esc(z.zone_id)}">${esc(z.name)} (${esc(z.provider_id)})</option>`).join('') || '<option value="">请先在「托管域名区域」授权至少一个 Zone</option>';
    if (prevRec && Array.from(recSel.options).some((o) => o.value === prevRec)) recSel.value = prevRec;
  }

  function renderZones(providerId) {
    const list = zonesByProvider.get(providerId) || [];
    const tbody = $('zones-tbody');
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted">该服务商下暂无已发现的托管域</td></tr>';
      return;
    }
    tbody.innerHTML = list.map((z) => {
      const badge = z.authorized ? '<span class="badge ok">已授权</span>' : '<span class="badge">未授权</span>';
      const actionBtn = z.authorized
        ? `<button type="button" class="btn sm danger" data-zone-revoke="${esc(z.provider_id)}|${esc(z.zone_id)}" data-rev="${esc(z.revision || '')}">解绑授权</button>
           <button type="button" class="btn sm" data-zone-records="${esc(z.provider_id)}|${esc(z.zone_id)}">管理记录</button>`
        : `<button type="button" class="btn sm primary" data-zone-auth="${esc(z.provider_id)}|${esc(z.zone_id)}" data-rev="${esc(z.revision || 'absent')}">授权托管</button>`;
      return `<tr>
        <td><strong>${esc(z.name)}</strong></td>
        <td><code>${esc(z.zone_id)}</code></td>
        <td>${badge}</td>
        <td><code>${esc(z.revision || '—')}</code></td>
        <td class="actions-row">${actionBtn}</td>
      </tr>`;
    }).join('');
    syncProviderAndZoneSelectors();
  }

  function renderRecords() {
    const tbody = $('records-tbody');
    if (!currentRecords.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">当前 Zone 暂无解析记录</td></tr>';
      return;
    }
    tbody.innerHTML = currentRecords.map((r) => {
      const flags = [
        r.proxied ? '<span class="badge warn">Proxy</span>' : '',
        r.managed_challenge ? '<span class="badge">ACME</span>' : ''
      ].filter(Boolean).join(' ') || '—';
      return `<tr>
        <td><code>${esc(r.type)}</code></td>
        <td><strong>${esc(r.name)}</strong></td>
        <td><code>${esc(r.value)}</code></td>
        <td>${Number(r.ttl || 0)}</td>
        <td>${flags}</td>
        <td class="actions-row">
          <button type="button" class="btn sm" data-edit-rec="${esc(r.id)}">编辑</button>
          <button type="button" class="btn sm" data-check-rec="${esc(r.id)}">预检</button>
          <button type="button" class="btn sm danger" data-del-rec="${esc(r.id)}">删除</button>
        </td>
      </tr>`;
    }).join('');
  }

  function resetRecordForm() {
    $('rec-edit-id').value = '';
    $('rec-edit-rev').value = '';
    $('rec-type').value = 'A';
    $('rec-name').value = '';
    $('rec-value').value = '';
    $('rec-ttl').value = '600';
    $('rec-proxied').checked = false;
    $('rec-form-title').textContent = '新增解析记录';
    $('rec-submit-btn').textContent = '提交记录变更';
    $('rec-reset-btn').hidden = true;
  }

  function parseSelectedZone() {
    const raw = $('rec-zone-select').value;
    const [providerId, zoneId] = raw.split('|');
    if (!providerId || !zoneId) return null;
    return { providerId, zoneId };
  }

  function switchTab(name) {
    document.querySelectorAll('.tab').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
    ['providers', 'zones', 'records'].forEach((t) => { $(`tab-${t}`).hidden = t !== name; });
  }

  async function refreshSummaryAndProviders() {
    setStatus('同步中…');
    try {
      const sum = await invoke('providers.status', {}, 8000);
      renderSummary(sum);
    } catch {
      // summary best-effort
    }
    try {
      const listRes = await invoke('providers.list', {}, 20000, { subject: 'providers' });
      providers = Array.isArray(listRes.providers) ? listRes.providers : [];
      renderProviders();
      setStatus('已连接', 'ok');
    } catch (err) {
      if (err.awaitingApproval) showNotice(err.message, 'warn');
      else setStatus(err.message || '加载失败', 'danger');
    }
  }

  async function loadZonesForProvider(providerId) {
    if (!providerId) return;
    setStatus('发现托管域…');
    try {
      const res = await invoke('providers.zones', { provider_id: providerId }, 20000, {
        subject: `providers/${providerId}`
      });
      zonesByProvider.set(providerId, Array.isArray(res.zones) ? res.zones : []);
      renderZones(providerId);
      setStatus('已连接', 'ok');
    } catch (err) {
      showNotice(`拉取托管域失败：${err.message}`, 'error');
      setStatus('请求异常', 'danger');
    }
  }

  async function loadRecordsForSelectedZone() {
    const target = parseSelectedZone();
    if (!target) {
      showNotice('请先在「托管域名区域」发现并授权一个 Zone', 'warn');
      return;
    }
    setStatus('加载解析记录…');
    try {
      const res = await invoke('records.list', { provider_id: target.providerId, zone_id: target.zoneId }, 25000, {
        subject: `zones/${target.providerId}/${target.zoneId}`
      });
      currentZoneRevision = res.revision || '';
      currentRecords = Array.isArray(res.records) ? res.records : [];
      $('records-rev-hint').textContent = `当前快照版本：${currentZoneRevision || '—'} · 共 ${currentRecords.length} 条记录`;
      renderRecords();
      setStatus('已连接', 'ok');
    } catch (err) {
      showNotice(`加载记录失败：${err.message}`, 'error');
      setStatus('请求异常', 'danger');
    }
  }

  // ===== 事件绑定 =====
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  $('refresh-all').addEventListener('click', () => { void refreshSummaryAndProviders(); });
  $('reload-providers-btn').addEventListener('click', () => { void refreshSummaryAndProviders(); });

  $('open-register-btn').addEventListener('click', () => { $('register-modal').hidden = false; });
  $('close-register-btn').addEventListener('click', () => { $('register-modal').hidden = true; });
  $('reg-kind').addEventListener('change', () => {
    const kind = $('reg-kind').value;
    $('cred-cloudflare').hidden = kind !== 'cloudflare';
    $('cred-aliyun').hidden = kind !== 'aliyun';
    $('cred-dnspod').hidden = kind !== 'dnspod';
  });

  $('submit-register-btn').addEventListener('click', async () => {
    const providerId = $('reg-provider-id').value.trim();
    const kind = $('reg-kind').value;
    const name = $('reg-name').value.trim();
    if (!providerId || !name) {
      showNotice('请填写服务商 ID 和显示名称', 'warn');
      return;
    }
    let credential;
    if (kind === 'aliyun') {
      credential = { access_key_id: $('reg-ali-id').value.trim(), access_key_secret: $('reg-ali-secret').value.trim() };
    } else if (kind === 'dnspod') {
      credential = { secret_id: $('reg-dnspod-id').value.trim(), secret_key: $('reg-dnspod-key').value.trim() };
    } else {
      credential = { token: $('reg-cf-token').value.trim() };
    }
    try {
      const res = await invoke('providers.register', { provider_id: providerId, kind, name, credential }, 35000, {
        subject: `providers/${providerId}`,
        expected_revision: 'absent'
      });
      if (Array.isArray(res.zones)) zonesByProvider.set(providerId, res.zones);
      clearRegisterSecrets();
      showNotice(`服务商「${name}」已登记并发现 ${(res.zones || []).length} 个托管域`);
      await refreshSummaryAndProviders();
    } catch (err) {
      if (err.awaitingApproval) clearRegisterSecrets();
      showNotice(err.message, err.awaitingApproval ? 'warn' : 'error');
    }
  });

  $('providers-tbody').addEventListener('click', async (e) => {
    const inspectBtn = e.target.closest('[data-inspect-zones]');
    if (inspectBtn) {
      const pid = inspectBtn.dataset.inspectZones;
      $('zone-provider-select').value = pid;
      switchTab('zones');
      await loadZonesForProvider(pid);
      return;
    }
    const revokeBtn = e.target.closest('[data-revoke-provider]');
    if (revokeBtn) {
      const pid = revokeBtn.dataset.revokeProvider;
      const rev = revokeBtn.dataset.rev;
      const ok = await hostConfirm('撤销 DNS 服务商授权', `确认撤销服务商 ${pid}？撤销后不再执行新的 DNS 变更或续期。`);
      if (!ok) return;
      try {
        await invoke('providers.revoke', { provider_id: pid }, 20000, {
          subject: `providers/${pid}`,
          expected_revision: rev || undefined
        });
        showNotice(`已撤销服务商 ${pid}`);
        await refreshSummaryAndProviders();
      } catch (err) {
        showNotice(err.message, err.awaitingApproval ? 'warn' : 'error');
      }
    }
  });

  $('discover-zones-btn').addEventListener('click', () => {
    void loadZonesForProvider($('zone-provider-select').value);
  });

  $('zones-tbody').addEventListener('click', async (e) => {
    const authBtn = e.target.closest('[data-zone-auth]');
    if (authBtn) {
      const [pid, zid] = authBtn.dataset.zoneAuth.split('|');
      const rev = authBtn.dataset.rev;
      try {
        await invoke('zones.authorize', { provider_id: pid, zone_id: zid }, 20000, {
          subject: `zones/${pid}/${zid}`,
          expected_revision: rev || 'absent'
        });
        showNotice(`托管域 ${zid} 已授权`);
        await loadZonesForProvider(pid);
      } catch (err) {
        showNotice(err.message, err.awaitingApproval ? 'warn' : 'error');
      }
      return;
    }
    const revBtn = e.target.closest('[data-zone-revoke]');
    if (revBtn) {
      const [pid, zid] = revBtn.dataset.zoneRevoke.split('|');
      const rev = revBtn.dataset.rev;
      const ok = await hostConfirm('解绑托管域授权', `确认撤销托管域 ${zid} 授权？`);
      if (!ok) return;
      try {
        await invoke('zones.revoke', { provider_id: pid, zone_id: zid }, 20000, {
          subject: `zones/${pid}/${zid}`,
          expected_revision: rev || undefined
        });
        showNotice(`已解绑托管域 ${zid}`);
        await loadZonesForProvider(pid);
      } catch (err) {
        showNotice(err.message, err.awaitingApproval ? 'warn' : 'error');
      }
      return;
    }
    const recBtn = e.target.closest('[data-zone-records]');
    if (recBtn) {
      $('rec-zone-select').value = recBtn.dataset.zoneRecords;
      switchTab('records');
      await loadRecordsForSelectedZone();
    }
  });

  $('load-records-btn').addEventListener('click', () => { void loadRecordsForSelectedZone(); });
  $('rec-reset-btn').addEventListener('click', resetRecordForm);

  $('rec-submit-btn').addEventListener('click', async () => {
    const target = parseSelectedZone();
    if (!target) {
      showNotice('请先选择一个已授权的 Zone', 'warn');
      return;
    }
    const editId = $('rec-edit-id').value.trim();
    const editRev = $('rec-edit-rev').value.trim();
    const zoneApex = findZoneApex(target.providerId, target.zoneId);
    const recName = normalizeFQDN($('rec-name').value, zoneApex);
    const recVal = $('rec-value').value.trim();
    if (!recName || !recVal) {
      showNotice('请填写域名（可填 @ 或子域名前缀）与记录目标值', 'warn');
      return;
    }
    const attemptId = makeAttemptID('dns-apply');
    $('rec-attempt-id').value = attemptId;
    const rawTTL = Math.floor(Number($('rec-ttl').value || 600));
    const change = {
      action: editId ? 'update' : 'create',
      record: {
        type: $('rec-type').value,
        name: recName,
        value: recVal,
        ttl: rawTTL === 1 ? 1 : Math.max(60, Math.min(86400, rawTTL || 600)),
        proxied: $('rec-proxied').checked
      }
    };
    if (editId) {
      change.record.id = editId;
      if (editRev) change.expected_record_revision = editRev;
    }
    try {
      const res = await invoke('records.apply', {
        provider_id: target.providerId,
        zone_id: target.zoneId,
        attempt_id: attemptId,
        change
      }, 35000, {
        subject: `zones/${target.providerId}/${target.zoneId}`,
        expected_revision: currentZoneRevision || undefined
      });
      showNotice(`记录变更状态：${res.state || 'applied'}（attempt_id: ${attemptId}）`);
      resetRecordForm();
      await loadRecordsForSelectedZone();
    } catch (err) {
      showNotice(err.message, err.awaitingApproval ? 'warn' : 'error');
    }
  });

  $('rec-reconcile-btn').addEventListener('click', async () => {
    const target = parseSelectedZone();
    const attemptId = $('rec-attempt-id').value.trim();
    if (!target || !attemptId) {
      showNotice('请先选择 Zone 并填写待对账的 attempt_id', 'warn');
      return;
    }
    try {
      const res = await invoke('records.reconcile', {
        provider_id: target.providerId,
        zone_id: target.zoneId,
        attempt_id: attemptId
      }, 35000, {
        subject: `zones/${target.providerId}/${target.zoneId}`
      });
      showNotice(`对账完成：当前状态 ${res.state || 'reconciled'}`);
      await loadRecordsForSelectedZone();
    } catch (err) {
      showNotice(err.message, err.awaitingApproval ? 'warn' : 'error');
    }
  });

  $('records-tbody').addEventListener('click', async (e) => {
    const editBtn = e.target.closest('[data-edit-rec]');
    if (editBtn) {
      const rec = currentRecords.find((r) => r.id === editBtn.dataset.editRec);
      if (!rec) return;
      $('rec-edit-id').value = rec.id;
      $('rec-edit-rev').value = rec.revision || '';
      $('rec-type').value = rec.type || 'A';
      $('rec-name').value = rec.name || '';
      $('rec-value').value = rec.value || '';
      $('rec-ttl').value = String(rec.ttl || 0);
      $('rec-proxied').checked = Boolean(rec.proxied);
      $('rec-form-title').textContent = `编辑解析记录 (${rec.id})`;
      $('rec-submit-btn').textContent = '保存记录修改';
      $('rec-reset-btn').hidden = false;
      $('rec-name').focus();
      return;
    }
    const chkBtn = e.target.closest('[data-check-rec]');
    if (chkBtn) {
      const rec = currentRecords.find((r) => r.id === chkBtn.dataset.checkRec);
      if (!rec) return;
      $('chk-name').value = rec.name || '';
      $('chk-type').value = rec.type || 'A';
      $('chk-value').value = rec.value || '';
      $('run-check-btn').click();
      return;
    }
    const delBtn = e.target.closest('[data-del-rec]');
    if (delBtn) {
      const target = parseSelectedZone();
      const rec = currentRecords.find((r) => r.id === delBtn.dataset.delRec);
      if (!target || !rec) return;
      const ok = await hostConfirm('删除解析记录', `确认删除 ${rec.type} ${rec.name} -> ${rec.value}？`);
      if (!ok) return;
      const attemptId = makeAttemptID('dns-del');
      $('rec-attempt-id').value = attemptId;
      try {
        await invoke('records.apply', {
          provider_id: target.providerId,
          zone_id: target.zoneId,
          attempt_id: attemptId,
          change: {
            action: 'delete',
            expected_record_revision: rec.revision || '',
            record: { id: rec.id, type: rec.type, name: rec.name, value: rec.value, ttl: rec.ttl || 0, proxied: Boolean(rec.proxied) }
          }
        }, 35000, {
          subject: `zones/${target.providerId}/${target.zoneId}`,
          expected_revision: currentZoneRevision || undefined
        });
        showNotice(`已删除解析记录 ${rec.name}`);
        await loadRecordsForSelectedZone();
      } catch (err) {
        showNotice(err.message, err.awaitingApproval ? 'warn' : 'error');
      }
    }
  });

  $('run-check-btn').addEventListener('click', async () => {
    const target = parseSelectedZone();
    const zoneApex = target ? findZoneApex(target.providerId, target.zoneId) : '';
    const name = normalizeFQDN($('chk-name').value, zoneApex);
    const type = $('chk-type').value;
    const value = $('chk-value').value.trim();
    if (!target || !name || !value) {
      showNotice('请先选择 Zone 并填写待校验域名与期望记录值', 'warn');
      return;
    }
    $('chk-summary').textContent = '正在并行探测权威 NS 与公共递归解析器…';
    try {
      const res = await invoke('dns.check', {
        provider_id: target.providerId,
        zone_id: target.zoneId,
        name,
        type,
        value
      }, 25000, {
        subject: `zones/${target.providerId}/${target.zoneId}`
      });
      $('chk-summary').textContent = res.propagated
        ? '传播已生效（权威 NS 与公共解析器均观测到期望值）'
        : `尚未完全传播${res.retry_at ? ` · 建议重试时间 ${res.retry_at}` : ''}`;
      const obs = Array.isArray(res.observations) ? res.observations : [];
      $('chk-observations').innerHTML = obs.map((o) => {
        const vals = Array.isArray(o.values) && o.values.length ? o.values.join(', ') : (o.error_code || '无结果');
        const cls = o.error_code ? 'danger' : 'ok';
        return `<div class="obs-item">
          <div>
            <strong>${esc(o.source)}</strong> <span class="badge">${esc(o.kind || 'resolver')}</span>
            <div class="muted">${esc(o.collected_at || '')}</div>
          </div>
          <div><span class="badge ${cls}">${esc(vals)}</span></div>
        </div>`;
      }).join('') || '<p class="muted">未返回观测点数据</p>';
    } catch (err) {
      $('chk-summary').textContent = '';
      showNotice(`传播预检失败：${err.message}`, 'error');
    }
  });

  const observer = new ResizeObserver(() => {
    send({ t: 'ui.resize', height: Math.ceil($('dns-app').getBoundingClientRect().height) + 20 });
  });
  observer.observe($('dns-app'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (e) => accept(e.data);
    send({ t: 'ui.ready' });
    send({ t: 'api.subscribe', subjects: ['plugins/domain.dns'] });
    void refreshSummaryAndProviders();
  });

  window.addEventListener('pagehide', () => {
    if (refreshTimer) clearTimeout(refreshTimer);
    observer.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.deadline);
      req.reject(new Error('页面已关闭'));
    }
    pending.clear();
    pendingConfirm.clear();
    port?.close();
    port = undefined;
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
