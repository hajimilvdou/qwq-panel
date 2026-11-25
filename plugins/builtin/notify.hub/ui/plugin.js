// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';

  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const hash = new URLSearchParams(location.hash.slice(1));
  const initialTheme = pick(hash.get('theme'), ['light', 'dark'], 'light');
  root.dataset.theme = initialTheme;
  root.style.colorScheme = initialTheme;
  root.dataset.density = pick(hash.get('density'), ['comfortable', 'compact'], 'comfortable');

  function applyHostVisualSettings(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.theme === 'light' || msg.theme === 'dark') {
      root.dataset.theme = msg.theme;
      root.style.colorScheme = msg.theme;
    }
    if (msg.density === 'comfortable' || msg.density === 'compact') {
      root.dataset.density = msg.density;
    }
    if (msg.tokens && typeof msg.tokens === 'object') {
      for (const [k, v] of Object.entries(msg.tokens)) {
        if (k.startsWith('--') && typeof v === 'string' && !/[;{}<>]/.test(v)) {
          root.style.setProperty(k, v.trim());
        }
      }
      if (msg.tokens['--accent-strong']) root.style.setProperty('--cocoa', msg.tokens['--accent-strong'].trim());
      else if (msg.tokens['--accent']) root.style.setProperty('--cocoa', msg.tokens['--accent'].trim());
      if (msg.tokens['--on-accent']) root.style.setProperty('--on-cocoa', msg.tokens['--on-accent'].trim());
    }
  }

  const $ = (id) => document.getElementById(id);
  const statusEl = $('bridge-status');
  let port = null;
  let seq = 0;
  const pending = new Map();
  const pendingConfirm = new Map();
  const pendingCopy = new Map();

  let latestChannels = [];
  let latestRules = [];

  const setStatus = (t) => { statusEl.textContent = t; };
  const send = (msg) => { if (port) port.postMessage(msg); };

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function formatUnixTime(sec) {
    if (!sec || sec <= 0) return '—';
    const d = new Date(sec * 1000);
    if (Number.isNaN(d.getTime())) return '—';
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  const runAction = async (fn, okMsg) => {
    try {
      await fn();
      if (okMsg) setStatus(okMsg);
    } catch (err) {
      if (err && err.awaitingApproval) {
        setStatus('等待审批确认：请在宿主审批浮窗确认后刷新');
        send({ t: 'ui.toast', text: '操作已提交，等待审批确认' });
        return;
      }
      setStatus('操作失败：' + (err?.message || '未知错误'));
    }
  };

  const invoke = (operation, payload = {}) => new Promise((resolve, reject) => {
    if (!port) return reject(new Error('宿主桥尚未就绪'));
    const id = `nh_${++seq}`;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error('宿主响应超时'));
    }, 15000);
    pending.set(id, { resolve, reject, timer });
    send({ t: 'api.invoke', id, operation, payload });
  });

  const hostConfirm = (title, body, { danger = false, confirmLabel } = {}) => new Promise((resolve) => {
    if (!port) return resolve(false);
    const id = `cf_${++seq}`;
    pendingConfirm.set(id, { resolve });
    const msg = { t: 'ui.confirm', id, title, body, danger: Boolean(danger) };
    if (confirmLabel) msg.confirm_label = confirmLabel;
    send(msg);
  });

  const hostCopy = (text, label) => new Promise((resolve, reject) => {
    if (!port) return reject(new Error('宿主桥尚未就绪'));
    if (!text) return reject(new Error('没有可复制的内容'));
    const id = `cp_${++seq}`;
    const timer = setTimeout(() => {
      pendingCopy.delete(id);
      reject(new Error('复制响应超时'));
    }, 8000);
    pendingCopy.set(id, { resolve, reject, timer });
    const msg = { t: 'ui.copy', id, text: String(text) };
    if (label) msg.label = label;
    send(msg);
  });

  function syncChannelKindFields() {
    const kind = $('ch-kind').value;
    $('fields-telegram').hidden = kind !== 'telegram';
    $('fields-smtp').hidden = kind !== 'smtp';
    $('fields-webhook').hidden = kind === 'telegram' || kind === 'smtp';
  }

  function resetChannelForm() {
    $('ch-id').value = '';
    $('ch-name').value = '';
    $('ch-kind').value = 'telegram';
    $('ch-enabled').checked = true;
    $('tg-token').value = '';
    $('tg-chat').value = '';
    $('tg-thread').value = '';
    $('tg-api-base').value = '';
    $('wh-url').value = '';
    $('wh-secret').value = '';
    $('smtp-host').value = '';
    $('smtp-port').value = '587';
    $('smtp-user').value = '';
    $('smtp-pass').value = '';
    $('smtp-from').value = '';
    $('smtp-to').value = '';
    $('smtp-tls').checked = false;
    $('ch-form-title').textContent = '添加 / 更新通知渠道（密钥 AES-256-GCM 加密存储）';
    $('ch-edit-hint').hidden = true;
    $('btn-ch-cancel').hidden = true;
    syncChannelKindFields();
  }

  function editChannel(c) {
    resetChannelForm();
    const m = c.config_masked || {};
    $('ch-id').value = c.id || '';
    $('ch-name').value = c.name || '';
    $('ch-kind').value = c.kind || 'telegram';
    $('ch-enabled').checked = Boolean(c.enabled);
    syncChannelKindFields();

    if (c.kind === 'telegram') {
      $('tg-chat').value = m.chat_id || '';
      $('tg-thread').value = m.thread_id || '';
      $('tg-api-base').value = '';
    } else if (c.kind === 'smtp') {
      $('smtp-host').value = m.smtp_host || '';
      $('smtp-port').value = String(m.smtp_port || 587);
      $('smtp-user').value = m.smtp_user || '';
      $('smtp-from').value = m.smtp_from || '';
      $('smtp-to').value = Array.isArray(m.smtp_to) ? m.smtp_to.join(', ') : '';
      $('smtp-tls').checked = Boolean(m.smtp_tls);
    }

    $('ch-form-title').textContent = `编辑通知渠道 · ${c.name}`;
    $('ch-edit-hint').hidden = false;
    $('btn-ch-cancel').hidden = false;
    $('ch-name').focus();
  }

  function renderRuleChannelCheckboxes(selectedIds = []) {
    const box = $('rl-channels-box');
    const selected = new Set(selectedIds);
    box.replaceChildren();
    if (!latestChannels.length) {
      const hint = document.createElement('span');
      hint.className = 'sub';
      hint.textContent = '暂无已创建渠道，请先在「通知渠道」标签页创建至少一个渠道。';
      box.appendChild(hint);
      return;
    }
    for (const c of latestChannels) {
      const label = document.createElement('label');
      label.className = 'ch-checkbox-item';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = c.id;
      cb.checked = selected.has(c.id);
      const txt = document.createElement('span');
      txt.textContent = `${c.name} (${c.kind})${c.enabled ? '' : ' [已停用]'}`;
      label.append(cb, txt);
      box.appendChild(label);
    }
  }

  function getSelectedRuleChannelIDs() {
    const ids = [];
    for (const cb of document.querySelectorAll('#rl-channels-box input[type="checkbox"]:checked')) {
      if (cb.value) ids.push(cb.value);
    }
    return ids;
  }

  function resetRuleForm() {
    $('rl-id').value = '';
    $('rl-name').value = '';
    $('rl-src').value = '*';
    $('rl-sev').value = 'warn';
    $('rl-cool').value = '300';
    $('rl-qs').value = '';
    $('rl-qe').value = '';
    $('rl-tz').value = 'Asia/Shanghai';
    $('rl-enabled').checked = true;
    $('rl-bypass').checked = true;
    $('rl-form-title').textContent = '告警路由、聚合冷却与静默时段';
    $('rl-edit-hint').hidden = true;
    $('btn-rl-cancel').hidden = true;
    renderRuleChannelCheckboxes([]);
  }

  function editRule(r) {
    $('rl-id').value = r.id || '';
    $('rl-name').value = r.name || '';
    $('rl-src').value = r.source_pattern || '*';
    $('rl-sev').value = r.min_severity || 'warn';
    $('rl-cool').value = String(r.cooldown_sec ?? 300);
    $('rl-qs').value = r.quiet_start || '';
    $('rl-qe').value = r.quiet_end || '';
    $('rl-tz').value = r.quiet_tz || 'Asia/Shanghai';
    $('rl-enabled').checked = Boolean(r.enabled);
    $('rl-bypass').checked = Boolean(r.allow_critical_bypass);
    renderRuleChannelCheckboxes(Array.isArray(r.channel_ids) ? r.channel_ids : []);
    $('rl-form-title').textContent = `编辑路由规则 · ${r.name}`;
    $('rl-edit-hint').hidden = false;
    $('btn-rl-cancel').hidden = false;
    $('rl-name').focus();
  }

  function badge(status, customCls) {
    const span = document.createElement('span');
    const cls = customCls || (status === 'ok' || status === 'sent' ? 'ok' : (status === 'error' || status === 'failed' ? 'err' : 'warn'));
    span.className = 'badge ' + cls;
    span.textContent = status;
    return span;
  }

  function summarizeMaskedConfig(c) {
    const m = c.config_masked || {};
    if (c.kind === 'smtp') {
      const toList = Array.isArray(m.smtp_to) && m.smtp_to.length ? m.smtp_to.join(', ') : `${m.smtp_to_count || 0} 个收件人`;
      return `${m.smtp_host || '—'}:${m.smtp_port || 587} · 发件 ${m.smtp_from || '—'} -> ${toList}${m.smtp_user ? ` (用户 ${m.smtp_user})` : ''}`;
    }
    if (c.kind === 'telegram') {
      return `chat_id=${m.chat_id || '—'}${m.thread_id ? ` · thread=${m.thread_id}` : ''}${m.has_token ? ' · 已配 Token' : ''}`;
    }
    return `${m.webhook_host || '—'}${m.has_secret ? ' · 已配签名密钥' : ''}`;
  }

  async function refresh() {
    try {
      const data = await invoke('notify.overview', {});
      const chs = Array.isArray(data.channels) ? data.channels : [];
      const rls = Array.isArray(data.rules) ? data.rules : [];
      const dels = Array.isArray(data.deliveries) ? data.deliveries : [];
      latestChannels = chs;
      latestRules = rls;

      const chNameById = new Map(chs.map((c) => [c.id, c.name]));
      const boundChannelIDs = new Set();
      for (const r of rls) {
        if (r && r.enabled && Array.isArray(r.channel_ids)) {
          for (const cid of r.channel_ids) boundChannelIDs.add(cid);
        }
      }

      $('st-channels').textContent = String(chs.filter((c) => c.enabled).length);
      $('st-rules').textContent = String(rls.length);
      $('st-sent').textContent = String(data.sent_24h || 0);
      $('st-fail').textContent = `${data.suppressed_24h || 0} / ${data.failed_24h || 0}`;

      const prevSelectedChs = getSelectedRuleChannelIDs();
      renderRuleChannelCheckboxes(prevSelectedChs);

      const ct = $('channels-tbody');
      ct.replaceChildren();
      if (!chs.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 5;
        td.className = 'empty-cell';
        td.textContent = '暂无已配置的通知渠道。';
        tr.appendChild(td);
        ct.appendChild(tr);
      }
      for (const c of chs) {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        const nameStack = document.createElement('div');
        nameStack.className = 'cell-stack';
        const topLine = document.createElement('div');
        topLine.className = 'cell-inline';
        const strong = document.createElement('strong');
        strong.textContent = c.name;
        topLine.append(strong, badge(c.enabled ? '已启用' : '已停用', c.enabled ? 'ok' : 'muted'));
        if (c.enabled && !boundChannelIDs.has(c.id)) {
          const orphanBadge = badge('未绑定规则', 'warn');
          orphanBadge.title = '真实系统告警不会发送至此渠道，请前往「路由与降噪规则」绑定';
          topLine.appendChild(orphanBadge);
        }
        const idCode = document.createElement('code');
        idCode.textContent = c.id;
        nameStack.append(topLine, idCode);
        if (c.enabled && !boundChannelIDs.has(c.id)) {
          const orphanTip = document.createElement('div');
          orphanTip.className = 'orphan-tip';
          orphanTip.textContent = '⚠ 未绑定启用的路由规则：真实系统告警不会发送至此渠道';
          nameStack.appendChild(orphanTip);
        }
        nameTd.appendChild(nameStack);
        tr.appendChild(nameTd);

        const kindTd = document.createElement('td');
        kindTd.textContent = c.kind;
        tr.appendChild(kindTd);

        const cfgTd = document.createElement('td');
        cfgTd.textContent = summarizeMaskedConfig(c);
        tr.appendChild(cfgTd);

        const stTd = document.createElement('td');
        const stStack = document.createElement('div');
        stStack.className = 'cell-stack';
        stStack.appendChild(badge(c.last_status || 'unknown'));
        if (c.last_error) {
          const errDiv = document.createElement('div');
          errDiv.className = 'err-msg';
          errDiv.textContent = c.last_error;
          stStack.appendChild(errDiv);
        }
        stTd.appendChild(stStack);
        tr.appendChild(stTd);

        const act = document.createElement('td');
        const editBtn = document.createElement('button');
        editBtn.className = 'btn ghost sm';
        editBtn.type = 'button';
        editBtn.textContent = '编辑';
        editBtn.addEventListener('click', () => editChannel(c));

        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'btn ghost sm btn-gap';
        toggleBtn.type = 'button';
        toggleBtn.textContent = c.enabled ? '停用' : '启用';
        toggleBtn.addEventListener('click', () => void runAction(async () => {
          await invoke('notify.channel.upsert', {
            id: c.id,
            name: c.name,
            kind: c.kind,
            enabled: !c.enabled,
            config: {},
          });
          await refresh();
        }, `渠道 ${c.name} 已${c.enabled ? '停用' : '启用'}`));

        const tBtn = document.createElement('button');
        tBtn.className = 'btn ghost sm btn-gap';
        tBtn.type = 'button';
        tBtn.textContent = '测试';
        tBtn.addEventListener('click', () => void runAction(async () => {
          const r = await invoke('notify.channel.test', { id: c.id });
          await refresh();
          setStatus(r.ok ? `渠道 ${c.name} 测试成功 (HTTP ${r.http_status})` : `测试失败：${r.error || '未知错误'}`);
        }));

        const dBtn = document.createElement('button');
        dBtn.className = 'btn danger sm btn-gap';
        dBtn.type = 'button';
        dBtn.textContent = '删除';
        dBtn.addEventListener('click', () => void runAction(async () => {
          const ok = await hostConfirm('删除通知渠道', `确认删除通知渠道「${c.name}」及其加密凭据？`, { danger: true, confirmLabel: '确认删除' });
          if (!ok) return;
          await invoke('notify.channel.delete', { id: c.id });
          if ($('ch-id').value === c.id) resetChannelForm();
          await refresh();
          setStatus(`已删除渠道 ${c.name}`);
        }));

        act.append(editBtn, toggleBtn, tBtn, dBtn);
        tr.appendChild(act);
        ct.appendChild(tr);
      }

      const rt = $('rules-tbody');
      rt.replaceChildren();
      if (!rls.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 6;
        td.className = 'empty-cell';
        td.textContent = '暂无告警路由规则。';
        tr.appendChild(td);
        rt.appendChild(tr);
      }
      for (const r of rls) {
        const tr = document.createElement('tr');

        const nameTd = document.createElement('td');
        const nameLine = document.createElement('div');
        nameLine.className = 'cell-inline';
        const strong = document.createElement('strong');
        strong.textContent = r.name;
        nameLine.append(strong, badge(r.enabled ? '启用' : '停用', r.enabled ? 'ok' : 'muted'));
        nameTd.appendChild(nameLine);
        tr.appendChild(nameTd);

        const matchTd = document.createElement('td');
        matchTd.textContent = `${r.source_pattern} · >= ${r.min_severity}`;
        tr.appendChild(matchTd);

        const chsTd = document.createElement('td');
        const names = (r.channel_ids || []).map((id) => chNameById.get(id) || id);
        chsTd.textContent = names.length ? names.join(', ') : '未绑定渠道';
        tr.appendChild(chsTd);

        const coolTd = document.createElement('td');
        coolTd.textContent = `${r.cooldown_sec}s`;
        tr.appendChild(coolTd);

        const quietTd = document.createElement('td');
        quietTd.textContent = r.quiet_start ? `${r.quiet_start}-${r.quiet_end} (${r.quiet_tz})` : '关闭';
        tr.appendChild(quietTd);

        const act = document.createElement('td');
        const editBtn = document.createElement('button');
        editBtn.className = 'btn ghost sm';
        editBtn.type = 'button';
        editBtn.textContent = '编辑';
        editBtn.addEventListener('click', () => editRule(r));

        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'btn ghost sm btn-gap';
        toggleBtn.type = 'button';
        toggleBtn.textContent = r.enabled ? '停用' : '启用';
        toggleBtn.addEventListener('click', () => void runAction(async () => {
          await invoke('notify.rule.upsert', {
            id: r.id,
            name: r.name,
            enabled: !r.enabled,
            source_pattern: r.source_pattern,
            min_severity: r.min_severity,
            channel_ids: r.channel_ids || [],
            cooldown_sec: r.cooldown_sec ?? 300,
            quiet_start: r.quiet_start || '',
            quiet_end: r.quiet_end || '',
            quiet_tz: r.quiet_tz || 'UTC',
            allow_critical_bypass: Boolean(r.allow_critical_bypass),
          });
          await refresh();
        }, `规则 ${r.name} 已${r.enabled ? '停用' : '启用'}`));

        const dBtn = document.createElement('button');
        dBtn.className = 'btn danger sm btn-gap';
        dBtn.type = 'button';
        dBtn.textContent = '删除';
        dBtn.addEventListener('click', () => void runAction(async () => {
          const ok = await hostConfirm('删除路由规则', `确认删除路由规则「${r.name}」？`, { danger: true, confirmLabel: '确认删除' });
          if (!ok) return;
          await invoke('notify.rule.delete', { id: r.id });
          if ($('rl-id').value === r.id) resetRuleForm();
          await refresh();
          setStatus(`已删除规则 ${r.name}`);
        }));

        act.append(editBtn, toggleBtn, dBtn);
        tr.appendChild(act);
        rt.appendChild(tr);
      }

      const dt = $('deliveries-tbody');
      dt.replaceChildren();
      if (!dels.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 6;
        td.className = 'empty-cell';
        td.textContent = '暂无投递审计记录。';
        tr.appendChild(td);
        dt.appendChild(tr);
      }
      for (const d of dels) {
        const tr = document.createElement('tr');

        const tsTd = document.createElement('td');
        tsTd.className = 'ts-cell';
        tsTd.textContent = formatUnixTime(d.created_at);
        tr.appendChild(tsTd);

        const srcTd = document.createElement('td');
        const srcStack = document.createElement('div');
        srcStack.className = 'cell-stack';
        const srcTxt = document.createElement('span');
        srcTxt.textContent = d.source || '—';
        srcStack.append(srcTxt, badge(d.severity || 'info', d.severity === 'critical' ? 'err' : (d.severity === 'warn' ? 'warn' : 'muted')));
        srcTd.appendChild(srcStack);
        tr.appendChild(srcTd);

        const titleTd = document.createElement('td');
        titleTd.textContent = d.title || '—';
        tr.appendChild(titleTd);

        const chTd = document.createElement('td');
        chTd.textContent = d.channel_name || d.channel_id || '—';
        tr.appendChild(chTd);

        const stTd = document.createElement('td');
        const stStack = document.createElement('div');
        stStack.className = 'cell-stack';
        stStack.appendChild(badge(d.status));
        if (d.error_msg) {
          const msgDiv = document.createElement('div');
          msgDiv.className = d.status === 'failed' ? 'err-msg' : 'sup-msg';
          msgDiv.textContent = d.error_msg;
          stStack.appendChild(msgDiv);
        }
        stTd.appendChild(stStack);
        tr.appendChild(stTd);

        const atTd = document.createElement('td');
        atTd.textContent = String(d.attempts || 0);
        tr.appendChild(atTd);

        dt.appendChild(tr);
      }

      setStatus('已连接');
    } catch (err) {
      setStatus('加载失败：' + (err.message || '未知错误'));
    }
  }

  $('nav-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    for (const b of document.querySelectorAll('#nav-tabs button')) b.classList.toggle('active', b === btn);
    for (const p of document.querySelectorAll('[data-pane]')) p.hidden = p.dataset.pane !== btn.dataset.tab;
  });

  $('ch-kind').addEventListener('change', syncChannelKindFields);
  $('btn-ch-cancel').addEventListener('click', resetChannelForm);
  $('btn-rl-cancel').addEventListener('click', resetRuleForm);
  $('btn-refresh').addEventListener('click', () => void refresh());

  $('btn-save-ch').addEventListener('click', () => void runAction(async () => {
    const id = $('ch-id').value.trim();
    const name = $('ch-name').value.trim();
    const kind = $('ch-kind').value;
    const enabled = $('ch-enabled').checked;
    if (!name) throw new Error('请填写渠道名称');

    const config = {};
    if (kind === 'telegram') {
      const tok = $('tg-token').value.trim();
      const chat = $('tg-chat').value.trim();
      const thread = $('tg-thread').value.trim();
      const apiBase = $('tg-api-base').value.trim();
      if (tok) config.bot_token = tok;
      if (chat) config.chat_id = chat;
      if (thread) config.thread_id = thread;
      if (apiBase) config.api_base = apiBase;
    } else if (kind === 'smtp') {
      const host = $('smtp-host').value.trim();
      const portNum = Number($('smtp-port').value || 587);
      const user = $('smtp-user').value.trim();
      const pass = $('smtp-pass').value.trim();
      const from = $('smtp-from').value.trim();
      const toList = $('smtp-to').value.split(',').map((s) => s.trim()).filter(Boolean);
      const useTls = $('smtp-tls').checked;
      if (host) config.smtp_host = host;
      if (Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535) config.smtp_port = portNum;
      if (user) config.smtp_user = user;
      if (pass) config.smtp_pass = pass;
      if (from) config.smtp_from = from;
      if (toList.length) config.smtp_to = toList;
      config.smtp_tls = useTls;
    } else {
      const urlVal = $('wh-url').value.trim();
      const secVal = $('wh-secret').value.trim();
      if (urlVal) config.webhook_url = urlVal;
      if (secVal) config.secret = secVal;
    }

    const payload = { name, kind, enabled, config };
    if (id) payload.id = id;
    const res = await invoke('notify.channel.upsert', payload);
    resetChannelForm();
    await refresh();
    if (res && res.auto_created_rule) {
      setStatus(`渠道已加密保存，并已自动创建默认全局告警规则「${res.auto_created_rule.name || '默认全局告警'}」（接收 warn 及以上系统告警）`);
    } else {
      setStatus('渠道已加密保存');
    }
  }));

  $('btn-save-rl').addEventListener('click', () => void runAction(async () => {
    const id = $('rl-id').value.trim();
    const name = $('rl-name').value.trim();
    if (!name) throw new Error('请填写规则名称');
    const channelIds = getSelectedRuleChannelIDs();
    const payload = {
      name,
      enabled: $('rl-enabled').checked,
      source_pattern: $('rl-src').value.trim() || '*',
      min_severity: $('rl-sev').value,
      channel_ids: channelIds,
      cooldown_sec: Number($('rl-cool').value || 300),
      quiet_start: $('rl-qs').value.trim(),
      quiet_end: $('rl-qe').value.trim(),
      quiet_tz: $('rl-tz').value.trim() || 'UTC',
      allow_critical_bypass: $('rl-bypass').checked,
    };
    if (id) payload.id = id;
    await invoke('notify.rule.upsert', payload);
    resetRuleForm();
    await refresh();
  }, '路由规则已保存'));

  $('btn-dispatch').addEventListener('click', () => void runAction(async () => {
    const res = await invoke('notify.dispatch', {
      source: $('dp-src').value.trim(),
      severity: $('dp-sev').value,
      title: $('dp-title').value.trim(),
      message: $('dp-msg').value.trim(),
    });
    await refresh();
    setStatus(`演练分发完成：命中 ${res.matched_rules ?? 0} 条规则，成功 ${res.sent ?? 0} / 降噪 ${res.suppressed ?? 0} / 失败 ${res.failed ?? 0}`);
  }));

  function accept(data) {
    if (!data || typeof data !== 'object') return;
    if (data.t === 'api.result' && pending.has(data.id)) {
      const p = pending.get(data.id);
      clearTimeout(p.timer);
      pending.delete(data.id);
      if (data.ok === true) {
        const env = data.data;
        if (env && typeof env === 'object' && (env.status === 'AWAITING_APPROVAL' || env.approval_id)) {
          const err = new Error('等待审批确认');
          err.awaitingApproval = true;
          err.approvalId = env.approval_id;
          p.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'EXPIRED')) {
          p.reject(new Error(extractErrorMessage(env.error, `操作未完成 (${env.status || 'ERROR'})`)));
          return;
        }
        const result = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        p.resolve(result ?? {});
      } else {
        p.reject(new Error(extractErrorMessage(data.problem || data.error, '请求失败')));
      }
      return;
    }
    if (data.t === 'ui.confirm.result' && pendingConfirm.has(data.id)) {
      const req = pendingConfirm.get(data.id);
      pendingConfirm.delete(data.id);
      req.resolve(Boolean(data.ok && data.data?.confirmed));
      return;
    }
    if (data.t === 'ui.copy.result' && pendingCopy.has(data.id)) {
      const req = pendingCopy.get(data.id);
      clearTimeout(req.timer);
      pendingCopy.delete(data.id);
      if (data.ok) req.resolve(true);
      else req.reject(new Error(extractErrorMessage(data.problem || data.error, '复制失败')));
      return;
    }
    if (data.t === 'ui.settings') {
      applyHostVisualSettings(data);
    }
  }

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
  syncChannelKindFields();

  let lastSentHeight = 0;
  const ro = new ResizeObserver(() => {
    const height = Math.ceil($('notify-root').getBoundingClientRect().height) + 52;
    if (Math.abs(height - lastSentHeight) < 2) return;
    lastSentHeight = height;
    send({ t: 'ui.resize', height });
  });
  ro.observe($('notify-root'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (m) => accept(m.data);
    send({ t: 'ui.ready' });
    void refresh();
  });

  window.addEventListener('pagehide', () => {
    ro.disconnect();
    for (const p of pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error('页面已关闭'));
    }
    pending.clear();
    for (const req of pendingConfirm.values()) req.resolve(false);
    pendingConfirm.clear();
    for (const req of pendingCopy.values()) {
      clearTimeout(req.timer);
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
})();
