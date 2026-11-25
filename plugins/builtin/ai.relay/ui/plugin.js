// SPDX-License-Identifier: AGPL-3.0-only
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const hash = new URLSearchParams(location.hash.slice(1));
  const initialTheme = pick(hash.get('theme'), ['light', 'dark'], 'light');
  root.dataset.theme = initialTheme;
  root.style.colorScheme = initialTheme;
  const initialDensity = pick(hash.get('density'), ['comfortable', 'compact'], 'comfortable');
  root.dataset.density = initialDensity;

  let hostViewport = null;
  function applyHostVisualSettings(settings) {
    if (!settings || typeof settings !== 'object') return;
    if (settings.theme) {
      const theme = pick(settings.theme, ['light', 'dark'], root.dataset.theme || 'light');
      root.dataset.theme = theme;
      root.style.colorScheme = theme;
    }
    if (settings.density) {
      root.dataset.density = pick(settings.density, ['comfortable', 'compact'], root.dataset.density || 'comfortable');
    }
    if (settings.tokens && typeof settings.tokens === 'object') {
      const accent = settings.tokens['--accent'] || settings.tokens.accent;
      if (typeof accent === 'string' && accent.trim()) {
        root.style.setProperty('--accent', accent.trim());
      }
    }
  }

  for (const btn of document.querySelectorAll('#nav-tabs button')) {
    btn.addEventListener('click', () => {
      for (const b of document.querySelectorAll('#nav-tabs button')) b.classList.toggle('active', b === btn);
      for (const p of document.querySelectorAll('[data-pane]')) p.hidden = p.dataset.pane !== btn.dataset.tab;
    });
  }

  let port = null;
  let seq = 0;
  let publicOrigin = '';
  let editingChannelId = '';
  let adjustingUser = null;
  const savedPricings = new Map();
  const pending = new Map();
  const pendingConfirm = new Map();
  const pendingCopy = new Map();

  const send = (msg) => { if (port) port.postMessage(msg); };
  const setStatus = (t) => { document.getElementById('bridge-status').textContent = t; };
  const fmtUsd = (m) => `$${((Number(m) || 0) / 1e6).toFixed(2)}`;

  function normalizeOrigin(raw) {
    if (typeof raw !== 'string') return '';
    const trimmed = raw.trim().replace(/\/+$/, '');
    return /^https?:\/\/[^/\s]+$/i.test(trimmed) ? trimmed : '';
  }

  function publicUrl(path) {
    return publicOrigin ? `${publicOrigin}${path}` : path;
  }

  function updatePublicUrls() {
    const portalEl = document.getElementById('portal-url');
    const gwEl = document.getElementById('gateway-url');
    if (portalEl) portalEl.textContent = publicUrl('/p/ai.relay/portal/');
    if (gwEl) gwEl.textContent = publicUrl('/p/ai.relay/v1');
  }

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function invoke(operation, payload = {}) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    const id = String(++seq);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error('宿主响应超时'));
      }, 15000);
      pending.set(id, { resolve, reject, timer });
      send({ t: 'api.invoke', id, operation, payload });
    });
  }

  function hostConfirm(title, body, { danger = false, confirmLabel } = {}) {
    if (!port) return Promise.resolve(false);
    const id = `cf_${++seq}`;
    return new Promise((resolve) => {
      pendingConfirm.set(id, { resolve });
      const msg = { t: 'ui.confirm', id, title, body, danger: Boolean(danger) };
      if (confirmLabel) msg.confirm_label = confirmLabel;
      send(msg);
    });
  }

  function hostCopy(text, label) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    if (!text) return Promise.reject(new Error('没有可复制的内容'));
    const id = `cp_${++seq}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingCopy.delete(id);
        reject(new Error('复制响应超时'));
      }, 8000);
      pendingCopy.set(id, { resolve, reject, timer });
      const msg = { t: 'ui.copy', id, text: String(text) };
      if (label) msg.label = label;
      send(msg);
    });
  }

  async function runAction(fn, okMsg) {
    try {
      await fn();
      if (okMsg) setStatus(okMsg);
    } catch (err) {
      if (err && err.awaitingApproval) {
        setStatus('等待审批确认：请在宿主审批浮窗确认后刷新');
        send({ t: 'ui.toast', text: '操作已提交，等待审批确认' });
        return;
      }
      setStatus(`操作失败：${err?.message || '未知错误'}`);
    }
  }

  function resetChannelForm() {
    editingChannelId = '';
    document.getElementById('ch-form-title').textContent = '新增上游 API 渠道 / OAuth 订阅账号池';
    const banner = document.getElementById('ch-edit-banner');
    banner.hidden = true;
    banner.textContent = '';
    document.getElementById('ch-name').value = '';
    document.getElementById('ch-kind').value = 'openai_compatible';
    document.getElementById('ch-url').value = 'https://api.anthropic.com';
    const sec = document.getElementById('ch-secret');
    sec.value = '';
    sec.placeholder = 'sk-... 或 OAuth JSON';
    document.getElementById('ch-groups').value = 'default,standard,pro';
    document.getElementById('ch-models').value = 'claude-sonnet-4-5,gpt-4o,gemini-2.5-pro';
    document.getElementById('ch-prio').value = '10';
    document.getElementById('btn-save-channel').textContent = '加密保存上游渠道';
    document.getElementById('btn-cancel-channel-edit').hidden = true;
  }

  function enterChannelEdit(c) {
    editingChannelId = c.id || '';
    document.getElementById('ch-form-title').textContent = `编辑上游渠道：${c.name}`;
    const banner = document.getElementById('ch-edit-banner');
    banner.hidden = false;
    banner.textContent = `正在编辑渠道 ${c.name}（ID: ${c.id}）；若无需更换密钥或 OAuth 凭据，请将凭据输入框留空。`;
    document.getElementById('ch-name').value = c.name || '';
    document.getElementById('ch-kind').value = c.kind || 'openai_compatible';
    document.getElementById('ch-url').value = c.base_url || '';
    const sec = document.getElementById('ch-secret');
    sec.value = '';
    sec.placeholder = '已加密保存，留空表示保持原凭据不变';
    document.getElementById('ch-groups').value = Array.isArray(c.groups) ? c.groups.join(', ') : '';
    document.getElementById('ch-models').value = Array.isArray(c.models) ? c.models.join(', ') : '';
    document.getElementById('ch-prio').value = String(c.priority ?? 0);
    document.getElementById('btn-save-channel').textContent = '保存渠道修改';
    document.getElementById('btn-cancel-channel-edit').hidden = false;
  }

  function openUserAdjustModal(u) {
    adjustingUser = u;
    document.getElementById('adj-user-summary').textContent =
      `目标成员：${u.username}（ID: ${u.id}）· 当前余额 ${fmtUsd(u.balance_micros)} · 状态 ${u.status || 'active'}`;
    document.getElementById('adj-delta-usd').value = '0';
    document.getElementById('adj-group').value = u.group_name || 'default';
    document.getElementById('adj-status').value = u.status === 'disabled' ? 'disabled' : 'active';
    document.getElementById('adj-refill-usd').value = String((Number(u.auto_refill_cap_micros) || 0) / 1e6);
    document.getElementById('adj-refill-cycle').value = u.auto_refill_cycle || 'none';
    document.getElementById('adj-note').value = '';
    const modal = document.getElementById('user-adjust-modal');
    if (hostViewport && hostViewport.visibleHeight > 0) {
      modal.style.alignItems = 'flex-start';
      modal.style.paddingTop = `${Math.max(16, Math.round(hostViewport.scrollTop + Math.min(80, hostViewport.visibleHeight * 0.12)))}px`;
    }
    modal.hidden = false;
    requestAnimationFrame(notifyResize);
  }

  function closeUserAdjustModal() {
    adjustingUser = null;
    document.getElementById('user-adjust-modal').hidden = true;
    notifyResize();
  }

  function renderSavedPricings() {
    const tbody = document.getElementById('pricings-tbody');
    tbody.replaceChildren();
    for (const p of savedPricings.values()) {
      const tr = document.createElement('tr');
      const cells = [
        p.model_name,
        p.billing_mode,
        String(p.input_micros_per_1k),
        String(p.output_micros_per_1k),
        `${p.cache_read_ratio} / ${p.cache_write_ratio}`,
        String(p.per_call_micros),
      ];
      for (const txt of cells) {
        const td = document.createElement('td');
        td.textContent = txt;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }

  function accept(data) {
    if (!data || typeof data !== 'object') return;
    if (data.t === 'api.result' && pending.has(data.id)) {
      const req = pending.get(data.id);
      clearTimeout(req.timer);
      pending.delete(data.id);
      if (data.ok === true) {
        const env = data.data;
        if (env && typeof env === 'object' && (env.status === 'AWAITING_APPROVAL' || env.approval_id)) {
          const err = new Error('等待审批确认');
          err.awaitingApproval = true;
          err.approvalId = env.approval_id;
          req.reject(err);
          return;
        }
        if (env && typeof env === 'object' && (env.error || env.status === 'FAILED' || env.status === 'REJECTED' || env.status === 'CANCELED' || env.status === 'EXPIRED')) {
          req.reject(new Error(extractErrorMessage(env.error, `操作未完成 (${env.status || 'ERROR'})`)));
          return;
        }
        const result = env && typeof env === 'object' && 'result' in env && env.result !== undefined ? env.result : env;
        req.resolve(result ?? {});
      } else {
        req.reject(new Error(extractErrorMessage(data.problem || data.error, '请求失败')));
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
      const nextOrigin = normalizeOrigin(data.public_origin);
      if (nextOrigin !== publicOrigin) {
        publicOrigin = nextOrigin;
        updatePublicUrls();
      }
      return;
    }
    if (data.t === 'ui.viewport') {
      const vpTop = Math.max(0, Math.round(Number(data.offsetTopPx ?? data.visibleTop ?? data.scroll_top) || 0));
      const vpH = Math.max(280, Math.round(Number(data.viewportHeightPx ?? data.visibleHeight ?? data.visible_height) || 720));
      root.style.setProperty('--qwq-vp-top', `${vpTop}px`);
      root.style.setProperty('--qwq-vp-h', `${vpH}px`);
      hostViewport = {
        scrollTop: vpTop,
        visibleHeight: vpH,
        viewportWidth: Math.max(0, Number(data.viewport_width) || 0),
      };
      const modal = document.getElementById('user-adjust-modal');
      if (modal && !modal.hidden) {
        modal.style.paddingTop = `${Math.max(16, Math.round(vpTop + Math.min(80, vpH * 0.12)))}px`;
        notifyResize();
      }
    }
  }

  async function loadInitialData() {
    try {
      const [chData, uData, sData, prData] = await Promise.all([
        invoke('relay.channels.list', { limit: 100 }),
        invoke('relay.users.list', { limit: 100 }),
        invoke('relay.settings.get', {}),
        invoke('relay.pricings.list', {}).catch(() => ({ pricings: [] })),
      ]);
      savedPricings.clear();
      for (const p of prData?.pricings || []) {
        if (p && p.model_name) savedPricings.set(p.model_name, p);
      }
      renderSavedPricings();
      if (sData && typeof sData === 'object') {
        const setVal = (id, val) => {
          const el = document.getElementById(id);
          if (el && val !== undefined && val !== null) el.value = String(val);
        };
        setVal('st-title', sData.site_title ?? '');
        setVal('st-invite', sData.allow_invite_signup ? '1' : '0');
        setVal('st-email', sData.allow_email_signup ? '1' : '0');
        setVal('st-email-domains', Array.isArray(sData.email_domain_allowlist) ? sData.email_domain_allowlist.join(', ') : '');
        setVal('st-linuxdo', sData.allow_linuxdo_signup ? '1' : '0');
        setVal('st-ld-id', sData.linuxdo_client_id ?? '');
        setVal('st-ld-mintl', sData.linuxdo_min_trust_level ?? 1);
        setVal('st-init-usd', Number(sData.default_signup_micros ?? 5000000) / 1e6);
        setVal('st-drip-usd', Number(sData.checkin_drip_below_micros ?? 10000000) / 1e6);
        const ldSec = document.getElementById('st-ld-secret');
        if (ldSec) {
          ldSec.value = '';
          if (sData.linuxdo_client_secret_configured) {
            ldSec.placeholder = '已加密保存，留空表示不修改';
          }
        }
        const smtpBadge = document.getElementById('st-smtp-badge');
        const smtpPass = document.getElementById('st-smtp-pass');
        if (smtpBadge) {
          const configured = Boolean(sData.smtp_configured);
          smtpBadge.textContent = configured ? '已配置' : '未配置';
          smtpBadge.classList.toggle('ok', configured);
        }
        if (smtpPass) {
          smtpPass.value = '';
          smtpPass.placeholder = sData.smtp_configured ? '已加密保存，留空表示不修改' : 'SMTP 登录密码或授权码';
        }
      }

      const tbody = document.getElementById('channels-tbody');
      tbody.replaceChildren();
      for (const c of chData.channels || []) {
        const tr = document.createElement('tr');
        for (const txt of [c.name, c.kind, (c.groups || []).join(','), c.health_state, `${c.last_ttft_ms || 0} ms`]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const actTd = document.createElement('td');
        const actWrap = document.createElement('div');
        actWrap.className = 'row-actions';

        const testBtn = document.createElement('button');
        testBtn.className = 'btn ghost sm';
        testBtn.type = 'button';
        testBtn.textContent = '测速验活';
        testBtn.addEventListener('click', () => {
          void runAction(async () => {
            await invoke('relay.channels.test', { id: c.id });
            await loadInitialData();
          }, `渠道 ${c.name} 测速完成`);
        });
        actWrap.appendChild(testBtn);

        const editBtn = document.createElement('button');
        editBtn.className = 'btn ghost sm';
        editBtn.type = 'button';
        editBtn.textContent = '编辑';
        editBtn.addEventListener('click', () => enterChannelEdit(c));
        actWrap.appendChild(editBtn);

        const delBtn = document.createElement('button');
        delBtn.className = 'btn danger sm';
        delBtn.type = 'button';
        delBtn.textContent = '删除';
        delBtn.addEventListener('click', () => {
          void runAction(async () => {
            const ok = await hostConfirm(
              '删除上游渠道',
              `确认永久删除上游渠道「${c.name}」及其加密凭据？此操作不可撤销。`,
              { danger: true, confirmLabel: '确认删除' },
            );
            if (!ok) return;
            await invoke('relay.channels.remove', { id: c.id });
            if (editingChannelId === c.id) resetChannelForm();
            await loadInitialData();
          }, `渠道 ${c.name} 已删除`);
        });
        actWrap.appendChild(delBtn);

        actTd.appendChild(actWrap);
        tr.appendChild(actTd);
        tbody.appendChild(tr);
      }

      const utbody = document.getElementById('users-tbody');
      utbody.replaceChildren();
      for (const u of uData.users || []) {
        const tr = document.createElement('tr');
        const baseCells = [u.username, u.signup_source, u.group_name];
        for (const txt of baseCells) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const statusTd = document.createElement('td');
        const statusBadge = document.createElement('span');
        const isDisabled = u.status === 'disabled';
        statusBadge.className = isDisabled ? 'badge danger' : 'badge ok';
        statusBadge.textContent = isDisabled ? '已封禁' : '正常';
        statusTd.appendChild(statusBadge);
        tr.appendChild(statusTd);

        for (const txt of [fmtUsd(u.balance_micros), fmtUsd(u.used_micros), fmtUsd(u.auto_refill_cap_micros)]) {
          const td = document.createElement('td');
          td.textContent = txt;
          tr.appendChild(td);
        }
        const uActTd = document.createElement('td');
        const adjBtn = document.createElement('button');
        adjBtn.type = 'button';
        adjBtn.className = 'btn ghost sm';
        adjBtn.textContent = '调额 / 封禁';
        adjBtn.addEventListener('click', () => openUserAdjustModal(u));
        uActTd.appendChild(adjBtn);
        tr.appendChild(uActTd);
        utbody.appendChild(tr);
      }
      setStatus('已连接');
    } catch (err) {
      setStatus(`加载失败：${err.message || '未知错误'}`);
    }
  }

  document.getElementById('btn-cancel-channel-edit').addEventListener('click', () => {
    resetChannelForm();
  });

  document.getElementById('btn-save-channel').addEventListener('click', () => {
    void runAction(async () => {
      const payload = {
        name: document.getElementById('ch-name').value.trim(),
        kind: document.getElementById('ch-kind').value,
        base_url: document.getElementById('ch-url').value.trim(),
        groups: document.getElementById('ch-groups').value.split(',').map((s) => s.trim()).filter(Boolean),
        models: document.getElementById('ch-models').value.split(',').map((s) => s.trim()).filter(Boolean),
        priority: Number(document.getElementById('ch-prio').value || 0),
      };
      if (editingChannelId) payload.id = editingChannelId;
      const secretVal = document.getElementById('ch-secret').value.trim();
      if (secretVal) payload.credential = secretVal;
      await invoke('relay.channels.upsert', payload);
      resetChannelForm();
      await loadInitialData();
    }, '上游渠道已加密保存');
  });

  function applyPricingPreset(model, inMicros, outMicros, cacheR, cacheW) {
    document.getElementById('pr-model').value = model;
    document.getElementById('pr-mode').value = 'token';
    document.getElementById('pr-in').value = String(inMicros);
    document.getElementById('pr-out').value = String(outMicros);
    document.getElementById('pr-cache-r').value = String(cacheR);
    document.getElementById('pr-cache-w').value = String(cacheW);
    document.getElementById('pr-per-call').value = '0';
  }

  document.getElementById('btn-preset-claude').addEventListener('click', () => {
    applyPricingPreset('claude-sonnet-4-5', 3000, 15000, 0.1, 1.25);
  });
  document.getElementById('btn-preset-gpt4o').addEventListener('click', () => {
    applyPricingPreset('gpt-4o', 2500, 10000, 0.5, 1.0);
  });
  document.getElementById('btn-preset-gemini').addEventListener('click', () => {
    applyPricingPreset('gemini-2.5-pro', 1250, 10000, 0.25, 1.0);
  });

  document.getElementById('btn-save-pricing').addEventListener('click', () => {
    void runAction(async () => {
      const payload = {
        model_name: document.getElementById('pr-model').value.trim(),
        billing_mode: document.getElementById('pr-mode').value,
        input_micros_per_1k: Math.max(0, Math.round(Number(document.getElementById('pr-in').value || 0))),
        output_micros_per_1k: Math.max(0, Math.round(Number(document.getElementById('pr-out').value || 0))),
        cache_read_ratio: Number(document.getElementById('pr-cache-r').value || 0.1),
        cache_write_ratio: Number(document.getElementById('pr-cache-w').value || 1.25),
        per_call_micros: Math.max(0, Math.round(Number(document.getElementById('pr-per-call').value || 0))),
      };
      if (!payload.model_name) throw new Error('模型标识不能为空');
      await invoke('relay.pricings.upsert', payload);
      savedPricings.set(payload.model_name, payload);
      renderSavedPricings();
    }, '模型倍率已保存');
  });

  document.getElementById('btn-save-settings').addEventListener('click', () => {
    void runAction(async () => {
      const payload = {
        site_title: document.getElementById('st-title').value.trim(),
        allow_invite_signup: document.getElementById('st-invite').value === '1',
        allow_email_signup: document.getElementById('st-email').value === '1',
        email_domain_allowlist: document.getElementById('st-email-domains').value.split(',').map((s) => s.trim()).filter(Boolean),
        allow_linuxdo_signup: document.getElementById('st-linuxdo').value === '1',
        linuxdo_client_id: document.getElementById('st-ld-id').value.trim(),
        linuxdo_min_trust_level: Number(document.getElementById('st-ld-mintl').value || 1),
        default_signup_micros: Math.round(Number(document.getElementById('st-init-usd').value || 5) * 1e6),
        checkin_drip_below_micros: Math.round(Number(document.getElementById('st-drip-usd').value || 10) * 1e6),
      };
      const ldSecret = document.getElementById('st-ld-secret').value.trim();
      if (ldSecret) payload.linuxdo_client_secret = ldSecret;

      const smtpHost = document.getElementById('st-smtp-host').value.trim();
      if (smtpHost) {
        const smtp = {
          host: smtpHost,
          port: Number(document.getElementById('st-smtp-port').value || 587),
          username: document.getElementById('st-smtp-user').value.trim(),
          from_address: document.getElementById('st-smtp-from').value.trim(),
        };
        const smtpPass = document.getElementById('st-smtp-pass').value.trim();
        if (smtpPass) smtp.password = smtpPass;
        payload.smtp = smtp;
      }

      await invoke('relay.settings.update', payload);
      document.getElementById('st-ld-secret').value = '';
      document.getElementById('st-smtp-pass').value = '';
      await loadInitialData();
    }, '策略已保存');
  });

  document.getElementById('btn-gen-codes').addEventListener('click', () => {
    void runAction(async () => {
      const res = await invoke('relay.codes.generate', {
        kind: document.getElementById('cd-kind').value,
        amount_micros: Math.round(Number(document.getElementById('cd-usd').value || 10) * 1e6),
        count: Number(document.getElementById('cd-count').value || 1),
        custom_code: document.getElementById('cd-custom').value.trim(),
      });
      document.getElementById('cd-output').value = (res.codes || []).join('\n');
    }, '已签发兑换码 / 邀请码');
  });

  document.getElementById('btn-copy-codes').addEventListener('click', () => {
    const text = document.getElementById('cd-output').value.trim();
    void runAction(async () => {
      await hostCopy(text, '已复制签发结果');
    }, '已复制签发结果');
  });

  document.getElementById('btn-create-user').addEventListener('click', () => {
    void runAction(async () => {
      await invoke('relay.users.create', {
        username: document.getElementById('u-name').value.trim(),
        password: document.getElementById('u-pass').value,
        group_name: document.getElementById('u-group').value.trim() || 'default',
        init_micros: Math.round(Number(document.getElementById('u-init-usd').value || 0) * 1e6),
        daily_refill_micros: Math.round(Number(document.getElementById('u-daily-usd').value || 0) * 1e6),
      });
      document.getElementById('u-pass').value = '';
      await loadInitialData();
    }, '分发成员已创建');
  });

  document.getElementById('btn-adj-close').addEventListener('click', closeUserAdjustModal);
  document.getElementById('btn-adj-cancel').addEventListener('click', closeUserAdjustModal);
  document.getElementById('btn-adj-submit').addEventListener('click', () => {
    if (!adjustingUser) return;
    const target = adjustingUser;
    void runAction(async () => {
      const payload = {
        user_id: target.id,
        delta_micros: Math.round(Number(document.getElementById('adj-delta-usd').value || 0) * 1e6),
        group_name: document.getElementById('adj-group').value.trim(),
        status: document.getElementById('adj-status').value,
        auto_refill_cap_micros: Math.max(0, Math.round(Number(document.getElementById('adj-refill-usd').value || 0) * 1e6)),
        auto_refill_cycle: document.getElementById('adj-refill-cycle').value,
        note: document.getElementById('adj-note').value.trim() || '管理员调额与状态变更',
      };
      await invoke('relay.users.adjust_quota', payload);
      closeUserAdjustModal();
      await loadInitialData();
    }, `已更新成员 ${target.username}`);
  });

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

  let lastSentHeight = 0;
  function notifyResize() {
    const rootEl = document.getElementById('ai-relay-root');
    if (!rootEl) return;
    let height = Math.ceil(rootEl.getBoundingClientRect().height) + 52;
    const modal = document.getElementById('user-adjust-modal');
    if (modal && !modal.hidden) {
      const card = modal.querySelector('.modal-card');
      const cardH = card ? Math.ceil(card.getBoundingClientRect().height) : 420;
      const vpTop = Math.max(0, Number(hostViewport?.scrollTop) || 0);
      height = Math.max(height, vpTop + cardH + 72);
    }
    if (Math.abs(height - lastSentHeight) < 2) return;
    lastSentHeight = height;
    send({ t: 'ui.resize', height });
  }

  const observer = new ResizeObserver(() => notifyResize());
  observer.observe(document.getElementById('ai-relay-root'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (msg) => accept(msg.data);
    send({ t: 'ui.ready' });
    void loadInitialData();
  });

  window.addEventListener('pagehide', () => {
    observer.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
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
