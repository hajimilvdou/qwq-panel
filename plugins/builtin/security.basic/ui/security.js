// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== 基础安全 5 标签工作台与 OpenSSH Ed25519 本地密钥生成 ======================== */
(() => {
  'use strict';

  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const hash = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(hash.get('theme'), ['light', 'dark'], 'light');

  const $ = (id) => document.getElementById(id);
  let port = null;
  let seq = 0;
  const pending = new Map();
  const pendingConfirm = new Map();
  const pendingCopy = new Map();

  const state = {
    overview: null,
    fw: null,
    fwPolicy: 'accept',
    fwRules: [],
    fwGuards: [],
    fwDirty: false,
    conflicts: null,
    sshd: null,
    bans: null,
    keysUser: 'root',
    keysRevision: '',
    keys: [],
  };

  const send = (msg) => { if (port) port.postMessage(msg); };
  const setStatus = (text) => { $('status').textContent = text; };

  function showGlobalAlert(text, kind = 'warn') {
    const el = $('global-alert');
    if (!text) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    el.className = `banner ${kind}`;
    el.textContent = text;
    el.hidden = false;
  }

  function setKeyFeedback(text, kind = 'muted') {
    const el = $('key-feedback');
    el.textContent = text;
    el.className = kind === 'warn' ? 'warn-text feedback' : (kind === 'err' ? 'danger-text feedback' : 'muted feedback');
  }

  function extractErrorMessage(errObj, fallback) {
    if (!errObj) return fallback;
    if (typeof errObj === 'string') return errObj;
    return errObj.detail || errObj.message || errObj.code || fallback;
  }

  function invoke(operation, payload = {}, timeoutMs = 20000) {
    if (!port) return Promise.reject(new Error('宿主通道未就绪'));
    const id = `sec_${++seq}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error('宿主响应超时'));
      }, timeoutMs);
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
      showGlobalAlert('');
      await fn();
      if (okMsg) {
        setStatus(okMsg);
        send({ t: 'ui.toast', text: okMsg });
      }
    } catch (err) {
      if (err && err.awaitingApproval) {
        const msg = '操作已提交宿主审批，请在右侧审批浮窗点击批准后自动刷新。';
        setStatus(msg);
        showGlobalAlert(msg, 'info');
        send({ t: 'ui.toast', text: '操作已提交，等待审批确认' });
        return;
      }
      const msg = `操作失败：${err?.message || '未知错误'}`;
      setStatus(msg);
      showGlobalAlert(msg, 'err');
    }
  }

  function switchTab(tabName) {
    for (const btn of document.querySelectorAll('#nav-tabs button[data-tab]')) {
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    }
    for (const pane of document.querySelectorAll('[data-pane]')) {
      pane.hidden = pane.dataset.pane !== tabName;
    }
    if (tabName === 'keys' && port && state.keys.length === 0) {
      void loadKeys();
    }
  }

  function makeBadge(text, cls) {
    const span = document.createElement('span');
    span.className = `badge ${cls}`;
    span.textContent = text;
    return span;
  }

  function formatDuration(sec) {
    const s = Math.max(0, Math.floor(sec));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const r = s % 60;
    const pad = (n) => String(n).padStart(2, '0');
    return h > 0 ? `${h}h ${pad(m)}m ${pad(r)}s` : `${pad(m)}m ${pad(r)}s`;
  }

  function formatTimestampMs(ms) {
    if (!ms || ms <= 0) return '—';
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return '—';
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  /* ======================== OpenSSH Ed25519 原生私钥编码器（零触网） ======================== */

  function writeSSHBytes(parts, payload) {
    const lenBuf = new Uint8Array(4);
    new DataView(lenBuf.buffer).setUint32(0, payload.byteLength, false);
    parts.push(lenBuf, payload);
  }

  function writeSSHString(parts, str) {
    writeSSHBytes(parts, new TextEncoder().encode(str));
  }

  function concatUint8(chunks) {
    let total = 0;
    for (const c of chunks) total += c.byteLength;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.byteLength;
    }
    return out;
  }

  function toBase64Wrapped(bytes, lineWidth = 70) {
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    const b64 = btoa(binary);
    if (lineWidth <= 0) return b64;
    const lines = [];
    for (let i = 0; i < b64.length; i += lineWidth) {
      lines.push(b64.slice(i, i + lineWidth));
    }
    return lines.join('\n');
  }

  function encodeOpenSSHEd25519PrivateKey(seed32, pub32, comment) {
    const cleanComment = (comment || 'qwq-browser').trim() || 'qwq-browser';

    // 公钥 blob: string("ssh-ed25519") + string(pub32)
    const pubParts = [];
    writeSSHString(pubParts, 'ssh-ed25519');
    writeSSHBytes(pubParts, pub32);
    const pubBlob = concatUint8(pubParts);
    const publicKeyAuthorized = `ssh-ed25519 ${toBase64Wrapped(pubBlob, 0)} ${cleanComment}`;

    // OpenSSH 私钥段（openssh-key-v1 unencrypted）
    const checkInt = window.crypto.getRandomValues(new Uint8Array(4));
    const privSection = [checkInt, checkInt];
    writeSSHString(privSection, 'ssh-ed25519');
    writeSSHBytes(privSection, pub32);

    const secret64 = new Uint8Array(64);
    secret64.set(seed32, 0);
    secret64.set(pub32, 32);
    writeSSHBytes(privSection, secret64);
    writeSSHString(privSection, cleanComment);

    const rawPrivPrePad = concatUint8(privSection);
    const blockSize = 8;
    const padLen = (blockSize - (rawPrivPrePad.byteLength % blockSize)) % blockSize;
    const padBytes = new Uint8Array(padLen);
    for (let i = 0; i < padLen; i += 1) padBytes[i] = (i + 1) & 0xff;
    const paddedPrivBlob = concatUint8([rawPrivPrePad, padBytes]);

    const magic = new TextEncoder().encode('openssh-key-v1\0');
    const outerParts = [magic];
    writeSSHString(outerParts, 'none');
    writeSSHString(outerParts, 'none');
    writeSSHBytes(outerParts, new Uint8Array(0));
    outerParts.push(new Uint8Array([0, 0, 0, 1]));
    writeSSHBytes(outerParts, pubBlob);
    writeSSHBytes(outerParts, paddedPrivBlob);

    const fullDer = concatUint8(outerParts);
    secret64.fill(0);

    const pemTag = ['OPENSSH', 'PRIVATE', 'KEY'].join(' ');
    const beginLine = ['-----', 'BEGIN ', pemTag, '-----'].join('');
    const endLine = ['-----', 'END ', pemTag, '-----'].join('');
    const privateKeyOpenSSHPEM = `${beginLine}\n${toBase64Wrapped(fullDer, 70)}\n${endLine}\n`;
    return { publicKeyAuthorized, privateKeyOpenSSHPEM };
  }

  async function generateOpenSSHEd25519KeyPair(comment) {
    const pair = await window.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const rawPub = new Uint8Array(await window.crypto.subtle.exportKey('raw', pair.publicKey));
    const pkcs8Priv = new Uint8Array(await window.crypto.subtle.exportKey('pkcs8', pair.privateKey));
    if (rawPub.byteLength !== 32 || pkcs8Priv.byteLength < 32) {
      throw new Error('Ed25519 导出长度异常');
    }
    const seed32 = pkcs8Priv.slice(pkcs8Priv.byteLength - 32);
    try {
      return encodeOpenSSHEd25519PrivateKey(seed32, rawPub, comment);
    } finally {
      seed32.fill(0);
      pkcs8Priv.fill(0);
    }
  }

  function downloadTextFile(filename, content) {
    const blob = new Blob([content], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /* ======================== nftables JSON 规则集解析与构造 ======================== */

  function parseNftRuleset(ruleset) {
    const out = { policy: 'accept', rules: [], guards: [] };
    const entries = Array.isArray(ruleset?.nftables) ? ruleset.nftables : [];
    for (const item of entries) {
      if (!item || typeof item !== 'object') continue;
      if (item.chain && item.chain.name === 'input' && (item.chain.policy === 'accept' || item.chain.policy === 'drop')) {
        out.policy = item.chain.policy;
        continue;
      }
      if (!item.rule) continue;
      const r = item.rule;
      const comment = typeof r.comment === 'string' ? r.comment : '';
      if (comment.startsWith('qwq:')) {
        out.guards.push({ comment, raw: r });
        continue;
      }
      const parsed = parseSingleNftRule(r);
      if (parsed) {
        out.rules.push(parsed);
      }
    }
    return out;
  }

  function parseSingleNftRule(rule) {
    const exprs = Array.isArray(rule.expr) ? rule.expr : [];
    let proto = '';
    let portVal = '';
    let saddr = '';
    let action = 'accept';
    for (const ex of exprs) {
      if (!ex || typeof ex !== 'object') continue;
      if ('accept' in ex) {
        action = 'accept';
        continue;
      }
      if ('drop' in ex) {
        action = 'drop';
        continue;
      }
      if (ex.match && ex.match.left?.payload) {
        const pl = ex.match.left.payload;
        if ((pl.protocol === 'tcp' || pl.protocol === 'udp') && pl.field === 'dport') {
          proto = pl.protocol;
          if (typeof ex.match.right === 'number') {
            portVal = String(ex.match.right);
          } else if (Array.isArray(ex.match.right?.set)) {
            portVal = ex.match.right.set.join(', ');
          }
        } else if ((pl.protocol === 'ip' || pl.protocol === 'ip6') && pl.field === 'saddr') {
          if (typeof ex.match.right === 'string') {
            saddr = ex.match.right;
          } else if (ex.match.right?.prefix) {
            saddr = `${ex.match.right.prefix.addr}/${ex.match.right.prefix.len}`;
          }
        }
      }
    }
    return {
      proto: proto || 'any',
      port: portVal || '全部',
      saddr: saddr || '0.0.0.0/0',
      action,
      comment: rule.comment || '',
      raw: rule,
    };
  }

  function buildNftRuleFromInput(proto, portNum, saddrInput, action, comment) {
    const expr = [];
    const saddr = saddrInput.trim();
    if (saddr) {
      const isV6 = saddr.includes(':');
      const left = { payload: { protocol: isV6 ? 'ip6' : 'ip', field: 'saddr' } };
      let right = saddr;
      if (saddr.includes('/')) {
        const [addr, lenStr] = saddr.split('/');
        const prefixLen = Number(lenStr);
        if (!addr || !Number.isInteger(prefixLen) || prefixLen < 0 || prefixLen > (isV6 ? 128 : 32)) {
          throw new Error('来源 CIDR 前缀长度无效');
        }
        right = { prefix: { addr: addr.trim(), len: prefixLen } };
      }
      expr.push({ match: { op: '==', left, right } });
    }
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      throw new Error('端口必须是 1 到 65535 之间的整数');
    }
    expr.push({
      match: {
        op: '==',
        left: { payload: { protocol: proto === 'udp' ? 'udp' : 'tcp', field: 'dport' } },
        right: portNum,
      },
    });
    expr.push(action === 'drop' ? { drop: null } : { accept: null });

    const rule = { family: 'inet', table: 'qwq', chain: 'input', expr };
    const cleanComment = comment.trim();
    if (cleanComment) {
      if (cleanComment.startsWith('qwq:')) {
        throw new Error('自定义备注不可使用保留前缀 qwq:');
      }
      rule.comment = cleanComment;
    }
    return rule;
  }

  function buildNftDocument() {
    const nftables = [
      { table: { family: 'inet', name: 'qwq' } },
      { chain: { family: 'inet', table: 'qwq', name: 'input', type: 'filter', hook: 'input', prio: 0, policy: state.fwPolicy } },
    ];
    for (const r of state.fwRules) {
      const clean = { family: 'inet', table: 'qwq', chain: 'input', expr: r.raw.expr };
      if (r.raw.comment) clean.comment = r.raw.comment;
      nftables.push({ rule: clean });
    }
    return { nftables };
  }

  /* ======================== 各标签页渲染 ======================== */

  function findSetting(settings, key) {
    if (!Array.isArray(settings)) return null;
    const lower = key.toLowerCase();
    return settings.find((s) => s && String(s.key || '').toLowerCase() === lower) || null;
  }

  function renderOverview() {
    const ov = state.overview || {};
    const sshd = state.sshd || {};
    const conflicts = state.conflicts || {};

    $('ov-bans').textContent = String(ov.active_ban_count ?? (state.bans?.bans?.length ?? 0));
    $('ov-bans-sub').textContent = ov.sub || '已同步';

    const ports = Array.isArray(sshd.listening_ports) && sshd.listening_ports.length ? sshd.listening_ports : [22];
    $('ov-ssh-port').textContent = ports.join(', ');
    $('ov-saga-sub').textContent = sshd.port_saga
      ? `切换进行中：${sshd.port_saga.old_port} -> ${sshd.port_saga.new_port}`
      : '无挂起改端口事务';

    const pwSetting = findSetting(sshd.settings, 'passwordauthentication');
    const rootSetting = findSetting(sshd.settings, 'permitrootlogin');
    $('ov-pw-auth').textContent = pwSetting ? (pwSetting.value === 'yes' ? '允许密码' : '仅公钥') : '未知';
    $('ov-pw-src').textContent = pwSetting ? `${pwSetting.source_file || '默认'}${pwSetting.overridden_by ? ` (被 ${pwSetting.overridden_by} 覆盖)` : ''}` : '—';

    $('ov-root-login').textContent = rootSetting ? rootSetting.value : '未知';
    $('ov-root-src').textContent = rootSetting ? `${rootSetting.source_file || '默认'}${rootSetting.overridden_by ? ` (被 ${rootSetting.overridden_by} 覆盖)` : ''}` : '—';

    // 高亮展示 overridden_by 覆盖警告条（如 50-cloud-init.conf）
    const overridden = (sshd.settings || []).filter((s) => s && s.overridden_by);
    if (overridden.length > 0) {
      const details = overridden.map((s) => `${s.key}=${s.value} 被 ${s.overridden_by} 覆盖`).join('；');
      $('ov-override-text').textContent = `${details}。修改 00-qwq.conf 前请核查高优先级 drop-in 文件。`;
      $('ov-override-banner').hidden = false;
      $('sshd-override-warn').textContent = `警告：${details}`;
      $('sshd-override-warn').hidden = false;
    } else {
      $('ov-override-banner').hidden = true;
      $('sshd-override-warn').hidden = true;
    }

    if (sshd.port_saga) {
      $('ov-saga-text').textContent = `端口 ${sshd.port_saga.old_port} -> ${sshd.port_saga.new_port}（待验证并确认提交）`;
      $('ov-saga-banner').hidden = false;
    } else {
      $('ov-saga-banner').hidden = true;
    }

    const mgrs = Array.isArray(conflicts.managers) ? conflicts.managers : [];
    const activeConflict = Boolean(conflicts.has_active_firewall_conflict);
    const badge = $('ov-conflict-badge');
    if (activeConflict) {
      badge.className = 'badge warn';
      badge.textContent = '存在活跃外部防火墙';
    } else if (conflicts.fail2ban_active) {
      badge.className = 'badge ok';
      badge.textContent = 'fail2ban 共存旁观';
    } else {
      badge.className = 'badge ok';
      badge.textContent = '无冲突';
    }

    const grid = $('conflicts-grid');
    grid.replaceChildren();
    if (mgrs.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'muted';
      empty.textContent = '未检测到 ufw、firewalld 或 fail2ban 等外部管理器。';
      grid.appendChild(empty);
    } else {
      for (const m of mgrs) {
        const card = document.createElement('div');
        card.className = 'mgr-card';
        const head = document.createElement('div');
        head.className = 'mgr-card-head';
        const name = document.createElement('strong');
        name.textContent = m.kind || 'unknown';
        const st = makeBadge(
          m.active ? (String(m.kind).toLowerCase() === 'fail2ban' ? '活跃（旁观）' : '活跃（冲突）') : '未激活',
          m.active ? (String(m.kind).toLowerCase() === 'fail2ban' ? 'ok' : 'warn') : 'muted',
        );
        head.append(name, st);
        const detail = document.createElement('div');
        detail.className = 'muted';
        detail.textContent = m.detail || (m.active ? '服务运行中' : '未运行');
        card.append(head, detail);
        grid.appendChild(card);
      }
    }
  }

  function renderFirewall() {
    const fw = state.fw || {};
    $('fw-rev-chip').textContent = `修订号：${fw.revision || '—'}`;
    $('fw-persist-badge').hidden = !fw.persistence_pending;
    $('fw-policy').value = state.fwPolicy;
    $('fw-dirty-hint').hidden = !state.fwDirty;

    const chips = $('fw-preserved-chips');
    chips.replaceChildren();
    const preserved = Array.isArray(fw.preserved_ports) ? fw.preserved_ports : [];
    if (preserved.length === 0) {
      const span = document.createElement('span');
      span.className = 'muted';
      span.textContent = '暂无保留端口';
      chips.appendChild(span);
    } else {
      for (const p of preserved) {
        const chip = document.createElement('span');
        chip.className = 'chip port';
        chip.textContent = `TCP ${p} · 宿主保留`;
        chips.appendChild(chip);
      }
    }

    const tbody = $('fw-rules-tbody');
    tbody.replaceChildren();
    for (const g of state.fwGuards) {
      const tr = document.createElement('tr');
      for (const txt of ['system', '保护规则', '全部', 'accept', `${g.comment}（宿主自动保护）`]) {
        const td = document.createElement('td');
        td.textContent = txt;
        tr.appendChild(td);
      }
      const actTd = document.createElement('td');
      actTd.appendChild(makeBadge('只读保护', 'muted'));
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    }

    state.fwRules.forEach((r, idx) => {
      const tr = document.createElement('tr');
      const cells = [r.proto.toUpperCase(), r.port, r.saddr];
      for (const txt of cells) {
        const td = document.createElement('td');
        td.textContent = txt;
        tr.appendChild(td);
      }
      const actionTd = document.createElement('td');
      actionTd.appendChild(makeBadge(r.action === 'drop' ? 'DROP' : 'ACCEPT', r.action === 'drop' ? 'err' : 'ok'));
      tr.appendChild(actionTd);

      const commentTd = document.createElement('td');
      commentTd.textContent = r.comment || '自定义规则';
      tr.appendChild(commentTd);

      const opTd = document.createElement('td');
      const delBtn = document.createElement('button');
      delBtn.className = 'btn danger sm';
      delBtn.type = 'button';
      delBtn.textContent = '删除';
      delBtn.addEventListener('click', () => {
        state.fwRules.splice(idx, 1);
        state.fwDirty = true;
        renderFirewall();
      });
      opTd.appendChild(delBtn);
      tr.appendChild(opTd);
      tbody.appendChild(tr);
    });

    if (state.fwGuards.length === 0 && state.fwRules.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'empty-cell';
      td.textContent = '当前无自定义防火墙规则。';
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }

  function renderSSHD() {
    const sshd = state.sshd || {};
    $('sshd-rev-chip').textContent = `修订号：${sshd.revision || '—'}`;

    const pwSetting = findSetting(sshd.settings, 'passwordauthentication');
    if (pwSetting) {
      $('sshd-pw-auth').value = pwSetting.value === 'yes' ? 'true' : 'false';
    }
    const rootSetting = findSetting(sshd.settings, 'permitrootlogin');
    if (rootSetting) {
      if (rootSetting.value === 'yes') $('sshd-root-mode').value = 'allow';
      else if (rootSetting.value === 'no') $('sshd-root-mode').value = 'deny';
      else $('sshd-root-mode').value = 'keys_only';
    }

    const stTbody = $('sshd-settings-tbody');
    stTbody.replaceChildren();
    const settings = Array.isArray(sshd.settings) ? sshd.settings : [];
    for (const s of settings) {
      const tr = document.createElement('tr');
      for (const txt of [s.key, s.value, s.source_file || '默认']) {
        const td = document.createElement('td');
        td.textContent = txt;
        tr.appendChild(td);
      }
      const ovTd = document.createElement('td');
      if (s.overridden_by) {
        ovTd.appendChild(makeBadge(`被 ${s.overridden_by} 覆盖`, 'warn'));
      } else {
        ovTd.appendChild(makeBadge('生效中', 'ok'));
      }
      tr.appendChild(ovTd);
      stTbody.appendChild(tr);
    }

    const saga = sshd.port_saga;
    const steps = document.querySelectorAll('#saga-stepper .step');
    if (saga) {
      steps.forEach((el) => {
        const n = Number(el.dataset.step);
        el.classList.toggle('done', n === 1);
        el.classList.toggle('active', n === 2 || n === 3);
      });
      $('saga-prepare-panel').hidden = true;
      $('saga-active-panel').hidden = false;
      $('saga-ports-text').textContent = `${saga.old_port} -> ${saga.new_port}`;
      $('saga-ref-text').textContent = saga.transaction_ref;
      const hostHint = window.location.hostname || '服务器IP';
      $('saga-test-cmd').textContent = `ssh -p ${saga.new_port} root@${hostHint}`;
      const extBadge = $('saga-ext-badge');
      if (saga.external_connection_detected) {
        extBadge.className = 'badge ok';
        extBadge.textContent = '已检测到外部 ESTABLISHED 连接';
      } else {
        extBadge.className = 'badge warn';
        extBadge.textContent = '暂未检测到外部连接';
      }
      updateSagaCountdown();
    } else {
      steps.forEach((el) => {
        const n = Number(el.dataset.step);
        el.classList.toggle('done', false);
        el.classList.toggle('active', n === 1);
      });
      $('saga-prepare-panel').hidden = false;
      $('saga-active-panel').hidden = true;
    }
  }

  function updateSagaCountdown() {
    const saga = state.sshd?.port_saga;
    if (!saga || !saga.deadline_unix) return;
    const remain = saga.deadline_unix - Math.floor(Date.now() / 1000);
    $('saga-countdown').textContent = remain > 0 ? formatDuration(remain) : '已到期，等待后台自动回滚…';
  }

  function renderKeys() {
    const tbody = $('keys-tbody');
    tbody.replaceChildren();
    if (!state.keys.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'empty-cell';
      td.textContent = `用户 ${state.keysUser} 暂无已配置 SSH 公钥。`;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const k of state.keys) {
      const tr = document.createElement('tr');
      for (const txt of [k.type || '—', String(k.bits || '—'), k.fingerprint_sha256 || '—', k.comment || '—']) {
        const td = document.createElement('td');
        if (txt === k.fingerprint_sha256) {
          const code = document.createElement('code');
          code.textContent = txt;
          td.appendChild(code);
        } else {
          td.textContent = txt;
        }
        tr.appendChild(td);
      }
      const actTd = document.createElement('td');
      const rmBtn = document.createElement('button');
      rmBtn.className = 'btn danger sm';
      rmBtn.type = 'button';
      rmBtn.textContent = '移除';
      rmBtn.addEventListener('click', () => void runAction(async () => {
        const ok = await hostConfirm(
          '移除 SSH 公钥',
          `确认从用户 ${state.keysUser} 的 authorized_keys 移除指纹 ${k.fingerprint_sha256}？`,
          { danger: true, confirmLabel: '确认移除' },
        );
        if (!ok) return;
        await invoke('security.keys.remove', {
          user: state.keysUser,
          fingerprint_sha256: k.fingerprint_sha256,
          expected_revision: state.keysRevision || undefined,
        });
        await loadKeys();
      }, '公钥已移除'));
      actTd.appendChild(rmBtn);
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    }
  }

  function renderBans() {
    const bansData = state.bans || {};
    const list = Array.isArray(bansData.bans) ? bansData.bans : [];
    $('ban-rev-chip').textContent = `修订号：${bansData.revision || '—'}`;
    $('ban-count-chip').textContent = `${list.length} 条封禁`;
    const modeBadge = $('ban-mode-badge');
    if (bansData.fail2ban_observer) {
      modeBadge.className = 'badge warn';
      modeBadge.textContent = 'fail2ban 旁观模式';
      $('ban-mode-desc').textContent = '检测到 fail2ban 正在运行，本插件自动切入只读旁观模式，不重复自动写入封禁；您仍可手动管理 inet qwq 封禁集合。';
    } else {
      modeBadge.className = 'badge ok';
      modeBadge.textContent = '轻量防爆破运行中';
      $('ban-mode-desc').textContent = '增量扫描 SSH 认证失败日志并自动封禁超阈值来源 IP（支持手动封禁与一键解封）。';
    }

    const tbody = $('bans-tbody');
    tbody.replaceChildren();
    if (list.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 4;
      td.className = 'empty-cell';
      td.textContent = '当前无活跃封禁 IP。';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    for (const b of list) {
      const tr = document.createElement('tr');
      const ipTd = document.createElement('td');
      const code = document.createElement('code');
      code.textContent = b.ip;
      ipTd.appendChild(code);

      const expTd = document.createElement('td');
      expTd.textContent = formatTimestampMs(b.expires_at);

      const ttlTd = document.createElement('td');
      ttlTd.dataset.banExpires = String(b.expires_at || 0);
      const remain = b.expires_at > 0 ? Math.floor(b.expires_at / 1000) - nowSec : 0;
      ttlTd.textContent = remain > 0 ? formatDuration(remain) : '即将过期';

      const actTd = document.createElement('td');
      const unbanBtn = document.createElement('button');
      unbanBtn.className = 'btn ghost sm';
      unbanBtn.type = 'button';
      unbanBtn.textContent = '解封';
      unbanBtn.addEventListener('click', () => void runAction(async () => {
        const ok = await hostConfirm('解除 IP 封禁', `确认立即解除对 ${b.ip} 的封禁？`, { confirmLabel: '确认解封' });
        if (!ok) return;
        await invoke('security.bans.remove', {
          ip: b.ip,
          expected_revision: state.bans?.revision || undefined,
        });
        await refresh();
      }, `已解除 ${b.ip} 封禁`));
      actTd.appendChild(unbanBtn);

      tr.append(ipTd, expTd, ttlTd, actTd);
      tbody.appendChild(tr);
    }
  }

  function updateBanCountdowns() {
    const nowSec = Math.floor(Date.now() / 1000);
    for (const td of document.querySelectorAll('td[data-ban-expires]')) {
      const expMs = Number(td.dataset.banExpires || 0);
      const remain = expMs > 0 ? Math.floor(expMs / 1000) - nowSec : 0;
      td.textContent = remain > 0 ? formatDuration(remain) : '即将过期';
    }
  }

  /* ======================== 数据拉取 ======================== */

  async function loadKeys() {
    if (!port) return;
    const user = ($('key-user').value || 'root').trim() || 'root';
    state.keysUser = user;
    $('pwd-user').value = user;
    try {
      const res = await invoke('security.keys.list', { user });
      state.keysRevision = res.revision || '';
      state.keys = Array.isArray(res.keys) ? res.keys : [];
      renderKeys();
    } catch (err) {
      setKeyFeedback(`读取用户 ${user} 公钥失败：${err.message || '未知错误'}`, 'err');
    }
  }

  async function refresh() {
    if (!port) return;
    setStatus('正在同步安全状态…');
    try {
      const [overview, fw, conflicts, sshd, bans] = await Promise.all([
        invoke('security.overview', {}),
        invoke('security.firewall.status', {}),
        invoke('security.conflicts.detect', {}),
        invoke('security.sshd.status', {}),
        invoke('security.bans.list', {}),
      ]);
      state.overview = overview;
      state.fw = fw;
      const parsedFw = parseNftRuleset(fw.ruleset);
      state.fwPolicy = parsedFw.policy;
      state.fwRules = parsedFw.rules;
      state.fwGuards = parsedFw.guards;
      state.fwDirty = false;
      state.conflicts = conflicts;
      state.sshd = sshd;
      state.bans = bans;

      renderOverview();
      renderFirewall();
      renderSSHD();
      renderBans();
      setStatus('已连接');
    } catch (err) {
      setStatus(`读取失败：${err.message || '未知错误'}`);
    }
  }

  /* ======================== 事件绑定 ======================== */

  $('nav-tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    switchTab(btn.dataset.tab);
  });

  $('refresh').addEventListener('click', () => { void refresh(); });
  $('btn-jump-saga').addEventListener('click', () => { switchTab('sshd'); });

  // Tab 2: 防火墙操作
  $('fw-policy').addEventListener('change', () => {
    state.fwPolicy = $('fw-policy').value === 'drop' ? 'drop' : 'accept';
    state.fwDirty = true;
    renderFirewall();
  });

  $('fw-add-rule').addEventListener('click', () => {
    try {
      const proto = $('fw-proto').value;
      const portNum = Number($('fw-port').value);
      const saddr = $('fw-saddr').value;
      const action = $('fw-action').value;
      const comment = $('fw-comment').value;
      const rawRule = buildNftRuleFromInput(proto, portNum, saddr, action, comment);
      state.fwRules.push(parseSingleNftRule(rawRule));
      state.fwDirty = true;
      $('fw-port').value = '';
      $('fw-saddr').value = '';
      $('fw-comment').value = '';
      renderFirewall();
      showGlobalAlert('');
    } catch (err) {
      showGlobalAlert(err.message || '规则参数无效', 'err');
    }
  });

  $('fw-apply-btn').addEventListener('click', () => void runAction(async () => {
    const ok = await hostConfirm(
      '应用防火墙规则集',
      `确认应用当前 inet qwq 规则集（默认策略 ${state.fwPolicy}，自定义规则 ${state.fwRules.length} 条）？宿主保留端口将自动放行。`,
      { danger: state.fwPolicy === 'drop', confirmLabel: '确认应用' },
    );
    if (!ok) return;
    const payload = {
      ruleset: buildNftDocument(),
      preserved_ports: Array.isArray(state.fw?.preserved_ports) ? state.fw.preserved_ports : undefined,
      expected_revision: state.fw?.revision || undefined,
    };
    await invoke('security.firewall.apply', payload, 30000);
    await refresh();
  }, '防火墙规则集已应用'));

  $('fw-reset-btn').addEventListener('click', () => void runAction(async () => {
    const ok = await hostConfirm(
      '重置防火墙规则集',
      '确认将 inet qwq 防火墙重置为默认放行基线并保留 SSH 与管理端口？',
      { danger: true, confirmLabel: '确认重置' },
    );
    if (!ok) return;
    await invoke('security.firewall.reset', { expected_revision: state.fw?.revision || undefined }, 30000);
    await refresh();
  }, '防火墙已重置为默认基线'));

  // Tab 3: SSH 登录策略与改端口向导
  $('sshd-save-policy').addEventListener('click', () => void runAction(async () => {
    const passwordAuth = $('sshd-pw-auth').value === 'true';
    const rootMode = $('sshd-root-mode').value;
    const recoveryUser = ($('sshd-recovery-user').value || '').trim();
    const ok = await hostConfirm(
      '更新 SSH 登录策略',
      `确认修改 SSH 登录策略（密码登录=${passwordAuth ? '允许' : '禁用'}，Root=${rootMode}，恢复用户=${recoveryUser || '未填写'}）？`,
      { danger: !passwordAuth || rootMode === 'deny', confirmLabel: '确认更新' },
    );
    if (!ok) return;
    const payload = {
      password_auth: passwordAuth,
      root_login_mode: rootMode,
      expected_revision: state.sshd?.revision || undefined,
    };
    if (recoveryUser) payload.recovery_user = recoveryUser;
    await invoke('security.sshd.set_login_policy', payload, 30000);
    await refresh();
  }, 'SSH 登录策略已更新'));

  $('saga-prepare-btn').addEventListener('click', () => void runAction(async () => {
    const newPort = Number($('saga-new-port').value);
    const timeoutSec = Number($('saga-timeout').value || 600);
    const skipFw = $('saga-skip-fw').checked;
    if (!Number.isInteger(newPort) || newPort < 1024 || newPort > 65535) {
      throw new Error('新 SSH 端口必须在 1024 到 65535 之间');
    }
    await invoke('security.sshd.change_port_prepare', {
      new_port: newPort,
      timeout_seconds: timeoutSec,
      skip_firewall: skipFw,
      expected_revision: state.sshd?.revision || undefined,
    }, 30000);
    await refresh();
  }, '双端口监听已就绪，请从新终端测试连通性'));

  $('saga-copy-cmd').addEventListener('click', () => void runAction(async () => {
    const cmd = $('saga-test-cmd').textContent || '';
    await hostCopy(cmd, '已复制 SSH 测试命令');
  }, '已复制 SSH 测试命令'));

  $('saga-probe-btn').addEventListener('click', () => void runAction(async () => {
    await refresh();
  }, '已刷新新端口外部连接探测状态'));

  $('saga-commit-btn').addEventListener('click', () => void runAction(async () => {
    const saga = state.sshd?.port_saga;
    if (!saga) throw new Error('当前无进行中的改端口事务');
    const confirmExt = $('saga-confirm-ext').checked;
    const ok = await hostConfirm(
      '确认切换 SSH 端口',
      `确认提交新端口 ${saga.new_port} 并关闭旧端口 ${saga.old_port}？请确保云安全组已放行新端口。`,
      { danger: true, confirmLabel: '确认切换' },
    );
    if (!ok) return;
    await invoke('security.sshd.change_port_commit', {
      transaction_ref: saga.transaction_ref,
      expected_revision: state.sshd?.revision || undefined,
      confirm_external_reachable: confirmExt,
    }, 30000);
    $('saga-confirm-ext').checked = false;
    await refresh();
  }, 'SSH 端口切换已提交生效'));

  $('saga-rollback-btn').addEventListener('click', () => void runAction(async () => {
    const saga = state.sshd?.port_saga;
    if (!saga) throw new Error('当前无进行中的改端口事务');
    const ok = await hostConfirm(
      '回滚 SSH 端口切换',
      `确认立即回滚并恢复原 SSH 端口 ${saga.old_port}？`,
      { danger: true, confirmLabel: '确认回滚' },
    );
    if (!ok) return;
    await invoke('security.sshd.change_port_rollback', {
      transaction_ref: saga.transaction_ref,
      expected_revision: state.sshd?.revision || undefined,
    }, 30000);
    await refresh();
  }, 'SSH 改端口事务已回滚'));

  // Tab 4: SSH 密钥与账户密码
  $('btn-load-keys').addEventListener('click', () => { void loadKeys(); });

  $('gen-ed25519').addEventListener('click', async () => {
    const user = ($('key-user').value || 'root').trim();
    const comment = ($('key-comment').value || 'qwq-browser').trim().replace(/\s+/g, '-');
    if (!user) {
      setKeyFeedback('请先填写目标系统用户名。', 'warn');
      return;
    }
    if (!window.crypto || !window.crypto.subtle) {
      setKeyFeedback('当前浏览器上下文不支持 WebCrypto，请点击「服务端回退生成」或使用本地 ssh-keygen 后导入公钥。', 'warn');
      return;
    }
    $('gen-ed25519').disabled = true;
    setKeyFeedback('正在浏览器本地生成 OpenSSH Ed25519 密钥对…');
    try {
      const { publicKeyAuthorized, privateKeyOpenSSHPEM } = await generateOpenSSHEd25519KeyPair(comment);
      downloadTextFile(`qwq-${user}-id_ed25519`, privateKeyOpenSSHPEM);
      const preview = $('key-pubkey');
      preview.textContent = publicKeyAuthorized;
      preview.hidden = false;
      $('copy-pubkey').hidden = false;
      try {
        await invoke('security.keys.import', {
          user,
          public_key: publicKeyAuthorized,
          expected_revision: state.keysRevision || undefined,
        });
        setKeyFeedback('标准 OpenSSH 私钥已触发本地下载（全程不触网），公钥已自动导入目标用户。');
        await loadKeys();
      } catch (err) {
        if (err && err.awaitingApproval) {
          setKeyFeedback('标准 OpenSSH 私钥已本地下载（不会上传服务器）；公钥导入已提交审批，请在审批浮窗确认。', 'warn');
          send({ t: 'ui.toast', text: '公钥导入已提交，等待审批确认' });
        } else {
          setKeyFeedback(`私钥已本地下载，但公钥自动导入未完成：${err.message || '请手动复制导入'}`, 'warn');
        }
      }
    } catch {
      setKeyFeedback('当前浏览器不支持 WebCrypto Ed25519，请点击「服务端回退生成」或使用本地 ssh-keygen 导入公钥。', 'warn');
    } finally {
      $('gen-ed25519').disabled = false;
    }
  });

  $('gen-fallback').addEventListener('click', () => void runAction(async () => {
    const user = ($('key-user').value || 'root').trim();
    if (!user) throw new Error('请先填写目标系统用户名');
    const ok = await hostConfirm(
      '服务端回退生成 SSH 密钥',
      `将在服务端为用户 ${user} 生成 Ed25519 密钥对并一次性返回私钥（推荐优先使用浏览器本地生成）。确认继续？`,
      { confirmLabel: '确认生成' },
    );
    if (!ok) return;
    const res = await invoke('security.keys.generate_fallback', {
      user,
      type: 'ed25519',
      expected_revision: state.keysRevision || undefined,
    });
    if (res.private_key_pem) {
      downloadTextFile(`qwq-${user}-fallback-id_ed25519`, res.private_key_pem);
    }
    if (res.public_key) {
      $('key-pubkey').textContent = res.public_key;
      $('key-pubkey').hidden = false;
      $('copy-pubkey').hidden = false;
    }
    setKeyFeedback('服务端回退密钥已生成并触发私钥下载，请妥善保存。');
    await loadKeys();
  }, '服务端回退密钥已生成'));

  $('copy-pubkey').addEventListener('click', () => void runAction(async () => {
    const pub = $('key-pubkey').textContent || '';
    await hostCopy(pub, '已复制 OpenSSH 公钥');
  }, '已复制 OpenSSH 公钥'));

  $('btn-import-pubkey').addEventListener('click', () => void runAction(async () => {
    const user = ($('key-user').value || 'root').trim();
    const pub = ($('import-pubkey-input').value || '').trim();
    if (!user || !pub) throw new Error('请填写用户名和有效的单行 OpenSSH 公钥');
    await invoke('security.keys.import', {
      user,
      public_key: pub,
      expected_revision: state.keysRevision || undefined,
    });
    $('import-pubkey-input').value = '';
    await loadKeys();
  }, 'SSH 公钥已导入'));

  $('btn-set-password').addEventListener('click', () => void runAction(async () => {
    const user = ($('pwd-user').value || '').trim();
    const pw = $('pwd-new').value;
    const pw2 = $('pwd-confirm').value;
    if (!user) throw new Error('请填写系统用户名');
    if (!pw || pw.length < 6) throw new Error('新密码长度至少 6 个字符');
    if (pw !== pw2) throw new Error('两次输入的密码不一致');
    const ok = await hostConfirm(
      '修改系统账户密码',
      `确认修改系统用户 ${user} 的登录密码？`,
      { danger: true, confirmLabel: '确认修改' },
    );
    if (!ok) return;
    await invoke('security.account.set_password', { user, password: pw });
    $('pwd-new').value = '';
    $('pwd-confirm').value = '';
  }, '系统账户密码已更新'));

  // Tab 5: 防爆破封禁操作
  $('btn-ban-add').addEventListener('click', () => void runAction(async () => {
    const ip = ($('ban-ip-input').value || '').trim();
    const ttl = Number($('ban-ttl-input').value || 3600);
    if (!ip) throw new Error('请填写待封禁来源 IP');
    const ok = await hostConfirm(
      '手动封禁来源 IP',
      `确认封禁 ${ip}（时长 ${ttl} 秒）？请确保不是当前管理终端 IP。`,
      { danger: true, confirmLabel: '确认封禁' },
    );
    if (!ok) return;
    await invoke('security.bans.add', {
      ip,
      ttl_seconds: ttl,
      expected_revision: state.bans?.revision || undefined,
    });
    $('ban-ip-input').value = '';
    await refresh();
  }, '已添加 IP 封禁'));

  /* ======================== 宿主消息通道与定时器 ======================== */

  function handleMessage(data) {
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
        if (!result || typeof result !== 'object') {
          req.reject(new Error('操作返回异常'));
        } else {
          req.resolve(result);
        }
      } else {
        req.reject(new Error(extractErrorMessage(data.problem || data.error, '操作调用失败')));
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
    if (data.t === 'ui.settings' && data.theme) {
      root.dataset.theme = pick(data.theme, ['light', 'dark'], root.dataset.theme);
    }
  }

  const countdownTimer = setInterval(() => {
    updateSagaCountdown();
    updateBanCountdowns();
  }, 1000);

  const observer = new ResizeObserver(() => {
    const height = Math.ceil($('security-root').getBoundingClientRect().height) + 24;
    send({ t: 'ui.resize', height });
  });
  observer.observe($('security-root'));

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.data?.t !== 'plugin.port' || !event.ports[0] || port) return;
    port = event.ports[0];
    port.onmessage = (msg) => handleMessage(msg.data);
    send({ t: 'ui.ready' });
    void refresh();
  });

  window.addEventListener('pagehide', () => {
    clearInterval(countdownTimer);
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
