// SPDX-License-Identifier: AGPL-3.0-only
/* ======================== 宿主沙箱桥接与 WebCrypto Ed25519 密钥生成 ======================== */
(() => {
  'use strict';
  const root = document.documentElement;
  const pick = (v, list, fb) => (list.includes(v) ? v : fb);
  const hash = new URLSearchParams(location.hash.slice(1));
  root.dataset.theme = pick(hash.get('theme'), ['light', 'dark'], 'light');

  const $ = (id) => document.getElementById(id);
  let port;
  let seq = 0;
  const pending = new Map();
  const pendingCopy = new Map();

  const send = (msg) => { if (port) port.postMessage(msg); };
  const setStatus = (text) => { $('status').textContent = text; };
  const setKeyFeedback = (text, warn = false) => {
    const el = $('key-feedback');
    el.textContent = text;
    el.className = warn ? 'warn' : 'muted';
  };

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
      }, 10000);
      pending.set(id, { resolve, reject, timer });
      send({ t: 'api.invoke', id, operation, payload });
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

  function toBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function encodeSSHString(bytes) {
    const out = new Uint8Array(4 + bytes.length);
    const view = new DataView(out.buffer);
    view.setUint32(0, bytes.length, false);
    out.set(bytes, 4);
    return out;
  }

  function formatOpenSSHEd25519PublicKey(rawPublicKey, comment) {
    const alg = new TextEncoder().encode('ssh-ed25519');
    const a = encodeSSHString(alg);
    const k = encodeSSHString(new Uint8Array(rawPublicKey));
    const blob = new Uint8Array(a.length + k.length);
    blob.set(a, 0);
    blob.set(k, a.length);
    const suffix = comment ? ` ${comment}` : '';
    return `ssh-ed25519 ${toBase64(blob)}${suffix}`;
  }

  function wrapPEM(label, derBytes) {
    const b64 = toBase64(new Uint8Array(derBytes));
    const lines = b64.match(/.{1,64}/g) || [];
    const begin = ['-----', 'BEGIN ', label, '-----'].join('');
    const end = ['-----', 'END ', label, '-----'].join('');
    return `${begin}\n${lines.join('\n')}\n${end}\n`;
  }

  function downloadBlob(filename, content) {
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function generateBrowserEd25519() {
    const user = ($('key-user').value || '').trim();
    const comment = ($('key-comment').value || 'qwq-browser').trim().replace(/\s+/g, '-');
    if (!user) {
      setKeyFeedback('请先填写目标系统用户名。', true);
      return;
    }
    if (!window.crypto || !window.crypto.subtle) {
      setKeyFeedback('当前浏览器上下文不支持 WebCrypto，请改用本地 ssh-keygen 后导入公钥，或通过审批触发服务端回退生成（security.keys.generate_fallback）。', true);
      return;
    }
    $('gen-ed25519').disabled = true;
    setKeyFeedback('正在浏览器本地生成 Ed25519 密钥对…');
    try {
      const pair = await window.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      const rawPub = await window.crypto.subtle.exportKey('raw', pair.publicKey);
      const pkcs8Priv = await window.crypto.subtle.exportKey('pkcs8', pair.privateKey);
      const publicLine = formatOpenSSHEd25519PublicKey(rawPub, comment);
      const privateLabel = ['PRIVATE', 'KEY'].join(' ');
      const pem = wrapPEM(privateLabel, pkcs8Priv);
      downloadBlob(`qwq-${user}-ed25519.pem`, pem);
      const preview = $('key-pubkey');
      preview.textContent = publicLine;
      preview.hidden = false;
      $('copy-pubkey').hidden = false;
      if (port) {
        try {
          await invoke('security.keys.import', { user, public_key: publicLine });
          setKeyFeedback('私钥已触发本地下载（不会上传服务器），且已仅上传 OpenSSH 公钥完成导入。');
        } catch (err) {
          if (err && err.awaitingApproval) {
            setKeyFeedback('私钥已本地下载（不会上传服务器）；OpenSSH 公钥导入已提交宿主审批，请在审批浮窗确认。', true);
            send({ t: 'ui.toast', text: '公钥导入已提交，等待审批确认' });
          } else {
            setKeyFeedback(`私钥已本地下载，OpenSSH 公钥已生成；自动提交导入需宿主审批或手动重试：${err.message || '请通过受审作业提交公钥'}`, true);
          }
        }
      } else {
        setKeyFeedback('私钥已触发本地下载（不会上传服务器），请连接宿主后仅提交上方 OpenSSH 公钥。');
      }
    } catch {
      setKeyFeedback('当前浏览器不支持 WebCrypto Ed25519 密钥生成，请改用本地 ssh-keygen 导入公钥，或通过审批执行 security.keys.generate_fallback 服务端回退生成。', true);
    } finally {
      $('gen-ed25519').disabled = false;
    }
  }

  async function refresh() {
    if (!port) return;
    setStatus('正在同步安全状态…');
    try {
      const [overview, fw, conflicts, sshd, bans] = await Promise.all([
        invoke('security.overview'),
        invoke('security.firewall.status'),
        invoke('security.conflicts.detect'),
        invoke('security.sshd.status'),
        invoke('security.bans.list'),
      ]);
      $('overview-summary').textContent = `${overview.value ?? 0} ${overview.unit ?? '项'}`;
      $('overview-sub').textContent = overview.sub || '已同步';
      const ports = Array.isArray(fw.preserved_ports) ? fw.preserved_ports.join(', ') : '—';
      $('fw-summary').textContent = `保留端口：${ports}${fw.persistence_pending ? '（存在未持久化变更）' : ''}`;
      const activeMgrs = (conflicts.managers || []).filter((m) => m.active).map((m) => m.kind);
      $('conflicts-summary').textContent = activeMgrs.length ? `活跃共存管理器：${activeMgrs.join(', ')}` : '未发现活跃外部冲突管理器';
      const listening = Array.isArray(sshd.listening_ports) && sshd.listening_ports.length ? sshd.listening_ports.join(', ') : '22';
      $('sshd-summary').textContent = `当前 SSH 端口：${listening}`;
      $('saga-summary').textContent = sshd.port_saga
        ? `改端口事务进行中：${sshd.port_saga.old_port} -> ${sshd.port_saga.new_port}`
        : '无进行中的改端口事务';
      $('ban-summary').textContent = `当前封禁 IP 数：${(bans.bans || []).length}`;
      $('ban-mode').textContent = bans.fail2ban_observer ? 'fail2ban 活跃：已切入只读旁观模式' : '轻量防爆破巡检模式';
      setStatus('已连接');
    } catch (err) {
      setStatus(`读取失败：${err.message || '未知错误'}`);
    }
  }

  $('refresh').addEventListener('click', () => { void refresh(); });
  $('gen-ed25519').addEventListener('click', () => { void generateBrowserEd25519(); });
  $('copy-pubkey').addEventListener('click', () => {
    const pub = $('key-pubkey').textContent || '';
    void hostCopy(pub, '已复制 OpenSSH 公钥').catch((err) => {
      setKeyFeedback(`复制公钥失败：${err.message || '未知错误'}`, true);
    });
  });

  const observer = new ResizeObserver(() => {
    const height = Math.ceil($('security-root').getBoundingClientRect().height) + 8;
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
    observer.disconnect();
    for (const req of pending.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
    }
    pending.clear();
    for (const req of pendingCopy.values()) {
      clearTimeout(req.timer);
      req.reject(new Error('页面已关闭'));
    }
    pendingCopy.clear();
    port?.close();
    port = undefined;
  });

  window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*');
})();
