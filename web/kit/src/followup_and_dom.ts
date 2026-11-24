// SPDX-License-Identifier: Apache-2.0
/* ==========================================================================
 * @qwq/kit v2 · 自动审批跟单、零内联 CSP 安全 DOM 构造器与浏览器端 OpenSSH 密钥生成
 * ========================================================================== */

import type { InvokeOutcome, KitInvokeOptions, PluginBridgeClient } from './bridge';

// ======================== 1. 自动审批跟单与页面自动重刷扩展 ========================

export interface TrackedInvokeOptions<TRes> extends KitInvokeOptions {
  /** 插件 ID（如 "server.probe"），用于在进入 AWAITING_APPROVAL / RUNNING 后自动订阅对应资源变更事件 */
  pluginId: string;
  /** 当宿主右侧审批浮窗批准并执行完成（收到对应插件变更事件）时的回调，用于自动重拉列表或回显结果 */
  onBackgroundSettled?: () => void | Promise<void>;
  /** 当立即完成（无需人工审批）时的回调 */
  onImmediateDone?: (result: TRes, operationId: string) => void | Promise<void>;
  /** 最长等待人工审批毫秒数（默认 10 分钟，超时自动释放订阅防内存泄漏） */
  approvalWaitTimeoutMs?: number;
}

/**
 * invokeWithApprovalFollowup 封装完整的三态调用闭环：
 *  - 若直接 `done`：立即触发 `onImmediateDone` 并返回结果；
 *  - 若进入 `awaiting_approval` 或 `running`：自动调用宿主 `toast` 提示用户前往右侧审批卡确认，
 *    同时自动订阅 `plugins/<pluginId>/*`，审批通过落地后自动触发 `onBackgroundSettled()` 并销毁监听器。
 */
export async function invokeWithApprovalFollowup<TRes = unknown>(
  bridge: PluginBridgeClient,
  operation: string,
  payload: Record<string, unknown>,
  opts: TrackedInvokeOptions<TRes>,
): Promise<InvokeOutcome<TRes>> {
  const outcome = await bridge.invokeOutcome<TRes>(operation, payload, opts);

  if (outcome.kind === 'done') {
    if (opts.onImmediateDone) {
      await opts.onImmediateDone(outcome.result, outcome.operationId);
    }
    return outcome;
  }

  if (outcome.kind === 'awaiting_approval') {
    bridge.toast('操作已提交，请在右侧审批浮窗点击批准后自动生效');
  } else {
    bridge.toast('后台任务执行中，完成后将自动刷新');
  }

  if (opts.onBackgroundSettled) {
    const waitMs = opts.approvalWaitTimeoutMs ?? 10 * 60 * 1000;
    let settled = false;
    let unsub: (() => void) | null = null;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        unsub?.();
      }
    }, waitMs);

    unsub = bridge.subscribe([`plugins/${opts.pluginId}/*`], (ev) => {
      if (settled) return;
      const evOpId = typeof ev.operation_id === 'string' ? ev.operation_id : '';
      const matchesOp = Boolean(outcome.operationId && evOpId === outcome.operationId);
      const matchesPluginResource = ev.subject.includes(`plugins/${opts.pluginId}/`);
      if (matchesOp || matchesPluginResource) {
        settled = true;
        clearTimeout(timer);
        unsub?.();
        Promise.resolve(opts.onBackgroundSettled?.()).catch(() => {});
      }
    });
  }

  return outcome;
}

// ======================== 2. 零内联 CSP 安全的轻量 DOM 构造器与自适应高度挂载器 ========================

export type ChildSpec = Node | string | number | null | undefined | false;

/**
 * h() 创建严格符合 `script-src 'self'; style-src 'self'` 零内联 CSP 的 DOM 节点：
 *  - 自动使用 `textContent` 防御不可信输入 XSS；
 *  - 硬拦截 `style` 与 `on*` 属性，强制使用 CSS class 或 `dataset` 状态驱动样式。
 */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs?: {
    className?: string;
    id?: string;
    text?: string;
    attrs?: Record<string, string>;
    dataset?: Record<string, string>;
    on?: Partial<{ [E in keyof HTMLElementEventMap]: (ev: HTMLElementEventMap[E]) => void }>;
  } | null,
  ...children: ChildSpec[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (attrs) {
    if (attrs.className) el.className = attrs.className;
    if (attrs.id) el.id = attrs.id;
    if (attrs.text !== undefined) el.textContent = attrs.text;
    if (attrs.attrs) {
      for (const [k, v] of Object.entries(attrs.attrs)) {
        const lower = k.toLowerCase();
        if (lower === 'style' || lower.startsWith('on')) {
          continue;
        }
        el.setAttribute(k, v);
      }
    }
    if (attrs.dataset) {
      for (const [k, v] of Object.entries(attrs.dataset)) {
        el.dataset[k] = v;
      }
    }
    if (attrs.on) {
      for (const [evName, handler] of Object.entries(attrs.on)) {
        if (typeof handler === 'function') {
          el.addEventListener(evName, handler as EventListener);
        }
      }
    }
  }
  for (const ch of children) {
    if (ch === null || ch === undefined || ch === false) continue;
    if (typeof ch === 'string' || typeof ch === 'number') {
      el.appendChild(document.createTextNode(String(ch)));
    } else {
      el.appendChild(ch);
    }
  }
  return el;
}

/** mountAutoResize 自动绑定 ResizeObserver 与 pagehide 清理，避免 iframe 滚动条截断或内存泄漏 */
export function mountAutoResize(bridge: PluginBridgeClient, target: HTMLElement = document.body): () => void {
  const report = () => {
    const height = Math.max(target.scrollHeight, document.documentElement.scrollHeight, 320);
    bridge.resize(height);
  };
  const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(report) : null;
  ro?.observe(target);
  report();

  const cleanup = () => {
    ro?.disconnect();
    bridge.dispose();
  };
  window.addEventListener('pagehide', cleanup, { once: true });
  return cleanup;
}

// ======================== 3. 浏览器端零触网 OpenSSH Ed25519 私钥编码器 ========================

function writeSSHBytes(parts: Uint8Array[], payload: Uint8Array): void {
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, payload.byteLength, false);
  parts.push(lenBuf, payload);
}

function writeSSHString(parts: Uint8Array[], str: string): void {
  writeSSHBytes(parts, new TextEncoder().encode(str));
}

function concatUint8(chunks: Uint8Array[]): Uint8Array {
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

function toBase64Wrapped(bytes: Uint8Array, lineWidth = 70): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i] ?? 0);
  }
  const b64 = btoa(binary);
  if (lineWidth <= 0) return b64;
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += lineWidth) {
    lines.push(b64.slice(i, i + lineWidth));
  }
  return lines.join('\n');
}

function opensshPemFence(edge: string): string {
  return `-----${edge} OPENSSH PRIVATE KEY-----`;
}

/**
 * generateOpenSSHEd25519KeyPair 在浏览器沙箱内用 WebCrypto 生成 Ed25519 密钥对，并直接编码为标准 OpenSSH PEM。
 */
export async function generateOpenSSHEd25519KeyPair(comment = 'qwq-admin'): Promise<{
  publicKeyAuthorized: string;
  privateKeyOpenSSHPEM: string;
}> {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const pkcs8Priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));

  if (rawPub.byteLength !== 32 || pkcs8Priv.byteLength < 32) {
    throw new Error('Unexpected Ed25519 WebCrypto key length');
  }
  const seed32 = pkcs8Priv.slice(pkcs8Priv.byteLength - 32);

  const pubParts: Uint8Array[] = [];
  writeSSHString(pubParts, 'ssh-ed25519');
  writeSSHBytes(pubParts, rawPub);
  const pubBlob = concatUint8(pubParts);
  const cleanComment = comment.trim() || 'qwq-key';
  const publicKeyAuthorized = `ssh-ed25519 ${toBase64Wrapped(pubBlob, 0)} ${cleanComment}`;

  const checkInt = crypto.getRandomValues(new Uint8Array(4));
  const privSection: Uint8Array[] = [checkInt, checkInt];
  writeSSHString(privSection, 'ssh-ed25519');
  writeSSHBytes(privSection, rawPub);

  const secret64 = new Uint8Array(64);
  secret64.set(seed32, 0);
  secret64.set(rawPub, 32);
  writeSSHBytes(privSection, secret64);
  writeSSHString(privSection, cleanComment);

  const rawPrivPrePad = concatUint8(privSection);
  const blockSize = 8;
  const padLen = (blockSize - (rawPrivPrePad.byteLength % blockSize)) % blockSize;
  const padBytes = new Uint8Array(padLen);
  for (let i = 0; i < padLen; i++) padBytes[i] = (i + 1) & 0xff;
  const paddedPrivBlob = concatUint8([rawPrivPrePad, padBytes]);

  const magic = new TextEncoder().encode('openssh-key-v1\0');
  const outerParts: Uint8Array[] = [magic];
  writeSSHString(outerParts, 'none');
  writeSSHString(outerParts, 'none');
  writeSSHBytes(outerParts, new Uint8Array(0));
  outerParts.push(new Uint8Array([0, 0, 0, 1]));
  writeSSHBytes(outerParts, pubBlob);
  writeSSHBytes(outerParts, paddedPrivBlob);

  const fullDer = concatUint8(outerParts);
  seed32.fill(0);
  secret64.fill(0);
  pkcs8Priv.fill(0);

  const privateKeyOpenSSHPEM = `${opensshPemFence('BEGIN')}\n${toBase64Wrapped(fullDer, 70)}\n${opensshPemFence('END')}\n`;
  return { publicKeyAuthorized, privateKeyOpenSSHPEM };
}
