// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * Top-Layer 协调工具（纯 DOM，无 $lib / $api 依赖）
 * --------------------------------------------------------------------------
 * 当原生 <dialog>.showModal() 进入浏览器 Top Layer 时，位于常规文档流的
 * position: fixed 吐司会被遮罩压在下方且受 inert 影响无法点击。
 * 为 <Toaster> 启用 popover="manual"，在挂载、新吐司到来以及每次任意
 * <dialog>.showModal() 之后重新置顶，确保提示条永远浮于最顶层。
 * ========================================================================== */

const TOPLAYER_CHANGE_EVENT = 'qwq:toplayer-change';
const modalStack: HTMLDialogElement[] = [];

function pruneModalStack(): void {
  for (let i = modalStack.length - 1; i >= 0; i--) {
    const dlg = modalStack[i];
    if (!dlg || !dlg.isConnected || !dlg.open) {
      modalStack.splice(i, 1);
    }
  }
}

function emitTopLayerChange(): void {
  if (typeof window === 'undefined') return;
  try {
    window.dispatchEvent(new CustomEvent(TOPLAYER_CHANGE_EVENT));
  } catch {
    /* 忽略非浏览器测试环境 */
  }
}

/** 获取当前位于最顶层的已打开模态 <dialog>；无模态弹窗时返回 null */
export function getTopModalDialog(): HTMLDialogElement | null {
  pruneModalStack();
  return modalStack[modalStack.length - 1] ?? null;
}

/** 登记已通过 showModal() 打开的模态 <dialog>，便于 <Toaster> 挂载其内以避免被 inert 拦截并保持置顶 */
export function registerModalDialog(dlg: HTMLDialogElement | null | undefined): void {
  if (!dlg) {
    emitTopLayerChange();
    return;
  }
  const idx = modalStack.indexOf(dlg);
  if (idx >= 0) modalStack.splice(idx, 1);
  if (dlg.isConnected && dlg.open) {
    modalStack.push(dlg);
  }
  pruneModalStack();
  emitTopLayerChange();
}

/** 注销关闭或卸载的模态 <dialog>，让 <Toaster> 回归上一层弹窗或常规锚点 */
export function unregisterModalDialog(dlg: HTMLDialogElement | null | undefined): void {
  if (dlg) {
    const idx = modalStack.indexOf(dlg);
    if (idx >= 0) modalStack.splice(idx, 1);
  }
  pruneModalStack();
  emitTopLayerChange();
}

/** 任意原生 <dialog>.showModal() 打开后调用，通知 <Toaster> 挂载并重新置顶于 Top Layer 最上层 */
export function notifyTopLayerOpened(dlg?: HTMLDialogElement | null): void {
  registerModalDialog(dlg);
}

/** 订阅顶层 <dialog> 栈变化通知，返回取消订阅函数 */
export function onTopLayerChanged(fn: () => void): () => void {
  if (typeof window === 'undefined') return () => {};
  const handler = () => fn();
  window.addEventListener(TOPLAYER_CHANGE_EVENT, handler);
  return () => window.removeEventListener(TOPLAYER_CHANGE_EVENT, handler);
}

/** 兼容旧导出名 */
export const onTopLayerOpened = onTopLayerChanged;

/** 通过 HTML Popover API 将 manual popover 提升到 Top Layer 最顶层；不支持时静默回退 z-index */
export function promoteToasterToTopLayer(el: HTMLElement | null | undefined): void {
  if (!el || typeof el.showPopover !== 'function') return;
  try {
    if (el.matches(':popover-open')) {
      el.hidePopover();
    }
    el.showPopover();
  } catch {
    /* 老浏览器或无 DOM 环境回退常规 fixed + z-index */
  }
}

/** 隐藏 Top Layer manual popover（无吐司时释放顶层占位） */
export function hideToasterFromTopLayer(el: HTMLElement | null | undefined): void {
  if (!el || typeof el.hidePopover !== 'function') return;
  try {
    if (el.matches(':popover-open')) {
      el.hidePopover();
    }
  } catch {
    /* 忽略 */
  }
}
