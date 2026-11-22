// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * Toast 队列
 * --------------------------------------------------------------------------
 * 顶部居中，最多同时 3 条（新的挤掉最旧的非错误条）；错误需手动关闭。
 * 文本一律纯文本渲染。<Toaster/> 在根组件挂一次。
 * ========================================================================== */

export type ToastKind = 'info' | 'success' | 'warn' | 'error';

export interface ToastAction {
  label: string;
  run: () => void;
}

export interface Toast {
  id: number;
  kind: ToastKind;
  text: string;
  /** 次要说明，如 request_id */
  detail?: string;
  action?: ToastAction;
}

const MAX = 3;
const TTL = 4000;

class ToastStore {
  items = $state<Toast[]>([]);
  #seq = 0;
  #timers = new Map<number, ReturnType<typeof setTimeout>>();

  push(t: Omit<Toast, 'id'>): number {
    const id = ++this.#seq;
    const next = [...this.items, { ...t, id }];
    /* 超出上限：先挤掉最旧的非错误条，全是错误时挤掉最旧的 */
    while (next.length > MAX) {
      const i = next.findIndex((x) => x.kind !== 'error');
      const [gone] = next.splice(i >= 0 ? i : 0, 1);
      if (gone) this.#clear(gone.id);
    }
    this.items = next;
    if (t.kind !== 'error') this.#timers.set(id, setTimeout(() => this.dismiss(id), TTL));
    return id;
  }

  info = (text: string, action?: ToastAction) => this.push({ kind: 'info', text, action });
  success = (text: string, action?: ToastAction) => this.push({ kind: 'success', text, action });
  warn = (text: string, action?: ToastAction) => this.push({ kind: 'warn', text, action });
  error = (text: string, detail?: string, action?: ToastAction) => this.push({ kind: 'error', text, detail, action });

  dismiss(id: number): void {
    this.#clear(id);
    this.items = this.items.filter((t) => t.id !== id);
  }

  #clear(id: number) {
    const t = this.#timers.get(id);
    if (t) clearTimeout(t);
    this.#timers.delete(id);
  }
}

export const toasts = new ToastStore();
