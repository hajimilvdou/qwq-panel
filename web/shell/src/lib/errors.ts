// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 错误 → 人话（ENG §6）
 * --------------------------------------------------------------------------
 * 只按 code 分支，未知 code 按 HTTP 状态类兜底；绝不展示 title 与堆栈。
 * PLUGIN_ERROR 的 detail 是插件文本：原样（纯文本）显示并标"来自插件"。
 *
 *   describeError(err)  → { message, action, requestId?, fromPlugin?, fields }
 *   reportError(err)    → 直接弹 Toast（错误条，需手动关）
 * ========================================================================== */
import { ApiError, NetworkError } from '$api/client';
import { toasts } from './toast.svelte';

export type ErrorAction = 'retry' | 'reload' | 'login' | 'none';

export interface ErrorView {
  message: string;
  action: ErrorAction;
  /** 5xx / INTERNAL：供用户复制给管理员 */
  requestId?: string;
  /** detail 来自插件，界面需标注 */
  fromPlugin?: string;
  /** VALIDATION_FAILED：JSON Pointer → 文案 */
  fields: Record<string, string>;
  code: string;
}

const MESSAGES: Record<string, [string, ErrorAction]> = {
  VALIDATION_FAILED: ['有些内容填得不对，请检查标红的地方', 'none'],
  UNAUTHENTICATED: ['登录已过期，请重新登录', 'login'],
  MFA_REQUIRED: ['需要两步验证码', 'none'],
  CSRF_FAILED: ['页面状态过期了，刷新后再试', 'reload'],
  PERMISSION_DENIED: ['你没有权限做这件事', 'none'],
  APPROVAL_REQUIRED: ['这项操作需要先批准', 'none'],
  NOT_FOUND: ['找不到了，可能已被删除', 'none'],
  METHOD_NOT_ALLOWED: ['这项操作暂不支持', 'none'],
  REVISION_CONFLICT: ['内容已被别人改过，请重新加载后再改', 'reload'],
  PRECONDITION_FAILED: ['情况已经变了，请刷新后再试', 'reload'],
  PLAN_EXPIRED: ['预览已过期，请重新预览', 'retry'],
  STATE_CONFLICT: ['当前状态下不能这么做', 'none'],
  IDEMPOTENCY_IN_PROGRESS: ['上一次请求还在处理，请稍候', 'retry'],
  IDEMPOTENCY_KEY_REUSED: ['请求重复了，请刷新后重试', 'reload'],
  PAYLOAD_TOO_LARGE: ['内容太大了', 'none'],
  UNSUPPORTED_MEDIA_TYPE: ['文件格式不对', 'none'],
  PLUGIN_ERROR: ['应用报告了一个错误', 'retry'],
  RATE_LIMITED: ['操作太频繁，请稍后再试', 'retry'],
  INTERNAL: ['服务器出错了', 'retry'],
  UNAVAILABLE: ['服务暂时不可用', 'retry'],
  NODE_OFFLINE: ['服务器节点离线', 'retry'],
  PLUGIN_UNAVAILABLE: ['应用没有在运行', 'retry'],
  TIMEOUT: ['等太久了，没有响应', 'retry'],
  INSUFFICIENT_STORAGE: ['磁盘空间不足', 'none'],
};

function byStatus(status: number): [string, ErrorAction] {
  if (status === 401) return MESSAGES.UNAUTHENTICATED!;
  if (status === 403) return MESSAGES.PERMISSION_DENIED!;
  if (status === 404) return MESSAGES.NOT_FOUND!;
  if (status === 409) return MESSAGES.STATE_CONFLICT!;
  if (status === 429) return MESSAGES.RATE_LIMITED!;
  if (status >= 500) return MESSAGES.INTERNAL!;
  return ['请求没有成功', 'retry'];
}

export function describeError(err: unknown): ErrorView {
  if (err instanceof ApiError) {
    const [message, action] = MESSAGES[err.code] ?? byStatus(err.status);
    const fields: Record<string, string> = {};
    if (err.code === 'VALIDATION_FAILED') Object.assign(fields, err.fieldErrors());
    let msg = message;
    if (err.code === 'RATE_LIMITED' && err.retryAfter) msg = `操作太频繁，请在 ${err.retryAfter} 秒后再试`;
    return {
      message: msg,
      action,
      code: err.code,
      fields,
      requestId: err.status >= 500 || err.code === 'INTERNAL' ? err.requestId : undefined,
      fromPlugin: err.code === 'PLUGIN_ERROR' ? err.problem?.detail : undefined,
    };
  }
  if (err instanceof NetworkError) {
    return { message: '连不上服务器，请检查网络', action: 'retry', code: 'NETWORK', fields: {} };
  }
  if (err instanceof DOMException && err.name === 'AbortError') {
    return { message: '已取消', action: 'none', code: 'ABORTED', fields: {} };
  }
  return { message: '出了点意外', action: 'reload', code: 'UNKNOWN', fields: {} };
}

/** 弹出错误 Toast；取消类错误静默 */
export function reportError(err: unknown, prefix?: string): void {
  const v = describeError(err);
  if (v.code === 'ABORTED') return;
  const text = prefix ? `${prefix}：${v.message}` : v.message;
  const detail = v.fromPlugin ? `来自插件：${v.fromPlugin}` : v.requestId ? `请求编号 ${v.requestId}` : undefined;
  toasts.error(text, detail);
}

/** 按字段指针取错误：fieldError(v, '/password') */
export function fieldError(v: ErrorView | null | undefined, pointer: string): string | undefined {
  return v?.fields[pointer];
}
