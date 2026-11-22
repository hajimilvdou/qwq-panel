// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 一次性令牌从 URL fragment 读取（SPEC §2：读取后立刻 replaceState 清除）
 * --------------------------------------------------------------------------
 * fragment 不随请求发送、不进服务端日志与 Referer；读完即从地址栏抹掉，
 * 防止截图、浏览器历史与同步把令牌带出去。
 * ========================================================================== */

export function takeFragmentToken(): string {
  if (typeof location === 'undefined' || !location.hash) return '';
  const token = new URLSearchParams(location.hash.slice(1)).get('token')?.trim() ?? '';
  history.replaceState(history.state, '', location.pathname + location.search);
  return token;
}
