// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * Shell CSP —— 唯一来源
 * --------------------------------------------------------------------------
 * vite.config.ts 引用它给 preview 加头；postbuild 写入 dist/.csp，
 * Go 侧 internal/webui embed 读取后原样下发（ENG §10、§12）。改这里即两边同步。
 * img-src 的 data: 仅为插件图标兜底；若最终无使用者，从这里删除。
 * ========================================================================== */
export const SHELL_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-src 'self'",
  "manifest-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ');
