// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * Vitest 配置
 * --------------------------------------------------------------------------
 * 与 vite.config.ts 分开：测试不需要 shell 的 root、mock 中间件与 CSP。
 * 测试运行在 Node 环境（自带 fetch / ReadableStream / BroadcastChannel），
 * 需要 DOM 的用例自行构造最小桩，不引入 jsdom。
 * ========================================================================== */
import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';
import { alias } from './vite.config';

export default defineConfig({
  plugins: [svelte({ configFile: fileURLToPath(new URL('./svelte.config.js', import.meta.url)) })],
  resolve: { alias },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    restoreMocks: true,
  },
});
