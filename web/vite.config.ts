// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * Vite 配置
 * --------------------------------------------------------------------------
 * 模式：
 *   npm run dev                 开发服务器 + 内置模拟后端（mock/）
 *   QWQ_BACKEND=https://127.0.0.1:8443 npm run dev
 *                               开发服务器 + 代理到真实宿主（不加载模拟后端）
 *   npm run build               生产构建到 dist/
 *   npm run preview             预览生产构建：带模拟后端 + 与宿主一致的严格 CSP
 * ========================================================================== */
import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';
import { mockBackend } from './mock/plugin.ts';
import { SHELL_CSP } from './scripts/csp.mjs';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/* 路径别名：vite 与 vitest 共用一份（tsconfig.base.json 的 paths 与此同步） */
export const alias = {
  $api: here('./shell/src/api'),
  $lib: here('./shell/src/lib'),
  $ui: here('./shell/src/ui'),
  '@fonts': here('./node_modules/@fontsource-variable'),
};

/* Shell CSP 的唯一来源在 scripts/csp.mjs（postbuild 写入 dist/.csp，Go 侧 internal/webui 读取下发） */
export { SHELL_CSP };

const backend = process.env.QWQ_BACKEND;

/* 预览服务器为 Shell 页面加上生产 CSP，E2E 借此捕获任何违规 */
function previewCsp(): Plugin {
  return {
    name: 'qwq-preview-csp',
    configurePreviewServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ?? '';
        if (!url.startsWith('/api/') && !url.startsWith('/plugin-ui/')) {
          res.setHeader('Content-Security-Policy', SHELL_CSP);
          res.setHeader('X-Content-Type-Options', 'nosniff');
          res.setHeader('Referrer-Policy', 'no-referrer');
        }
        next();
      });
    },
  };
}

export default defineConfig({
  root: here('./shell'),
  base: '/',
  publicDir: here('./shell/public'),
  plugins: [svelte({ configFile: here('./svelte.config.js') }), ...(backend ? [] : [mockBackend()]), previewCsp()],
  resolve: { alias },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: backend
      ? {
          '/api': { target: backend, secure: false, changeOrigin: true, ws: false },
          '/plugin-ui': { target: backend, secure: false, changeOrigin: true },
          '/healthz': { target: backend, secure: false, changeOrigin: true },
          '/readyz': { target: backend, secure: false, changeOrigin: true },
        }
      : undefined,
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
  },
  build: {
    outDir: here('./dist'),
    emptyOutDir: true,
    target: 'es2022',
    /* 字体与图片一律输出为文件：CSP 的 font-src 不允许 data: */
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    /* .vite/manifest.json：postbuild 据此计算首屏预算，读完即删，不随产物发布 */
    manifest: true,
    reportCompressedSize: false,
    chunkSizeWarningLimit: 400,
    /* 按 chunk 拆分 CSS，避免首屏携带全部二级页面的样式 */
    cssCodeSplit: true,
    rollupOptions: {
      /* $ui 与 endpoints 是纯 re-export 桶文件：声明无副作用（兼容 Windows 反斜杠路径），打包器才会把各模块分给真正用到它的 chunk */
      treeshake: {
        moduleSideEffects: (id: string) => {
          const norm = id.replace(/\\/g, '/');
          return !norm.endsWith('/shell/src/ui/index.ts') && !norm.endsWith('/shell/src/api/endpoints.ts');
        },
      },
    },
  },
});
