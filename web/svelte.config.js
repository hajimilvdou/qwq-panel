// SPDX-License-Identifier: AGPL-3.0-only
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/vite-plugin-svelte').SvelteConfig} */
export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    runes: true,
  },
  /* 只对本仓库源码强制 runes；依赖保持其自身模式 */
  vitePlugin: {
    dynamicCompileOptions({ filename }) {
      if (filename.includes('node_modules')) return { runes: undefined };
    },
  },
};
