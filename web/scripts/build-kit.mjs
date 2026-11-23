// SPDX-License-Identifier: AGPL-3.0-only
/* 将 web/kit/src/index.ts 构建为零外部依赖的单文件 ESM，输出至 internal/pluginui/kit/v1/ */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const webDir = dirname(scriptDir);
const repoRoot = dirname(webDir);
const outDir = join(repoRoot, 'internal', 'pluginui', 'kit', 'v1');

mkdirSync(outDir, { recursive: true });

await build({
  configFile: false,
  root: webDir,
  logLevel: 'warn',
  build: {
    outDir,
    emptyOutDir: true,
    minify: true,
    sourcemap: false,
    lib: {
      entry: join(webDir, 'kit', 'src', 'index.ts'),
      formats: ['es'],
      fileName: () => 'kit.js',
    },
  },
});

// 统一附加仓库目录要求的 SPDX 头（internal/ 分区要求 AGPL-3.0-only）
const kitJsPath = join(outDir, 'kit.js');
const kitJsRaw = readFileSync(kitJsPath, 'utf8');
if (!kitJsRaw.startsWith('// SPDX-License-Identifier:')) {
  writeFileSync(kitJsPath, `// SPDX-License-Identifier: AGPL-3.0-only\n${kitJsRaw}`, 'utf8');
}

const baseCssRaw = readFileSync(join(webDir, 'kit', 'src', 'kit-base.css'), 'utf8');
const normalizedCss = baseCssRaw.replace(
  '/* SPDX-License-Identifier: Apache-2.0 */',
  '/* SPDX-License-Identifier: AGPL-3.0-only */',
);
writeFileSync(join(outDir, 'kit-base.css'), normalizedCss, 'utf8');

console.log('Built shared plugin UI kit -> internal/pluginui/kit/v1/{kit.js,kit-base.css}');
