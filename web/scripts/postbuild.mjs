// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 构建后处理（ENG §11）—— `npm run build` 的第二步
 * --------------------------------------------------------------------------
 *   1. 校验产物不含模拟后端（"__mock"、mock/ 源码痕迹）
 *   2. 写 dist/.csp（Shell CSP 唯一来源，Go 侧 internal/webui 读取）
 *   3. 体积预算（check-budget.mjs）
 *   4. 第三方许可证声明 dist/THIRD_PARTY_LICENSES.txt
 *   5. 预压缩 .br / .gz（文本类资源，且压缩后确实更小）
 *   6. dist/manifest.json：文件 → content-type、是否带哈希（可长缓存）
 * 任何一步失败都以非 0 退出，构建即失败。
 * ========================================================================== */
import { existsSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';
import { checkBudget } from './check-budget.mjs';
import { SHELL_CSP } from './csp.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const dist = join(root, 'dist');

const fail = (msg) => {
  console.error(`postbuild: ${msg}`);
  process.exit(1);
};

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}
const rel = (p) => relative(dist, p).replace(/\\/g, '/');

if (!existsSync(join(dist, 'index.html'))) fail('dist/index.html 不存在，vite build 是否成功？');

/* ------------------------------------------------------------------ 1. 不含 mock */
const TEXT = /\.(js|css|html|svg|json|txt|mjs)$/;
const leaks = walk(dist)
  .filter((p) => TEXT.test(p) && !p.includes(`${join('dist', '.vite')}`))
  .filter((p) => {
    const s = readFileSync(p, 'utf8');
    return s.includes('__mock') || s.includes('qwq-mock-backend') || s.includes('createMockServer');
  })
  .map(rel);
if (leaks.length) fail(`产物包含模拟后端痕迹：${leaks.join(', ')}`);

/* ------------------------------------------------------------------ 2. CSP */
writeFileSync(join(dist, '.csp'), SHELL_CSP + '\n');

/* ------------------------------------------------------------------ 3. 预算 */
const { rows, problems } = checkBudget(dist);
console.log('体积（gzip -9）：\n  ' + rows.join('\n  '));
if (problems.length) fail('超出预算：\n  ' + problems.join('\n  '));
rmSync(join(dist, '.vite'), { recursive: true, force: true });

/* ------------------------------------------------------------------ 4. 许可证 */
const THIRD_PARTY = [
  ['svelte', 'node_modules/svelte/LICENSE.md'],
  ['uqr', 'node_modules/uqr/LICENSE'],
  ['Plus Jakarta Sans（OFL-1.1）', 'node_modules/@fontsource-variable/plus-jakarta-sans/LICENSE'],
  ['JetBrains Mono（OFL-1.1）', 'node_modules/@fontsource-variable/jetbrains-mono/LICENSE'],
];
const notice = THIRD_PARTY.map(([name, file]) => {
  const p = join(root, file);
  if (!existsSync(p)) fail(`缺少许可证文件：${file}`);
  return `==== ${name} ====\n\n${readFileSync(p, 'utf8').trim()}\n`;
}).join('\n');
writeFileSync(join(dist, 'THIRD_PARTY_LICENSES.txt'), `qwq Web Shell 随附的第三方组件许可证\n\n${notice}`);

/* ------------------------------------------------------------------ 5. 预压缩 */
const COMPRESSIBLE = /\.(js|css|html|svg|json|txt)$/;
for (const p of walk(dist)) {
  if (!COMPRESSIBLE.test(p)) continue;
  const buf = readFileSync(p);
  if (buf.length < 512) continue;
  const br = brotliCompressSync(buf, { params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_SIZE_HINT]: buf.length } });
  const gz = gzipSync(buf, { level: 9 });
  if (br.length < buf.length) writeFileSync(p + '.br', br);
  if (gz.length < buf.length) writeFileSync(p + '.gz', gz);
}

/* ------------------------------------------------------------------ 6. manifest */
const TYPES = {
  html: 'text/html; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  svg: 'image/svg+xml',
  json: 'application/json',
  txt: 'text/plain; charset=utf-8',
  woff2: 'font/woff2',
  png: 'image/png',
  ico: 'image/x-icon',
};
const files = {};
for (const p of walk(dist)) {
  const f = rel(p);
  if (f.endsWith('.br') || f.endsWith('.gz') || f === '.csp') continue;
  const ext = f.split('.').pop();
  files[f] = {
    type: TYPES[ext] ?? 'application/octet-stream',
    immutable: f.startsWith('assets/'),
    br: existsSync(p + '.br'),
    gz: existsSync(p + '.gz'),
  };
}
writeFileSync(join(dist, 'manifest.json'), JSON.stringify({ csp: '.csp', files }, null, 2) + '\n');
console.log(`postbuild: 完成（${Object.keys(files).length} 个文件，不含模拟后端）`);
