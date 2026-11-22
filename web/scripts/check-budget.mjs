// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 体积预算（ENG §10，gzip -9）
 * --------------------------------------------------------------------------
 *   首屏 JS（入口 + 主页 chunk 及其静态依赖）  ≤ 60 KiB
 *   全部 CSS                                  ≤ 45 KiB
 *   HTML（+ 图标）                            ≤ 10 KiB
 *   单个懒加载 chunk                          ≤ 40 KiB
 *   首屏字体（latin 子集）                    ≤ 90 KiB（woff2 已压缩，按原始大小计）
 * 读取 vite 的 .vite/manifest.json 计算首屏图。超额返回问题列表。
 * 用法：node scripts/check-budget.mjs（或由 postbuild 调用 checkBudget()）
 * ========================================================================== */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const KiB = 1024;
export const BUDGET = { firstJs: 60 * KiB, css: 45 * KiB, html: 10 * KiB, chunk: 40 * KiB, fonts: 90 * KiB };

const gz = (buf) => gzipSync(buf, { level: 9 }).length;
const kb = (n) => `${(n / KiB).toFixed(1)} KiB`;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

/** 从入口出发收集静态 import 闭包 */
function closure(manifest, key, seen = new Set()) {
  if (seen.has(key) || !manifest[key]) return seen;
  seen.add(key);
  for (const dep of manifest[key].imports ?? []) closure(manifest, dep, seen);
  return seen;
}

export function checkBudget(dist) {
  const manifest = JSON.parse(readFileSync(join(dist, '.vite/manifest.json'), 'utf8'));
  const size = (file) => gz(readFileSync(join(dist, file)));
  const entryKey = Object.keys(manifest).find((k) => manifest[k].isEntry);
  const homeKey = Object.keys(manifest).find((k) => k.endsWith('features/home/Page.svelte'));
  const first = new Set([...closure(manifest, entryKey), ...(homeKey ? closure(manifest, homeKey) : [])]);
  const firstJs = [...first].reduce((n, k) => n + size(manifest[k].file), 0);

  const files = walk(dist).map((p) => relative(dist, p).replace(/\\/g, '/'));
  const cssTotal = files.filter((f) => f.endsWith('.css')).reduce((n, f) => n + size(f), 0);
  const html = files.filter((f) => f.endsWith('.html') || f === 'favicon.svg').reduce((n, f) => n + size(f), 0);
  const firstFiles = new Set([...first].map((k) => manifest[k].file));
  const lazy = files
    .filter((f) => f.startsWith('assets/') && f.endsWith('.js') && !firstFiles.has(f))
    .map((f) => ({ f, n: size(f) }));
  const fonts = files
    .filter((f) => /-latin-wght-normal.*\.woff2$/.test(f) && !f.includes('latin-ext'))
    .reduce((n, f) => n + statSync(join(dist, f)).size, 0);

  const rows = [
    ['首屏 JS', firstJs, BUDGET.firstJs],
    ['全部 CSS', cssTotal, BUDGET.css],
    ['HTML + 图标', html, BUDGET.html],
    ['首屏字体', fonts, BUDGET.fonts],
    ['最大懒加载 chunk', Math.max(0, ...lazy.map((x) => x.n)), BUDGET.chunk],
  ];
  const problems = rows.filter(([, n, max]) => n > max).map(([name, n, max]) => `${name} ${kb(n)} > ${kb(max)}`);
  for (const x of lazy) if (x.n > BUDGET.chunk) problems.push(`chunk ${x.f} ${kb(x.n)} > ${kb(BUDGET.chunk)}`);
  return { rows: rows.map(([name, n, max]) => `${name.padEnd(14)} ${kb(n).padStart(10)} / ${kb(max)}`), problems };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const dist = fileURLToPath(new URL('../dist', import.meta.url));
  const { rows, problems } = checkBudget(dist);
  console.log(rows.join('\n'));
  if (problems.length) {
    console.error('超出预算：\n  ' + problems.join('\n  '));
    process.exit(1);
  }
}
