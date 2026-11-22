// SPDX-License-Identifier: AGPL-3.0-only
/* 工程纪律（ENG §1 / §6 / §11）：依赖方向、禁 {@html}、写入只经 endpoints/ops、生产不含 mock、SPDX 头 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(__dirname, '..');
function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|svelte|mjs|js|css)$/.test(name)) out.push(p);
  }
  return out;
}
const shell = walk(join(ROOT, 'shell/src'));
const rel = (p: string) => relative(ROOT, p).replace(/\\/g, '/');
const offenders = (files: string[], re: RegExp) => files.filter((f) => re.test(readFileSync(f, 'utf8'))).map(rel);

describe('boundaries', () => {
  it('ui/ 不依赖 $lib / $api', () => {
    expect(offenders(shell.filter((f) => rel(f).startsWith('shell/src/ui/')), /from ['"](\$lib|\$api)/)).toEqual([]);
  });

  it('全仓禁 {@html}', () => {
    expect(offenders(shell.filter((f) => f.endsWith('.svelte')), /\{@html/)).toEqual([]);
  });

  it('features/ 不直接调用 http 写方法', () => {
    expect(offenders(shell.filter((f) => rel(f).startsWith('shell/src/features/')), /\bhttp\.(post|put|patch|del)\b/)).toEqual([]);
  });

  it('shell/src 不引用 mock/', () => {
    expect(offenders(shell, /from ['"][./]*mock\//)).toEqual([]);
  });

  it('模板中没有内联 style="…"（CSP：动态值用 style: 指令）', () => {
    expect(offenders(shell.filter((f) => f.endsWith('.svelte')), /\sstyle="/)).toEqual([]);
  });

  it('每个源文件都有 SPDX 头（shell/mock/scripts 为 AGPL，kit 为 Apache）', () => {
    const agpl = [...shell, ...walk(join(ROOT, 'mock')), ...walk(join(ROOT, 'scripts')), ...walk(join(ROOT, 'test'))];
    const missing = agpl.filter((f) => !readFileSync(f, 'utf8').slice(0, 200).includes('SPDX-License-Identifier: AGPL-3.0-only')).map(rel);
    expect(missing).toEqual([]);
    const kit = walk(join(ROOT, 'kit'));
    expect(kit.filter((f) => !readFileSync(f, 'utf8').includes('SPDX-License-Identifier: Apache-2.0')).map(rel)).toEqual([]);
  });
});
