// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 从公共契约生成 TypeScript 类型（ADR-0006 D1）
 * --------------------------------------------------------------------------
 *   api/public/v1/openapi.yaml  ──openapi-typescript──▶  shell/src/api/schema.d.ts
 * 生成物提交入库；CI 重新生成并比较差异。只生成类型，运行时封装手写（client.ts）。
 * ========================================================================== */
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import openapiTS, { astToString } from 'openapi-typescript';

const spec = fileURLToPath(new URL('../../api/public/v1/openapi.yaml', import.meta.url));
const out = fileURLToPath(new URL('../shell/src/api/schema.d.ts', import.meta.url));

const HEADER = `// SPDX-License-Identifier: AGPL-3.0-only
// 由 scripts/gen-api.mjs 从 api/public/v1/openapi.yaml 生成，不要手改。
`;

const ast = await openapiTS(pathToFileURL(spec), {
  alphabetize: false,
  exportType: true,
  emptyObjectsUnknown: true,
});
const body = astToString(ast);
const next = HEADER + body;

let prev = '';
try {
  prev = await readFile(out, 'utf8');
} catch {
  /* 首次生成 */
}

if (process.argv.includes('--check')) {
  if (prev !== next) {
    console.error('schema.d.ts 与 openapi.yaml 不一致：运行 npm run gen:api');
    process.exit(1);
  }
  console.log('schema.d.ts 无漂移');
} else if (prev !== next) {
  await writeFile(out, next);
  console.log(`已生成 ${out}（${next.length} 字节）`);
} else {
  console.log('schema.d.ts 已是最新');
}
