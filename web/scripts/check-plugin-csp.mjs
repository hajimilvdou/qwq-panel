// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 内置插件 HTML 严格 CSP 静态门禁（STEP-16）
 * --------------------------------------------------------------------------
 * 扫描 ../plugins/builtin/*\/ui/*.html，禁止出现违反 `script-src 'self'; style-src 'self'`
 * 的以下写法：
 *   1. 内联 <script>（无 src= 属性的 <script> 标签）
 *   2. 内联 <style> 标签
 *   3. 内联事件属性（onclick=、onchange= 等 on*= 属性）
 *   4. 内联样式属性（style="..." / style='...'）
 *
 * 用法：node web/scripts/check-plugin-csp.mjs（零违规返回 0，否则输出文件与行号并返回 1）
 * ========================================================================== */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const builtinDir = join(repoRoot, 'plugins', 'builtin');

/**
 * 扫描单个 HTML 源码，返回违规项列表（含 1-based 行号与原因）。
 */
export function scanHtmlForCspViolations(html) {
  const violations = [];
  /* 剥离 HTML 注释但保留换行，确保行号准确 */
  const cleaned = html.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '));
  const lineAt = (idx) => cleaned.slice(0, idx).split('\n').length;

  const tagRe = /<([a-zA-Z][a-zA-Z0-9-]*)(\s[^>]*?)?>/g;
  let m;
  while ((m = tagRe.exec(cleaned)) !== null) {
    const tag = m[1].toLowerCase();
    const attrs = m[2] ?? '';
    const line = lineAt(m.index);

    if (tag === 'script' && !/\bsrc\s*=/i.test(attrs)) {
      violations.push({ line, kind: 'inline-script', detail: '内联 <script>（必须改用外部 <script src="..."></script>）' });
    }
    if (tag === 'style') {
      violations.push({ line, kind: 'inline-style-tag', detail: '内联 <style>（必须提取为外部 CSS 并用 <link rel="stylesheet"> 引入）' });
    }
    if (/\sstyle\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/i.test(attrs)) {
      violations.push({ line, kind: 'inline-style-attr', detail: `<${tag}> 含内联 style 属性（改用 CSS class）` });
    }
    const handlerMatch = /\s(on[a-z]+)\s*=/i.exec(attrs);
    if (handlerMatch) {
      violations.push({ line, kind: 'inline-event-handler', detail: `<${tag}> 含内联事件属性 ${handlerMatch[1]}=（改用 addEventListener）` });
    }
  }
  return violations;
}

function collectPluginHtmlFiles() {
  const files = [];
  if (!existsSync(builtinDir)) return files;
  for (const pluginName of readdirSync(builtinDir)) {
    const uiDir = join(builtinDir, pluginName, 'ui');
    if (!existsSync(uiDir) || !statSync(uiDir).isDirectory()) continue;
    for (const entry of readdirSync(uiDir)) {
      if (entry.toLowerCase().endsWith('.html')) {
        files.push(join(uiDir, entry));
      }
    }
  }
  return files.sort();
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const htmlFiles = collectPluginHtmlFiles();
  let totalViolations = 0;
  for (const file of htmlFiles) {
    const content = readFileSync(file, 'utf8');
    const found = scanHtmlForCspViolations(content);
    if (found.length > 0) {
      const relPath = relative(repoRoot, file).replace(/\\/g, '/');
      for (const v of found) {
        console.error(`${relPath}:${v.line}: [${v.kind}] ${v.detail}`);
        totalViolations++;
      }
    }
  }
  if (totalViolations > 0) {
    console.error(`\nCSP 扫描失败：发现 ${totalViolations} 处内联脚本/样式违规（扫描 ${htmlFiles.length} 个插件 HTML 文件）`);
    process.exit(1);
  }
  console.log(`CSP 扫描通过：${htmlFiles.length} 个内置插件 HTML 文件零内联脚本/样式违规`);
}
