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

/**
 * 扫描单个 JS 源码，禁止通过 .setAttribute('style', ...) 注入内联样式（违反严格 style-src 'self' CSP）。
 */
export function scanJsForCspViolations(js) {
  const violations = [];
  const lineAt = (idx) => js.slice(0, idx).split('\n').length;
  const re = /\.setAttribute\s*\(\s*(['"`])style\1/gi;
  let m;
  while ((m = re.exec(js)) !== null) {
    violations.push({
      line: lineAt(m.index),
      kind: 'js-inline-style-attr',
      detail: `JS 调用 .setAttribute('style', ...)（改用 CSS class 或 adoptedStyleSheets）`,
    });
  }
  return violations;
}

function collectPluginFilesByExt(ext) {
  const files = [];
  if (!existsSync(builtinDir)) return files;
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        walk(full);
      } else if (entry.toLowerCase().endsWith(ext)) {
        files.push(full);
      }
    }
  };
  for (const pluginName of readdirSync(builtinDir)) {
    for (const sub of ['ui', 'portal_ui']) {
      const uiDir = join(builtinDir, pluginName, sub);
      if (!existsSync(uiDir) || !statSync(uiDir).isDirectory()) continue;
      walk(uiDir);
    }
  }
  return files.sort();
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const htmlFiles = collectPluginFilesByExt('.html');
  const jsFiles = collectPluginFilesByExt('.js');
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
  for (const file of jsFiles) {
    const content = readFileSync(file, 'utf8');
    const found = scanJsForCspViolations(content);
    if (found.length > 0) {
      const relPath = relative(repoRoot, file).replace(/\\/g, '/');
      for (const v of found) {
        console.error(`${relPath}:${v.line}: [${v.kind}] ${v.detail}`);
        totalViolations++;
      }
    }
  }
  if (totalViolations > 0) {
    console.error(
      `\nCSP 扫描失败：发现 ${totalViolations} 处内联脚本/样式违规（扫描 ${htmlFiles.length} 个 HTML 与 ${jsFiles.length} 个 JS 文件）`,
    );
    process.exit(1);
  }
  console.log(`CSP 扫描通过：${htmlFiles.length} 个 HTML 与 ${jsFiles.length} 个 JS 内置插件文件零内联脚本/样式违规`);
}
