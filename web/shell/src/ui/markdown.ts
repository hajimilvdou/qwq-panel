// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 安全 Markdown 子集 → AST（供 <Markdown> 用元素逐个渲染；不产出 HTML 字符串）
 * --------------------------------------------------------------------------
 * 输入一律视为不可信（模型输出、插件文本）。设计取舍：
 *   - 只认识少量语法；其余原样当文本，绝不解释 HTML（<b> 就显示成 "<b>"）
 *   - 链接仅允许 https:// 与站内相对路径 "/"，其余降级为纯文本
 *   - 长度上限防止超长输入拖慢主线程
 *
 *   块级   段落 · 标题 #~### · 无序/有序列表 · ``` 代码块 · > 引用
 *   行内   **粗体** · *斜体* / _斜体_ · `代码` · [文字](链接) · 行内换行
 * ========================================================================== */

export type Inline =
  | { t: 'text'; v: string }
  | { t: 'strong' | 'em'; c: Inline[] }
  | { t: 'code'; v: string }
  | { t: 'link'; href: string; c: Inline[] }
  | { t: 'br' };

export type Block =
  | { t: 'p' | 'quote'; c: Inline[] }
  | { t: 'h'; level: 1 | 2 | 3; c: Inline[] }
  | { t: 'list'; ordered: boolean; start: number; items: Inline[][] }
  | { t: 'pre'; lang: string; v: string };

export const MARKDOWN_MAX = 64 * 1024;

/* ------------------------------------------------------------------ 块级 */

const FENCE = /^ {0,3}```\s*([\w+-]*)\s*$/;
const HEADING = /^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$/;
const BULLET = /^ {0,3}[-*+]\s+(.*)$/;
const ORDERED = /^ {0,3}(\d{1,9})[.)]\s+(.*)$/;
const QUOTE = /^ {0,3}>\s?(.*)$/;

export function parseMarkdown(src: string): Block[] {
  const lines = src.slice(0, MARKDOWN_MAX).replace(/\r\n?/g, '\n').split('\n');
  const out: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i]!;
    if (!line.trim()) {
      i++;
      continue;
    }

    /* ``` 代码块：直到下一个 ``` 或文末 */
    const fence = FENCE.exec(line);
    if (fence) {
      const body: string[] = [];
      for (i++; i < lines.length && !FENCE.test(lines[i]!); i++) body.push(lines[i]!);
      i++;
      out.push({ t: 'pre', lang: fence[1] ?? '', v: body.join('\n') });
      continue;
    }

    const h = HEADING.exec(line);
    if (h) {
      out.push({ t: 'h', level: Math.min(3, h[1]!.length) as 1 | 2 | 3, c: parseInline(h[2]!) });
      i++;
      continue;
    }

    /* 列表：同类连续项；缩进的续行并入上一项 */
    const listStart = BULLET.exec(line) ?? ORDERED.exec(line);
    if (listStart) {
      const ordered = !BULLET.test(line);
      const re = ordered ? ORDERED : BULLET;
      const items: string[] = [];
      const start = ordered ? Number(ORDERED.exec(line)![1]) : 1;
      while (i < lines.length) {
        const l = lines[i]!;
        const m = re.exec(l);
        if (m) items.push(m[m.length - 1]!);
        else if (items.length && /^\s{2,}\S/.test(l)) items[items.length - 1] += '\n' + l.trim();
        else break;
        i++;
      }
      out.push({ t: 'list', ordered, start, items: items.map(parseInline) });
      continue;
    }

    if (QUOTE.test(line)) {
      const body: string[] = [];
      for (; i < lines.length && QUOTE.test(lines[i]!); i++) body.push(QUOTE.exec(lines[i]!)![1]!);
      out.push({ t: 'quote', c: parseInline(body.join('\n')) });
      continue;
    }

    /* 段落：直到空行或其它块起点 */
    const body: string[] = [];
    for (; i < lines.length; i++) {
      const l = lines[i]!;
      if (!l.trim() || FENCE.test(l) || HEADING.test(l) || BULLET.test(l) || ORDERED.test(l) || QUOTE.test(l)) break;
      body.push(l);
    }
    out.push({ t: 'p', c: parseInline(body.join('\n')) });
  }
  return out;
}

/* ------------------------------------------------------------------ 行内 */

/** 只放行 https 与站内路径（拒绝控制字符、反斜杠、"//" 及任意跨源归一） */
export function safeHref(raw: string): string | null {
  const href = raw.trim();
  if (!href || /[\u0000-\u001f\u007f]/.test(href)) return null;
  if (href.startsWith('/')) {
    if (href.startsWith('//') || href.includes('\\')) return null;
    try {
      const u = new URL(href, 'https://qwq.invalid');
      return u.origin === 'https://qwq.invalid' ? href : null;
    } catch {
      return null;
    }
  }
  try {
    const u = new URL(href);
    return u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

export function parseInline(src: string): Inline[] {
  const out: Inline[] = [];
  let text = '';
  const flush = () => {
    if (text) out.push({ t: 'text', v: text });
    text = '';
  };

  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    const rest = src.slice(i);

    if (ch === '\\' && i + 1 < src.length && /[\\`*_[\]()#>-]/.test(src[i + 1]!)) {
      text += src[i + 1];
      i += 2;
      continue;
    }
    if (ch === '\n') {
      flush();
      out.push({ t: 'br' });
      i++;
      continue;
    }
    if (ch === '`') {
      const end = src.indexOf('`', i + 1);
      if (end > i + 1) {
        flush();
        out.push({ t: 'code', v: src.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }
    const strong = /^(\*\*|__)(?=\S)([\s\S]*?\S)\1/.exec(rest);
    if (strong) {
      flush();
      out.push({ t: 'strong', c: parseInline(strong[2]!) });
      i += strong[0].length;
      continue;
    }
    const em = /^([*_])(?=\S)([\s\S]*?\S)\1(?![*_])/.exec(rest);
    if (em && (ch === '*' || !/\w/.test(src[i - 1] ?? ''))) {
      flush();
      out.push({ t: 'em', c: parseInline(em[2]!) });
      i += em[0].length;
      continue;
    }
    const link = /^\[([^\]\n]+)\]\(([^)\s]+)\)/.exec(rest);
    if (link) {
      const href = safeHref(link[2]!);
      flush();
      if (href) out.push({ t: 'link', href, c: parseInline(link[1]!) });
      else out.push({ t: 'text', v: `${link[1]} (${link[2]})` });
      i += link[0].length;
      continue;
    }
    text += ch;
    i++;
  }
  flush();
  return out;
}
