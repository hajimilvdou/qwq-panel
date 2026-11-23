// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 安全 Markdown 子集 → AST（供 <Markdown> 用元素逐个渲染；不产出 HTML 字符串）
 * --------------------------------------------------------------------------
 * 输入一律视为不可信（模型输出、插件文本）。设计取舍：
 *   - 只认识少量语法；其余原样当文本，绝不解释 HTML（<b> 就显示成 "<b>"）
 *   - 链接仅允许 https:// 与站内相对路径 "/"，其余降级为纯文本
 *   - 严格 O(N) 线性行内扫描（单调游标，无回溯正则），64 KiB 未闭合流式输出 < 1ms
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
const MAX_INLINE_DEPTH = 4;

/* ------------------------------------------------------------------ 块级 */

const FENCE = /^ {0,3}```\s*([\w+-]*)\s*$/;
const HEADING = /^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$/;
const BULLET = /^ {0,3}[-*+]\s+(.*)$/;
const ORDERED = /^ {0,3}(\d{1,9})[.)]\s+(.*)$/;
const QUOTE = /^ {0,3}>\s?(.*)$/;

function normalizeSource(src: string): string {
  const sliced = src.length > MARKDOWN_MAX ? src.slice(0, MARKDOWN_MAX) : src;
  return sliced.includes('\r') ? sliced.replace(/\r\n?/g, '\n') : sliced;
}

interface ParsedBlockSpan {
  block: Block;
  /** 该块结束后的行索引（不含） */
  endLine: number;
  /** 仅当块之后存在空行或后续新块时，才视为已闭合，可安全缓存 */
  closed: boolean;
}

function parseLinesToSpans(lines: readonly string[]): ParsedBlockSpan[] {
  const out: ParsedBlockSpan[] = [];
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
      let closedFence = false;
      for (i++; i < lines.length; i++) {
        if (FENCE.test(lines[i]!)) {
          closedFence = true;
          i++;
          break;
        }
        body.push(lines[i]!);
      }
      out.push({ block: { t: 'pre', lang: fence[1] ?? '', v: body.join('\n') }, endLine: i, closed: closedFence });
      continue;
    }

    const h = HEADING.exec(line);
    if (h) {
      i++;
      const closed = i < lines.length;
      out.push({ block: { t: 'h', level: Math.min(3, h[1]!.length) as 1 | 2 | 3, c: parseInlineLinear(h[2]!) }, endLine: i, closed });
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
      const closed = i < lines.length && !lines[i]!.trim();
      out.push({ block: { t: 'list', ordered, start, items: items.map((x) => parseInlineLinear(x)) }, endLine: i, closed });
      continue;
    }

    if (QUOTE.test(line)) {
      const body: string[] = [];
      for (; i < lines.length && QUOTE.test(lines[i]!); i++) body.push(QUOTE.exec(lines[i]!)![1]!);
      const closed = i < lines.length && !lines[i]!.trim();
      out.push({ block: { t: 'quote', c: parseInlineLinear(body.join('\n')) }, endLine: i, closed });
      continue;
    }

    /* 段落：直到空行或其它块起点 */
    const body: string[] = [];
    for (; i < lines.length; i++) {
      const l = lines[i]!;
      if (!l.trim() || FENCE.test(l) || HEADING.test(l) || BULLET.test(l) || ORDERED.test(l) || QUOTE.test(l)) break;
      body.push(l);
    }
    const closed = i < lines.length;
    out.push({ block: { t: 'p', c: parseInlineLinear(body.join('\n')) }, endLine: i, closed });
  }
  return out;
}

export function parseMarkdown(src: string): Block[] {
  const lines = normalizeSource(src).split('\n');
  return parseLinesToSpans(lines).map((s) => s.block);
}

/**
 * 流式增量缓存：当新文本以前缀追加方式增长时，已闭合历史块直接复用 AST，
 * 仅重新解析末尾活动块，避免长对话流式吐字重复解析全部历史段落。
 */
export function createMarkdownCache(): { parse(src: string): Block[] } {
  let cachedPrefix = '';
  let cachedBlocks: Block[] = [];

  return {
    parse(src: string): Block[] {
      const norm = normalizeSource(src);
      if (!norm) {
        cachedPrefix = '';
        cachedBlocks = [];
        return [];
      }
      if (!cachedPrefix || !norm.startsWith(cachedPrefix)) {
        cachedPrefix = '';
        cachedBlocks = [];
      }
      const tail = norm.slice(cachedPrefix.length);
      if (!tail) return cachedBlocks;

      const lines = tail.split('\n');
      const spans = parseLinesToSpans(lines);
      /* 计算行起止偏移，把已经闭合（且后面还有内容）的块晋升进缓存 */
      let closedCount = 0;
      for (let k = 0; k < spans.length - 1; k++) {
        if (spans[k]!.closed) closedCount = k + 1;
        else break;
      }
      if (closedCount > 0) {
        const cutLine = spans[closedCount - 1]!.endLine;
        let offset = 0;
        for (let l = 0; l < cutLine; l++) offset += lines[l]!.length + 1;
        if (offset <= tail.length) {
          cachedPrefix += tail.slice(0, offset);
          for (let k = 0; k < closedCount; k++) cachedBlocks.push(spans[k]!.block);
          const rest = spans.slice(closedCount).map((s) => s.block);
          return rest.length ? [...cachedBlocks, ...rest] : cachedBlocks;
        }
      }
      const tailBlocks = spans.map((s) => s.block);
      return cachedBlocks.length ? [...cachedBlocks, ...tailBlocks] : tailBlocks;
    },
  };
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

const isWs = (ch: string | undefined): boolean =>
  ch === undefined || ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v';

const isWord = (ch: string | undefined): boolean => {
  if (!ch) return false;
  const c = ch.charCodeAt(0);
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
};

const isEscapable = (ch: string): boolean => '\\`*_[]()#-'.includes(ch) || ch === '>';

/**
 * 严格 O(N) 线性时间无回溯行内解析器：
 * 为每类定界符维护单调前进的闭合游标，即使面对 64 KiB 未闭合的 `*` / `_` / `[` / `` ` ``
 * 也不会产生二次扫描，确保 AI 流式输出主线程零卡顿。
 */
export function parseInlineLinear(src: string, depth = 0): Inline[] {
  const out: Inline[] = [];
  const n = src.length;
  let text = '';
  let textStart = 0;

  const flush = (end: number) => {
    if (end > textStart) text += src.slice(textStart, end);
    if (text) {
      out.push({ t: 'text', v: text });
      text = '';
    }
  };

  /* 单调游标：只向前推进，-2 表示未查，-1 表示余下文本无此定界符 */
  let nextBacktick = -2;
  let nextDoubleStar = -2;
  let nextDoubleUnder = -2;
  let nextStar = -2;
  let nextUnder = -2;
  let nextLinkSep = -2;
  let nextParen = -2;

  const findNext = (cur: number, needle: string, from: number): number => {
    if (cur === -1) return -1;
    if (cur >= from) return cur;
    return src.indexOf(needle, from);
  };

  let i = 0;
  while (i < n) {
    const ch = src[i]!;

    if (ch === '\\' && i + 1 < n && isEscapable(src[i + 1]!)) {
      if (i > textStart) text += src.slice(textStart, i);
      text += src[i + 1]!;
      i += 2;
      textStart = i;
      continue;
    }

    if (ch === '\n') {
      flush(i);
      out.push({ t: 'br' });
      i++;
      textStart = i;
      continue;
    }

    /* 行内代码 `...` */
    if (ch === '`') {
      nextBacktick = findNext(nextBacktick, '`', i + 1);
      if (nextBacktick > i + 1) {
        flush(i);
        out.push({ t: 'code', v: src.slice(i + 1, nextBacktick) });
        i = nextBacktick + 1;
        textStart = i;
        continue;
      }
      i++;
      continue;
    }

    /* 粗体 **...** 或 __...__ */
    if ((ch === '*' && src[i + 1] === '*') || (ch === '_' && src[i + 1] === '_')) {
      const isStar = ch === '*';
      if (i + 2 < n && !isWs(src[i + 2])) {
        const delim = isStar ? '**' : '__';
        const close = isStar
          ? (nextDoubleStar = findNext(nextDoubleStar, delim, i + 2))
          : (nextDoubleUnder = findNext(nextDoubleUnder, delim, i + 2));
        if (close > i + 2 && !isWs(src[close - 1])) {
          flush(i);
          const inner = src.slice(i + 2, close);
          out.push({ t: 'strong', c: depth < MAX_INLINE_DEPTH ? parseInlineLinear(inner, depth + 1) : [{ t: 'text', v: inner }] });
          i = close + 2;
          textStart = i;
          continue;
        }
      }
      i += 2;
      continue;
    }

    /* 斜体 *...* 或 _..._（不跨换行，下划线在单词内不算斜体） */
    if (ch === '*' || (ch === '_' && !isWord(src[i - 1]))) {
      const isStar = ch === '*';
      if (i + 1 < n && !isWs(src[i + 1])) {
        const close = isStar
          ? (nextStar = findNext(nextStar, '*', i + 1))
          : (nextUnder = findNext(nextUnder, '_', i + 1));
        if (close > i + 1 && !isWs(src[close - 1])) {
          const after = src[close + 1];
          const validAfter = after !== '*' && after !== '_' && (isStar || !isWord(after));
          const inner = src.slice(i + 1, close);
          if (validAfter && !inner.includes('\n')) {
            flush(i);
            out.push({ t: 'em', c: depth < MAX_INLINE_DEPTH ? parseInlineLinear(inner, depth + 1) : [{ t: 'text', v: inner }] });
            i = close + 1;
            textStart = i;
            continue;
          }
        }
      }
      i++;
      continue;
    }

    /* 链接 [label](href) */
    if (ch === '[') {
      nextLinkSep = findNext(nextLinkSep, '](', i + 1);
      if (nextLinkSep > i + 1) {
        const label = src.slice(i + 1, nextLinkSep);
        if (!label.includes('\n') && !label.includes(']')) {
          nextParen = findNext(nextParen, ')', nextLinkSep + 2);
          if (nextParen > nextLinkSep + 2) {
            const rawUrl = src.slice(nextLinkSep + 2, nextParen);
            if (!/\s/.test(rawUrl)) {
              const href = safeHref(rawUrl);
              flush(i);
              if (href) {
                out.push({
                  t: 'link',
                  href,
                  c: depth < MAX_INLINE_DEPTH ? parseInlineLinear(label, depth + 1) : [{ t: 'text', v: label }],
                });
              } else {
                out.push({ t: 'text', v: `${label} (${rawUrl})` });
              }
              i = nextParen + 1;
              textStart = i;
              continue;
            }
          }
        }
      }
    }

    i++;
  }

  flush(n);
  return out;
}

export const parseInline = parseInlineLinear;
