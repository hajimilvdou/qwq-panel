<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Markdown · 安全子集渲染（不可信文本：模型输出、插件说明）
  ───────────────────────────────────────────────────────────────
  <Markdown source={text} />
  逐元素渲染 AST，从不拼 HTML 字符串；语法见 markdown.ts。
  外链新窗口打开并带 noopener noreferrer；站内链接走路由拦截。
-->
<script lang="ts">
  import { createMarkdownCache, type Inline } from './markdown';

  let { source }: { source: string } = $props();

  const cache = createMarkdownCache();
  const blocks = $derived(cache.parse(source));
</script>

{#snippet inline(nodes: Inline[])}
  {#each nodes as n, i (i)}
    {#if n.t === 'text'}{n.v}{:else if n.t === 'br'}<br />{:else if n.t === 'code'}<code>{n.v}</code>{:else if n.t === 'strong'}<strong
        >{@render inline(n.c)}</strong
      >{:else if n.t === 'em'}<em>{@render inline(n.c)}</em>{:else if n.t === 'link'}<a
        href={n.href}
        target={n.href.startsWith('/') ? undefined : '_blank'}
        rel={n.href.startsWith('/') ? undefined : 'noopener noreferrer'}>{@render inline(n.c)}</a
      >{/if}
  {/each}
{/snippet}

<div class="md">
  {#each blocks as b, i (i)}
    {#if b.t === 'p'}
      <p>{@render inline(b.c)}</p>
    {:else if b.t === 'h'}
      <p class="h h{b.level}">{@render inline(b.c)}</p>
    {:else if b.t === 'quote'}
      <blockquote>{@render inline(b.c)}</blockquote>
    {:else if b.t === 'pre'}
      <pre><code>{b.v}</code></pre>
    {:else if b.t === 'list' && b.ordered}
      <ol start={b.start}>
        {#each b.items as item, j (j)}<li>{@render inline(item)}</li>{/each}
      </ol>
    {:else if b.t === 'list'}
      <ul>
        {#each b.items as item, j (j)}<li>{@render inline(item)}</li>{/each}
      </ul>
    {/if}
  {/each}
</div>

<style>
  .md {
    line-height: 1.65;
    overflow-wrap: anywhere;
  }
  .md > :first-child {
    margin-top: 0;
  }
  .md > :last-child {
    margin-bottom: 0;
  }
  p,
  ul,
  ol,
  pre,
  blockquote {
    margin: 0 0 var(--s-2);
  }
  /* 标题不进文档大纲（消息内容不是页面结构），只做视觉强调 */
  .h {
    font-weight: var(--fw-semibold);
    margin-top: var(--s-3);
  }
  .h1 {
    font-size: var(--fs-lg);
  }
  ul,
  ol {
    padding-left: 1.4em;
  }
  li + li {
    margin-top: 2px;
  }
  code {
    font-family: var(--font-mono);
    font-size: 0.92em;
    padding: 1px 5px;
    border-radius: var(--r-xs);
    background: var(--surface-3);
  }
  pre {
    padding: var(--s-3);
    border-radius: var(--r-md);
    background: var(--surface-sunk);
    overflow-x: auto;
  }
  pre code {
    padding: 0;
    background: none;
    white-space: pre;
  }
  blockquote {
    padding-left: var(--s-3);
    border-left: 3px solid var(--line-strong);
    color: var(--text-2);
  }
  a {
    color: var(--accent-text);
    text-decoration: underline;
    text-underline-offset: 2px;
  }
</style>
