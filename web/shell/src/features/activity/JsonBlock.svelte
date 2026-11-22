<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  JsonBlock · 只读展示一段结构化数据（参数、结果；untrusted，按纯文本输出）
  标量直接显示；对象/数组缩进 2 格，超过 LIMIT 截断并注明。
-->
<script lang="ts">
  let { value }: { value: unknown } = $props();

  const LIMIT = 20_000;
  const text = $derived.by(() => {
    if (value === null || value === undefined) return '（空）';
    if (typeof value !== 'object') return String(value);
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return '（无法显示）';
    }
  });
  const cut = $derived(text.length > LIMIT);
</script>

<pre class="json mono">{cut ? text.slice(0, LIMIT) : text}</pre>
{#if cut}<p class="cut">内容太长，只显示了前 {LIMIT.toLocaleString()} 个字符</p>{/if}

<style>
  .json {
    max-height: 360px;
    margin: 0;
    padding: var(--s-3);
    overflow: auto;
    border-radius: var(--r-md);
    background: var(--surface-sunk);
    color: var(--text);
    font-size: var(--fs-xs);
    line-height: 1.6;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .cut {
    margin-top: var(--s-2);
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
</style>
