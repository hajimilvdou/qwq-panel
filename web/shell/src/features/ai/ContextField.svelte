<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ContextField · 模型上下文窗口自动匹配与自定义选择组件（对齐 EffortField）
  ───────────────────────────────────────────────────────────────────────────────
  - value 为字符串形式的 token 数（'0' 或 '' 表示自动匹配模型清单，否则为手动覆盖值）
  - 根据 model 名称实时匹配主流 AI 模型官方上下文窗口，并支持一键点选、自定义输入与展开参考清单
-->
<script lang="ts">
  import { Input } from '$ui';
  import {
    CONTEXT_PRESETS,
    MODEL_CONTEXT_CATALOG,
    formatContextTokens,
    resolveModelContext,
  } from '$lib/ai/model-context-catalog';

  interface Props {
    label?: string;
    model?: string;
    value?: string;
    error?: string;
  }
  let {
    label = '上下文窗口大小（自动识别主流模型，可手动覆盖）',
    model = '',
    value = $bindable('0'),
    error,
  }: Props = $props();

  let catalogOpen = $state(false);
  const resolved = $derived(resolveModelContext(model, value));
  const isAuto = $derived((Number.parseInt(String(value || '0'), 10) || 0) <= 0);
  const displayInput = $derived(isAuto ? '' : String(value));

  function handleInput(next: string) {
    const cleaned = next.replace(/[^\d]/g, '');
    value = cleaned ? cleaned : '0';
  }
</script>

<div class="cf">
  <Input
    {label}
    mono
    maxlength={8}
    autocomplete="off"
    placeholder={resolved.profile
      ? `留空自动匹配 ${resolved.profile.label} (${resolved.profile.contextTokens.toLocaleString()})，或输入自定义 token 数`
      : '留空自动默认 128K (128,000)，或输入 1024 ~ 10000000'}
    {error}
    value={displayInput}
    oninput={(e) => handleInput((e.currentTarget as HTMLInputElement).value)}
  />

  <div class="status-row">
    {#if resolved.source === 'custom'}
      <span class="badge custom">自定义：{resolved.label}（{resolved.tokens.toLocaleString()}）</span>
      <button type="button" class="link-btn" onclick={() => (value = '0')}>恢复自动</button>
    {:else if resolved.source === 'catalog' && resolved.profile}
      <span class="badge ok">已匹配 {resolved.profile.family} · 自动 {resolved.label}</span>
    {:else}
      <span class="badge muted">{model.trim() ? '未命中清单 · 自动默认 128K' : '识别模型名后自动选择上下文（默认 128K）'}</span>
    {/if}
    <button type="button" class="link-btn right" onclick={() => (catalogOpen = !catalogOpen)}>
      {catalogOpen ? '收起清单' : '主流模型上下文清单'}
    </button>
  </div>

  <div class="chips" aria-label="快捷选择上下文窗口">
    <button
      type="button"
      class="chip"
      class:on={isAuto}
      title="自动识别模型名并选择官方上下文窗口"
      onclick={() => (value = '0')}
    >
      自动 ({resolved.profile ? resolved.profile.label : '128K'})
    </button>
    {#each CONTEXT_PRESETS as p (p.tokens)}
      <button
        type="button"
        class="chip"
        class:on={!isAuto && Number(value) === p.tokens}
        onclick={() => (value = String(p.tokens))}
      >
        {p.label}{#if resolved.profile && resolved.profile.label === p.label && isAuto} · 匹配{/if}
      </button>
    {/each}
  </div>

  {#if catalogOpen}
    <div class="catalog" role="region" aria-label="主流 AI 模型上下文窗口参考清单">
      <p class="cat-tip">选择「自动」时，面板会按模型名（含后缀如 <code>[1m]</code> / <code>-64k</code>）自动匹配官方上下文窗口用于容量统计与自动压缩；如使用中转自定义上限，随时可手动覆盖。</p>
      <div class="cat-list">
        {#each MODEL_CONTEXT_CATALOG as item (item.family)}
          <div class="cat-row" class:hit={resolved.profile?.family === item.family}>
            <span class="cat-fam">{item.family}</span>
            <span class="cat-note">{item.notes}</span>
            <span class="cat-def"><code>{item.label}</code> ({formatContextTokens(item.contextTokens) === item.label ? item.contextTokens.toLocaleString() : item.label})</span>
          </div>
        {/each}
      </div>
    </div>
  {/if}
</div>

<style>
  .cf {
    display: grid;
    gap: 6px;
    min-width: 0;
  }
  .status-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    font-size: var(--fs-xs);
  }
  .badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--r-pill);
    font-size: var(--fs-2xs);
    font-weight: var(--fw-medium);
  }
  .badge.ok {
    background: var(--ok-soft);
    color: var(--ok-text);
  }
  .badge.custom {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .badge.muted {
    background: var(--surface-2);
    color: var(--text-3);
  }
  .link-btn {
    border: 0;
    background: none;
    padding: 0;
    color: var(--accent-text);
    font: inherit;
    font-size: var(--fs-2xs);
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .link-btn.right {
    margin-left: auto;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }
  .chip {
    padding: 2px 8px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface-2);
    color: var(--text-2);
    font-family: var(--font-mono);
    font-size: var(--fs-2xs);
    cursor: pointer;
  }
  .chip:hover {
    border-color: var(--line-strong);
    color: var(--text);
  }
  .chip.on {
    border-color: var(--accent);
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: var(--fw-semibold);
  }
  .catalog {
    padding: 10px;
    border-radius: var(--r-md);
    border: 1px solid var(--line);
    background: var(--surface-2);
    display: grid;
    gap: 8px;
  }
  .cat-tip {
    margin: 0;
    font-size: var(--fs-2xs);
    color: var(--text-3);
    line-height: 1.5;
  }
  .cat-list {
    display: grid;
    gap: 4px;
    max-height: 200px;
    overflow-y: auto;
  }
  .cat-row {
    display: grid;
    grid-template-columns: minmax(140px, 1.1fr) minmax(130px, 1.5fr) auto;
    gap: 8px;
    align-items: center;
    padding: 4px 6px;
    border-radius: var(--r-sm);
    font-size: var(--fs-2xs);
  }
  .cat-row.hit {
    background: var(--ok-soft);
  }
  .cat-fam {
    font-weight: var(--fw-medium);
    color: var(--text);
  }
  .cat-note {
    color: var(--text-2);
  }
  .cat-def {
    color: var(--text-3);
    white-space: nowrap;
  }
  @media (max-width: 640px) {
    .cat-row {
      grid-template-columns: 1fr;
      gap: 2px;
    }
  }
</style>
