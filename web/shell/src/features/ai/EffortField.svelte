<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  EffortField · 模型思考挡位输入与主流模型清单自动匹配组件
  ───────────────────────────────────────────────────────────────────────────────
  - 默认允许用户直接输入任意自定义思考挡位代号（例如 minimal / xhigh / max / 16384 / off 等）；
  - 实时将当前模型名与内置主流 AI 模型清单比对：
      * 命中清单：自动标出命中的模型家族与推荐默认挡位，并给出该模型官方支持的快捷点选芯片；
      * 未命中且留空：自动兜底为 high；
  - 可展开查看完整的内置主流 AI 思考挡位参考清单。
-->
<script lang="ts">
  import { Input } from '$ui';
  import {
    GENERIC_EFFORT_LEVELS,
    MODEL_EFFORT_CATALOG,
    resolveModelEffort,
  } from '$lib/ai/model-effort-catalog';

  interface Props {
    label?: string;
    model?: string;
    value?: string;
    error?: string;
    compact?: boolean;
  }
  let {
    label = '思考挡位（Effort，可自由填写）',
    model = '',
    value = $bindable(''),
    error,
    compact = false,
  }: Props = $props();

  let catalogOpen = $state(false);

  const resolved = $derived(resolveModelEffort(model, value));
  const chips = $derived<readonly string[]>(resolved.profile ? resolved.profile.levels : GENERIC_EFFORT_LEVELS);
  const placeholder = $derived(
    resolved.profile
      ? `留空自动匹配 ${resolved.profile.defaultEffort}，或直接输入自定义代号`
      : '留空默认不额外注入，或直接输入自定义代号（如 high / max / minimal / 16384）',
  );
</script>

<div class="ef" class:compact>
  <Input
    {label}
    mono
    maxlength={48}
    autocomplete="off"
    {placeholder}
    {error}
    bind:value
  />

  <div class="status-row">
    {#if resolved.source === 'custom'}
      <span class="badge custom">自定义：{resolved.effort}</span>
      <button type="button" class="link-btn" onclick={() => (value = '')}>恢复自动</button>
    {:else if resolved.source === 'catalog' && resolved.profile}
      <span class="badge ok">已匹配 {resolved.profile.family} · 自动 {resolved.effort}</span>
    {:else}
      <span class="badge muted">{model.trim() ? '未命中推理模型清单 · 默认不额外注入' : '自动匹配推理清单 · 非推理模型不强塞'}</span>
    {/if}
    <button type="button" class="link-btn right" onclick={() => (catalogOpen = !catalogOpen)}>
      {catalogOpen ? '收起清单' : '主流模型挡位清单'}
    </button>
  </div>

  <div class="chips" aria-label="快捷选择思考挡位">
    <button
      type="button"
      class="chip"
      class:on={!value.trim()}
      title="留空：命中内置推理清单时自动套用推荐挡位，未命中则不额外注入"
      onclick={() => (value = '')}
    >
      自动 ({resolved.profile ? resolved.profile.defaultEffort : '不注入'})
    </button>
    {#each chips as lv (lv)}
      <button
        type="button"
        class="chip"
        class:on={value.trim().toLowerCase() === lv}
        onclick={() => (value = lv)}
      >
        {lv}{#if resolved.profile?.defaultEffort === lv && value.trim().toLowerCase() !== lv} · 推荐{/if}
      </button>
    {/each}
  </div>

  {#if catalogOpen}
    <div class="catalog" role="region" aria-label="内置主流 AI 模型思考挡位清单">
      <p class="cat-tip">填写模型名后系统会自动按下方推理模型清单匹配挡位；若不在清单内且未自定义，则默认不额外注入（避免非推理接口返回 400）。任何时候都可在上方直接输入自定义代号或数字预算。</p>
      <div class="cat-list">
        {#each MODEL_EFFORT_CATALOG as item (item.family)}
          <div class="cat-row" class:hit={resolved.profile?.family === item.family}>
            <span class="cat-fam">{item.family}</span>
            <span class="cat-lvs">{item.levels.join(' / ')}</span>
            <span class="cat-def">默认 <code>{item.defaultEffort}</code></span>
          </div>
        {/each}
      </div>
    </div>
  {/if}
</div>

<style>
  .ef {
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
    grid-template-columns: minmax(140px, 1.2fr) minmax(120px, 1.5fr) auto;
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
  .cat-lvs {
    font-family: var(--font-mono);
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
